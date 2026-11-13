import test from 'node:test';
import assert from 'node:assert/strict';
import { CursorPage, CursorError, createCursorCodec } from '../src/index.js';

const KEY = 'test-key-do-not-use-in-production';

// A fake clock keeps every timestamp assertion deterministic: no sleeping, no
// flakiness on slow CI machines.
function fixedClock(ms) {
  let current = ms;
  const fn = () => current;
  fn.advance = (delta) => {
    current += delta;
  };
  return fn;
}

test('codec round-trips a JSON payload', () => {
  const codec = createCursorCodec({ key: KEY });
  const cursor = codec.encode({ i: 7 }, 1_000);
  assert.equal(typeof cursor, 'string');
  assert.deepEqual(codec.decode(cursor, 1_001), { i: 7 });
});

test('codec rejects a tampered payload', () => {
  const codec = createCursorCodec({ key: KEY });
  const cursor = codec.encode({ i: 7 }, 1_000);
  // Flip a character in the body half; the MAC must no longer match.
  const [body, mac] = cursor.split('.');
  const flipped = body.slice(0, -1) + (body.endsWith('A') ? 'B' : 'A');
  assert.throws(() => codec.decode(`${flipped}.${mac}`, 1_001), CursorError);
});

test('codec rejects a cursor signed with a different key', () => {
  const a = createCursorCodec({ key: 'key-a' });
  const b = createCursorCodec({ key: 'key-b' });
  const cursor = a.encode({ i: 1 }, 1_000);
  assert.throws(() => b.decode(cursor, 1_001), CursorError);
});

test('codec rejects an expired cursor', () => {
  const codec = createCursorCodec({ key: KEY, ttlMs: 100 });
  const cursor = codec.encode({ i: 1 }, 1_000);
  // Exactly at expiry is expired: the boundary is inclusive on the past side.
  assert.throws(() => codec.decode(cursor, 1_100), CursorError);
  assert.deepEqual(codec.decode(cursor, 1_099), { i: 1 });
});

test('codec rejects malformed cursors', () => {
  const codec = createCursorCodec({ key: KEY });
  for (const bad of ['', 'no-dot', '.onlymac', 'onlybody.', 'a.b.c']) {
    assert.throws(() => codec.decode(bad, 1_000), CursorError);
  }
});

test('codec rejects non-string and empty keys', () => {
  assert.throws(() => createCursorCodec({ key: 42 }), TypeError);
  assert.throws(() => createCursorCodec({ key: '' }), TypeError);
  assert.throws(() => createCursorCodec({ key: Buffer.alloc(0) }), TypeError);
});

test('page returns the first window and a next cursor', () => {
  const clock = fixedClock(1_000);
  const page = new CursorPage({ items: [1, 2, 3, 4, 5], key: KEY, clock });
  const first = page.page({ limit: 2 });
  assert.deepEqual(first.items, [1, 2]);
  assert.equal(typeof first.nextCursor, 'string');
  const second = page.page({ limit: 2, cursor: first.nextCursor });
  assert.deepEqual(second.items, [3, 4]);
  const third = page.page({ limit: 2, cursor: second.nextCursor });
  assert.deepEqual(third.items, [5]);
  assert.equal(third.nextCursor, null);
});

test('page returns an empty page and no cursor when the list is empty', () => {
  const page = new CursorPage({ items: [], key: KEY });
  const result = page.page({ limit: 3 });
  assert.deepEqual(result.items, []);
  assert.equal(result.nextCursor, null);
});

test('page rejects a forged cursor', () => {
  const page = new CursorPage({ items: [1, 2, 3], key: KEY });
  assert.throws(() => page.page({ cursor: 'not-a-real-cursor' }), CursorError);
});

test('page rejects a cursor signed with a different key', () => {
  const signer = new CursorPage({ items: [1, 2, 3, 4], key: 'other-key' });
  const forged = signer.page({ limit: 2 }).nextCursor;
  const victim = new CursorPage({ items: [1, 2, 3, 4], key: KEY });
  assert.throws(() => victim.page({ cursor: forged }), CursorError);
});

test('page rejects a cursor whose payload index is out of range', () => {
  // A validly signed cursor can still be nonsense if the application signed
  // it itself. The page layer re-validates the payload shape.
  const codec = createCursorCodec({ key: KEY });
  const cursor = codec.encode({ i: -1 }, 1_000);
  const page = new CursorPage({ items: [1, 2, 3], key: KEY });
  assert.throws(() => page.page({ cursor }), CursorError);
});

test('page rejects a cursor payload without an integer index', () => {
  const codec = createCursorCodec({ key: KEY });
  const cursor = codec.encode({ i: 'nope' }, 1_000);
  const page = new CursorPage({ items: [1, 2, 3], key: KEY });
  assert.throws(() => page.page({ cursor }), CursorError);
});

test('page honours an injected clock for expiry', () => {
  const clock = fixedClock(1_000);
  const page = new CursorPage({ items: [1, 2, 3, 4], key: KEY, ttlMs: 50, clock });
  const cursor = page.page({ limit: 2 }).nextCursor;
  clock.advance(49);
  assert.deepEqual(page.page({ limit: 2, cursor }).items, [3, 4]);
  clock.advance(1);
  assert.throws(() => page.page({ limit: 2, cursor }), CursorError);
});

test('page validates limit and options', () => {
  const page = new CursorPage({ items: [1, 2, 3], key: KEY });
  assert.throws(() => page.page({ limit: 0 }), TypeError);
  assert.throws(() => page.page({ limit: -1 }), TypeError);
  assert.throws(() => page.page({ limit: 1.5 }), TypeError);
  assert.throws(() => page.page(null), TypeError);
});

test('constructor copies the item list so later mutation cannot change pages', () => {
  const items = [1, 2, 3];
  const page = new CursorPage({ items, key: KEY });
  items.push(4);
  assert.deepEqual(page.page({ limit: 10 }).items, [1, 2, 3]);
});
