import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Error thrown when a cursor is malformed, tampered with, or signed with the
 * wrong key. Callers can distinguish "the client sent us garbage" from "the
 * database is down" by catching this specific class.
 */
export class CursorError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'CursorError';
  }
}

const VERSION = 1;
const DEFAULT_TTL_MS = 60 * 60 * 1000; // one hour

function b64urlEncode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function b64urlDecode(text) {
  return Buffer.from(text, 'base64url');
}

function isPlainObject(value) {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * Create a codec bound to a secret key. The key is copied into a Buffer so a
 * caller mutating the original string later cannot change the MAC behaviour
 * out from under us.
 *
 * @param {{ key: string | Buffer, ttlMs?: number }} options
 */
export function createCursorCodec(options) {
  if (!isPlainObject(options)) {
    throw new TypeError('createCursorCodec requires an options object');
  }
  const { key } = options;
  if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
    throw new TypeError('key must be a string or Buffer');
  }
  const keyBuf = Buffer.from(key);
  if (keyBuf.length === 0) {
    throw new TypeError('key must not be empty');
  }
  const ttlMs = options.ttlMs === undefined ? DEFAULT_TTL_MS : options.ttlMs;
  if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new TypeError('ttlMs must be a positive integer');
  }

  function sign(payloadText) {
    return createHmac('sha256', keyBuf).update(payloadText).digest();
  }

  /**
   * Encode a payload into a signed cursor string.
   *
   * `now` is injected so tests can pin time without sleeping. The default is
   * the real clock, which is what production wants.
   */
  function encode(payload, now = Date.now()) {
    if (!Number.isFinite(now)) {
      throw new TypeError('now must be a finite number');
    }
    const body = {
      v: VERSION,
      iat: now,
      exp: now + ttlMs,
      p: payload === undefined ? null : payload,
    };
    const bodyText = JSON.stringify(body);
    const mac = sign(bodyText);
    return `${b64urlEncode(bodyText)}.${b64urlEncode(mac)}`;
  }

  /**
   * Decode and verify a cursor. Throws CursorError on any failure: wrong
   * shape, bad signature, wrong version, or expiry. We verify the MAC before
   * parsing the JSON so an attacker cannot probe the parser with forged
   * bodies.
   */
  function decode(cursor, now = Date.now()) {
    if (!Number.isFinite(now)) {
      throw new TypeError('now must be a finite number');
    }
    if (typeof cursor !== 'string' || cursor.length === 0) {
      throw new CursorError('cursor must be a non-empty string');
    }
    const dot = cursor.indexOf('.');
    if (dot <= 0 || dot === cursor.length - 1) {
      throw new CursorError('cursor is not in <body>.<mac> form');
    }
    const bodyText = b64urlDecode(cursor.slice(0, dot)).toString('utf8');
    const macBytes = b64urlDecode(cursor.slice(dot + 1));
    const expected = sign(bodyText);
    if (macBytes.length !== expected.length || !timingSafeEqual(macBytes, expected)) {
      throw new CursorError('cursor signature does not match');
    }

    let body;
    try {
      body = JSON.parse(bodyText);
    } catch {
      throw new CursorError('cursor body is not valid JSON');
    }
    if (!isPlainObject(body)) {
      throw new CursorError('cursor body must be a JSON object');
    }
    if (body.v !== VERSION) {
      throw new CursorError('unsupported cursor version');
    }
    if (typeof body.exp !== 'number' || !Number.isFinite(body.exp)) {
      throw new CursorError('cursor is missing an expiry');
    }
    if (now >= body.exp) {
      throw new CursorError('cursor has expired');
    }
    return body.p;
  }

  return { encode, decode };
}

/**
 * A thin wrapper that pairs an ordered list of items with a codec and hands
 * out opaque cursors pointing at positions in that list.
 *
 * The page boundary is encoded as the index of the *next* item to return. That
 * choice means an empty page and a final page are the same shape: the cursor
 * is simply absent when there is nothing left.
 */
export class CursorPage {
  /**
   * @param {object} options
   * @param {Array<unknown>} options.items
   * @param {string | Buffer} options.key
   * @param {number} [options.ttlMs]
   * @param {() => number} [options.clock]
   */
  constructor(options) {
    if (!isPlainObject(options)) {
      throw new TypeError('CursorPage requires an options object');
    }
    const { items, key } = options;
    if (!Array.isArray(items)) {
      throw new TypeError('items must be an array');
    }
    this.items = items.slice();
    this.codec = createCursorCodec({ key, ttlMs: options.ttlMs });
    const clock = options.clock === undefined ? Date.now : options.clock;
    if (typeof clock !== 'function') {
      throw new TypeError('clock must be a function returning a number');
    }
    this.clock = clock;
  }

  /**
   * Return one page of items plus the cursor for the following page.
   *
   * @param {{ cursor?: string | null, limit?: number }} [options]
   * @returns {{ items: Array<unknown>, nextCursor: string | null }}
   */
  page(options = {}) {
    if (!isPlainObject(options)) {
      throw new TypeError('page options must be an object');
    }
    const limit = options.limit === undefined ? 10 : options.limit;
    if (!Number.isInteger(limit) || limit <= 0) {
      throw new TypeError('limit must be a positive integer');
    }
    let start = 0;
    if (options.cursor !== undefined && options.cursor !== null) {
      const payload = this.codec.decode(options.cursor, this.clock());
      if (!isPlainObject(payload) || !Number.isInteger(payload.i) || payload.i < 0) {
        throw new CursorError('cursor payload does not carry a valid index');
      }
      start = payload.i;
    }
    const slice = this.items.slice(start, start + limit);
    const nextIndex = start + slice.length;
    const nextCursor =
      slice.length === limit && nextIndex < this.items.length
        ? this.codec.encode({ i: nextIndex }, this.clock())
        : null;
    return { items: slice, nextCursor };
  }
}
