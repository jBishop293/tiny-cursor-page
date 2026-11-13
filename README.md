# tiny-cursor-page

Signs and verifies pagination cursors so a client cannot move the cursor to an
arbitrary offset by editing it.

```js
import { CursorPage } from 'tiny-cursor-page';

const page = new CursorPage({ items: ['a', 'b', 'c', 'd', 'e'], key: 'shared-secret' });

const first = page.page({ limit: 2 });
// { items: ['a', 'b'], nextCursor: 'eyJ2IjoxLCJpYXQiOjE3...' }

const second = page.page({ limit: 2, cursor: first.nextCursor });
// { items: ['c', 'd'], nextCursor: 'eyJ2IjoxLCJpYXQiOjE3...' }

const last = page.page({ limit: 2, cursor: second.nextCursor });
// { items: ['e'], nextCursor: null }
```

The lower-level codec is exported too:

```js
import { createCursorCodec } from 'tiny-cursor-page';

const codec = createCursorCodec({ key: 'shared-secret' });
const cursor = codec.encode({ i: 42 });
codec.decode(cursor); // { i: 42 }
```

## Why this exists

Offset pagination is easy to forge: a client that sees `?offset=20` can ask for
`?offset=2000` and the server has no way to know whether that offset is where
the previous page ended. A cursor that is just a base64-encoded offset is no
better, because base64 is not a signature.

This library wraps the payload in an HMAC-SHA256 tag with a server-held key, so
any edit to the body invalidates the cursor. The trade-off is that cursors are
opaque and stateful: they carry a fixed payload, and changing the payload shape
means invalidating every cursor already handed out. In exchange, the server
never has to trust the client's idea of where it is in the list.

## What it does not do

The codec does not encrypt. The payload is readable base64url JSON; only its
integrity is protected. Do not put secrets in a cursor.

Cursors expire. The default time-to-live is one hour, and the expiry is checked
against the clock the codec was built with. `CursorPage` accepts a `clock`
function so tests can advance time without sleeping; production callers should
leave it out and use the real clock.

## The awkward edge

A cursor is bound to the key that signed it. Rotating the key invalidates every
cursor in flight, and clients holding one will get a `CursorError` on their next
request. That is the intended failure mode: a cursor is a short-lived token, not
a durable identifier. If you need cursors to survive a key rotation, keep the old
key available for verification for at least one TTL.

Another edge: `CursorPage` copies the item array in its constructor. If you
reuse one instance across requests while the underlying data changes, the pages
will reflect the snapshot taken at construction time. Build a new instance per
request, or hand the pagination to a data source that can seek to an index.
