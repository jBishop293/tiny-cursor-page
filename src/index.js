// tiny-cursor-page: public entry point.
//
// The cursor format is deliberately unglamorous: a base64url-encoded JSON
// envelope with an HMAC-SHA256 tag. JSON keeps the payload inspectable while
// debugging, and the MAC makes the whole envelope tamper-evident. There is no
// encryption here: cursors are pagination state, not secrets.
export { CursorPage, CursorError, createCursorCodec } from './core.js';
