import { randomBytes } from 'node:crypto';
import { decodeBytes } from '../crypto/bytes.js';

/**
 * Ids: 32 random bytes everywhere (pods, requests, rooms, messages, ...),
 * 64 lowercase hex characters on the wire, BYTEA with a length check in the
 * database. Base64 is accepted on the way in, as for every byte string.
 */

/** Byte length of every id. */
export const ID_BYTES = 32;

/** A fresh random id, as a 32-byte Buffer. */
export function randomId() {
  return randomBytes(ID_BYTES);
}

/** The wire form of raw bytes: lowercase hex. Null and undefined stay null. */
export function toHex(buffer) {
  return buffer === null || buffer === undefined ? null : Buffer.from(buffer).toString('hex');
}

/** Decodes an id from hex or base64. Null unless it is exactly 32 bytes. */
export function decodeId(encoded) {
  return decodeBytes(encoded, [ID_BYTES]);
}
