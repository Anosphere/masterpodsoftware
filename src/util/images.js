import { env } from '../config/env.js';
import { isObject } from './is-object.js';

/**
 * Images on the wire are { contentType, image }: the type of the bytes as
 * stored (for a security image, of the plaintext) and the bytes as base64.
 * Public selfies are plaintext, security images ciphertext; this module does
 * not care which.
 */

/** The three content types a pod may upload. */
export const IMAGE_CONTENT_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

/**
 * Decodes one image object from a request. Returns { contentType, bytes }
 * when the content type is one of the three and the image is base64 of 1 to
 * MAX_IMAGE_BYTES bytes; otherwise { reason }, safe to send back.
 */
export function decodeImage(value) {
  if (!isObject(value)) return { reason: 'image must be an object' };
  const { contentType, image } = value;
  if (!IMAGE_CONTENT_TYPES.includes(contentType)) {
    return { reason: 'contentType must be image/jpeg, image/png or image/webp' };
  }
  const bytes = decodeBase64(image, env.maxImageBytes);
  if (bytes === null) return { reason: `image must be base64 of 1 to ${env.maxImageBytes} bytes` };
  return { contentType, bytes };
}

/**
 * Decodes base64 (standard or URL-safe alphabet, padding optional) to a
 * Buffer of 1 to `maxBytes` bytes. Null for anything else. A string too long
 * to fit is refused before it is decoded.
 */
export function decodeBase64(text, maxBytes) {
  if (typeof text !== 'string' || text.length === 0) return null;
  // Four characters carry three bytes.
  if (text.length > Math.ceil(maxBytes / 3) * 4) return null;
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.length >= 1 && bytes.length <= maxBytes ? bytes : null;
}

/** The wire form of an image row (content_type, image): { contentType, image }. */
export function encodeImage(row) {
  return { contentType: row.content_type, image: row.image.toString('base64') };
}
