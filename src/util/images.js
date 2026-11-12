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

/**
 * What is wrong with a plaintext picture (2026-11-12), or null: its bytes
 * must begin as a picture of its content type does, and the width and the
 * height its own header names must each be 1 to `maxSide` pixels. Takes
 * what decodeImage returns. For a picture stored in the clear only (the
 * selfie): a security image is ciphertext, and nothing can be read in it.
 * The reason is safe to send back.
 */
export function pictureProblem({ contentType, bytes }, maxSide) {
  const size = imageSize(contentType, bytes);
  if (size === null) return 'image must be a picture of its contentType';
  if (size.width > maxSide || size.height > maxSide) return `image must be at most ${maxSide} pixels wide and high`;
  return null;
}

/**
 * The width and height a picture names in its own header, or null when the
 * bytes do not begin as a picture of `contentType` does, the header ends
 * early, or it names a width or height of 0. Only the header is read;
 * nothing is decoded, and no read goes past the end of the bytes.
 */
export function imageSize(contentType, bytes) {
  let size = null;
  if (contentType === 'image/jpeg') size = jpegSize(bytes);
  else if (contentType === 'image/png') size = pngSize(bytes);
  else if (contentType === 'image/webp') size = webpSize(bytes);
  return size !== null && size.width >= 1 && size.height >= 1 ? size : null;
}

/**
 * JPEG: FF D8, then segments, each FF, a marker byte and a two-byte length
 * that counts itself. The first frame header (SOF: C0 to CF without C4, C8
 * and CC) carries a precision byte, the height and the width. A scan (DA)
 * or the end (D9) before any frame header is not a picture.
 */
function jpegSize(bytes) {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  let at = 2;
  while (at + 4 <= bytes.length) {
    if (bytes[at] !== 0xff) return null;
    const marker = bytes[at + 1];
    // FF may repeat as fill in front of a marker.
    if (marker === 0xff) {
      at += 1;
      continue;
    }
    if (marker === 0xda || marker === 0xd9 || marker === 0xd8) return null;
    // The markers that stand alone, without a length: TEM and the restarts.
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      at += 2;
      continue;
    }
    const length = bytes.readUInt16BE(at + 2);
    if (length < 2) return null;
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      if (length < 8 || at + 9 > bytes.length) return null;
      return { width: bytes.readUInt16BE(at + 7), height: bytes.readUInt16BE(at + 5) };
    }
    at += 2 + length;
  }
  return null;
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** PNG: the eight signature bytes, then the IHDR chunk first: its length (13), its name, the width and the height. */
function pngSize(bytes) {
  if (bytes.length < 33 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE)) return null;
  if (bytes.readUInt32BE(8) !== 13 || bytes.toString('latin1', 12, 16) !== 'IHDR') return null;
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

/**
 * WebP: RIFF, the file size, WEBP, then the first chunk, which is one of
 * three and keeps the size in its own place. VP8 (lossy): a key frame (bit
 * 0 of the frame tag clear), the start code 9D 01 2A, then 14 bits each of
 * width and height. VP8L (lossless): the byte 2F, then width - 1 and
 * height - 1 in 14 bits each. VP8X (extended): the canvas, width - 1 and
 * height - 1 in 24 bits each, after the flags and three reserved bytes.
 */
function webpSize(bytes) {
  if (bytes.length < 20 || bytes.toString('latin1', 0, 4) !== 'RIFF' || bytes.toString('latin1', 8, 12) !== 'WEBP') return null;
  const chunk = bytes.toString('latin1', 12, 16);
  if (chunk === 'VP8 ') {
    if (bytes.length < 30 || (bytes[20] & 1) !== 0 || bytes[23] !== 0x9d || bytes[24] !== 0x01 || bytes[25] !== 0x2a) return null;
    return { width: bytes.readUInt16LE(26) & 0x3fff, height: bytes.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === 'VP8L') {
    if (bytes.length < 25 || bytes[20] !== 0x2f) return null;
    const bits = bytes.readUInt32LE(21);
    return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
  }
  if (chunk === 'VP8X') {
    if (bytes.length < 30) return null;
    return { width: bytes.readUIntLE(24, 3) + 1, height: bytes.readUIntLE(27, 3) + 1 };
  }
  return null;
}
