/**
 * The rules of a sticker (2026-11-23, spec section 28), in one place for
 * the two reads and for scripts/stickers.js. The checks of the three
 * sticker tables in db/schema.sql say the same.
 */

/** A set's name: small letters, digits and hyphens, 1 to 32 characters. */
const SET_NAME = /^[a-z0-9-]{1,32}$/;

/** A sticker's number: two digits. 00 is not one. */
const STICKER_NUMBER = /^[0-9]{2}$/;

/** A sticker's picture is a WebP of at most this many bytes, at most this many pixels wide and this many high. */
export const STICKER_MAX_BYTES = 150_000;
export const STICKER_MAX_WIDTH = 370;
export const STICKER_MAX_HEIGHT = 320;

/** A tag is 1 to this many characters. */
export const TAG_MAX_CHARS = 100;

/** True for a string that is a set's name. */
export function isSetName(value) {
  return typeof value === 'string' && SET_NAME.test(value);
}

/** True for a string that is a sticker's number: 01 to 99. */
export function isStickerNumber(value) {
  return typeof value === 'string' && STICKER_NUMBER.test(value) && value !== '00';
}
