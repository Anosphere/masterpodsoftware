import { ok, refuse } from '../util/result.js';
import { isSetName, isStickerNumber } from './sticker-rules.js';
import { findStickerPicture, listStickerSets } from './stickers.queries.js';

/**
 * The stickers of the wallet's chat (2026-11-23, spec section 28): two
 * reads. The stickers are the team's, free and the same for everybody,
 * so neither read looks at who asks. They come into the database by
 * scripts/stickers.js; no route writes them. A sticker that somebody
 * sends is an ordinary encrypted message, which this server cannot tell
 * from any other. Each function returns ok(status, body) or
 * refuse(status, reason).
 */

/**
 * POST /list-stickers. Body {}. Every set in the order of the row, each
 * with its stickers in their order, each sticker with its number and its
 * tags. Text only: no picture travels here.
 */
export async function listSets() {
  return ok(200, { sets: await listStickerSets() });
}

/**
 * GET /sticker-picture/:set/:number. The picture of one sticker, its
 * bytes as a Buffer. A name or a number that cannot be one gets the same
 * answer as a sticker that is not there, and the database is not asked.
 */
export async function getPicture(setName, number) {
  if (!isSetName(setName) || !isStickerNumber(number)) return refuse(404, 'no sticker');
  const image = await findStickerPicture(setName, number);
  if (image === null) return refuse(404, 'no sticker');
  return ok(200, image);
}
