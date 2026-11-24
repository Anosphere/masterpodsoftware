import { answer } from '../util/result.js';
import { getPicture, listSets } from './stickers.service.js';

/**
 * Route handlers for the stickers feature. HTTP in and out only; the
 * service answers.
 */

/** POST /list-stickers */
export async function listStickers(req, res) {
  answer(res, await listSets());
}

/**
 * GET /sticker-picture/:set/:number. The one answer of this server that
 * is not JSON: the picture's bytes, as image/webp. A refusal is JSON like
 * every other.
 */
export async function getStickerPicture(req, res) {
  const result = await getPicture(req.params.set, req.params.number);
  if (!result.ok) return answer(res, result);
  res.status(result.status).type('image/webp').send(result.body);
}
