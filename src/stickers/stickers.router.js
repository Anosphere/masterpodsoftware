import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import { getStickerPicture, listStickers } from './stickers.handlers.js';

/**
 * Stickers feature router (2026-11-23, spec section 28): two reads.
 * /list-stickers is level "setup", signed like every chat route.
 * /sticker-picture is level "none" and a GET, the first of this server
 * that hands out data: a sticker is the same for everybody, and a picture
 * on a page is fetched by its address alone, with nothing signed.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const stickersRouter = Router();

stickersRouter.post('/list-stickers', requireSetup, listStickers);
stickersRouter.get('/sticker-picture/:set/:number', getStickerPicture);
