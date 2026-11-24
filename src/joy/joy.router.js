import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import { askJoyHandler, getJoyMemoryHandler, setJoyMemoryHandler } from './joy.handlers.js';

/**
 * Joy's feature router (spec section 30): the three routes, all at level
 * setup, for the pod that calls: a message to Joy, and the read and the
 * write of the pod's memory file.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const joyRouter = Router();

joyRouter.post('/ask-joy', requireSetup, askJoyHandler);
joyRouter.post('/get-joy-memory', requireSetup, getJoyMemoryHandler);
joyRouter.post('/set-joy-memory', requireSetup, setJoyMemoryHandler);
