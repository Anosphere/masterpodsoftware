import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import { addPasskeyHandler, listPasskeysHandler } from './passkeys.handlers.js';

/**
 * Passkeys feature router (spec section 19): more than one passkey on a
 * pod. Two routes, both at level setup, for the pod whose passkeys they
 * are.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const passkeysRouter = Router();

passkeysRouter.post('/add-passkey', requireSetup, addPasskeyHandler);
passkeysRouter.post('/list-passkeys', requireSetup, listPasskeysHandler);
