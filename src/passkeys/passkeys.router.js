import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import { addPasskeyHandler, checkSigningPasskeyHandler, listPasskeysHandler } from './passkeys.handlers.js';

/**
 * Passkeys feature router (spec section 19): more than one passkey on a
 * pod. Two routes at level setup, for the pod whose passkeys they are,
 * and since 2026-11-20 one at level none, /check-signing-passkey, for the
 * signing servers (spec section 22).
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const passkeysRouter = Router();

passkeysRouter.post('/add-passkey', requireSetup, addPasskeyHandler);
passkeysRouter.post('/list-passkeys', requireSetup, listPasskeysHandler);
passkeysRouter.post('/check-signing-passkey', checkSigningPasskeyHandler);
