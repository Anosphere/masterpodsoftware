import { answer } from '../util/result.js';
import { addPasskey, checkSigningPasskey, listPasskeys } from './passkeys.service.js';

/**
 * Route handlers for the passkeys feature. HTTP in and out only: read the
 * request, call the service, send the answer. /add-passkey and
 * /list-passkeys are behind requireSetup, so the caller is req.anopod and
 * req.body is the route's own object; /check-signing-passkey has no
 * caller; the checking and storing lives in passkeys.service.js.
 */

/** POST /add-passkey */
export async function addPasskeyHandler(req, res) {
  answer(res, await addPasskey(req.anopod, req.body));
}

/** POST /list-passkeys */
export async function listPasskeysHandler(req, res) {
  answer(res, await listPasskeys(req.anopod));
}

/** POST /check-signing-passkey: no caller; req.body is the plain JSON body. */
export async function checkSigningPasskeyHandler(req, res) {
  answer(res, await checkSigningPasskey(req.body));
}
