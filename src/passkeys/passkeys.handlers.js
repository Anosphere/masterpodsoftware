import { answer } from '../util/result.js';
import { addPasskey, listPasskeys } from './passkeys.service.js';

/**
 * Route handlers for the passkeys feature. HTTP in and out only: read the
 * request, call the service, send the answer. Both routes are behind
 * requireSetup, so the caller is req.anopod and req.body is the route's own
 * object; the checking and storing lives in passkeys.service.js.
 */

/** POST /add-passkey */
export async function addPasskeyHandler(req, res) {
  answer(res, await addPasskey(req.anopod, req.body));
}

/** POST /list-passkeys */
export async function listPasskeysHandler(req, res) {
  answer(res, await listPasskeys(req.anopod));
}
