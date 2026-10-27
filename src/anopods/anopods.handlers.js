import { answer } from '../util/result.js';
import { checkUsername, completeSetup, createAnopod, profile, sessionKeys, status, unlock } from './anopods.service.js';

/**
 * Route handlers for the anoPods feature. HTTP in and out only: read the
 * request, call the service, send the answer. On the routes behind
 * requireSession the caller is req.anopod and req.body is the route's own
 * object; the checking and storing lives in anopods.service.js.
 */

/** POST /create-anopod */
export async function createAnopodHandler(req, res) {
  answer(res, await createAnopod(req.body));
}

/** POST /unlock */
export async function unlockHandler(req, res) {
  answer(res, await unlock(req.body));
}

/** POST /check-username */
export async function checkUsernameHandler(req, res) {
  answer(res, await checkUsername(req.body));
}

/** POST /check-anopod-status */
export async function checkAnopodStatus(req, res) {
  answer(res, await status(req.anopod));
}

/** POST /get-anopod-profile */
export async function getAnopodProfile(req, res) {
  answer(res, await profile(req.body));
}

/** POST /get-anopod-session-keys */
export async function getAnopodSessionKeys(req, res) {
  answer(res, await sessionKeys(req.body));
}

/** POST /complete-setup */
export async function completeSetupHandler(req, res) {
  answer(res, await completeSetup(req.anopod, req.body));
}
