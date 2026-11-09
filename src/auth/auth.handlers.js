import { findById } from '../anopods/anopods.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { answer, ok, refuse } from '../util/result.js';
import { issue } from './challenges.queries.js';

/**
 * Route handlers for the auth feature: the one route without a caller.
 * HTTP in and out only, the way anossoftware's handlers are; the challenge
 * itself is made in challenges.queries.js.
 */

/** What /challenge issues for: the two purposes of spec section 5 and the three recovery ones of 12.4.2; openCase takes the anoPod id the keyholders named (2026-11-08). */
const PURPOSES = ['create', 'unlock', 'openCase', 'unlockCase', 'recover'];

/**
 * POST /challenge. Body { purpose }, one of create, unlock, openCase,
 * unlockCase and recover; openCase also takes { anopodId }, the pod the
 * keyholders named for the person's lookup id (keyholder spec section 15).
 * For 'create' the server mints the id the new pod will have; for
 * 'openCase' it looks the pod up by that id (400 invalid anopodId, 404
 * unknown anopod), binds the challenge to it and answers its username too,
 * so the wallet shows the account found and names the recovery passkey
 * with it. Either way the phone passes the id to WebAuthn as the user
 * handle and sends it back in /create-anopod or /open-recovery-case. The
 * other three answer without an id, like 'unlock'.
 */
export async function challenge(req, res) {
  if (!isObject(req.body) || !PURPOSES.includes(req.body.purpose)) return answer(res, refuse(400, 'bad request shape'));
  const { purpose } = req.body;

  let anopodId = null;
  let anopod = null;
  if (purpose === 'create') anopodId = randomId();
  if (purpose === 'openCase') {
    if (typeof req.body.anopodId !== 'string') return answer(res, refuse(400, 'bad request shape'));
    anopodId = decodeId(req.body.anopodId);
    if (anopodId === null) return answer(res, refuse(400, 'invalid anopodId'));
    anopod = await findById(anopodId);
    if (anopod === null) return answer(res, refuse(404, 'unknown anopod'));
  }

  const issued = await issue(purpose, anopodId);
  const body = { challenge: toHex(issued.challenge), expiresAt: issued.expiresAt.toISOString() };
  if (anopodId !== null) body.anopodId = toHex(anopodId);
  if (anopod !== null) body.username = anopod.username;
  answer(res, ok(200, body));
}
