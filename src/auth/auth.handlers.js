import { findByUsername } from '../anopods/anopods.queries.js';
import { randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { answer, ok, refuse } from '../util/result.js';
import { issue } from './challenges.queries.js';

/**
 * Route handlers for the auth feature: the one route without a caller.
 * HTTP in and out only, the way anossoftware's handlers are; the challenge
 * itself is made in challenges.queries.js.
 */

/** What /challenge issues for: the two purposes of spec section 5 and the three recovery ones of 12.4.2. */
const PURPOSES = ['create', 'unlock', 'openCase', 'unlockCase', 'recover'];

/**
 * POST /challenge. Body { purpose }, one of create, unlock, openCase,
 * unlockCase and recover; openCase also takes { username }. For 'create' the
 * server mints the id the new pod will have; for 'openCase' it lowercases
 * the username and looks the pod up (404 unknown username) and binds the
 * challenge to that pod's id. Either way the phone passes the id to WebAuthn
 * as the user handle and sends it back in /create-anopod or
 * /open-recovery-case. The other three answer without an id, like 'unlock'.
 */
export async function challenge(req, res) {
  if (!isObject(req.body) || !PURPOSES.includes(req.body.purpose)) return answer(res, refuse(400, 'bad request shape'));
  const { purpose } = req.body;

  let anopodId = null;
  if (purpose === 'create') anopodId = randomId();
  if (purpose === 'openCase') {
    if (typeof req.body.username !== 'string') return answer(res, refuse(400, 'bad request shape'));
    const anopod = await findByUsername(req.body.username.toLowerCase());
    if (anopod === null) return answer(res, refuse(404, 'unknown username'));
    anopodId = anopod.anopodId;
  }

  const issued = await issue(purpose, anopodId);
  const body = { challenge: toHex(issued.challenge), expiresAt: issued.expiresAt.toISOString() };
  if (anopodId !== null) body.anopodId = toHex(anopodId);
  answer(res, ok(200, body));
}
