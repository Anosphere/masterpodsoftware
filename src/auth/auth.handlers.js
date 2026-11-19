import { findById } from '../anopods/anopods.queries.js';
import { env } from '../config/env.js';
import { listAdded } from '../passkeys/added-passkeys.queries.js';
import { openCaseExists } from '../recovery/recovery-cases.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { answer, ok, refuse } from '../util/result.js';
import { issue } from './challenges.queries.js';

/**
 * Route handlers for the auth feature: the one route without a caller.
 * HTTP in and out only, the way anossoftware's handlers are; the challenge
 * itself is made in challenges.queries.js.
 */

/** What /challenge issues for: the two purposes of spec section 5, the three recovery ones of 12.4.2 and, the sixth, addPasskey of section 19 (2026-11-18); openCase takes the anoPod id the keyholders named (2026-11-08), addPasskey the id of the pod the passkey is added to. Since 2026-11-18 (spec section 20) openCase may also take the person's lookup id, is refused 409 case already open when a case is open for it, and answers the credential ids of the pod's passkeys. */
const PURPOSES = ['create', 'unlock', 'openCase', 'unlockCase', 'recover', 'addPasskey'];

/**
 * POST /challenge. Body { purpose }, one of create, unlock, openCase,
 * unlockCase, recover and addPasskey; openCase also takes { anopodId }, the
 * pod the keyholders named for the person's lookup id (keyholder spec
 * section 15). For 'create' the server mints the id the new pod will have;
 * for 'openCase' it looks the pod up by that id (400 invalid anopodId, 404
 * unknown anopod), binds the challenge to it and answers its username too,
 * so the wallet shows the account found and names the recovery passkey
 * with it. Either way the phone passes the id to WebAuthn as the user
 * handle and sends it back in /create-anopod or /open-recovery-case. The
 * sixth purpose, 'addPasskey' (spec section 19), takes { anopodId } too,
 * the pod the passkey is added to: the pod is looked up the same way and
 * the challenge bound to it, the answer carries the id and no username, and
 * the challenge lives ADD_PASSKEY_CHALLENGE_SECONDS, not CHALLENGE_SECONDS.
 * The other three answer without an id, like 'unlock'.
 *
 * Since 2026-11-18 (spec section 20) 'openCase' may also take { lookupId },
 * the person's lookup id, read only when the body has one: not a string is
 * 400 bad request shape, not 32 bytes is 400 invalid lookupId, and a case
 * already open for it is 409 case already open. That is the question
 * /open-recovery-case asks at its check 7, asked here before any passkey
 * is made; at the refusal no challenge is issued and nothing is written.
 * The lookup id is used for that one question and not stored. The answer
 * for 'openCase' also carries credentialIds, the credential ids of the
 * pod's passkeys in hex, the main one first, then the added ones, oldest
 * first: the wallet hands them to the device as the exclude list, so a
 * device that already holds one of them makes no new passkey. 'addPasskey'
 * reads no lookup id and answers no credentialIds.
 */
export async function challenge(req, res) {
  if (!isObject(req.body) || !PURPOSES.includes(req.body.purpose)) return answer(res, refuse(400, 'bad request shape'));
  const { purpose } = req.body;

  let anopodId = null;
  let anopod = null;
  if (purpose === 'create') anopodId = randomId();
  if (purpose === 'openCase' || purpose === 'addPasskey') {
    const hasLookupId = purpose === 'openCase' && req.body.lookupId !== undefined;
    if (typeof req.body.anopodId !== 'string') return answer(res, refuse(400, 'bad request shape'));
    if (hasLookupId && typeof req.body.lookupId !== 'string') return answer(res, refuse(400, 'bad request shape'));
    anopodId = decodeId(req.body.anopodId);
    if (anopodId === null) return answer(res, refuse(400, 'invalid anopodId'));
    const lookupId = hasLookupId ? decodeId(req.body.lookupId) : null;
    if (hasLookupId && lookupId === null) return answer(res, refuse(400, 'invalid lookupId'));
    anopod = await findById(anopodId);
    if (anopod === null) return answer(res, refuse(404, 'unknown anopod'));
    if (hasLookupId && (await openCaseExists(lookupId))) return answer(res, refuse(409, 'case already open'));
  }
  const added = purpose === 'openCase' ? await listAdded(anopodId) : [];

  const issued = await issue(purpose, anopodId, purpose === 'addPasskey' ? env.addPasskeyChallengeSeconds : env.challengeSeconds);
  const body = { challenge: toHex(issued.challenge), expiresAt: issued.expiresAt.toISOString() };
  if (anopodId !== null) body.anopodId = toHex(anopodId);
  if (purpose === 'openCase') body.username = anopod.username;
  if (purpose === 'openCase') body.credentialIds = [toHex(anopod.passKeyCredentialId), ...added.map((row) => toHex(row.passKeyCredentialId))];
  answer(res, ok(200, body));
}
