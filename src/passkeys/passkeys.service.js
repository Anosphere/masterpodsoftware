import { findByCredentialId, findById } from '../anopods/anopods.queries.js';
import { findAccount } from '../anos-accounts/anos-accounts.queries.js';
import { find as findChallenge, take as takeChallenge } from '../auth/challenges.queries.js';
import {
  decodeBase64Url,
  prfEnabled,
  prfResultsPresent,
  verifyAuthentication,
  verifyRegistration,
} from '../auth/webauthn.js';
import { decodeBytes } from '../crypto/bytes.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { notify } from '../notifications/notifications.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { findAddedByCredentialId, insertAdded, listAdded } from './added-passkeys.queries.js';

/**
 * The passkeys feature (spec section 19): more than one passkey on a pod.
 * The main passkey stays on the pod's anopods row, and nothing stored
 * before changes. Each passkey a pod adds is one added_passkeys row: the
 * passkey, and its own copies of the pod's encryption key (its blob1) and
 * of the pod's key blob key, each locked under a key from that passkey's
 * PRF output, which this server cannot open. So every passkey of a pod
 * opens the same two keys. /add-passkey writes a row and /list-passkeys
 * reads them; /unlock finds an added passkey by its credential id
 * (src/anopods/anopods.service.js); the finish of a recovery deletes the
 * pod's rows (src/recovery/recovery.service.js). /check-signing-passkey
 * (spec section 22) answers the signing servers whether a
 * passkey answer is from one of a pod's passkeys; it is at
 * level none and writes nothing. No route removes one
 * passkey, and there is no cap. Each function runs its route's checks in
 * the spec's order (19.3, and 22.4 for /check-signing-passkey) and returns
 * ok(status, body) or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

/** The credential id column takes 16 to 1023 bytes. */
const credentialIdLength = (n) => n >= 16 && n <= 1023;

/** A blob column takes 1 to 1024 bytes. */
const blobLength = (n) => n >= 1 && n <= 1024;

/**
 * POST /add-passkey (setup). Body { challenge, assertion, passkey, blob1,
 * wrappedKeyBlobKey }: the challenge of /challenge addPasskey, the WebAuthn
 * JSON of a fresh tap of a passkey the pod already has, the WebAuthn JSON
 * of the new passkey's registration, and the new passkey's own copies of
 * the pod's encryption key and key blob key (60 bytes each in practice).
 * The one challenge serves both passkey steps. The seven checks of spec
 * 19.3, then one transaction: the challenge consumed, the added_passkeys
 * row with a fresh passkey id, and the passkeyAdded notification to the
 * pod.
 */
export async function addPasskey(anopod, body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.challenge !== 'string' || typeof body.blob1 !== 'string'
    || typeof body.wrappedKeyBlobKey !== 'string' || !isObject(body.assertion)
    || !isObject(body.assertion.response) || !isObject(body.passkey)) {
    return refuse(400, BAD_SHAPE);
  }
  const { assertion, passkey } = body;

  // 2. The two copies: the encryption key under the new passkey's KEK_prf,
  //    and the key blob key under a key from the new passkey's PRF output.
  const blob1 = decodeBytes(body.blob1, blobLength);
  if (blob1 === null) return refuse(400, 'invalid blob1');
  const wrappedKeyBlobKey = decodeBytes(body.wrappedKeyBlobKey, blobLength);
  if (wrappedKeyBlobKey === null) return refuse(400, 'invalid wrappedKeyBlobKey');

  // 3. The challenge: issued for addPasskey, unexpired, bound to the caller's pod.
  const challenge = decodeId(body.challenge);
  const issued = challenge === null ? null : await findChallenge(challenge, 'addPasskey');
  if (issued === null || issued.anopodId === null || !issued.anopodId.equals(anopod.anopodId)) {
    return refuse(401, 'unknown or expired challenge');
  }

  // 4. No PRF output left the phone, in either step; the new passkey supports PRF.
  if (prfResultsPresent(assertion) || prfResultsPresent(passkey)) return refuse(400, 'prf output in request');
  if (!prfEnabled(passkey)) return refuse(400, 'passkey without prf');

  // 5. The fresh tap, by a passkey the pod already has: its main one, or
  //    one it added. A user handle is checked only when the tap carries
  //    one: the passkey is matched to the pod by this server's own rows.
  const tappedId = decodeBase64Url(assertion.rawId);
  let tapped = null;
  if (tappedId !== null) {
    if (tappedId.equals(anopod.passKeyCredentialId)) {
      tapped = anopod;
    } else {
      const added = await findAddedByCredentialId(tappedId);
      if (added !== null && added.anopodId.equals(anopod.anopodId)) tapped = added;
    }
  }
  if (tapped === null) return refuse(401, 'unknown passkey');
  const { userHandle } = assertion.response;
  if (userHandle !== undefined && userHandle !== null) {
    const handle = decodeBase64Url(userHandle);
    if (handle === null || !handle.equals(anopod.anopodId)) return refuse(401, 'user handle mismatch');
  }
  const verified = await verifyAuthentication(assertion, challenge, tapped.passKeyCredentialId, tapped.passKeyPublicKey);
  if (!verified.ok) {
    console.log('passkey verification failed:', verified.reason);
    return refuse(401, 'passkey verification failed');
  }

  // 6. The new passkey's registration, against the same challenge.
  const registration = await verifyRegistration(passkey, challenge);
  if (!registration.ok || !credentialIdLength(registration.credentialId.length)) {
    console.log('passkey verification failed:', registration.reason ?? 'credential id length');
    return refuse(401, 'passkey verification failed');
  }

  // 7. The new passkey is nobody's yet: not a pod's main one, not an added one.
  if ((await findByCredentialId(registration.credentialId)) !== null
    || (await findAddedByCredentialId(registration.credentialId)) !== null) {
    return refuse(409, 'passkey already registered');
  }

  // The writes. The challenge is taken first; if another write got it
  // meanwhile, nothing is written.
  const passkeyId = randomId();
  let createdAt;
  try {
    createdAt = await withTransaction(async (client) => {
      if ((await takeChallenge(client, challenge, 'addPasskey')) === null) return null;
      const insertedAt = await insertAdded(client, {
        passkeyId,
        anopodId: anopod.anopodId,
        passKeyCredentialId: registration.credentialId,
        passKeyPublicKey: registration.publicKey,
        encryptionKeyBlob1: blob1,
        wrappedKeyBlobKey,
      });
      await notify(client, anopod.anopodId, 'passkeyAdded', passkeyId);
      return insertedAt;
    });
    if (createdAt === null) return refuse(401, 'unknown or expired challenge');
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'passkey already registered');
    throw err;
  }

  return ok(201, {
    passkeyId: toHex(passkeyId),
    credentialId: toHex(registration.credentialId),
    createdAt: createdAt.toISOString(),
  });
}

/**
 * POST /list-passkeys (setup). Body { }. The caller's passkeys: the main
 * one, from its anopods row, by its credential id alone (the row keeps no
 * date for it), and the added ones, oldest first. Credential ids are hex,
 * like every id; the names are the wallet's (its settings), not here.
 */
export async function listPasskeys(anopod) {
  const rows = await listAdded(anopod.anopodId);
  return ok(200, {
    main: { credentialId: toHex(anopod.passKeyCredentialId) },
    added: rows.map((row) => ({
      passkeyId: toHex(row.passkeyId),
      credentialId: toHex(row.passKeyCredentialId),
      createdAt: row.createdAt.toISOString(),
    })),
  });
}

/**
 * POST /check-signing-passkey (none). Body { accountId, challenge,
 * assertion }: an anos account's id, a challenge of 32 bytes, and the
 * WebAuthn JSON of a passkey's answer to that challenge. For the signing
 * servers (spec section 22): before one signs for an account, it asks here
 * whether the passkey answer that came with the request is from a passkey
 * of the pod that made the account, and is an answer to the challenge the
 * signing server worked out from the exact thing it is asked to sign.
 * Unsigned, like /get-anos-account: the answer is yes or a refusal, and
 * nothing is written. The challenge is the caller's own, not one of
 * /challenge: the challenges table is neither read nor written, and the
 * same answer may be checked again. The six checks of spec 22.4, in order.
 */
export async function checkSigningPasskey(body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.accountId !== 'string' || typeof body.challenge !== 'string'
    || !isObject(body.assertion) || !isObject(body.assertion.response)) {
    return refuse(400, BAD_SHAPE);
  }
  const { assertion } = body;

  // 2. The account id and the challenge, 32 bytes each.
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  const challenge = decodeId(body.challenge);
  if (challenge === null) return refuse(400, 'invalid challenge');

  // 3. The PRF output stayed on the phone.
  if (prfResultsPresent(assertion)) return refuse(400, 'prf output in request');

  // 4. The account, and the pod that made it.
  const account = await findAccount(accountId);
  const anopod = account === null ? null : await findById(account.anopodId);
  if (anopod === null) return refuse(404, 'unknown account');

  // 5. The passkey that answered is one of that pod's: its main one, or
  //    one it added. A user handle is checked only when the answer carries
  //    one: the passkey is matched to the pod by this server's own rows.
  const credentialId = decodeBase64Url(assertion.rawId);
  let passkey = null;
  if (credentialId !== null) {
    if (credentialId.equals(anopod.passKeyCredentialId)) {
      passkey = anopod;
    } else {
      const added = await findAddedByCredentialId(credentialId);
      if (added !== null && added.anopodId.equals(anopod.anopodId)) passkey = added;
    }
  }
  if (passkey === null) return refuse(401, 'unknown passkey');
  const { userHandle } = assertion.response;
  if (userHandle !== undefined && userHandle !== null) {
    const handle = decodeBase64Url(userHandle);
    if (handle === null || !handle.equals(anopod.anopodId)) return refuse(401, 'user handle mismatch');
  }

  // 6. The answer itself, against that passkey's public key and the challenge.
  const verified = await verifyAuthentication(assertion, challenge, passkey.passKeyCredentialId, passkey.passKeyPublicKey);
  if (!verified.ok) {
    console.log('passkey verification failed:', verified.reason);
    return refuse(401, 'passkey verification failed');
  }
  return ok(200, { accountId: toHex(accountId), verified: true });
}
