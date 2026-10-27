import { find as findChallenge, take as takeChallenge } from '../auth/challenges.queries.js';
import { hasSignatureShape, verifySignatures } from '../auth/signed-request.js';
import {
  decodeBase64Url,
  prfEnabled,
  prfResultsPresent,
  verifyAuthentication,
  verifyRegistration,
} from '../auth/webauthn.js';
import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { ECDSA_P256, ML_DSA_87, decodePublicKey } from '../crypto/signatures.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { decodeId, toHex } from '../util/ids.js';
import { decodeImage } from '../util/images.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  completeSetup as writeSetup,
  countBucketRows,
  countVouches,
  findByCredentialId,
  findById,
  insertAnopod,
  profileOf,
  replaceEphemeralKeys,
  seedStatus,
  usernameTaken,
} from './anopods.queries.js';
import { findSelfie, insertSelfie } from './public-selfies.queries.js';

/**
 * The anoPods feature: creating a pod, opening a session, the username
 * check, status, profile and setup. Each function runs its route's checks in
 * the spec's order (section 5) and returns ok(status, body) or
 * refuse(status, reason), so the handlers only log and answer.
 */

/** A username: 3 to 32 of a-z, 0-9 and underscore. The phone lowercases before signing. */
export const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;

const USERNAME_RULE = 'invalid username: 3 to 32 characters, a-z, 0-9 and _';
const BAD_SHAPE = 'bad request shape';

/** First and last names are 1 to 100 characters. */
const NAME_MAX_CHARS = 100;

/** The credential id column takes 16 to 1023 bytes. */
const credentialIdLength = (n) => n >= 16 && n <= 1023;

/**
 * The eight setup fields and the byte lengths each accepts (spec section 7;
 * blobs up to the column limits), checked in this order. identityBlob is
 * the wallet's (wallet spec 4.1): the public ledger id and lookup id under
 * the encryption key, 92 bytes in practice.
 */
const SETUP_FIELDS = [
  ['blob1', (n) => n >= 1 && n <= 1024],
  ['blob2', (n) => n >= 1 && n <= 1024],
  ['backupCodePublicKey', [33, 65]],
  ['backupCodePublicKeyPq', [2592]],
  ['chatPublicKey', [33, 65]],
  ['chatPublicKeyPq', [1568]],
  ['chatPrivateKeyBlob', (n) => n >= 1 && n <= 16384],
  ['identityBlob', (n) => n >= 1 && n <= 1024],
];

/** When a session opened now stops verifying: now + EPHEMERAL_KEY_HOURS. */
function sessionExpiry() {
  return new Date(Date.now() + env.ephemeralKeyHours * 3_600_000);
}

/**
 * The ephemeral keys inside a /create-anopod or /unlock payload, as Buffers:
 * { ephemeralAuthKey, ephemeralAuthKeyPq }, or null when either does not
 * decode to a key of its algorithm.
 */
function ephemeralKeysOf(payload) {
  const ephemeralAuthKey = decodePublicKey(ECDSA_P256, payload.ephemeralAuthKey);
  const ephemeralAuthKeyPq = decodePublicKey(ML_DSA_87, payload.ephemeralAuthKeyPq);
  if (ephemeralAuthKey === null || ephemeralAuthKeyPq === null) return null;
  return { ephemeralAuthKey, ephemeralAuthKeyPq };
}

/** True for a first or last name: a string of 1 to 100 characters. */
function isName(value) {
  if (typeof value !== 'string') return false;
  const chars = Array.from(value).length;
  return chars >= 1 && chars <= NAME_MAX_CHARS;
}

/** True when the body is a self-signed envelope: an object payload and a {ecdsa, mldsa} pair. */
function hasEnvelopeShape(body) {
  return isObject(body) && isObject(body.payload) && hasSignatureShape(body.signatures);
}

/**
 * POST /create-anopod. The six checks of the spec, then the three writes in
 * one transaction: the pod, its selfie, and the challenge consumed.
 */
export async function createAnopod(body) {
  // 1. Shape.
  if (!hasEnvelopeShape(body)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = body;
  for (const field of ['anopodId', 'challenge', 'firstName', 'lastName', 'username', 'ephemeralAuthKey', 'ephemeralAuthKeyPq']) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (!isObject(payload.selfie) || !isObject(payload.passkey)) return refuse(400, BAD_SHAPE);

  // 2. The challenge: issued for a sign-up, unexpired, minted with this id.
  const anopodId = decodeId(payload.anopodId);
  const challenge = decodeId(payload.challenge);
  const issued = anopodId !== null && challenge !== null ? await findChallenge(challenge, 'create') : null;
  if (issued === null || issued.anopodId === null || !issued.anopodId.equals(anopodId)) {
    return refuse(401, 'unknown or expired challenge');
  }

  // 3. Both signatures, by the ephemeral keys inside the payload.
  const keys = ephemeralKeysOf(payload);
  if (keys === null || !verifySignatures(payload, signatures, keys.ephemeralAuthKey, keys.ephemeralAuthKeyPq)) {
    return refuse(401, 'bad signature');
  }

  // 4. The passkey supports PRF, and its output stayed on the phone.
  if (!prfEnabled(payload.passkey) || prfResultsPresent(payload.passkey)) {
    return refuse(400, 'passkey without prf');
  }

  // 5. The registration itself.
  const registration = await verifyRegistration(payload.passkey, challenge);
  if (!registration.ok || !credentialIdLength(registration.credentialId.length)) {
    console.log('passkey verification failed:', registration.reason ?? 'credential id length');
    return refuse(401, 'passkey verification failed');
  }

  // 6. The profile.
  const { username, firstName, lastName } = payload;
  if (!USERNAME_PATTERN.test(username)) return refuse(400, USERNAME_RULE);
  if (!isName(firstName)) return refuse(400, 'invalid firstName');
  if (!isName(lastName)) return refuse(400, 'invalid lastName');
  const selfie = decodeImage(payload.selfie);
  if (selfie.reason) return refuse(400, `invalid selfie: ${selfie.reason}`);
  if (await usernameTaken(username)) return refuse(409, 'username taken');

  // The writes. The challenge is taken first; if another write got it
  // meanwhile, nothing is written.
  const ephemeralExpiresAt = sessionExpiry();
  try {
    const written = await withTransaction(async (client) => {
      if ((await takeChallenge(client, challenge, 'create')) === null) return false;
      await insertAnopod(client, {
        anopodId,
        firstName,
        lastName,
        username,
        passKeyCredentialId: registration.credentialId,
        passKeyPublicKey: registration.publicKey,
        ephemeralAuthKey: keys.ephemeralAuthKey,
        ephemeralAuthKeyPq: keys.ephemeralAuthKeyPq,
        ephemeralExpiresAt,
      });
      await insertSelfie(client, anopodId, selfie.contentType, selfie.bytes);
      return true;
    });
    if (!written) return refuse(401, 'unknown or expired challenge');
  } catch (err) {
    if (isUniqueViolation(err)) {
      return refuse(409, err.constraint === 'anopods_username_key' ? 'username taken' : 'key already registered');
    }
    throw err;
  }

  return ok(201, {
    anopodId: toHex(anopodId),
    username,
    vouched: false,
    ephemeralExpiresAt: ephemeralExpiresAt.toISOString(),
    success: true,
  });
}

/**
 * POST /unlock. The six checks of the spec, then the new session keys
 * written and the challenge consumed in one transaction.
 */
export async function unlock(body) {
  // 1. Shape.
  if (!hasEnvelopeShape(body)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = body;
  for (const field of ['challenge', 'ephemeralAuthKey', 'ephemeralAuthKeyPq']) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (!isObject(payload.assertion) || !isObject(payload.assertion.response)) return refuse(400, BAD_SHAPE);
  const { assertion } = payload;

  // 2. The challenge: issued for an unlock, unexpired.
  const challenge = decodeId(payload.challenge);
  if (challenge === null || (await findChallenge(challenge, 'unlock')) === null) {
    return refuse(401, 'unknown or expired challenge');
  }

  // 3. The PRF output stayed on the phone.
  if (prfResultsPresent(assertion)) return refuse(400, 'prf output in request');

  // 4. The pod, by the passkey's credential id; its user handle is the pod's id.
  const credentialId = decodeBase64Url(assertion.rawId);
  const anopod = credentialId === null ? null : await findByCredentialId(credentialId);
  if (anopod === null) return refuse(401, 'unknown passkey');
  const userHandle = decodeBase64Url(assertion.response.userHandle);
  if (userHandle === null || !userHandle.equals(anopod.anopodId)) return refuse(401, 'user handle mismatch');

  // 5. Both signatures, by the new ephemeral keys inside the payload.
  const keys = ephemeralKeysOf(payload);
  if (keys === null || !verifySignatures(payload, signatures, keys.ephemeralAuthKey, keys.ephemeralAuthKeyPq)) {
    return refuse(401, 'bad signature');
  }

  // 6. The assertion, against the stored passkey.
  const verified = await verifyAuthentication(assertion, challenge, anopod.passKeyCredentialId, anopod.passKeyPublicKey);
  if (!verified.ok) {
    console.log('passkey verification failed:', verified.reason);
    return refuse(401, 'passkey verification failed');
  }

  // The writes.
  const ephemeralExpiresAt = sessionExpiry();
  try {
    const written = await withTransaction(async (client) => {
      if ((await takeChallenge(client, challenge, 'unlock')) === null) return false;
      await replaceEphemeralKeys(client, anopod.anopodId, keys, ephemeralExpiresAt);
      return true;
    });
    if (!written) return refuse(401, 'unknown or expired challenge');
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'key already registered');
    throw err;
  }

  return ok(200, {
    anopodId: toHex(anopod.anopodId),
    username: anopod.username,
    vouched: anopod.vouched,
    setupComplete: anopod.setupComplete,
    blob1: toHex(anopod.encryptionKeyBlob1),
    chatPrivateKeyBlob: toHex(anopod.chatPrivateKeyBlob),
    identityBlob: toHex(anopod.identityBlob),
    ephemeralExpiresAt: ephemeralExpiresAt.toISOString(),
  });
}

/** POST /check-username. Body { username }; lowercased, checked against the rule, looked up. */
export async function checkUsername(body) {
  if (!isObject(body) || typeof body.username !== 'string') return refuse(400, BAD_SHAPE);
  const username = body.username.toLowerCase();
  if (!USERNAME_PATTERN.test(username)) return refuse(400, USERNAME_RULE);
  return ok(200, { username, available: !(await usernameTaken(username)) });
}

/**
 * POST /check-anopod-status. Read only; the caller is req.anopod. The three
 * counts (wallet spec 4.3) are the caller's rows in each bucket; the
 * wallet's next-step rule reads them.
 */
export async function status(anopod) {
  const [vouchCount, seeds, buckets] = await Promise.all([
    countVouches(anopod.anopodId),
    seedStatus(anopod.anopodId),
    countBucketRows(anopod.anopodId),
  ]);
  return ok(200, {
    anopodId: toHex(anopod.anopodId),
    vouched: anopod.vouched,
    vouchCount,
    setupComplete: anopod.setupComplete,
    isSeed: seeds.isSeed,
    isSuperSeed: seeds.isSuperSeed,
    bucketOneImages: buckets.bucketOneImages,
    bucketTwoImages: buckets.bucketTwoImages,
    bucketTwoInfos: buckets.bucketTwoInfos,
  });
}

/** POST /get-anopod-profile. Body { anopodId }. */
export async function profile(body) {
  if (!isObject(body) || typeof body.anopodId !== 'string') return refuse(400, BAD_SHAPE);
  const anopodId = decodeId(body.anopodId);
  const anopod = anopodId === null ? null : await findById(anopodId);
  if (anopod === null) return refuse(404, 'anopod not found');
  return ok(200, await profileWithSelfie(anopod));
}

/**
 * POST /get-anopod-session-keys (spec 5.10, level none). Body { anopodId }.
 * The pod's current session public keys and their expiry, for the keyholders,
 * which verify a pod's signature against them. Public keys are public.
 */
export async function sessionKeys(body) {
  if (!isObject(body) || typeof body.anopodId !== 'string') return refuse(400, BAD_SHAPE);
  const anopodId = decodeId(body.anopodId);
  if (anopodId === null) return refuse(400, BAD_SHAPE);
  const anopod = await findById(anopodId);
  if (anopod === null) return refuse(404, 'unknown anopod');
  return ok(200, {
    anopodId: toHex(anopod.anopodId),
    ephemeralAuthKey: toHex(anopod.ephemeralAuthKey),
    ephemeralAuthKeyPq: toHex(anopod.ephemeralAuthKeyPq),
    ephemeralExpiresAt: anopod.ephemeralExpiresAt.toISOString(),
  });
}

/** A pod's profile with its selfie, as /get-anopod-profile and /search-usernames answer. */
export async function profileWithSelfie(anopod) {
  const [seeds, selfie] = await Promise.all([seedStatus(anopod.anopodId), findSelfie(anopod.anopodId)]);
  return { ...profileOf(anopod, seeds), selfie };
}

/** POST /complete-setup. The eight fields of spec section 7 (identityBlob the wallet's), written once. */
export async function completeSetup(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  if (anopod.setupComplete) return refuse(409, 'setup already complete');

  const fields = {};
  for (const [name, accept] of SETUP_FIELDS) {
    const bytes = decodeBytes(body[name], accept);
    if (bytes === null) return refuse(400, `invalid ${name}`);
    fields[name] = bytes;
  }

  try {
    await withTransaction((client) => writeSetup(client, anopod.anopodId, fields));
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'key already registered');
    throw err;
  }
  return ok(200, { anopodId: toHex(anopod.anopodId), setupComplete: true });
}
