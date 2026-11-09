import { adoptRecoveryPasskey, findById as findAnopod, replaceBackupCode } from '../anopods/anopods.queries.js';
import { profileWithSelfie } from '../anopods/anopods.service.js';
import { findAccount, setBreakGlassBlob } from '../anos-accounts/anos-accounts.queries.js';

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
import { listFor as listSecurityRecords } from '../security/security.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  CASE_STATUSES,
  DEFAULT_LIST_STATUSES,
  FINAL_STATUSES,
  findById as findCase,
  insertCase,
  listByStatus,
  lockById,
  openCaseExists,
  updateStatus,
} from './recovery-cases.queries.js';
import {
  countApprovals,
  insertEvent,
  listForCase as listEvents,
  listForCaseWithUsernames,
  signedOffBy,
} from './recovery-events.queries.js';
import { findByCaseId as findPod, findByCredentialId, insertPod, replaceEphemeralKeys } from './recovery-pods.queries.js';
import { insertShare, listForCase as listShares } from './recovery-shares.queries.js';


/**
 * The recovery feature: the person's side (spec 12.4.2 and 12.4.3), opening
 * a case with its recovery pod, unlocking the recovery pod on a return
 * visit, and reading the case; and the moderator's side (12.4.4), the list,
 * one case, its security buckets, the appointment, the sign-off and the
 * dismissal; and the delivery and the finish (12.4.2, 12.4.3 and 12.4.5):
 * the keyholders' share route, the backup code proof that makes the
 * recovery passkey the pod's, the break-glass blobs, the backup code
 * rotation and the completion. The pattern is src/anopods/: each function
 * runs its route's checks in the spec's order and returns ok(status, body)
 * or refuse(status, reason), so the handlers only log and answer.
 */


const BAD_SHAPE = 'bad request shape';

/** The credential id column takes 16 to 1023 bytes. */
const credentialIdLength = (n) => n >= 16 && n <= 1023;

/** A blob column takes 1 to 1024 bytes. */
const blobLength = (n) => n >= 1 && n <= 1024;

/** Statuses in which the case's pod's blob2 is handed to the person and the bankers may post shares. */
const BLOB2_STATUSES = ['approved', 'delivering'];

/**
 * The events the person sees in /get-recovery-pod (spec 12.4.3) and the
 * detail fields of each: their own opening of the case, the appointment,
 * the verdicts and the finish; never a moderator's id, note or signature.
 */
const PERSON_EVENTS = {
  opened: [],
  scheduled: ['at', 'meetLink'],
  approved: [],
  dismissed: ['reason'],
  recovered: [],
  completed: [],
};

/** When a recovery session opened now stops verifying: now + EPHEMERAL_KEY_HOURS. */
function sessionExpiry() {
  return new Date(Date.now() + env.ephemeralKeyHours * 3_600_000);
}

/**
 * The ephemeral keys inside an /open-recovery-case or /unlock-recovery-pod
 * payload, as Buffers: { ephemeralAuthKey, ephemeralAuthKeyPq }, or null
 * when either does not decode to a key of its algorithm.
 */
function ephemeralKeysOf(payload) {
  const ephemeralAuthKey = decodePublicKey(ECDSA_P256, payload.ephemeralAuthKey);
  const ephemeralAuthKeyPq = decodePublicKey(ML_DSA_87, payload.ephemeralAuthKeyPq);
  if (ephemeralAuthKey === null || ephemeralAuthKeyPq === null) return null;
  return { ephemeralAuthKey, ephemeralAuthKeyPq };
}

/** True when the body is a self-signed envelope: an object payload and a {ecdsa, mldsa} pair. */
function hasEnvelopeShape(body) {
  return isObject(body) && isObject(body.payload) && hasSignatureShape(body.signatures);
}

/** True for a contact email: a string of 3 to 254 characters with an @ that is not first (the column's check). */
function isContactEmail(value) {
  if (typeof value !== 'string') return false;
  const chars = Array.from(value).length;
  return chars >= 3 && chars <= 254 && value.indexOf('@') > 0;
}

/**
 * POST /open-recovery-case. The seven checks of spec 12.4.2, then one
 * transaction: the challenge consumed, the case, its recovery pod and the
 * opened event.
 */
export async function openRecoveryCase(body) {
  // 1. Shape.
  if (!hasEnvelopeShape(body)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = body;
  for (const field of ['anopodId', 'challenge', 'lookupId', 'contactEmail', 'hybridKeyBlob', 'ephemeralAuthKey', 'ephemeralAuthKeyPq']) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (!isObject(payload.passkey) || !isObject(payload.hybridKey)) return refuse(400, BAD_SHAPE);
  if (typeof payload.hybridKey.x25519 !== 'string' || typeof payload.hybridKey.mlkem !== 'string') return refuse(400, BAD_SHAPE);

  // 2. The challenge: issued for openCase, unexpired, bound to this id, the pod the keyholders named for the lookup id, which must exist.
  const anopodId = decodeId(payload.anopodId);
  const challenge = decodeId(payload.challenge);
  const issued = anopodId !== null && challenge !== null ? await findChallenge(challenge, 'openCase') : null;
  if (issued === null || issued.anopodId === null || !issued.anopodId.equals(anopodId)) {
    return refuse(401, 'unknown or expired challenge');
  }
  if ((await findAnopod(anopodId)) === null) return refuse(401, 'unknown or expired challenge');

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

  // 6. The fields.
  const lookupId = decodeId(payload.lookupId);
  if (lookupId === null) return refuse(400, 'invalid lookupId');
  if (!isContactEmail(payload.contactEmail)) return refuse(400, 'invalid contactEmail');
  const hybridKeyX25519 = decodeBytes(payload.hybridKey.x25519, [32]);
  const hybridKeyMlkem = decodeBytes(payload.hybridKey.mlkem, [1568]);
  if (hybridKeyX25519 === null || hybridKeyMlkem === null) return refuse(400, 'invalid hybridKey');
  const hybridKeyBlob = decodeBytes(payload.hybridKeyBlob, blobLength);
  if (hybridKeyBlob === null) return refuse(400, 'invalid hybridKeyBlob');

  // 7. One open case per lookup id.
  if (await openCaseExists(lookupId)) return refuse(409, 'case already open');

  // The writes. The challenge is taken first; if another write got it
  // meanwhile, nothing is written.
  const caseId = randomId();
  const ephemeralExpiresAt = sessionExpiry();
  try {
    const written = await withTransaction(async (client) => {
      if ((await takeChallenge(client, challenge, 'openCase')) === null) return false;
      await insertCase(client, { caseId, lookupId, anopodId, contactEmail: payload.contactEmail });
      await insertPod(client, {
        caseId,
        anopodId,
        passKeyCredentialId: registration.credentialId,
        passKeyPublicKey: registration.publicKey,
        ephemeralAuthKey: keys.ephemeralAuthKey,
        ephemeralAuthKeyPq: keys.ephemeralAuthKeyPq,
        ephemeralExpiresAt,
        hybridKeyX25519,
        hybridKeyMlkem,
        hybridKeyBlob,
      });
      await insertEvent(client, caseId, 'opened', null, {});
      return true;
    });
    if (!written) return refuse(401, 'unknown or expired challenge');
  } catch (err) {
    if (isUniqueViolation(err)) {
      return refuse(409, err.constraint === 'recovery_cases_one_open_per_lookup_id' ? 'case already open' : 'key already registered');
    }
    throw err;
  }

  return ok(201, { caseId: toHex(caseId), status: 'open', ephemeralExpiresAt: ephemeralExpiresAt.toISOString() });
}

/**
 * POST /unlock-recovery-pod. The checks of /unlock against recovery_pods
 * (spec 12.4.2), then the new recovery session keys written and the
 * challenge consumed in one transaction.
 */
export async function unlockRecoveryPod(body) {
  // 1. Shape.
  if (!hasEnvelopeShape(body)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = body;
  for (const field of ['challenge', 'ephemeralAuthKey', 'ephemeralAuthKeyPq']) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (!isObject(payload.assertion) || !isObject(payload.assertion.response)) return refuse(400, BAD_SHAPE);
  const { assertion } = payload;

  // 2. The challenge: issued for unlockCase, unexpired.
  const challenge = decodeId(payload.challenge);
  if (challenge === null || (await findChallenge(challenge, 'unlockCase')) === null) {
    return refuse(401, 'unknown or expired challenge');
  }

  // 3. The PRF output stayed on the phone.
  if (prfResultsPresent(assertion)) return refuse(400, 'prf output in request');

  // 4. The recovery pod, by the passkey's credential id; its user handle is the pod being recovered.
  const credentialId = decodeBase64Url(assertion.rawId);
  const pod = credentialId === null ? null : await findByCredentialId(credentialId);
  if (pod === null) return refuse(401, 'unknown passkey');
  const userHandle = decodeBase64Url(assertion.response.userHandle);
  if (userHandle === null || !userHandle.equals(pod.anopodId)) return refuse(401, 'user handle mismatch');

  // 5. Both signatures, by the new ephemeral keys inside the payload.
  const keys = ephemeralKeysOf(payload);
  if (keys === null || !verifySignatures(payload, signatures, keys.ephemeralAuthKey, keys.ephemeralAuthKeyPq)) {
    return refuse(401, 'bad signature');
  }

  // 6. The assertion, against the stored recovery passkey.
  const verified = await verifyAuthentication(assertion, challenge, pod.passKeyCredentialId, pod.passKeyPublicKey);
  if (!verified.ok) {
    console.log('passkey verification failed:', verified.reason);
    return refuse(401, 'passkey verification failed');
  }

  // The writes.
  const ephemeralExpiresAt = sessionExpiry();
  try {
    const written = await withTransaction(async (client) => {
      if ((await takeChallenge(client, challenge, 'unlockCase')) === null) return false;
      await replaceEphemeralKeys(client, pod.caseId, keys, ephemeralExpiresAt);
      return true;
    });
    if (!written) return refuse(401, 'unknown or expired challenge');
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'key already registered');
    throw err;
  }

  const recoveryCase = await findCase(pod.caseId);
  return ok(200, {
    caseId: toHex(pod.caseId),
    status: recoveryCase?.status ?? null,
    hybridKey: { x25519: toHex(pod.hybridKeyX25519), mlkem: toHex(pod.hybridKeyMlkem) },
    hybridKeyBlob: toHex(pod.hybridKeyBlob),
    ephemeralExpiresAt: ephemeralExpiresAt.toISOString(),
  });
}

/**
 * POST /get-recovery-pod (level recovery). The person's view of their case
 * (spec 12.4.3): the case, the pod's hybrid key and blob, blob2 once the
 * status is approved or delivering, the person's subset of the events, and
 * the shares the keyholders posted, oldest first.
 */
export async function getRecoveryPod(recoveryPod, recoveryCase) {
  const [anopod, events, shares] = await Promise.all([
    findAnopod(recoveryCase.anopodId),
    listEvents(recoveryCase.caseId),
    listShares(recoveryCase.caseId),
  ]);
  return ok(200, {
    caseId: toHex(recoveryCase.caseId),
    status: recoveryCase.status,
    username: anopod?.username ?? null,
    contactEmail: recoveryCase.contactEmail,
    lookupId: toHex(recoveryCase.lookupId),
    hybridKey: { x25519: toHex(recoveryPod.hybridKeyX25519), mlkem: toHex(recoveryPod.hybridKeyMlkem) },
    hybridKeyBlob: toHex(recoveryPod.hybridKeyBlob),
    blob2: BLOB2_STATUSES.includes(recoveryCase.status) ? toHex(anopod?.encryptionKeyBlob2) : null,
    events: events
      .filter((event) => event.kind in PERSON_EVENTS)
      .map((event) => ({ kind: event.kind, details: pick(event.details, PERSON_EVENTS[event.kind]), createdAt: event.createdAt.toISOString() })),
    shares: shares.map((share) => ({
      shareId: toHex(share.shareId),
      keyholderId: share.keyholderId,
      shareType: share.shareType,
      keyId: toHex(share.keyId),
      share: toHex(share.share),
      receivedAt: share.createdAt.toISOString(),
    })),
  });
}

/** The named fields of `details` that are present, nothing else. */
function pick(details, fields) {
  const out = {};
  if (!isObject(details)) return out;
  for (const field of fields) {
    if (details[field] !== undefined) out[field] = details[field];
  }
  return out;
}

// --- the moderator level (spec 12.4.4) ----------------------------------------

/** What a moderator may dismiss a case for (spec 12.4.4). */
export const DISMISS_REASONS = ['selfieMismatch', 'documentsMismatch', 'unknownLookupId', 'noShow', 'other'];

/** A sign-off's verdicts. */
const VERDICTS = ['approve', 'reject'];

/** A note on a sign-off or a dismissal is 0 to 2000 characters. */
const NOTE_MAX_CHARS = 2000;

/** A meeting link is an https URL of at most 500 characters. */
const MEET_LINK_MAX_CHARS = 500;

/** How many distinct pods must sign an approval before the case is approved. */
const APPROVALS_NEEDED = 2;

/** The statuses a case can still be scheduled and signed off in. */
const REVIEW_STATUSES = ['open', 'inReview'];

/** The statuses a case can still be dismissed from: every one but the two final ones. */
const ACTIVE_STATUSES = CASE_STATUSES.filter((status) => !FINAL_STATUSES.includes(status));

/** The two buckets, as the `type` column has them, and the event each one's listing writes. */
const BUCKETS = [1, 2];
const BUCKET_VIEWED = { 1: 'bucketOneViewed', 2: 'bucketTwoViewed' };

/** True for a note: a string of at most 2000 characters. */
function isNote(value) {
  return typeof value === 'string' && Array.from(value).length <= NOTE_MAX_CHARS;
}

/** True for a meeting link: an https URL of at most 500 characters. */
function isMeetLink(value) {
  if (typeof value !== 'string' || value.length > MEET_LINK_MAX_CHARS) return false;
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

/** True for a time: a string Date.parse understands. */
function isTime(value) {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

/** The case a body's `caseId` (hex) names, or null. */
async function findCaseByHex(caseIdHex) {
  const caseId = decodeId(caseIdHex);
  return caseId === null ? null : findCase(caseId);
}

/**
 * Runs `write(client, lockedCase)` in one transaction with the case row
 * locked, after checking under the lock that its status is still one of
 * `statuses`. Returns what `write` returns, or null when the status moved on
 * between the checks and the lock (the caller answers 409 case closed).
 */
function withLockedCase(caseId, statuses, write) {
  return withTransaction(async (client) => {
    const locked = await lockById(client, caseId);
    if (locked === null || !statuses.includes(locked.status)) return null;
    return write(client, locked);
  });
}

/**
 * POST /list-recovery-cases. Body { statuses? }: the cases in those
 * statuses (the four in-progress ones by default), newest first, with the
 * pod's username and names and the count of distinct approving pods.
 */
export async function listRecoveryCases(body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  let statuses = DEFAULT_LIST_STATUSES;
  if (body.statuses !== undefined) {
    if (!Array.isArray(body.statuses) || !body.statuses.every((status) => CASE_STATUSES.includes(status))) {
      return refuse(400, BAD_SHAPE);
    }
    statuses = body.statuses;
  }
  const cases = await listByStatus(statuses);
  return ok(200, {
    cases: cases.map((item) => ({
      caseId: toHex(item.caseId),
      status: item.status,
      lookupId: toHex(item.lookupId),
      username: item.username,
      firstName: item.firstName,
      lastName: item.lastName,
      contactEmail: item.contactEmail,
      approvals: item.approvals,
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
    })),
  });
}

/**
 * POST /get-recovery-case. Body { caseId }. One case for the moderators:
 * the row, the pod's profile with its selfie, every event with the acting
 * moderator's username and its details complete, the shares received (never
 * the share bytes) and the banker packet.
 */
export async function getRecoveryCase(body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const recoveryCase = await findCaseByHex(body.caseId);
  if (recoveryCase === null) return refuse(404, 'unknown case');

  const [anopod, pod, events, shares] = await Promise.all([
    findAnopod(recoveryCase.anopodId),
    findPod(recoveryCase.caseId),
    listForCaseWithUsernames(recoveryCase.caseId),
    listShares(recoveryCase.caseId),
  ]);
  const caseId = toHex(recoveryCase.caseId);
  const lookupId = toHex(recoveryCase.lookupId);
  return ok(200, {
    case: {
      caseId,
      status: recoveryCase.status,
      lookupId,
      contactEmail: recoveryCase.contactEmail,
      createdAt: recoveryCase.createdAt.toISOString(),
      updatedAt: recoveryCase.updatedAt.toISOString(),
    },
    profile: anopod === null ? null : await profileWithSelfie(anopod),
    events: events.map((event) => ({
      eventId: toHex(event.eventId),
      kind: event.kind,
      anopodId: toHex(event.anopodId),
      username: event.username,
      details: event.details,
      createdAt: event.createdAt.toISOString(),
    })),
    shares: shares.map((share) => ({
      keyholderId: share.keyholderId,
      shareType: share.shareType,
      keyId: toHex(share.keyId),
      receivedAt: share.createdAt.toISOString(),
    })),
    bankerPacket: {
      lookupId,
      url: `${env.recoveryPodUrlBase}/receive-recovery-share/${caseId}`,
      hybridKey: pod === null ? null : { x25519: toHex(pod.hybridKeyX25519), mlkem: toHex(pod.hybridKeyMlkem) },
    },
  });
}

/**
 * POST /list-case-security-records. Body { caseId, bucket }, bucket 1 or 2.
 * The case's pod's rows of that bucket in the shape of
 * /list-security-records, oldest first (info is empty for bucket one, which
 * takes no texts), and the bucketOneViewed or bucketTwoViewed event with the
 * distinct key ids answered. The rows are ciphertext under the bucket key
 * the keyholders give the moderator for keyId; this server cannot open them.
 */
export async function listCaseSecurityRecords(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !BUCKETS.includes(body.bucket)) return refuse(400, BAD_SHAPE);
  const recoveryCase = await findCaseByHex(body.caseId);
  if (recoveryCase === null) return refuse(404, 'unknown case');

  const all = await listSecurityRecords(recoveryCase.anopodId);
  const images = all.images.filter((row) => row.type === body.bucket);
  const info = all.info.filter((row) => row.type === body.bucket);
  const keyIds = [...new Set([...images, ...info].map((row) => row.keyId))];
  await withTransaction((client) => insertEvent(client, recoveryCase.caseId, BUCKET_VIEWED[body.bucket], anopod.anopodId, { keyIds }));
  return ok(200, { images, info });
}

/**
 * POST /schedule-recovery-case. Body { caseId, at, meetLink }: the video
 * call. The scheduled event with { at, meetLink } (at normalised to ISO
 * 8601) and status inReview when the case was open.
 */
export async function scheduleRecoveryCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !isTime(body.at) || !isMeetLink(body.meetLink)) return refuse(400, BAD_SHAPE);
  const recoveryCase = await findCaseByHex(body.caseId);
  if (recoveryCase === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case closed');

  const status = await withLockedCase(recoveryCase.caseId, REVIEW_STATUSES, async (client, locked) => {
    await insertEvent(client, locked.caseId, 'scheduled', anopod.anopodId, { at: new Date(body.at).toISOString(), meetLink: body.meetLink });
    if (locked.status === 'open') await updateStatus(client, locked.caseId, 'inReview');
    return 'inReview';
  });
  if (status === null) return refuse(409, 'case closed');
  return ok(200, { caseId: toHex(recoveryCase.caseId), status });
}

/**
 * POST /sign-off-recovery-case. Body { caseId, accountId, verdict, note,
 * signedAt, signatures }: a verdict signed by pair one of an anos account in
 * the moderator's pod. The five checks of spec 12.4.4, then one transaction:
 * the approvalSigned or rejectionSigned event, status inReview when the case
 * was open, and status approved with the approved event once two distinct
 * pods have approved. A rejection changes nothing but the event.
 */
export async function signOffRecoveryCase(anopod, body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.caseId !== 'string' || typeof body.accountId !== 'string'
    || !VERDICTS.includes(body.verdict) || !isNote(body.note) || !isTime(body.signedAt) || !hasSignatureShape(body.signatures)) {
    return refuse(400, BAD_SHAPE);
  }

  // 2. The case, still under review.
  const recoveryCase = await findCaseByHex(body.caseId);
  if (recoveryCase === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case closed');

  // 3. The account lives in the caller's pod.
  const accountId = decodeId(body.accountId);
  const account = accountId === null ? null : await findAccount(accountId);
  if (account === null || !account.anopodId.equals(anopod.anopodId)) return refuse(403, 'not your account');

  // 4. Both signatures over the canonical sign-off message, by pair one of
  //    the account as its stored creation names it.
  const publicKeys = account.creation?.payload?.publicKeys;
  const message = { caseId: body.caseId, accountId: body.accountId, verdict: body.verdict, note: body.note, signedAt: body.signedAt };
  const key1 = isObject(publicKeys) ? decodePublicKey(ECDSA_P256, publicKeys.key1) : null;
  const postQuantumKey1 = isObject(publicKeys) ? decodePublicKey(ML_DSA_87, publicKeys.postQuantumKey1) : null;
  if (!verifySignatures(message, body.signatures, key1, postQuantumKey1)) return refuse(401, 'bad signature');

  // 5. One sign-off per pod per case.
  if (await signedOffBy(recoveryCase.caseId, anopod.anopodId)) return refuse(409, 'already signed off');

  // The writes, with the case locked so two second approvals cannot both
  // count one.
  const outcome = await withLockedCase(recoveryCase.caseId, REVIEW_STATUSES, async (client, locked) => {
    if (await signedOffBy(locked.caseId, anopod.anopodId, client)) return 'already signed off';
    const kind = body.verdict === 'approve' ? 'approvalSigned' : 'rejectionSigned';
    await insertEvent(client, locked.caseId, kind, anopod.anopodId, {
      accountId: body.accountId,
      note: body.note,
      signedAt: body.signedAt,
      signatures: { ecdsa: body.signatures.ecdsa, mldsa: body.signatures.mldsa },
    });
    const approvals = await countApprovals(locked.caseId, client);
    let status = 'inReview';
    if (approvals >= APPROVALS_NEEDED) {
      status = 'approved';
      await insertEvent(client, locked.caseId, 'approved', null, {});
    }
    if (status !== locked.status) await updateStatus(client, locked.caseId, status);
    return { status, approvals };
  });
  if (outcome === null) return refuse(409, 'case closed');
  if (outcome === 'already signed off') return refuse(409, outcome);
  return ok(200, { caseId: toHex(recoveryCase.caseId), status: outcome.status, approvals: outcome.approvals });
}

/**
 * POST /dismiss-recovery-case. Body { caseId, reason, note }, reason one of
 * DISMISS_REASONS. Final: status dismissed and the dismissed event; the
 * lookup id is free for a new case.
 */
export async function dismissRecoveryCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !DISMISS_REASONS.includes(body.reason) || !isNote(body.note)) return refuse(400, BAD_SHAPE);
  const recoveryCase = await findCaseByHex(body.caseId);
  if (recoveryCase === null) return refuse(404, 'unknown case');
  if (!ACTIVE_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case closed');

  const written = await withLockedCase(recoveryCase.caseId, ACTIVE_STATUSES, async (client, locked) => {
    await updateStatus(client, locked.caseId, 'dismissed');
    await insertEvent(client, locked.caseId, 'dismissed', anopod.anopodId, { reason: body.reason, note: body.note });
    return true;
  });
  if (written === null) return refuse(409, 'case closed');
  return ok(200, { caseId: toHex(recoveryCase.caseId), status: 'dismissed' });
}

// --- delivery and the finish (spec 12.4.2, 12.4.3 and 12.4.5) ------------------

/** The two kinds of share the keyholders deliver to a recovery pod (keyholder spec 5.8 and 5.9). */
const SHARE_TYPES = ['backupcode', 'breakglasskey'];

/** A delivered share is the keyholder's hybrid wire of a 33-byte Shamir share (keyholder spec 7.1): exactly 1661 bytes. */
const SHARE_BYTES = 1661;

/** A keyholder id is an integer 1 to 99, as the column has it. */
const isKeyholderId = (value) => Number.isInteger(value) && value >= 1 && value <= 99;

/** The three fields of a rotation (spec 12.4.5) and the byte lengths each accepts, checked in this order. */
const ROTATION_FIELDS = [
  ['newBlob2', blobLength],
  ['newBackupCodePublicKey', [33, 65]],
  ['newBackupCodePublicKeyPq', [2592]],
];

/**
 * POST /receive-recovery-share/:caseId (unsigned; the keyholders' decrypt
 * routes post here, keyholder spec 5.8 and 5.9). Body { keyholderId,
 * lookupId, shareType, keyId, share } as the keyholder sends it. The checks
 * of spec 12.4.2 in order, then one transaction with the case locked: the
 * share (a banker's second send of the same share is a no-op), its
 * shareReceived event, and status delivering when the case was approved.
 * Answers what the bankers' GUI shows: received true, or false for a
 * duplicate.
 */
export async function receiveRecoveryShare(caseIdHex, body) {
  // 1. The case.
  const recoveryCase = typeof caseIdHex === 'string' ? await findCaseByHex(caseIdHex) : null;
  if (recoveryCase === null) return refuse(404, 'unknown case');

  // 2. The case accepts shares: approved or delivering.
  if (!BLOB2_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case not accepting shares');

  // 3. Shape.
  if (!isObject(body) || !isKeyholderId(body.keyholderId) || !SHARE_TYPES.includes(body.shareType) || typeof body.lookupId !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const keyId = decodeId(body.keyId);
  const share = decodeBytes(body.share, [SHARE_BYTES]);
  if (keyId === null || share === null) return refuse(400, BAD_SHAPE);

  // 4. The lookup id is the case's.
  const lookupId = decodeId(body.lookupId);
  if (lookupId === null || !lookupId.equals(recoveryCase.lookupId)) return refuse(400, 'lookup id mismatch');

  // The writes, with the case locked so a dismissal racing the first share
  // sees it. A duplicate writes nothing and answers received false.
  const received = await withLockedCase(recoveryCase.caseId, BLOB2_STATUSES, async (client, locked) => {
    const inserted = await insertShare(client, {
      shareId: randomId(),
      caseId: locked.caseId,
      keyholderId: body.keyholderId,
      lookupId,
      shareType: body.shareType,
      keyId,
      share,
    });
    if (!inserted) return false;
    await insertEvent(client, locked.caseId, 'shareReceived', null, { keyholderId: body.keyholderId, shareType: body.shareType, keyId: toHex(keyId) });
    if (locked.status === 'approved') await updateStatus(client, locked.caseId, 'delivering');
    return true;
  });
  if (received === null) return refuse(409, 'case not accepting shares');
  return ok(200, { caseId: toHex(recoveryCase.caseId), keyholderId: body.keyholderId, shareType: body.shareType, keyId: toHex(keyId), received });
}

/**
 * POST /recover-with-backup-code (level none, signed by the backup code keys
 * inside the payload's proof): the finish. The person has combined the
 * backup code (spec 12.6) and proves it by signing { challenge, caseId,
 * newBlob1 } with the keys it derives. The five checks of spec 12.4.2, then
 * one transaction with the case locked: the challenge consumed, the
 * recovery passkey copied onto the pod with newBlob1 and the live session
 * ended (the lost device's keys die now), the recovered event.
 */
export async function recoverWithBackupCode(body) {
  // 1. Shape.
  if (!hasEnvelopeShape(body)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = body;
  for (const field of ['challenge', 'caseId', 'newBlob1']) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }

  // 2. The challenge: issued for recover, unexpired.
  const challenge = decodeId(payload.challenge);
  if (challenge === null || (await findChallenge(challenge, 'recover')) === null) {
    return refuse(401, 'unknown or expired challenge');
  }

  // 3. The case, ready; its pod, with setup complete; its recovery pod.
  const recoveryCase = await findCaseByHex(payload.caseId);
  if (recoveryCase === null) return refuse(404, 'unknown case');
  if (!BLOB2_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case not ready');
  const [anopod, pod] = await Promise.all([findAnopod(recoveryCase.anopodId), findPod(recoveryCase.caseId)]);
  if (anopod === null || pod === null) return refuse(404, 'unknown case');
  if (!anopod.setupComplete) return refuse(409, 'setup not complete');

  // 4. The proof: both signatures over the canonical payload by the pod's
  //    backup code keys, stored at setup (or at the last rotation).
  if (!verifySignatures(payload, signatures, anopod.backupCodePublicKey, anopod.backupCodePublicKeyPq)) {
    return refuse(401, 'bad signature');
  }

  // 5. The new blob1: the encryption key under the recovery passkey's KEK_prf.
  const newBlob1 = decodeBytes(payload.newBlob1, blobLength);
  if (newBlob1 === null) return refuse(400, 'invalid newBlob1');

  // The writes. The challenge is taken first; if another write got it
  // meanwhile, nothing is written.
  try {
    const written = await withLockedCase(recoveryCase.caseId, BLOB2_STATUSES, async (client, locked) => {
      if ((await takeChallenge(client, challenge, 'recover')) === null) return 'challenge';
      await adoptRecoveryPasskey(client, locked.anopodId, {
        passKeyCredentialId: pod.passKeyCredentialId,
        passKeyPublicKey: pod.passKeyPublicKey,
        blob1: newBlob1,
      });
      await insertEvent(client, locked.caseId, 'recovered', null, {});
      return true;
    });
    if (written === null) return refuse(409, 'case not ready');
    if (written === 'challenge') return refuse(401, 'unknown or expired challenge');
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'key already registered');
    throw err;
  }

  return ok(200, { anopodId: toHex(anopod.anopodId), username: anopod.username, recovered: true });
}

/**
 * POST /complete-recovery-case (level recovery). Body {}. The person closes
 * the case once they are back in: status completed and the completed
 * event, with the case locked. The lookup id is free for a new case from
 * here.
 */
export async function completeRecoveryCase(recoveryCase) {
  if (!BLOB2_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case not ready');
  const written = await withLockedCase(recoveryCase.caseId, BLOB2_STATUSES, async (client, locked) => {
    await updateStatus(client, locked.caseId, 'completed');
    await insertEvent(client, locked.caseId, 'completed', null, {});
    return true;
  });
  if (written === null) return refuse(409, 'case not ready');
  return ok(200, { caseId: toHex(recoveryCase.caseId), status: 'completed' });
}

/**
 * POST /rotate-backup-code (level setup). Body { newBlob2,
 * newBackupCodePublicKey, newBackupCodePublicKeyPq, proof }. The proof is
 * both signatures over the canonical JSON of { anopodId,
 * newBackupCodePublicKey, newBackupCodePublicKeyPq, newBlob2 } by the
 * CURRENT backup code keys: the caller shows it holds the code it is
 * replacing. The shape and lengths, the proof, then the three columns
 * replaced. The phone then deposits the new code with the keyholders.
 */
export async function rotateBackupCode(anopod, body) {
  // 1. Shape and lengths.
  if (!isObject(body) || !hasSignatureShape(body.proof)) return refuse(400, BAD_SHAPE);
  for (const [name] of ROTATION_FIELDS) {
    if (typeof body[name] !== 'string') return refuse(400, BAD_SHAPE);
  }
  const fields = {};
  for (const [name, accept] of ROTATION_FIELDS) {
    const bytes = decodeBytes(body[name], accept);
    if (bytes === null) return refuse(400, `invalid ${name}`);
    fields[name] = bytes;
  }

  // 2. The proof, verified over the message rebuilt from the strings as sent.
  const message = {
    anopodId: toHex(anopod.anopodId),
    newBackupCodePublicKey: body.newBackupCodePublicKey,
    newBackupCodePublicKeyPq: body.newBackupCodePublicKeyPq,
    newBlob2: body.newBlob2,
  };
  if (!verifySignatures(message, body.proof, anopod.backupCodePublicKey, anopod.backupCodePublicKeyPq)) {
    return refuse(401, 'bad signature');
  }

  // The write.
  try {
    await withTransaction((client) => replaceBackupCode(client, anopod.anopodId, fields));
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'key already registered');
    throw err;
  }
  return ok(200, { anopodId: toHex(anopod.anopodId), rotated: true });
}

/**
 * POST /store-break-glass-blob (level setup). Body { accountId,
 * breakGlassBlob }: the account's break-glass seed under the pod's
 * encryption key (60 bytes in practice), stored on the caller's account at
 * the finish of a recovery; a second call replaces it. The row must be the
 * caller's: 404 unknown account otherwise.
 */
export async function storeBreakGlassBlob(anopod, body) {
  if (!isObject(body) || typeof body.accountId !== 'string' || typeof body.breakGlassBlob !== 'string') return refuse(400, BAD_SHAPE);
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  const breakGlassBlob = decodeBytes(body.breakGlassBlob, blobLength);
  if (breakGlassBlob === null) return refuse(400, 'invalid breakGlassBlob');
  if (!(await setBreakGlassBlob(accountId, anopod.anopodId, breakGlassBlob))) return refuse(404, 'unknown account');
  return ok(200, { accountId: toHex(accountId), stored: true });
}
