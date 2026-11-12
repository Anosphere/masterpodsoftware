import { findById as findAnopod } from '../anopods/anopods.queries.js';
import { profileWithSelfie } from '../anopods/anopods.service.js';
import { findAccount } from '../anos-accounts/anos-accounts.queries.js';
import { isAttestorPod, listAttestorPods } from '../auth/require-attestor.js';
import { findChatPublicKeys } from '../chat/chat.queries.js';
import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { notify } from '../notifications/notifications.queries.js';
import { listFor as listSecurityRecords } from '../security/security.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { decodeBase64 } from '../util/images.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { hasAccountSignatureShape, verifyAccountSignatures } from './account-signatures.js';
import {
  CASE_STATUSES,
  DEFAULT_LIST_STATUSES,
  REVIEW_STATUSES,
  findById as findTrade,
  insertTrade,
  listByStatus as listTradesByStatus,
  listForPod as listTradesForPod,
  lockById as lockTrade,
  openTradeExists,
  setLookupId,
  updateStatus as updateTradeStatus,
} from './assisted-trades.queries.js';
import {
  countSignOffs,
  countVerdicts,
  insertEvent,
  listDetails,
  listForCase as listEvents,
  listForCaseWithUsernames,
  signedOffBy,
} from './attestor-events.queries.js';
import {
  clearCaseKeys,
  copyEvidence,
  findById as findEvidence,
  insertEvidence,
  listForCase as listEvidence,
  listForCaseAndPod as listEvidenceOfPod,
} from './escrow-dispute-evidence.queries.js';
import { deleteForCase as deleteKeys, findKey, insertKey, keyExists, listHolders } from './escrow-dispute-keys.queries.js';
import {
  findById as findDispute,
  insertDispute,
  listByStatus as listDisputesByStatus,
  listForPod as listDisputesForPod,
  lockById as lockDispute,
  openDisputeExists,
  updateStatus as updateDisputeStatus,
} from './escrow-disputes.queries.js';

/**
 * The attestation feature (spec section 13): the attestors' side, the six
 * reads of 13.4.3 and the eight writes of 13.4.4 on the two kinds of case,
 * an assisted trade waiting for attestations and a disputed escrow; and the
 * person's side (13.4.5), their cases, the lookup id of a trade case and
 * the evidence of a dispute case. The pattern is src/recovery/: each
 * function runs its route's checks in the spec's order and returns
 * ok(status, body) or refuse(status, reason), so the handlers only log and
 * answer; every write to a case runs with the case row locked and writes
 * its notifications in the same transaction.
 */


const BAD_SHAPE = 'bad request shape';

/** The two kinds of case, each in its own table (13.4.1). */
const TRADE = 'trade';
const DISPUTE = 'dispute';

/** The follow-up types a sign-off is (13.4.2; anossoftware spec 5.2 and 5.6). */
const ATTESTATION = 'attestation';
const ESCROW_VERDICT = 'escrowVerdict';

/** What an attestor may dismiss a case for (spec 13.4.4). */
export const DISMISS_REASONS = ['selfieMismatch', 'documentsMismatch', 'noShow', 'withdrawn', 'settled', 'other'];

/** The two values of an escrow verdict. */
const VERDICTS = ['success', 'cancel'];

/** A note on a dismissal is 0 to 2000 characters. */
const NOTE_MAX_CHARS = 2000;

/** A meeting link is an https URL of at most 500 characters. */
const MEET_LINK_MAX_CHARS = 500;

/** How many distinct pods must sign (an attestation; a verdict of one value) before the case is decided. */
const SIGN_OFFS_NEEDED = 2;

/** The two buckets, as the `type` column has them, and the event each one's listing writes. */
const BUCKETS = [1, 2];
const BUCKET_VIEWED = { 1: 'bucketOneViewed', 2: 'bucketTwoViewed' };

/** /list-anos-account-profiles takes 1 to 200 ids; /open-dispute-case 1 to 200 key wraps. */
const MAX_IDS = 200;

/** The halves of a case key (13.6): X25519 32 bytes, ML-KEM-1024 1568. */
const CASE_KEY_X25519_BYTES = 32;
const CASE_KEY_MLKEM_BYTES = 1568;

/** A wrapped case key is 1 to 4096 bytes (the column), 1725 in practice (13.6). */
const wrappedKeyLength = (n) => n >= 1 && n <= 4096;

/** The four content types evidence may have (13.3). */
const EVIDENCE_CONTENT_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];

/** keyForMe is the content key under the pod encryption key, 60 bytes; keyForCase the content key encrypted to the case key, 1660 (13.6). */
const KEY_FOR_ME_BYTES = 60;
const KEY_FOR_CASE_BYTES = 1660;

/** /add-dispute-evidence takes up to 20 `existing` entries; `files` up to MAX_IMAGES_PER_REQUEST. */
const MAX_EXISTING = 20;

/** /mark-attestor-case-sent: a validator is 1 to 99, `results` 1 to 10 entries, an error at most 500 characters. */
const MAX_RESULTS = 10;
const ERROR_MAX_CHARS = 500;
const isValidatorId = (value) => Number.isInteger(value) && value >= 1 && value <= 99;

/**
 * The events the person sees in /get-my-case (spec 13.4.5) and the detail
 * fields of each: the case's opening, their own sharing and uploads, the
 * appointment, the decision and the end; never an attestor's id, username,
 * note, object or signature, never the other party's uploads. `decided`
 * keeps `verdict` alone, so a trade's decision answers {} and a dispute's
 * { verdict }. The events still name no attestor; since 2026-11-11 a
 * dispute case itself names the attestors on it (`attestors`,
 * disputeAttestors below), for the invite into the marketplace chat
 * (spec section 18).
 */
const PERSON_EVENTS = {
  opened: [],
  lookupIdShared: [],
  evidenceAdded: ['evidenceIds'],
  scheduled: ['at', 'meetLink'],
  decided: ['verdict'],
  lookupIdCleared: [],
  evidenceDeleted: [],
  sent: [],
  dismissed: ['reason'],
};

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

/** The named fields of `details` that are present, nothing else. */
function pick(details, fields) {
  const out = {};
  if (!isObject(details)) return out;
  for (const field of fields) {
    if (details[field] !== undefined) out[field] = details[field];
  }
  return out;
}

/** The trade case a body's `caseId` (hex) names, or null. */
async function findTradeByHex(caseIdHex) {
  const caseId = decodeId(caseIdHex);
  return caseId === null ? null : findTrade(caseId);
}

/** The dispute case a body's `caseId` (hex) names, or null. */
async function findDisputeByHex(caseIdHex) {
  const caseId = decodeId(caseIdHex);
  return caseId === null ? null : findDispute(caseId);
}

/**
 * The case of either kind a body's `caseId` names, { kind, row } with kind
 * TRADE or DISPUTE, or null: assisted_trades first, then escrow_disputes
 * (13.4.1; an id names one row in one table).
 */
async function findCaseByHex(caseIdHex) {
  const trade = await findTradeByHex(caseIdHex);
  if (trade !== null) return { kind: TRADE, row: trade };
  const dispute = await findDisputeByHex(caseIdHex);
  return dispute === null ? null : { kind: DISPUTE, row: dispute };
}

/** The lock and the status update of a kind's table. */
const lockOf = (kind) => (kind === TRADE ? lockTrade : lockDispute);
const updateStatusOf = (kind) => (kind === TRADE ? updateTradeStatus : updateDisputeStatus);

/**
 * The parties of a case (13.4.1): the sender's pod of a trade; the seller's
 * and the buyer's pods of a dispute, once when they are one pod.
 */
function partiesOf(kind, row) {
  if (kind === TRADE) return [row.anopodId];
  return row.anopodId.equals(row.anopodIdTo) ? [row.anopodId] : [row.anopodId, row.anopodIdTo];
}

/** True when `anopodId` is a party to the case. */
const isParty = (kind, row, anopodId) => partiesOf(kind, row).some((pod) => pod.equals(anopodId));

/** Which side of a dispute `anopodId` is on: the seller's pod is the seller, anyone else the buyer. */
const sideOf = (dispute, anopodId) => (dispute.anopodId.equals(anopodId) ? 'seller' : 'buyer');

/**
 * Runs `write(client, lockedCase)` in one transaction with the case row
 * locked by `lock` (the kind's lockById), after checking under the lock
 * that its status is still one of `statuses`. Returns what `write` returns,
 * or null when the status moved on between the checks and the lock (the
 * caller answers 409).
 */
function withLockedCase(lock, caseId, statuses, write) {
  return withTransaction(async (client) => {
    const locked = await lock(client, caseId);
    if (locked === null || !statuses.includes(locked.status)) return null;
    return write(client, locked);
  });
}

/** One notification of `kind` to every party of the case on `client`, the case id as the reference (13.7). */
async function notifyParties(client, kind, row, notificationKind) {
  for (const pod of partiesOf(kind, row)) await notify(client, pod, notificationKind, row.caseId);
}

/** A pod's profile with its selfie, as /get-anopod-profile answers it, or null when the pod's row is gone. */
async function profileOf(anopodId) {
  const anopod = await findAnopod(anopodId);
  return anopod === null ? null : profileWithSelfie(anopod);
}

/** The events of a case as the attestors see them: complete, with the acting pod's username. */
function attestorEvents(events) {
  return events.map((event) => ({
    eventId: toHex(event.eventId),
    kind: event.kind,
    anopodId: toHex(event.anopodId),
    username: event.username,
    details: event.details,
    createdAt: event.createdAt.toISOString(),
  }));
}

/** The clearing of a trade's decision or dismissal on `client`: lookup_id null and the lookupIdCleared event. */
async function clearTrade(client, caseId) {
  await setLookupId(client, caseId, null);
  await insertEvent(client, caseId, 'lookupIdCleared', null, {});
}

/**
 * The clearing of a dispute's decision or dismissal on `client`: the
 * case-key copy removed from every evidence row, every key row deleted, and
 * the evidenceDeleted event with the two counts. From here nobody but the
 * uploaders can open the files.
 */
async function clearDispute(client, caseId) {
  const evidence = await clearCaseKeys(client, caseId);
  const keys = await deleteKeys(client, caseId);
  await insertEvent(client, caseId, 'evidenceDeleted', null, { evidence, keys });
}

// --- the attestor level, reads (spec 13.4.3) --------------------------------------

/**
 * POST /list-attestors. Body {}. Every attestor pod whose setup is complete,
 * username order, with its chat public keys: what the opener's app wraps a
 * case key for.
 */
export async function listAttestors() {
  const pods = await listAttestorPods();
  const keys = new Map((await findChatPublicKeys(pods.map((pod) => pod.anopodId))).map((key) => [key.anopodId, key]));
  return ok(200, {
    attestors: pods.map((pod) => {
      const anopodId = toHex(pod.anopodId);
      const chat = keys.get(anopodId);
      return {
        anopodId,
        username: pod.username,
        firstName: pod.firstName,
        lastName: pod.lastName,
        chatPublicKey: chat?.chatPublicKey ?? null,
        chatPublicKeyPq: chat?.chatPublicKeyPq ?? null,
      };
    }),
  });
}

/**
 * POST /list-anos-account-profiles. Body { accountIds }, 1 to 200 ids. One
 * entry per id in the order given: the account's type and pod with the
 * pod's profile; nulls for an id this server does not know. The lists of
 * trades and disputes from a validator carry account ids; this turns them
 * into people.
 */
export async function listAnosAccountProfiles(body) {
  if (!isObject(body) || !Array.isArray(body.accountIds) || body.accountIds.length < 1 || body.accountIds.length > MAX_IDS
    || !body.accountIds.every((id) => typeof id === 'string')) {
    return refuse(400, BAD_SHAPE);
  }
  const accountIds = body.accountIds.map(decodeId);
  if (accountIds.includes(null)) return refuse(400, 'invalid accountIds');

  const profiles = new Map(); // a pod with several accounts is read once
  const out = [];
  for (const accountId of accountIds) {
    const account = await findAccount(accountId);
    if (account === null) {
      out.push({ accountId: toHex(accountId), accountType: null, anopodId: null, profile: null });
      continue;
    }
    const anopodId = toHex(account.anopodId);
    if (!profiles.has(anopodId)) profiles.set(anopodId, await profileOf(account.anopodId));
    out.push({ accountId: toHex(accountId), accountType: account.accountType, anopodId, profile: profiles.get(anopodId) });
  }
  return ok(200, { profiles: out });
}

/**
 * POST /list-attestor-cases. Body { statuses? }: the cases of both kinds in
 * those statuses (open and inReview by default; an empty list answers no
 * cases), newest first, with the parties' names, the opener's username and
 * the sign-off counts.
 */
export async function listAttestorCases(body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  let statuses = DEFAULT_LIST_STATUSES;
  if (body.statuses !== undefined) {
    if (!Array.isArray(body.statuses) || !body.statuses.every((status) => CASE_STATUSES.includes(status))) {
      return refuse(400, BAD_SHAPE);
    }
    statuses = body.statuses;
  }
  const [trades, disputes] = await Promise.all([listTradesByStatus(statuses), listDisputesByStatus(statuses)]);
  return ok(200, {
    trades: trades.map((item) => ({
      caseId: toHex(item.caseId),
      transactionId: toHex(item.transactionId),
      accountId: toHex(item.accountId),
      status: item.status,
      username: item.username,
      firstName: item.firstName,
      lastName: item.lastName,
      openedBy: item.openedByUsername,
      signOffs: item.signOffs,
      lookupIdShared: item.lookupId !== null,
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
    })),
    disputes: disputes.map((item) => ({
      caseId: toHex(item.caseId),
      transactionId: toHex(item.transactionId),
      accountId: toHex(item.accountId),
      accountIdTo: toHex(item.accountIdTo),
      status: item.status,
      seller: item.seller,
      buyer: item.buyer,
      openedBy: item.openedByUsername,
      signOffs: item.signOffs,
      evidenceCount: item.evidenceCount,
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
    })),
  });
}

/**
 * POST /get-trade-case. Body { caseId }. One trade case for the attestors:
 * the row, the sender's profile with its selfie, every event with the acting
 * pod's username and its details complete (the stored attestations
 * included, for the posting after the decision).
 */
export async function getTradeCase(body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const trade = await findTradeByHex(body.caseId);
  if (trade === null) return refuse(404, 'unknown case');

  const [profile, events] = await Promise.all([profileOf(trade.anopodId), listForCaseWithUsernames(trade.caseId)]);
  return ok(200, {
    case: {
      caseId: toHex(trade.caseId),
      transactionId: toHex(trade.transactionId),
      accountId: toHex(trade.accountId),
      anopodId: toHex(trade.anopodId),
      openedBy: toHex(trade.openedBy),
      lookupId: toHex(trade.lookupId),
      status: trade.status,
      createdAt: trade.createdAt.toISOString(),
      updatedAt: trade.updatedAt.toISOString(),
    },
    profile,
    events: attestorEvents(events),
  });
}

/**
 * POST /get-dispute-case. Body { caseId }. One dispute case for the
 * attestors: the row with the case key, both parties' profiles, the
 * caller's wrapped case key (null when it holds none) and who holds one,
 * every event complete (the stored verdicts included), and every evidence
 * row of both sides with its case-key copy (null after the decision).
 */
export async function getDisputeCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const dispute = await findDisputeByHex(body.caseId);
  if (dispute === null) return refuse(404, 'unknown case');

  const [seller, buyer, myKey, holders, events, evidence] = await Promise.all([
    profileOf(dispute.anopodId),
    profileOf(dispute.anopodIdTo),
    findKey(dispute.caseId, anopod.anopodId),
    listHolders(dispute.caseId),
    listForCaseWithUsernames(dispute.caseId),
    listEvidence(dispute.caseId),
  ]);
  return ok(200, {
    case: {
      caseId: toHex(dispute.caseId),
      transactionId: toHex(dispute.transactionId),
      accountId: toHex(dispute.accountId),
      accountIdTo: toHex(dispute.accountIdTo),
      anopodId: toHex(dispute.anopodId),
      anopodIdTo: toHex(dispute.anopodIdTo),
      disputedBy: toHex(dispute.disputedBy),
      openedBy: toHex(dispute.openedBy),
      caseKey: { x25519: toHex(dispute.caseKeyX25519), mlkem: toHex(dispute.caseKeyMlkem) },
      status: dispute.status,
      createdAt: dispute.createdAt.toISOString(),
      updatedAt: dispute.updatedAt.toISOString(),
    },
    seller,
    buyer,
    myKey: toHex(myKey),
    keyHolders: holders.map(toHex),
    events: attestorEvents(events),
    evidence: evidence.map((row) => ({
      evidenceId: toHex(row.evidenceId),
      anopodId: toHex(row.anopodId),
      username: row.username,
      side: sideOf(dispute, row.anopodId),
      contentType: row.contentType,
      file: row.file.toString('base64'),
      keyForCase: toHex(row.keyForCase),
      createdAt: row.createdAt.toISOString(),
    })),
  });
}

/**
 * POST /list-trade-case-security-records. Body { caseId, bucket }, bucket 1
 * or 2. The sender pod's rows of that bucket in the shape of
 * /list-security-records, oldest first (info is empty for bucket one), and
 * the bucketOneViewed or bucketTwoViewed event with the distinct key ids
 * answered. No status check. The rows are ciphertext under the bucket key
 * the keyholders give the attestor for keyId; this server cannot open them.
 */
export async function listTradeCaseSecurityRecords(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !BUCKETS.includes(body.bucket)) return refuse(400, BAD_SHAPE);
  const trade = await findTradeByHex(body.caseId);
  if (trade === null) return refuse(404, 'unknown case');

  const all = await listSecurityRecords(trade.anopodId);
  const images = all.images.filter((row) => row.type === body.bucket);
  const info = all.info.filter((row) => row.type === body.bucket);
  const keyIds = [...new Set([...images, ...info].map((row) => row.keyId))];
  await withTransaction((client) => insertEvent(client, trade.caseId, BUCKET_VIEWED[body.bucket], anopod.anopodId, { keyIds }));
  return ok(200, { images, info });
}

// --- the attestor level, writes (spec 13.4.4) -------------------------------------

/**
 * POST /open-trade-case. Body { transactionId, accountId }: a case on an
 * assisted trade, the request to the person. The checks of 13.4.4, then one
 * transaction: the case, the opened event, the tradeCaseOpened notification
 * to the sender's pod.
 */
export async function openTradeCase(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const transactionId = decodeId(body.transactionId);
  if (transactionId === null) return refuse(400, 'invalid transactionId');
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  const account = await findAccount(accountId);
  if (account === null) return refuse(404, 'unknown account');
  if (account.accountType !== 'assisted') return refuse(409, 'not an assisted account');
  if (await openTradeExists(transactionId)) return refuse(409, 'case already open');

  const caseId = randomId();
  try {
    await withTransaction(async (client) => {
      await insertTrade(client, { caseId, transactionId, accountId, anopodId: account.anopodId, openedBy: anopod.anopodId });
      await insertEvent(client, caseId, 'opened', anopod.anopodId, { transactionId: toHex(transactionId), accountId: toHex(accountId) });
      await notify(client, account.anopodId, 'tradeCaseOpened', caseId);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'case already open');
    throw err;
  }
  return ok(201, { caseId: toHex(caseId), status: 'open' });
}

/**
 * The `keys` of /open-dispute-case: 1 to 200 entries { anopodId,
 * wrappedKey }, each pod an attestor (13.2), each key 1 to 4096 bytes, no
 * pod twice. Returns [ { anopodId, wrappedKey } ] as Buffers, or null.
 */
async function decodeKeyWraps(keys) {
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > MAX_IDS) return null;
  const out = [];
  const seen = new Set();
  for (const entry of keys) {
    if (!isObject(entry)) return null;
    const anopodId = decodeId(entry.anopodId);
    const wrappedKey = decodeBytes(entry.wrappedKey, wrappedKeyLength);
    if (anopodId === null || wrappedKey === null || seen.has(toHex(anopodId))) return null;
    if (!(await isAttestorPod(anopodId))) return null;
    seen.add(toHex(anopodId));
    out.push({ anopodId, wrappedKey });
  }
  return out;
}

/**
 * POST /open-dispute-case. Body { transactionId, accountId, accountIdTo,
 * disputedBy, caseKey, keys }: a case on a disputed escrow with the case
 * key's public halves and the private halves wrapped to every attestor pod.
 * The checks of 13.4.4 in order, then one transaction: the case, one key
 * row per entry, the opened event, the disputeCaseOpened notification to
 * both parties (the request for evidence).
 */
export async function openDisputeCase(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const ids = {};
  for (const field of ['transactionId', 'accountId', 'accountIdTo', 'disputedBy']) {
    const id = decodeId(body[field]);
    if (id === null) return refuse(400, `invalid ${field}`);
    ids[field] = id;
  }
  if (ids.accountId.equals(ids.accountIdTo)) return refuse(400, 'invalid accountIdTo');
  const seller = await findAccount(ids.accountId);
  if (seller === null) return refuse(404, 'unknown seller account');
  const buyer = await findAccount(ids.accountIdTo);
  if (buyer === null) return refuse(404, 'unknown buyer account');
  if (!ids.disputedBy.equals(ids.accountId) && !ids.disputedBy.equals(ids.accountIdTo)) return refuse(400, 'invalid disputedBy');
  const caseKeyX25519 = isObject(body.caseKey) ? decodeBytes(body.caseKey.x25519, [CASE_KEY_X25519_BYTES]) : null;
  const caseKeyMlkem = isObject(body.caseKey) ? decodeBytes(body.caseKey.mlkem, [CASE_KEY_MLKEM_BYTES]) : null;
  if (caseKeyX25519 === null || caseKeyMlkem === null) return refuse(400, 'invalid caseKey');
  const keys = await decodeKeyWraps(body.keys);
  if (keys === null) return refuse(400, 'invalid keys');
  if (await openDisputeExists(ids.transactionId)) return refuse(409, 'case already open');

  const caseId = randomId();
  const dispute = {
    caseId,
    transactionId: ids.transactionId,
    accountId: ids.accountId,
    accountIdTo: ids.accountIdTo,
    anopodId: seller.anopodId,
    anopodIdTo: buyer.anopodId,
    disputedBy: ids.disputedBy,
    openedBy: anopod.anopodId,
    caseKeyX25519,
    caseKeyMlkem,
  };
  try {
    await withTransaction(async (client) => {
      await insertDispute(client, dispute);
      for (const { anopodId, wrappedKey } of keys) await insertKey(client, caseId, anopodId, wrappedKey);
      await insertEvent(client, caseId, 'opened', anopod.anopodId, {
        transactionId: toHex(ids.transactionId),
        accountId: toHex(ids.accountId),
        accountIdTo: toHex(ids.accountIdTo),
        disputedBy: toHex(ids.disputedBy),
        keyHolders: keys.length,
      });
      await notifyParties(client, DISPUTE, dispute, 'disputeCaseOpened');
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'case already open');
    throw err;
  }
  return ok(201, { caseId: toHex(caseId), status: 'open' });
}

/**
 * POST /schedule-attestor-case. Body { caseId, at, meetLink }, either kind:
 * the video call. Under the case lock: the scheduled event with { at,
 * meetLink } (at normalised to ISO 8601), status inReview when the case was
 * open, the caseScheduled notification to the parties.
 */
export async function scheduleAttestorCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !isTime(body.at) || !isMeetLink(body.meetLink)) return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(found.row.status)) return refuse(409, 'case closed');

  const status = await withLockedCase(lockOf(found.kind), found.row.caseId, REVIEW_STATUSES, async (client, locked) => {
    await insertEvent(client, locked.caseId, 'scheduled', anopod.anopodId, { at: new Date(body.at).toISOString(), meetLink: body.meetLink });
    if (locked.status === 'open') await updateStatusOf(found.kind)(client, locked.caseId, 'inReview');
    await notifyParties(client, found.kind, locked, 'caseScheduled');
    return 'inReview';
  });
  if (status === null) return refuse(409, 'case closed');
  return ok(200, { caseId: toHex(found.row.caseId), status });
}

/**
 * POST /share-case-key. Body { caseId, anopodId, wrappedKey }, a dispute
 * case: a holder of the case key wraps it for an attestor appointed after
 * the case was opened. The checks of 13.4.4 in order, then, under the case
 * lock, the key row and the caseKeyShared event.
 */
export async function shareCaseKey(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || typeof body.anopodId !== 'string' || typeof body.wrappedKey !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const dispute = await findDisputeByHex(body.caseId);
  if (dispute === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(dispute.status)) return refuse(409, 'case closed');
  if (!(await keyExists(dispute.caseId, anopod.anopodId))) return refuse(403, 'no key for this case');
  const anopodId = decodeId(body.anopodId);
  if (anopodId === null || !(await isAttestorPod(anopodId))) return refuse(400, 'not an attestor');
  if (await keyExists(dispute.caseId, anopodId)) return refuse(409, 'key already shared');
  const wrappedKey = decodeBytes(body.wrappedKey, wrappedKeyLength);
  if (wrappedKey === null) return refuse(400, 'invalid wrappedKey');

  try {
    const written = await withLockedCase(lockDispute, dispute.caseId, REVIEW_STATUSES, async (client, locked) => {
      if (await keyExists(locked.caseId, anopodId, client)) return 'shared';
      await insertKey(client, locked.caseId, anopodId, wrappedKey);
      await insertEvent(client, locked.caseId, 'caseKeyShared', anopod.anopodId, { anopodId: toHex(anopodId) });
      return true;
    });
    if (written === null) return refuse(409, 'case closed');
    if (written === 'shared') return refuse(409, 'key already shared');
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'key already shared');
    throw err;
  }
  return ok(200, { caseId: toHex(dispute.caseId), anopodId: toHex(anopodId), shared: true });
}

/**
 * The five checks of spec 13.4.2 on a sign-off `object`, the validators'
 * follow-up of `type` (ATTESTATION or ESCROW_VERDICT) for `caseRow`, by
 * the caller `anopod`: the shape (`fields` the payload's strings, the
 * signatures object), the match with the case, the signer's account
 * (`signer` names the payload field) in the caller's pod and, for a
 * verdict, the caller no party, every present pair verified against the
 * stored creation, one sign-off per pod. Returns { account, payload } or a
 * refusal (ok false).
 */
async function checkSignOff(anopod, type, caseRow, object, fields, signer) {
  // 1. Shape.
  if (!isObject(object) || !isObject(object.payload) || !hasAccountSignatureShape(object.signatures)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = object;
  if (payload.type !== type) return refuse(400, BAD_SHAPE);
  for (const field of fields) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (!isTime(payload.signedAt)) return refuse(400, BAD_SHAPE);
  if (type === ESCROW_VERDICT && !VERDICTS.includes(payload.verdict)) return refuse(400, BAD_SHAPE);

  // 2. The object is about this case.
  const transactionId = decodeId(payload.transactionId);
  if (transactionId === null || !transactionId.equals(caseRow.transactionId)) return refuse(400, 'sign-off does not match the case');
  if (type === ATTESTATION) {
    const accountId = decodeId(payload.accountId);
    if (accountId === null || !accountId.equals(caseRow.accountId)) return refuse(400, 'sign-off does not match the case');
  }

  // 3. The signer's account lives in the caller's pod; a verdict's caller is no party.
  const signerId = decodeId(payload[signer]);
  const account = signerId === null ? null : await findAccount(signerId);
  if (account === null || !account.anopodId.equals(anopod.anopodId)) return refuse(403, 'not your account');
  if (type === ESCROW_VERDICT && isParty(DISPUTE, caseRow, anopod.anopodId)) return refuse(403, 'a party to the escrow');

  // 4. Every present pair, over the canonical bytes of the payload as sent,
  //    against the keys the stored creation names.
  if (!verifyAccountSignatures(account.creation?.payload?.publicKeys, signatures, payload)) return refuse(401, 'bad signature');

  // 5. One sign-off per pod per case.
  if (await signedOffBy(caseRow.caseId, anopod.anopodId)) return refuse(409, 'already signed off');

  return { account, payload };
}

/**
 * POST /sign-off-trade-case. Body { caseId, attestation }, a trade case; the
 * attestation is the validators' follow-up object, verified against the
 * signer's stored creation (13.4.2). Under the case lock: the
 * attestationSigned event with the whole object, status inReview when the
 * case was open, and, once two distinct pods have signed, status decided,
 * the decided event, the lookup id cleared with its event, and the
 * caseDecided notification to the sender's pod.
 */
export async function signOffTradeCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const trade = await findTradeByHex(body.caseId);
  if (trade === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(trade.status)) return refuse(409, 'case closed');
  const checked = await checkSignOff(anopod, ATTESTATION, trade, body.attestation, ['transactionId', 'accountId', 'attestorId', 'signedAt'], 'attestorId');
  if (checked.ok === false) return checked;

  const outcome = await withLockedCase(lockTrade, trade.caseId, REVIEW_STATUSES, async (client, locked) => {
    if (await signedOffBy(locked.caseId, anopod.anopodId, client)) return 'already signed off';
    await insertEvent(client, locked.caseId, 'attestationSigned', anopod.anopodId, {
      attestorId: toHex(checked.account.accountId),
      attestation: body.attestation,
    });
    const signOffs = await countSignOffs(locked.caseId, 'attestationSigned', client);
    let status = 'inReview';
    if (signOffs >= SIGN_OFFS_NEEDED) {
      status = 'decided';
      const attestorIds = (await listDetails(locked.caseId, 'attestationSigned', client)).map((details) => details.attestorId);
      await insertEvent(client, locked.caseId, 'decided', null, { attestorIds });
      await clearTrade(client, locked.caseId);
      await notifyParties(client, TRADE, locked, 'caseDecided');
    }
    if (status !== locked.status) await updateTradeStatus(client, locked.caseId, status);
    return { status, signOffs };
  });
  if (outcome === null) return refuse(409, 'case closed');
  if (outcome === 'already signed off') return refuse(409, outcome);
  return ok(200, { caseId: toHex(trade.caseId), status: outcome.status, signOffs: outcome.signOffs });
}

/**
 * POST /sign-off-dispute-case. Body { caseId, verdict }, a dispute case; the
 * verdict is the validators' escrowVerdict object, verified as above. Under
 * the case lock: the verdictSigned event with the whole object, status
 * inReview when the case was open, and, once two distinct pods have signed
 * the same value, status decided, the decided event, the case-key copies
 * and key rows removed with their event, and the caseDecided notification
 * to both parties. A third attestor may sign while the first two disagree.
 */
export async function signOffDisputeCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const dispute = await findDisputeByHex(body.caseId);
  if (dispute === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(dispute.status)) return refuse(409, 'case closed');
  const checked = await checkSignOff(anopod, ESCROW_VERDICT, dispute, body.verdict, ['transactionId', 'arbitratorId', 'verdict', 'signedAt'], 'arbitratorId');
  if (checked.ok === false) return checked;
  const { verdict } = checked.payload;

  const outcome = await withLockedCase(lockDispute, dispute.caseId, REVIEW_STATUSES, async (client, locked) => {
    if (await signedOffBy(locked.caseId, anopod.anopodId, client)) return 'already signed off';
    await insertEvent(client, locked.caseId, 'verdictSigned', anopod.anopodId, {
      arbitratorId: toHex(checked.account.accountId),
      verdict,
      object: body.verdict,
    });
    const signOffs = await countSignOffs(locked.caseId, 'verdictSigned', client);
    let status = 'inReview';
    let decidedVerdict = null;
    if ((await countVerdicts(locked.caseId, verdict, client)) >= SIGN_OFFS_NEEDED) {
      status = 'decided';
      decidedVerdict = verdict;
      const arbitratorIds = (await listDetails(locked.caseId, 'verdictSigned', client))
        .filter((details) => details.verdict === verdict)
        .map((details) => details.arbitratorId);
      await insertEvent(client, locked.caseId, 'decided', null, { verdict, arbitratorIds });
      await clearDispute(client, locked.caseId);
      await notifyParties(client, DISPUTE, locked, 'caseDecided');
    }
    if (status !== locked.status) await updateDisputeStatus(client, locked.caseId, status);
    return { status, signOffs, decidedVerdict };
  });
  if (outcome === null) return refuse(409, 'case closed');
  if (outcome === 'already signed off') return refuse(409, outcome);
  return ok(200, { caseId: toHex(dispute.caseId), status: outcome.status, signOffs: outcome.signOffs, decidedVerdict: outcome.decidedVerdict });
}

/**
 * POST /mark-attestor-case-sent. Body { caseId, validator, results }, either
 * kind: the app posted the stored objects to validator `validator` and
 * records the answers, a failed post included; a later retry writes another
 * event. The case must be decided. Under the case lock: the sent event
 * with { validator, results }.
 */
export async function markAttestorCaseSent(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !isValidatorId(body.validator)
    || !Array.isArray(body.results) || body.results.length < 1 || body.results.length > MAX_RESULTS) {
    return refuse(400, BAD_SHAPE);
  }
  const results = [];
  for (const entry of body.results) {
    if (!isObject(entry) || !Number.isInteger(entry.status)) return refuse(400, BAD_SHAPE);
    const signer = decodeId(entry.signer);
    if (signer === null) return refuse(400, BAD_SHAPE);
    if (entry.error !== undefined && (typeof entry.error !== 'string' || Array.from(entry.error).length > ERROR_MAX_CHARS)) return refuse(400, BAD_SHAPE);
    results.push(entry.error === undefined ? { signer: toHex(signer), status: entry.status } : { signer: toHex(signer), status: entry.status, error: entry.error });
  }
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');
  if (found.row.status !== 'decided') return refuse(409, 'case not decided');

  const written = await withLockedCase(lockOf(found.kind), found.row.caseId, ['decided'], async (client, locked) => {
    await insertEvent(client, locked.caseId, 'sent', anopod.anopodId, { validator: body.validator, results });
    return true;
  });
  if (written === null) return refuse(409, 'case not decided');
  return ok(200, { caseId: toHex(found.row.caseId), status: 'decided' });
}

/**
 * POST /dismiss-attestor-case. Body { caseId, reason, note }, either kind,
 * reason one of DISMISS_REASONS. Final: under the case lock, status
 * dismissed, the dismissed event, the clearing of a decision (the lookup id
 * of a trade; the case-key copies and key rows of a dispute, each with its
 * event) and the caseDismissed notification to the parties. Another
 * attestor may open a new case on the same transaction.
 */
export async function dismissAttestorCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !DISMISS_REASONS.includes(body.reason) || !isNote(body.note)) return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(found.row.status)) return refuse(409, 'case closed');

  const written = await withLockedCase(lockOf(found.kind), found.row.caseId, REVIEW_STATUSES, async (client, locked) => {
    await updateStatusOf(found.kind)(client, locked.caseId, 'dismissed');
    await insertEvent(client, locked.caseId, 'dismissed', anopod.anopodId, { reason: body.reason, note: body.note });
    if (found.kind === TRADE) await clearTrade(client, locked.caseId);
    else await clearDispute(client, locked.caseId);
    await notifyParties(client, found.kind, locked, 'caseDismissed');
    return true;
  });
  if (written === null) return refuse(409, 'case closed');
  return ok(200, { caseId: toHex(found.row.caseId), status: 'dismissed' });
}

// --- the setup level, the person (spec 13.4.5) ------------------------------------

/** A trade case as the person sees it (13.4.5). */
function personTrade(trade) {
  return {
    caseId: toHex(trade.caseId),
    transactionId: toHex(trade.transactionId),
    accountId: toHex(trade.accountId),
    status: trade.status,
    lookupIdShared: trade.lookupId !== null,
    createdAt: trade.createdAt.toISOString(),
    updatedAt: trade.updatedAt.toISOString(),
  };
}

/**
 * The attestors on a dispute case, as its two traders see them
 * (2026-11-11): [ { anopodId, username } ], the acting pods of the case's
 * events, each once, in the order they first acted, so the attestor who
 * opened the case comes first. A pod that is a party to the case is left
 * out (a party writes events too: evidenceAdded), and so is a pod that
 * holds no live appointment as attestor any more.
 */
async function disputeAttestors(dispute) {
  const attestors = [];
  const seen = new Set();
  for (const event of await listForCaseWithUsernames(dispute.caseId)) {
    if (event.anopodId === null) continue;
    const anopodId = toHex(event.anopodId);
    if (seen.has(anopodId)) continue;
    seen.add(anopodId);
    if (isParty(DISPUTE, dispute, event.anopodId) || !(await isAttestorPod(event.anopodId))) continue;
    attestors.push({ anopodId, username: event.username });
  }
  return attestors;
}

/**
 * A dispute case as a party sees it (13.4.5), with their side. Since
 * 2026-11-11 a dispute names the attestors on it, `attestors`, as
 * disputeAttestors lists them, for the invite into the marketplace chat of
 * the trade (spec section 18).
 */
function personDispute(dispute, anopodId, attestors) {
  return {
    caseId: toHex(dispute.caseId),
    transactionId: toHex(dispute.transactionId),
    accountId: toHex(dispute.accountId),
    accountIdTo: toHex(dispute.accountIdTo),
    side: sideOf(dispute, anopodId),
    attestors,
    status: dispute.status,
    createdAt: dispute.createdAt.toISOString(),
    updatedAt: dispute.updatedAt.toISOString(),
  };
}

/**
 * The person's subset of a case's events (13.4.5): the kinds of
 * PERSON_EVENTS with their named fields alone, and of evidenceAdded only
 * the caller's own; never an attestor's id, username, note, object or
 * signature.
 */
function personEvents(events, anopodId) {
  return events
    .filter((event) => event.kind in PERSON_EVENTS && (event.kind !== 'evidenceAdded' || (event.anopodId !== null && event.anopodId.equals(anopodId))))
    .map((event) => ({ kind: event.kind, details: pick(event.details, PERSON_EVENTS[event.kind]), createdAt: event.createdAt.toISOString() }));
}

/**
 * POST /list-my-cases. Body {}. The cases where the caller's pod is a
 * party, newest first, trades and disputes apart; every dispute with the
 * attestors on it.
 */
export async function listMyCases(anopod) {
  const [trades, disputes] = await Promise.all([listTradesForPod(anopod.anopodId), listDisputesForPod(anopod.anopodId)]);
  const personDisputes = [];
  for (const dispute of disputes) {
    personDisputes.push(personDispute(dispute, anopod.anopodId, await disputeAttestors(dispute)));
  }
  return ok(200, {
    trades: trades.map(personTrade),
    disputes: personDisputes,
  });
}

/**
 * POST /get-my-case. Body { caseId }. The person's view of one of their
 * cases, either kind: the case, their subset of the events and, for a
 * dispute, the attestors on it, the case key and their own evidence rows
 * with keyForMe. A case the caller is no party to is 404 unknown case,
 * like one that does not exist.
 */
export async function getMyCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null || !isParty(found.kind, found.row, anopod.anopodId)) return refuse(404, 'unknown case');

  const events = personEvents(await listEvents(found.row.caseId), anopod.anopodId);
  if (found.kind === TRADE) return ok(200, { kind: TRADE, case: personTrade(found.row), events });

  const evidence = await listEvidenceOfPod(found.row.caseId, anopod.anopodId);
  const attestors = await disputeAttestors(found.row);
  return ok(200, {
    kind: DISPUTE,
    case: {
      ...personDispute(found.row, anopod.anopodId, attestors),
      caseKey: { x25519: toHex(found.row.caseKeyX25519), mlkem: toHex(found.row.caseKeyMlkem) },
    },
    events,
    evidence: evidence.map((row) => ({
      evidenceId: toHex(row.evidenceId),
      contentType: row.contentType,
      file: row.file.toString('base64'),
      keyForMe: toHex(row.keyForMe),
      createdAt: row.createdAt.toISOString(),
    })),
  });
}

/**
 * POST /share-lookup-id. Body { caseId, lookupId }, a trade case of the
 * caller's pod: the 32 bytes the wallet opened from the identity blob, what
 * the attestor pulls the bucket keys by. The checks of 13.4.5, then, under
 * the case lock: lookup_id, the lookupIdShared event, status inReview when
 * the case was open.
 */
export async function shareLookupId(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || typeof body.lookupId !== 'string') return refuse(400, BAD_SHAPE);
  const trade = await findTradeByHex(body.caseId);
  if (trade === null || !trade.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(trade.status)) return refuse(409, 'case closed');
  if (trade.lookupId !== null) return refuse(409, 'lookup id already shared');
  const lookupId = decodeId(body.lookupId);
  if (lookupId === null) return refuse(400, 'invalid lookupId');

  const status = await withLockedCase(lockTrade, trade.caseId, REVIEW_STATUSES, async (client, locked) => {
    if (locked.lookupId !== null) return 'shared';
    await setLookupId(client, locked.caseId, lookupId);
    await insertEvent(client, locked.caseId, 'lookupIdShared', anopod.anopodId, {});
    if (locked.status === 'open') await updateTradeStatus(client, locked.caseId, 'inReview');
    return 'inReview';
  });
  if (status === null) return refuse(409, 'case closed');
  if (status === 'shared') return refuse(409, 'lookup id already shared');
  return ok(200, { caseId: toHex(trade.caseId), status });
}

/**
 * POST /add-dispute-evidence. Body { caseId, files?, existing? }, a dispute
 * case of the caller's pod: new files, each ciphertext with its content key
 * wrapped twice, and files of the caller's from any case supplied again
 * with a new case-key wrap (the server copies the row). The checks of
 * 13.4.5 in order, then, under the case lock: one row per file, one copy
 * per existing entry, the evidenceAdded event with every new id, status
 * inReview when the case was open. Once the case is decided the case key
 * is gone, so a closed case takes nothing.
 */
export async function addDisputeEvidence(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string'
    || (body.files !== undefined && !Array.isArray(body.files)) || (body.existing !== undefined && !Array.isArray(body.existing))) {
    return refuse(400, BAD_SHAPE);
  }
  const dispute = await findDisputeByHex(body.caseId);
  if (dispute === null || !isParty(DISPUTE, dispute, anopod.anopodId)) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(dispute.status)) return refuse(409, 'case closed');
  const files = body.files ?? [];
  const existing = body.existing ?? [];
  if (files.length + existing.length < 1 || files.length > env.maxImagesPerRequest || existing.length > MAX_EXISTING) return refuse(400, BAD_SHAPE);

  const rows = [];
  for (const entry of files) {
    if (!isObject(entry)) return refuse(400, BAD_SHAPE);
    if (!EVIDENCE_CONTENT_TYPES.includes(entry.contentType)) return refuse(400, 'invalid contentType');
    const file = decodeBase64(entry.file, env.maxImageBytes);
    if (file === null) return refuse(400, 'invalid file');
    const keyForMe = decodeBytes(entry.keyForMe, [KEY_FOR_ME_BYTES]);
    if (keyForMe === null) return refuse(400, 'invalid keyForMe');
    const keyForCase = decodeBytes(entry.keyForCase, [KEY_FOR_CASE_BYTES]);
    if (keyForCase === null) return refuse(400, 'invalid keyForCase');
    rows.push({ contentType: entry.contentType, file, keyForMe, keyForCase });
  }
  const copies = [];
  for (const entry of existing) {
    if (!isObject(entry) || typeof entry.evidenceId !== 'string') return refuse(400, BAD_SHAPE);
    const keyForCase = decodeBytes(entry.keyForCase, [KEY_FOR_CASE_BYTES]);
    if (keyForCase === null) return refuse(400, 'invalid keyForCase');
    const evidenceId = decodeId(entry.evidenceId);
    const source = evidenceId === null ? null : await findEvidence(evidenceId);
    if (source === null || !source.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown evidence');
    copies.push({ fromEvidenceId: evidenceId, keyForCase });
  }

  const evidenceIds = await withLockedCase(lockDispute, dispute.caseId, REVIEW_STATUSES, async (client, locked) => {
    const ids = [];
    for (const row of rows) {
      const evidenceId = randomId();
      await insertEvidence(client, { evidenceId, caseId: locked.caseId, anopodId: anopod.anopodId, ...row });
      ids.push(evidenceId);
    }
    for (const copy of copies) {
      const evidenceId = randomId();
      if (!(await copyEvidence(client, { evidenceId, caseId: locked.caseId, anopodId: anopod.anopodId, ...copy }))) {
        throw new Error('evidence row vanished between the check and the copy');
      }
      ids.push(evidenceId);
    }
    await insertEvent(client, locked.caseId, 'evidenceAdded', anopod.anopodId, { evidenceIds: ids.map(toHex) });
    if (locked.status === 'open') await updateDisputeStatus(client, locked.caseId, 'inReview');
    return ids;
  });
  if (evidenceIds === null) return refuse(409, 'case closed');
  return ok(201, { evidenceIds: evidenceIds.map(toHex) });
}
