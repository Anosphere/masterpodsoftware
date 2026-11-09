import { findById as findAnopod } from '../anopods/anopods.queries.js';
import { profileWithSelfie } from '../anopods/anopods.service.js';
import { findAccount } from '../anos-accounts/anos-accounts.queries.js';
import { hasAccountSignatureShape, verifyAccountSignatures } from '../attesting/account-signatures.js';
import { CASE_STATUSES, DEFAULT_LIST_STATUSES, REVIEW_STATUSES } from '../attesting/assisted-trades.queries.js';
import {
  countSignOffs,
  insertEvent,
  listDetails,
  listForCase as listEvents,
  listForCaseWithUsernames,
  signedOffBy,
} from '../attesting/attestor-events.queries.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { findById as findRecoveryCase } from '../recovery/recovery-cases.queries.js';
import { listForCaseWithUsernames as listRecoveryEvents } from '../recovery/recovery-events.queries.js';
import { listFor as listSecurityRecords } from '../security/security.queries.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  findCase,
  findMove,
  insertCase,
  insertMove,
  listCasesByStatus,
  listCasesForPod,
  listMoves,
  lockCase,
  updateStatus,
} from './break-glass.queries.js';

/**
 * The break-glass feature (spec section 14): the recovery case as the
 * attestors see it. The person's side (14.4.1): the finish of a recovery
 * files the breakGlassTransfers it posted to a validator, one per old
 * account whose keys died with the passkey, and the person's wallet reads
 * the case's progress. The attestors' side (14.4.2): the cases beside the
 * trades, one case with the recovery case's lookup id and its two moderator
 * approvals, the buckets, the appointment, one attestation per move signed
 * in one pass, the posting to a validator and the dismissal. The pattern is
 * src/attesting/: each function runs its route's checks in the spec's order
 * and returns ok(status, body) or refuse(status, reason), so the handlers
 * only log and answer; every write to a case runs with the case row locked.
 * The attestors' actions are attestor_events rows with the recovery case's
 * id, as trades and disputes share that log; the sign-off checks are those
 * of 13.4.2 (account-signatures.js), applied to each move's attestation.
 */

const BAD_SHAPE = 'bad request shape';

/** A filing names 1 to 20 moves, one per old account that holds anos; a sign-off one attestation per move. */
const MAX_MOVES = 20;

/** The three ids of a move as the wallet files it, decoded in this order. */
const MOVE_FIELDS = ['accountId', 'accountIdTo', 'transactionId'];

/** The recovery case statuses a filing is accepted in: the finish runs while the shares are delivered, and Retry may run after the case was completed. */
const FILING_STATUSES = ['delivering', 'completed'];

/** The follow-up type a sign-off is (13.4.2; anossoftware spec 5.2) and its payload's strings beside `type`. */
const ATTESTATION = 'attestation';
const ATTESTATION_FIELDS = ['transactionId', 'accountId', 'attestorId', 'signedAt'];

/** What an attestor may dismiss a case for (spec 14.4.2). */
export const DISMISS_REASONS = ['selfieMismatch', 'documentsMismatch', 'noShow', 'withdrawn', 'other'];

/** A note on a dismissal is 0 to 2000 characters. */
const NOTE_MAX_CHARS = 2000;

/** A meeting link is an https URL of at most 500 characters. */
const MEET_LINK_MAX_CHARS = 500;

/** How many distinct pods must sign before the case is decided. */
const SIGN_OFFS_NEEDED = 2;

/** The two buckets, as the `type` column has them, and the event each one's listing writes. */
const BUCKETS = [1, 2];
const BUCKET_VIEWED = { 1: 'bucketOneViewed', 2: 'bucketTwoViewed' };

/** /mark-break-glass-case-sent: a validator is 1 to 99, `results` 1 to 40 entries (two attestations per move), an error at most 500 characters. */
const MAX_RESULTS = 40;
const ERROR_MAX_CHARS = 500;
const isValidatorId = (value) => Number.isInteger(value) && value >= 1 && value <= 99;

/**
 * The events the person sees in /list-my-break-glass-moves (spec 14.4.1)
 * and the detail fields of each: the appointment, the decision, the posting
 * and the end; never an attestor's id, username, note or signature.
 */
const PERSON_EVENTS = {
  scheduled: ['at', 'meetLink'],
  decided: [],
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

/** The break-glass case a body's `caseId` (hex) names, or null. */
async function findCaseByHex(caseIdHex) {
  const caseId = decodeId(caseIdHex);
  return caseId === null ? null : findCase(caseId);
}

/**
 * Runs `write(client, lockedCase)` in one transaction with the case row
 * locked (lockCase), after checking under the lock that its status is still
 * one of `statuses`. Returns what `write` returns, or null when the status
 * moved on between the checks and the lock (the caller answers 409).
 */
function withLockedCase(caseId, statuses, write) {
  return withTransaction(async (client) => {
    const locked = await lockCase(client, caseId);
    if (locked === null || !statuses.includes(locked.status)) return null;
    return write(client, locked);
  });
}

/** A pod's profile with its selfie, as /get-anopod-profile answers it, or null when the pod's row is gone. */
async function profileOf(anopodId) {
  const anopod = await findAnopod(anopodId);
  return anopod === null ? null : profileWithSelfie(anopod);
}

/** A break_glass_moves row in wire form: the ids hex, createdAt ISO 8601. */
function moveOf(move) {
  return {
    accountId: toHex(move.accountId),
    accountIdTo: toHex(move.accountIdTo),
    transactionId: toHex(move.transactionId),
    accountType: move.accountType,
    createdAt: move.createdAt.toISOString(),
  };
}

/** A move as the lists aggregate it (break-glass.queries.js, the ids hex already): createdAt normalised to toISOString(). */
function listedMove(move) {
  return { ...move, createdAt: new Date(move.createdAt).toISOString() };
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

/** The person's subset of a case's events (14.4.1): the kinds of PERSON_EVENTS with their named fields alone. */
function personEvents(events) {
  return events
    .filter((event) => event.kind in PERSON_EVENTS)
    .map((event) => ({ kind: event.kind, details: pick(event.details, PERSON_EVENTS[event.kind]), createdAt: event.createdAt.toISOString() }));
}

// --- the setup level, the person (spec 14.4.1) ------------------------------------

/**
 * POST /file-break-glass-moves. Body { caseId, moves: [ { accountId,
 * accountIdTo, transactionId } ] }, 1 to 20 moves: the finish of a recovery
 * tells this server which breakGlassTransfers it posted, out of which old
 * accounts into which new ones. The checks of 14.4.1 in order: the shape
 * and the ids; the recovery case is the caller's and delivering or
 * completed; for each move both accounts are the caller's, differ, share a
 * type, and no move with its transaction id is filed yet. Then one
 * transaction with the case row locked: the case row when there is none
 * (status open), the moves with the shared type, the opened event with the
 * count. A second call for the same case adds moves (Retry).
 */
export async function fileBreakGlassMoves(anopod, body) {
  // 1. Shape, then the ids.
  if (!isObject(body) || typeof body.caseId !== 'string' || !Array.isArray(body.moves)
    || body.moves.length < 1 || body.moves.length > MAX_MOVES
    || !body.moves.every((move) => isObject(move) && MOVE_FIELDS.every((field) => typeof move[field] === 'string'))) {
    return refuse(400, BAD_SHAPE);
  }
  const caseId = decodeId(body.caseId);
  if (caseId === null) return refuse(400, 'invalid caseId');
  const moves = [];
  for (const entry of body.moves) {
    const move = { caseId };
    for (const field of MOVE_FIELDS) {
      const id = decodeId(entry[field]);
      if (id === null) return refuse(400, `invalid ${field}`);
      move[field] = id;
    }
    moves.push(move);
  }

  // 2. The recovery case: the caller's, and delivering or completed.
  const recoveryCase = await findRecoveryCase(caseId);
  if (recoveryCase === null || !recoveryCase.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown case');
  if (!FILING_STATUSES.includes(recoveryCase.status)) return refuse(409, 'case not ready');

  // 3. Each move: two accounts of the caller's pod, different, of one type, not filed yet.
  for (const move of moves) {
    const [from, to] = await Promise.all([findAccount(move.accountId), findAccount(move.accountIdTo)]);
    if (from === null || !from.anopodId.equals(anopod.anopodId) || to === null || !to.anopodId.equals(anopod.anopodId)) {
      return refuse(404, 'unknown account');
    }
    if (move.accountId.equals(move.accountIdTo)) return refuse(400, 'same account');
    if (from.accountType !== to.accountType) return refuse(400, 'account types differ');
    if ((await findMove(move.transactionId)) !== null) return refuse(409, 'move already filed');
    move.accountType = from.accountType;
  }

  // The writes. The case row is locked after the insert, so a filing and
  // an attestor's write see each other; the unique key on the moves is the
  // backstop for a transaction filed twice.
  try {
    const written = await withTransaction(async (client) => {
      await insertCase(client, caseId, anopod.anopodId);
      const locked = await lockCase(client, caseId);
      for (const move of moves) await insertMove(client, move);
      await insertEvent(client, caseId, 'opened', anopod.anopodId, { moves: moves.length });
      return { status: locked.status, moves: (await listMoves(caseId, client)).length };
    });
    return ok(201, { caseId: toHex(caseId), status: written.status, moves: written.moves });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'move already filed');
    throw err;
  }
}

/**
 * POST /list-my-break-glass-moves. Body {}. The caller's break-glass cases,
 * newest first, each with its moves and the person's subset of the events:
 * what the lost account's card reads.
 */
export async function listMyBreakGlassMoves(anopod) {
  const cases = await listCasesForPod(anopod.anopodId);
  const out = [];
  for (const item of cases) {
    const events = await listEvents(item.caseId);
    out.push({
      caseId: toHex(item.caseId),
      status: item.status,
      signOffs: item.signOffs,
      moves: item.moves.map(listedMove),
      events: personEvents(events),
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
    });
  }
  return ok(200, { cases: out });
}

// --- the attestor level (spec 14.4.2) ---------------------------------------------

/**
 * POST /list-break-glass-cases. Body { statuses? }: the cases in those
 * statuses (open and inReview by default; an empty list answers no cases),
 * newest first, each with the person's names, its moves and the sign-off
 * count.
 */
export async function listBreakGlassCases(body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  let statuses = DEFAULT_LIST_STATUSES;
  if (body.statuses !== undefined) {
    if (!Array.isArray(body.statuses) || !body.statuses.every((status) => CASE_STATUSES.includes(status))) {
      return refuse(400, BAD_SHAPE);
    }
    statuses = body.statuses;
  }
  const cases = await listCasesByStatus(statuses);
  return ok(200, {
    cases: cases.map((item) => ({
      caseId: toHex(item.caseId),
      status: item.status,
      username: item.username,
      firstName: item.firstName,
      lastName: item.lastName,
      signOffs: item.signOffs,
      moves: item.moves.map(({ accountId, accountIdTo, transactionId, accountType }) => ({ accountId, accountIdTo, transactionId, accountType })),
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
    })),
  });
}

/**
 * POST /get-break-glass-case. Body { caseId }. One case for the attestors:
 * the row with the recovery case's lookup id and status and its two
 * moderator approvals (the approvalSigned recovery events, the moderator's
 * username and the time), the person's profile with its selfie, the moves,
 * and every attestor event with the acting pod's username and its details
 * complete (the stored attestations included, for the posting after the
 * decision).
 */
export async function getBreakGlassCase(body) {
  if (!isObject(body) || typeof body.caseId !== 'string') return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');

  const [recoveryCase, recoveryEvents, profile, moves, events] = await Promise.all([
    findRecoveryCase(found.caseId),
    listRecoveryEvents(found.caseId),
    profileOf(found.anopodId),
    listMoves(found.caseId),
    listForCaseWithUsernames(found.caseId),
  ]);
  return ok(200, {
    case: {
      caseId: toHex(found.caseId),
      status: found.status,
      lookupId: toHex(recoveryCase?.lookupId),
      recoveryStatus: recoveryCase?.status ?? null,
      approvals: recoveryEvents
        .filter((event) => event.kind === 'approvalSigned')
        .map((event) => ({ username: event.username, signedAt: event.details?.signedAt ?? null })),
      createdAt: found.createdAt.toISOString(),
      updatedAt: found.updatedAt.toISOString(),
    },
    profile,
    moves: moves.map(moveOf),
    events: attestorEvents(events),
  });
}

/**
 * POST /list-break-glass-case-security-records. Body { caseId, bucket },
 * bucket 1 or 2. The case's pod's rows of that bucket in the shape of
 * /list-security-records, oldest first (info is empty for bucket one), and
 * the bucketOneViewed or bucketTwoViewed event with the distinct key ids
 * answered. No status check. The rows are ciphertext under the bucket key
 * the keyholders give the attestor for keyId, by the recovery case's lookup
 * id; this server cannot open them.
 */
export async function listBreakGlassCaseSecurityRecords(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !BUCKETS.includes(body.bucket)) return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');

  const all = await listSecurityRecords(found.anopodId);
  const images = all.images.filter((row) => row.type === body.bucket);
  const info = all.info.filter((row) => row.type === body.bucket);
  const keyIds = [...new Set([...images, ...info].map((row) => row.keyId))];
  await withTransaction((client) => insertEvent(client, found.caseId, BUCKET_VIEWED[body.bucket], anopod.anopodId, { keyIds }));
  return ok(200, { images, info });
}

/**
 * POST /schedule-break-glass-case. Body { caseId, at, meetLink }: the video
 * call. Under the case lock: the scheduled event with { at, meetLink } (at
 * normalised to ISO 8601) and status inReview when the case was open. No
 * notification: the person's wallet reads the event from
 * /list-my-break-glass-moves.
 */
export async function scheduleBreakGlassCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !isTime(body.at) || !isMeetLink(body.meetLink)) return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(found.status)) return refuse(409, 'case closed');

  const status = await withLockedCase(found.caseId, REVIEW_STATUSES, async (client, locked) => {
    await insertEvent(client, locked.caseId, 'scheduled', anopod.anopodId, { at: new Date(body.at).toISOString(), meetLink: body.meetLink });
    if (locked.status === 'open') await updateStatus(client, locked.caseId, 'inReview');
    return 'inReview';
  });
  if (status === null) return refuse(409, 'case closed');
  return ok(200, { caseId: toHex(found.caseId), status });
}

/**
 * Checks 1 to 4 of spec 13.4.2 on one attestation `object`, the validators'
 * follow-up for `move`, by the caller `anopod`: the shape (the payload's
 * four strings and `type`, the signatures object of account-signatures.js),
 * the match with the move (its transaction id and its old account), the
 * signer's account (`attestorId`) in the caller's pod, every present pair
 * verified against the stored creation. Check 5, one sign-off per pod per
 * case, runs once for the whole list in signOffBreakGlassCase. Returns
 * { account, payload } or a refusal (ok false).
 */
async function checkAttestation(anopod, move, object) {
  // 1. Shape.
  if (!isObject(object) || !isObject(object.payload) || !hasAccountSignatureShape(object.signatures)) return refuse(400, BAD_SHAPE);
  const { payload, signatures } = object;
  if (payload.type !== ATTESTATION) return refuse(400, BAD_SHAPE);
  for (const field of ATTESTATION_FIELDS) {
    if (typeof payload[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (!isTime(payload.signedAt)) return refuse(400, BAD_SHAPE);

  // 2. The object is about this move: its transaction, out of its old account.
  const transactionId = decodeId(payload.transactionId);
  const accountId = decodeId(payload.accountId);
  if (transactionId === null || !transactionId.equals(move.transactionId) || accountId === null || !accountId.equals(move.accountId)) {
    return refuse(400, 'sign-off does not match the case');
  }

  // 3. The signer's account lives in the caller's pod.
  const signerId = decodeId(payload.attestorId);
  const account = signerId === null ? null : await findAccount(signerId);
  if (account === null || !account.anopodId.equals(anopod.anopodId)) return refuse(403, 'not your account');

  // 4. Every present pair, over the canonical bytes of the payload as sent,
  //    against the keys the stored creation names.
  if (!verifyAccountSignatures(account.creation?.payload?.publicKeys, signatures, payload)) return refuse(401, 'bad signature');

  return { account, payload };
}

/**
 * POST /sign-off-break-glass-case. Body { caseId, attestations: [ {
 * transactionId, attestation } ] }: one attestation per move of the case,
 * the validators' follow-up objects, signed in one pass. The checks of
 * 14.4.2 in order: the shape; the case exists and is under review; the list
 * names every move exactly once and nothing else; each attestation passes
 * checks 1 to 4 of 13.4.2 against its move, in move order, with one
 * attestorId on all; no sign-off by the caller's pod yet. Under the case
 * lock: the attestationSigned event with the attestor's account id and the
 * whole objects in move order, status inReview when the case was open, and,
 * once two distinct pods have signed, status decided and the decided event.
 */
export async function signOffBreakGlassCase(anopod, body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.caseId !== 'string' || !Array.isArray(body.attestations)
    || body.attestations.length < 1 || body.attestations.length > MAX_MOVES
    || !body.attestations.every((entry) => isObject(entry) && typeof entry.transactionId === 'string')) {
    return refuse(400, BAD_SHAPE);
  }

  // 2. The case, still under review.
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(found.status)) return refuse(409, 'case closed');

  // 3. The list names every move of the case exactly once and nothing else.
  const moves = await listMoves(found.caseId);
  const byTransaction = new Map();
  for (const entry of body.attestations) {
    const transactionId = decodeId(entry.transactionId);
    const key = transactionId === null ? null : toHex(transactionId);
    if (key === null || byTransaction.has(key) || !moves.some((move) => toHex(move.transactionId) === key)) {
      return refuse(400, 'attestations do not match the moves');
    }
    byTransaction.set(key, entry.attestation);
  }
  if (byTransaction.size !== moves.length) return refuse(400, 'attestations do not match the moves');
  const ordered = moves.map((move) => ({ move, attestation: byTransaction.get(toHex(move.transactionId)) }));

  // 4. Checks 1 to 4 of 13.4.2 on each attestation against its move, in
  //    move order, and the same attestorId on all.
  let attestorId = null;
  for (const { move, attestation } of ordered) {
    const checked = await checkAttestation(anopod, move, attestation);
    if (checked.ok === false) return checked;
    if (attestorId === null) attestorId = checked.account.accountId;
    else if (!attestorId.equals(checked.account.accountId)) return refuse(400, 'attestations differ in attestorId');
  }

  // 5. One sign-off per pod per case.
  if (await signedOffBy(found.caseId, anopod.anopodId)) return refuse(409, 'already signed off');

  // The writes, with the case locked so two second sign-offs cannot both
  // count one.
  const outcome = await withLockedCase(found.caseId, REVIEW_STATUSES, async (client, locked) => {
    if (await signedOffBy(locked.caseId, anopod.anopodId, client)) return 'already signed off';
    await insertEvent(client, locked.caseId, 'attestationSigned', anopod.anopodId, {
      attestorId: toHex(attestorId),
      attestations: ordered.map(({ attestation }) => attestation),
    });
    const signOffs = await countSignOffs(locked.caseId, 'attestationSigned', client);
    let status = 'inReview';
    if (signOffs >= SIGN_OFFS_NEEDED) {
      status = 'decided';
      const attestorIds = (await listDetails(locked.caseId, 'attestationSigned', client)).map((details) => details.attestorId);
      await insertEvent(client, locked.caseId, 'decided', null, { attestorIds });
    }
    if (status !== locked.status) await updateStatus(client, locked.caseId, status);
    return { status, signOffs };
  });
  if (outcome === null) return refuse(409, 'case closed');
  if (outcome === 'already signed off') return refuse(409, outcome);
  return ok(200, { caseId: toHex(found.caseId), status: outcome.status, signOffs: outcome.signOffs });
}

/**
 * POST /mark-break-glass-case-sent. Body { caseId, validator, results }: the
 * app posted the stored attestations, two per move, to validator
 * `validator` and records the answers, a failed post included; a later
 * retry writes another event. The case must be decided. Under the case
 * lock: the sent event with { validator, results }.
 */
export async function markBreakGlassCaseSent(anopod, body) {
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
  if (found.status !== 'decided') return refuse(409, 'case not decided');

  const written = await withLockedCase(found.caseId, ['decided'], async (client, locked) => {
    await insertEvent(client, locked.caseId, 'sent', anopod.anopodId, { validator: body.validator, results });
    return true;
  });
  if (written === null) return refuse(409, 'case not decided');
  return ok(200, { caseId: toHex(found.caseId), status: 'decided' });
}

/**
 * POST /dismiss-break-glass-case. Body { caseId, reason, note }, reason one
 * of DISMISS_REASONS. Final: under the case lock, status dismissed and the
 * dismissed event. Nothing to clear (the lookup id is the recovery case's)
 * and nothing on the ledger: the held moves stay until a cancel (14.9).
 */
export async function dismissBreakGlassCase(anopod, body) {
  if (!isObject(body) || typeof body.caseId !== 'string' || !DISMISS_REASONS.includes(body.reason) || !isNote(body.note)) return refuse(400, BAD_SHAPE);
  const found = await findCaseByHex(body.caseId);
  if (found === null) return refuse(404, 'unknown case');
  if (!REVIEW_STATUSES.includes(found.status)) return refuse(409, 'case closed');

  const written = await withLockedCase(found.caseId, REVIEW_STATUSES, async (client, locked) => {
    await updateStatus(client, locked.caseId, 'dismissed');
    await insertEvent(client, locked.caseId, 'dismissed', anopod.anopodId, { reason: body.reason, note: body.note });
    return true;
  });
  if (written === null) return refuse(409, 'case closed');
  return ok(200, { caseId: toHex(found.caseId), status: 'dismissed' });
}
