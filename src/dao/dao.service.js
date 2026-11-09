import { env } from '../config/env.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  DECIDED_STATUSES,
  STAGES,
  findProposal,
  findVote,
  findWeight,
  hasPendingProposal,
  insertProposal,
  insertVote,
  listProposals,
  listVotes,
  lockProposal,
  replaceSnapshot,
  setOpen,
  sumVotes,
} from './dao.queries.js';
import { takeSnapshot } from './snapshot.js';

/**
 * The DAO voting feature (spec section 15): plain-text proposals and
 * stake-weighted votes, one staked anos one vote. A proposal is pending
 * while it collects support like a petition (the proposer's own weight the
 * first support), goes open on a fresh snapshot once the support reaches
 * `needed` (the flip, here), takes votes for and against while open, and is
 * closed by the clock (dao-clock.js). A pod's weight comes from the
 * proposal's snapshot (snapshot.js), never from a live read; one action per
 * pod per stage, no undo; every vote public. The pattern is the other
 * features': each function runs its route's checks in the spec's order and
 * returns ok(status, body) or refuse(status, reason), so the handlers only
 * log and answer; every write to a proposal runs with the row locked.
 */

const BAD_SHAPE = 'bad request shape';

/** A proposal is a title of 1 to 100 characters and a body of 1 to 5,000, both trimmed. */
const TITLE_MAX_CHARS = 100;
const BODY_MAX_CHARS = 5000;

/** What an official-stage row may say. */
const VOTES = ['for', 'against'];

/** /list-dao-proposals: the `status` asked for and the statuses it lists; decided is accepted and rejected together. */
const LIST_STATUSES = new Map([['pending', ['pending']], ['open', ['open']], ['decided', DECIDED_STATUSES]]);

/** The lists' paging: proposals 1 to 100 a page, 20 by default; votes 1 to 200, 50 by default. */
const PROPOSALS_DEFAULT_LIMIT = 20;
const PROPOSALS_MAX_LIMIT = 100;
const VOTES_DEFAULT_LIMIT = 50;
const VOTES_MAX_LIMIT = 200;

/** The refusal of a second pending proposal by one pod. */
const PENDING_ALREADY = 'a pending proposal is already open';

const MINUTE_MS = 60_000;

/** `value` trimmed at both ends when it is a string of 1 to `max` characters after the trim, else null. */
function trimmedText(value, max) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  const length = Array.from(text).length;
  return length >= 1 && length <= max ? text : null;
}

/** `value` as an ISO 8601 string when it is a string that parses to a time (Date.parse, as the session's timestamp check), else null. */
function timeOf(value) {
  if (typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

/** An optional integer field: `fallback` when absent, the value when an integer from `min` to `max`, else undefined. */
function integerOption(value, fallback, min, max) {
  if (value === undefined || value === null) return fallback;
  return Number.isInteger(value) && value >= min && value <= max ? value : undefined;
}

/** A time column in wire form: ISO 8601, null when null. */
function iso(date) {
  return date === null ? null : date.toISOString();
}

/** A BIGINT of votes (a decimal string or a BigInt) as a JSON number; votes stay far below 2^53. Null stays null. */
function votes(value) {
  return value === null || value === undefined ? null : Number(value);
}

/** The support that takes a proposal to a vote: ceil(total * DAO_PROPOSAL_PERCENT / 100), at least 1; BigInts of whole anos. */
function neededOf(total) {
  const needed = (total * BigInt(env.dao.proposalPercent) + 99n) / 100n;
  return needed < 1n ? 1n : needed;
}

/** A snapshot's weights as replaceSnapshot takes them: the BigInts as decimal strings. */
function weightRows(snapshot) {
  return snapshot.weights.map(({ anopodId, weight }) => ({ anopodId, weight: weight.toString() }));
}

/**
 * A proposal in wire form, the item of /list-dao-proposals (spec 15.4): ids
 * hex, times ISO 8601, votes as numbers; `for` and `against` the stored
 * results once decided and the live sums before.
 */
function itemOf(row) {
  return {
    proposalId: toHex(row.proposalId),
    title: row.title,
    status: row.status,
    proposer: { anopodId: toHex(row.anopodId), username: row.username },
    createdAt: iso(row.createdAt),
    pendingUntil: iso(row.pendingUntil),
    openedAt: iso(row.openedAt),
    voteClosesAt: iso(row.voteClosesAt),
    decidedAt: iso(row.decidedAt),
    snapshotTotal: votes(row.snapshotTotal),
    needed: votes(row.needed),
    support: votes(row.support),
    for: votes(row.resultFor ?? row.for),
    against: votes(row.resultAgainst ?? row.against),
    yourWeight: votes(row.yourWeight),
    yourSupport: row.yourSupport,
    yourVote: row.yourVote,
  };
}

/**
 * The flip (spec 15.5): a fresh snapshot and, in one transaction with the
 * row locked, a pending proposal whose support has reached `needed` goes
 * open: the fresh weights replace the snapshot rows and fix the voting
 * power, the fresh total and asOf go on the row, opened_at is now and
 * vote_closes_at now + DAO_VOTE_MINUTES. `needed` is not recomputed: it is
 * the posting snapshot's number, and the support rows carry that
 * snapshot's weights. Returns the status after: open; pending when the
 * support is under needed, or when no validator could be reached (the
 * clock retries every minute); a row that is no longer pending answers its
 * status.
 */
export async function flipIfReached(proposalId) {
  const snapshot = await takeSnapshot();
  if (snapshot === null) {
    console.log(`dao: the flip of ${toHex(proposalId)} waits, validators unreachable`);
    return 'pending';
  }
  return withTransaction(async (client) => {
    const locked = await lockProposal(client, proposalId);
    if (locked === null) return null;
    if (locked.status !== 'pending') return locked.status;
    const sums = await sumVotes(client, proposalId, 'pending');
    if (sums.for < BigInt(locked.needed)) return 'pending';

    await replaceSnapshot(client, proposalId, weightRows(snapshot));
    const openedAt = new Date();
    const voteClosesAt = new Date(openedAt.getTime() + env.dao.voteMinutes * MINUTE_MS);
    await setOpen(client, proposalId, {
      snapshotTotal: snapshot.total.toString(),
      snapshotAt: new Date(snapshot.asOf),
      openedAt,
      voteClosesAt,
    });
    console.log(`dao: proposal ${toHex(proposalId)} open, ${sums.for} of ${locked.needed} support, voting until ${voteClosesAt.toISOString()}`);
    return 'open';
  });
}

/**
 * POST /create-dao-proposal. Body { title, body }. The checks of 15.4 in
 * order: the shape; the title and the body, trimmed, within their lengths;
 * the snapshot (503 when no validator answers); the caller's weight in it
 * at least DAO_PROPOSE_MIN_VOTES; no pending proposal of the caller's. One
 * transaction: the proposal (pending, the snapshot's total and asOf,
 * needed, pending_until now + DAO_PENDING_MINUTES), the snapshot rows, the
 * proposer's pending-stage for row with their weight. Then the flip,
 * outside the transaction: the status answered is the one after it.
 */
export async function createDaoProposal(anopod, body) {
  if (!isObject(body) || typeof body.title !== 'string' || typeof body.body !== 'string') return refuse(400, BAD_SHAPE);
  const title = trimmedText(body.title, TITLE_MAX_CHARS);
  if (title === null) return refuse(400, 'invalid title');
  const text = trimmedText(body.body, BODY_MAX_CHARS);
  if (text === null) return refuse(400, 'invalid body');

  const snapshot = await takeSnapshot();
  if (snapshot === null) return refuse(503, 'validators unreachable');
  const weight = snapshot.weights.find((entry) => entry.anopodId.equals(anopod.anopodId))?.weight ?? 0n;
  if (weight < BigInt(env.dao.proposeMinVotes)) return refuse(403, 'not enough DAO votes');
  if (await hasPendingProposal(anopod.anopodId)) return refuse(409, PENDING_ALREADY);

  const proposalId = randomId();
  try {
    await withTransaction(async (client) => {
      await insertProposal(client, {
        proposalId,
        anopodId: anopod.anopodId,
        title,
        body: text,
        snapshotTotal: snapshot.total.toString(),
        snapshotAt: new Date(snapshot.asOf),
        needed: neededOf(snapshot.total).toString(),
        pendingUntil: new Date(Date.now() + env.dao.pendingMinutes * MINUTE_MS),
      });
      await replaceSnapshot(client, proposalId, weightRows(snapshot));
      await insertVote(client, { proposalId, anopodId: anopod.anopodId, stage: 'pending', vote: 'for', weight: weight.toString() });
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, PENDING_ALREADY);
    throw err;
  }
  const status = await flipIfReached(proposalId);
  return ok(201, { proposalId: toHex(proposalId), status });
}

/**
 * POST /support-dao-proposal. Body { proposalId }. One transaction with
 * the row locked: it exists, is pending, pending_until is ahead, the
 * caller has at least 1 vote in the snapshot and no pending-stage row yet
 * (the unique key the backstop); the row inserted with the caller's
 * weight. Then the flip, outside the transaction.
 */
export async function supportDaoProposal(anopod, body) {
  if (!isObject(body) || typeof body.proposalId !== 'string') return refuse(400, BAD_SHAPE);
  const proposalId = decodeId(body.proposalId);
  if (proposalId === null) return refuse(400, 'invalid proposalId');

  let written;
  try {
    written = await withTransaction(async (client) => {
      const locked = await lockProposal(client, proposalId);
      if (locked === null) return refuse(404, 'unknown proposal');
      if (locked.status !== 'pending') return refuse(409, 'proposal not pending');
      if (locked.pendingUntil.getTime() <= Date.now()) return refuse(409, 'proposal expired');
      const weight = await findWeight(client, proposalId, anopod.anopodId);
      if (BigInt(weight) < 1n) return refuse(403, 'no DAO votes in this proposal');
      if ((await findVote(client, proposalId, anopod.anopodId, 'pending')) !== null) return refuse(409, 'already supported');
      await insertVote(client, { proposalId, anopodId: anopod.anopodId, stage: 'pending', vote: 'for', weight });
      const sums = await sumVotes(client, proposalId, 'pending');
      return { support: sums.for, needed: locked.needed };
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'already supported');
    throw err;
  }
  if (written.ok === false) return written;
  const status = await flipIfReached(proposalId);
  return ok(200, { proposalId: toHex(proposalId), status, support: votes(written.support), needed: votes(written.needed) });
}

/**
 * POST /vote-dao-proposal. Body { proposalId, vote }, vote for or against.
 * One transaction with the row locked: it exists, is open, vote_closes_at
 * is ahead, the caller has at least 1 vote in the (fresh) snapshot and no
 * official-stage row yet (the unique key the backstop); the row inserted.
 * Answers the sums after the write.
 */
export async function voteDaoProposal(anopod, body) {
  if (!isObject(body) || typeof body.proposalId !== 'string') return refuse(400, BAD_SHAPE);
  const proposalId = decodeId(body.proposalId);
  if (proposalId === null) return refuse(400, 'invalid proposalId');
  if (!VOTES.includes(body.vote)) return refuse(400, 'invalid vote');

  let written;
  try {
    written = await withTransaction(async (client) => {
      const locked = await lockProposal(client, proposalId);
      if (locked === null) return refuse(404, 'unknown proposal');
      if (locked.status !== 'open') return refuse(409, 'proposal not open');
      if (locked.voteClosesAt.getTime() <= Date.now()) return refuse(409, 'voting closed');
      const weight = await findWeight(client, proposalId, anopod.anopodId);
      if (BigInt(weight) < 1n) return refuse(403, 'no DAO votes in this proposal');
      if ((await findVote(client, proposalId, anopod.anopodId, 'official')) !== null) return refuse(409, 'already voted');
      await insertVote(client, { proposalId, anopodId: anopod.anopodId, stage: 'official', vote: body.vote, weight });
      return sumVotes(client, proposalId, 'official');
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'already voted');
    throw err;
  }
  if (written.ok === false) return written;
  return ok(200, { proposalId: toHex(proposalId), for: votes(written.for), against: votes(written.against), yourVote: body.vote });
}

/**
 * POST /list-dao-proposals. Body { status, from?, to?, limit?, offset? }:
 * status pending, open or decided (accepted and rejected together); from
 * and to ISO 8601 bounds on created_at for pending and open and on
 * decided_at for decided; limit 1 to 100, 20 by default; offset 0 or more.
 * Expired proposals are never listed. Answers the items, newest first, and
 * the dials (`settings`), so the wallet's words carry the numbers.
 */
export async function listDaoProposals(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const statuses = LIST_STATUSES.get(body.status);
  if (statuses === undefined) return refuse(400, 'invalid status');
  const from = body.from === undefined || body.from === null ? null : timeOf(body.from);
  if (from === null && body.from !== undefined && body.from !== null) return refuse(400, 'invalid from');
  const to = body.to === undefined || body.to === null ? null : timeOf(body.to);
  if (to === null && body.to !== undefined && body.to !== null) return refuse(400, 'invalid to');
  const limit = integerOption(body.limit, PROPOSALS_DEFAULT_LIMIT, 1, PROPOSALS_MAX_LIMIT);
  if (limit === undefined) return refuse(400, 'invalid limit');
  const offset = integerOption(body.offset, 0, 0, Number.MAX_SAFE_INTEGER);
  if (offset === undefined) return refuse(400, 'invalid offset');

  const rows = await listProposals(anopod.anopodId, { statuses, from, to, limit, offset });
  return ok(200, { proposals: rows.map(itemOf), settings: env.dao });
}

/** POST /get-dao-proposal. Body { proposalId }. The item of the list with the body added; an expired proposal too, so an old link resolves. */
export async function getDaoProposal(anopod, body) {
  if (!isObject(body) || typeof body.proposalId !== 'string') return refuse(400, BAD_SHAPE);
  const proposalId = decodeId(body.proposalId);
  if (proposalId === null) return refuse(400, 'invalid proposalId');
  const row = await findProposal(proposalId, anopod.anopodId);
  if (row === null) return refuse(404, 'unknown proposal');
  return ok(200, { proposal: { ...itemOf(row), body: row.body } });
}

/**
 * POST /list-dao-votes. Body { proposalId, stage, limit?, offset? }: stage
 * pending (the supports) or official (the votes); limit 1 to 200, 50 by
 * default. The proposal's rows of that stage, newest first, each with the
 * voter's pod, username, vote, weight and time: every vote is public.
 */
export async function listDaoVotes(anopod, body) {
  if (!isObject(body) || typeof body.proposalId !== 'string') return refuse(400, BAD_SHAPE);
  const proposalId = decodeId(body.proposalId);
  if (proposalId === null) return refuse(400, 'invalid proposalId');
  if (!STAGES.includes(body.stage)) return refuse(400, 'invalid stage');
  const limit = integerOption(body.limit, VOTES_DEFAULT_LIMIT, 1, VOTES_MAX_LIMIT);
  if (limit === undefined) return refuse(400, 'invalid limit');
  const offset = integerOption(body.offset, 0, 0, Number.MAX_SAFE_INTEGER);
  if (offset === undefined) return refuse(400, 'invalid offset');
  if ((await findProposal(proposalId, anopod.anopodId)) === null) return refuse(404, 'unknown proposal');

  const rows = await listVotes(proposalId, body.stage, limit, offset);
  return ok(200, {
    votes: rows.map((row) => ({
      anopodId: toHex(row.anopodId),
      username: row.username,
      vote: row.vote,
      weight: votes(row.weight),
      createdAt: row.createdAt.toISOString(),
    })),
  });
}
