import { pool } from '../db/pool.js';

/**
 * SQL for the three DAO tables (spec 15.3): dao_proposals, dao_votes and
 * dao_snapshot_weights. Ids are Buffers of raw bytes, matching the BYTEA
 * columns; the BIGINT columns (votes, whole anos) go in and come out as
 * decimal strings, as pg hands them over, except sumVotes, which answers
 * BigInts for the flip's and the close's arithmetic. Reads take an optional
 * `db` (a client inside a transaction; the pool by default); writes take
 * the transaction's client first.
 */

/** The statuses of a proposal (spec 15.5), and the two a decided one has. */
export const PROPOSAL_STATUSES = ['pending', 'open', 'accepted', 'rejected', 'expired'];
export const DECIDED_STATUSES = ['accepted', 'rejected'];

/** The two stages a dao_votes row belongs to: a support, or a vote. */
export const STAGES = ['pending', 'official'];

const PROPOSAL_COLUMNS = `p.proposal_id, p.anopod_id, p.title, p.status, p.snapshot_total, p.snapshot_at, p.needed,
            p.pending_until, p.opened_at, p.vote_closes_at, p.decided_at, p.result_for, p.result_against,
            p.created_at, p.updated_at`;

/**
 * The select findProposal and listProposals share: the row (the body only
 * when asked), the proposer's username (null when the pod's row is gone),
 * the live sums as subselects (support, the pending-stage weights; for and
 * against, the official-stage weights) and the caller's part (your_weight
 * from the snapshot, 0 when none; your_support, whether the caller has a
 * pending-stage row; your_vote, the caller's official vote or null). $1 is
 * the caller's pod.
 */
function proposalSelect(withBody) {
  return `SELECT ${PROPOSAL_COLUMNS}${withBody ? ', p.body' : ''},
            a.username,
            (SELECT COALESCE(SUM(v.weight), 0)::bigint FROM dao_votes v
             WHERE v.proposal_id = p.proposal_id AND v.stage = 'pending') AS support,
            (SELECT COALESCE(SUM(v.weight), 0)::bigint FROM dao_votes v
             WHERE v.proposal_id = p.proposal_id AND v.stage = 'official' AND v.vote = 'for') AS votes_for,
            (SELECT COALESCE(SUM(v.weight), 0)::bigint FROM dao_votes v
             WHERE v.proposal_id = p.proposal_id AND v.stage = 'official' AND v.vote = 'against') AS votes_against,
            COALESCE((SELECT w.weight FROM dao_snapshot_weights w
                      WHERE w.proposal_id = p.proposal_id AND w.anopod_id = $1), 0) AS your_weight,
            EXISTS (SELECT 1 FROM dao_votes v
                    WHERE v.proposal_id = p.proposal_id AND v.anopod_id = $1 AND v.stage = 'pending') AS your_support,
            (SELECT v.vote FROM dao_votes v
             WHERE v.proposal_id = p.proposal_id AND v.anopod_id = $1 AND v.stage = 'official') AS your_vote
     FROM dao_proposals p
     LEFT JOIN anopods a ON a.anopod_id = p.anopod_id`;
}

/** A row of proposalSelect in camelCase. Byte columns stay Buffers; BIGINTs decimal strings; body undefined unless selected. */
function proposalRow(row) {
  return {
    proposalId: row.proposal_id,
    anopodId: row.anopod_id,
    username: row.username,
    title: row.title,
    body: row.body,
    status: row.status,
    snapshotTotal: row.snapshot_total,
    snapshotAt: row.snapshot_at,
    needed: row.needed,
    pendingUntil: row.pending_until,
    openedAt: row.opened_at,
    voteClosesAt: row.vote_closes_at,
    decidedAt: row.decided_at,
    resultFor: row.result_for,
    resultAgainst: row.result_against,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    support: row.support,
    for: row.votes_for,
    against: row.votes_against,
    yourWeight: row.your_weight,
    yourSupport: row.your_support,
    yourVote: row.your_vote,
  };
}

/**
 * Inserts a proposal on `client`, status pending: { proposalId, anopodId,
 * title, body, snapshotTotal, snapshotAt, needed, pendingUntil }. A second
 * pending proposal of the pod throws a unique violation on the partial
 * index (db/transaction.js isUniqueViolation).
 */
export async function insertProposal(client, { proposalId, anopodId, title, body, snapshotTotal, snapshotAt, needed, pendingUntil }) {
  await client.query(
    `INSERT INTO dao_proposals (proposal_id, anopod_id, title, body, snapshot_total, snapshot_at, needed, pending_until)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [proposalId, anopodId, title, body, snapshotTotal, snapshotAt, needed, pendingUntil],
  );
}

/** The proposal with this id (a 32-byte Buffer) as proposalSelect answers it for the caller `anopodId`, body included, or null. */
export async function findProposal(proposalId, anopodId, db = pool) {
  const { rows } = await db.query(`${proposalSelect(true)}
     WHERE p.proposal_id = $2`, [anopodId, proposalId]);
  return rows.length === 0 ? null : proposalRow(rows[0]);
}

/** True when the pod has a pending proposal: the "one pending proposal per pod" rule before the write. */
export async function hasPendingProposal(anopodId, db = pool) {
  const { rows } = await db.query(`SELECT 1 FROM dao_proposals WHERE anopod_id = $1 AND status = 'pending'`, [anopodId]);
  return rows.length > 0;
}

/**
 * The proposal with this id, locked for the rest of the transaction on
 * `client` (SELECT ... FOR UPDATE): the status, `needed` and the times; or
 * null. Every write to a proposal locks it first, so a support racing the
 * flip, or two flips, see each other's status.
 */
export async function lockProposal(client, proposalId) {
  const { rows } = await client.query(
    `SELECT proposal_id, anopod_id, status, needed, pending_until, opened_at, vote_closes_at, decided_at
     FROM dao_proposals WHERE proposal_id = $1 FOR UPDATE`,
    [proposalId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    proposalId: row.proposal_id,
    anopodId: row.anopod_id,
    status: row.status,
    needed: row.needed,
    pendingUntil: row.pending_until,
    openedAt: row.opened_at,
    voteClosesAt: row.vote_closes_at,
    decidedAt: row.decided_at,
  };
}

/**
 * The list (spec 15.4): the proposals in `statuses` as proposalSelect
 * answers them for the caller, without the body, newest first, `limit`
 * rows from `offset`. The time filtered and sorted is decided_at when the
 * statuses are the decided ones (accepted and rejected), else created_at;
 * `from` (at or after) and `to` (before) are ISO strings or null, typed in
 * the SQL as listNotes types its bounds.
 */
export async function listProposals(anopodId, { statuses, from, to, limit, offset }, db = pool) {
  const column = statuses.every((status) => DECIDED_STATUSES.includes(status)) ? 'decided_at' : 'created_at';
  const { rows } = await db.query(
    `${proposalSelect(false)}
     WHERE p.status = ANY ($2::text[])
       AND ($3::timestamptz IS NULL OR p.${column} >= $3)
       AND ($4::timestamptz IS NULL OR p.${column} < $4)
     ORDER BY p.${column} DESC, p.proposal_id
     LIMIT $5 OFFSET $6`,
    [anopodId, statuses, from, to, limit, offset],
  );
  return rows.map(proposalRow);
}

/** Deletes the proposal's snapshot rows on `client` (the pool will do): at the expiry and at the close. */
export async function deleteSnapshot(client, proposalId) {
  await client.query('DELETE FROM dao_snapshot_weights WHERE proposal_id = $1', [proposalId]);
}

/**
 * Replaces the proposal's snapshot rows on `client` with `weights`, a list
 * of { anopodId (Buffer), weight (a decimal string) }: the rows deleted,
 * then one INSERT ... SELECT over the two unnested arrays.
 */
export async function replaceSnapshot(client, proposalId, weights) {
  await deleteSnapshot(client, proposalId);
  await client.query(
    `INSERT INTO dao_snapshot_weights (proposal_id, anopod_id, weight)
     SELECT $1, * FROM unnest($2::bytea[], $3::bigint[])`,
    [proposalId, weights.map((entry) => entry.anopodId), weights.map((entry) => entry.weight)],
  );
}

/** The caller's weight in the proposal's snapshot, a decimal string, '0' when there is no row. */
export async function findWeight(client, proposalId, anopodId) {
  const { rows } = await client.query(
    'SELECT weight FROM dao_snapshot_weights WHERE proposal_id = $1 AND anopod_id = $2',
    [proposalId, anopodId],
  );
  return rows.length === 0 ? '0' : rows[0].weight;
}

/** The caller's dao_votes row of this stage: its vote ('for' or 'against'), or null when there is none. */
export async function findVote(client, proposalId, anopodId, stage) {
  const { rows } = await client.query(
    'SELECT vote FROM dao_votes WHERE proposal_id = $1 AND anopod_id = $2 AND stage = $3',
    [proposalId, anopodId, stage],
  );
  return rows.length === 0 ? null : rows[0].vote;
}

/**
 * Inserts a support or a vote on `client`: { proposalId, anopodId, stage,
 * vote, weight }. A second row of the pod in the stage throws a unique
 * violation on the primary key (db/transaction.js isUniqueViolation).
 */
export async function insertVote(client, { proposalId, anopodId, stage, vote, weight }) {
  await client.query(
    'INSERT INTO dao_votes (proposal_id, anopod_id, stage, vote, weight) VALUES ($1, $2, $3, $4, $5)',
    [proposalId, anopodId, stage, vote, weight],
  );
}

/** The sums of the proposal's weights in `stage`, { for, against } as BigInts, 0n when none (a pending stage has only for). */
export async function sumVotes(client, proposalId, stage) {
  const { rows } = await client.query(
    `SELECT COALESCE(SUM(weight) FILTER (WHERE vote = 'for'), 0)::bigint AS votes_for,
            COALESCE(SUM(weight) FILTER (WHERE vote = 'against'), 0)::bigint AS votes_against
     FROM dao_votes WHERE proposal_id = $1 AND stage = $2`,
    [proposalId, stage],
  );
  return { for: BigInt(rows[0].votes_for), against: BigInt(rows[0].votes_against) };
}

/** The proposal's rows of `stage` with the voter's username (null when the pod's row is gone), newest first, `limit` rows from `offset`. */
export async function listVotes(proposalId, stage, limit, offset, db = pool) {
  const { rows } = await db.query(
    `SELECT v.anopod_id, a.username, v.vote, v.weight, v.created_at
     FROM dao_votes v
     LEFT JOIN anopods a ON a.anopod_id = v.anopod_id
     WHERE v.proposal_id = $1 AND v.stage = $2
     ORDER BY v.created_at DESC, v.anopod_id
     LIMIT $3 OFFSET $4`,
    [proposalId, stage, limit, offset],
  );
  return rows.map((row) => ({ anopodId: row.anopod_id, username: row.username, vote: row.vote, weight: row.weight, createdAt: row.created_at }));
}

/** The flip's write on `client`: status open, the fresh snapshot's total and asOf, and the two times. */
export async function setOpen(client, proposalId, { snapshotTotal, snapshotAt, openedAt, voteClosesAt }) {
  await client.query(
    `UPDATE dao_proposals
     SET status = 'open', snapshot_total = $2, snapshot_at = $3, opened_at = $4, vote_closes_at = $5
     WHERE proposal_id = $1`,
    [proposalId, snapshotTotal, snapshotAt, openedAt, voteClosesAt],
  );
}

/** The expiry: every pending proposal whose pending_until has passed becomes expired, decided_at now. The ids changed. */
export async function expirePending(db = pool) {
  const { rows } = await db.query(
    `UPDATE dao_proposals SET status = 'expired', decided_at = now()
     WHERE status = 'pending' AND pending_until <= now()
     RETURNING proposal_id`,
  );
  return rows.map((row) => row.proposal_id);
}

/** The ids of the pending proposals whose pending-stage sum is at or above `needed`: what the clock's flip pass retries. */
export async function findPendingReached(db = pool) {
  const { rows } = await db.query(
    `SELECT p.proposal_id FROM dao_proposals p
     WHERE p.status = 'pending'
       AND (SELECT COALESCE(SUM(v.weight), 0) FROM dao_votes v
            WHERE v.proposal_id = p.proposal_id AND v.stage = 'pending') >= p.needed
     ORDER BY p.created_at, p.proposal_id`,
  );
  return rows.map((row) => row.proposal_id);
}

/**
 * The open proposals whose vote_closes_at has passed, locked for the rest
 * of the transaction on `client`, skipping the rows another box holds
 * (FOR UPDATE SKIP LOCKED): what one tick of the clock closes.
 */
export async function lockClosable(client) {
  const { rows } = await client.query(
    `SELECT proposal_id, status, vote_closes_at FROM dao_proposals
     WHERE status = 'open' AND vote_closes_at <= now()
     ORDER BY vote_closes_at, proposal_id
     FOR UPDATE SKIP LOCKED`,
  );
  return rows.map((row) => ({ proposalId: row.proposal_id, status: row.status, voteClosesAt: row.vote_closes_at }));
}

/** The close's write on `client`: the status (accepted or rejected), the two results (decimal strings), decided_at now. */
export async function setDecided(client, proposalId, status, resultFor, resultAgainst) {
  await client.query(
    `UPDATE dao_proposals SET status = $2, result_for = $3, result_against = $4, decided_at = now()
     WHERE proposal_id = $1`,
    [proposalId, status, resultFor, resultAgainst],
  );
}
