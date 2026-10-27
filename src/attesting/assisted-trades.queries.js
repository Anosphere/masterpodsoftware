import { pool } from '../db/pool.js';

/**
 * SQL for the assisted_trades table (spec 13.3): one case per assisted
 * trade. Ids are Buffers of raw bytes, matching the BYTEA columns. Reads
 * take an optional `db` (a client inside a transaction; the pool by
 * default); writes take the transaction's client first.
 */

/** The statuses of spec 13.5, in order; the last two are final. Both kinds of case share them. */
export const CASE_STATUSES = ['open', 'inReview', 'decided', 'dismissed'];

/** A case in one of these is open for work: scheduled, signed off or dismissed by an attestor; the lookup id shared or evidence added by a party. */
export const REVIEW_STATUSES = ['open', 'inReview'];

/** The statuses /list-attestor-cases shows by default (spec 13.4.3). */
export const DEFAULT_LIST_STATUSES = ['open', 'inReview'];

const COLUMNS = 'case_id, transaction_id, account_id, anopod_id, opened_by, lookup_id, status, created_at, updated_at';

/** An assisted_trades row in camelCase. Byte columns stay Buffers; lookupId is null until shared and after the end. */
export function tradeRow(row) {
  return {
    caseId: row.case_id,
    transactionId: row.transaction_id,
    accountId: row.account_id,
    anopodId: row.anopod_id,
    openedBy: row.opened_by,
    lookupId: row.lookup_id,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** The trade case with this id (a 32-byte Buffer), or null. */
export async function findById(caseId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM assisted_trades WHERE case_id = $1`, [caseId]);
  return rows.length === 0 ? null : tradeRow(rows[0]);
}

/**
 * The trade case with this id, locked for the rest of the transaction on
 * `client` (SELECT ... FOR UPDATE), or null. Every write to a case locks it
 * first, so two second attestations, or a dismissal racing a sign-off, see
 * each other's status.
 */
export async function lockById(client, caseId) {
  const { rows } = await client.query(`SELECT ${COLUMNS} FROM assisted_trades WHERE case_id = $1 FOR UPDATE`, [caseId]);
  return rows.length === 0 ? null : tradeRow(rows[0]);
}

/** True when a case for this transaction is open or inReview: the one-open-case-per-trade rule. */
export async function openTradeExists(transactionId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM assisted_trades WHERE transaction_id = $1 AND status = ANY ($2::text[])) AS open`,
    [transactionId, REVIEW_STATUSES],
  );
  return rows[0].open;
}

/**
 * Inserts a trade case on `client` with status open and no lookup id. `row`
 * is { caseId, transactionId, accountId, anopodId, openedBy }. A second
 * open case for the transaction throws a unique violation on
 * assisted_trades_one_open_per_transaction.
 */
export async function insertTrade(client, row) {
  await client.query(
    `INSERT INTO assisted_trades (case_id, transaction_id, account_id, anopod_id, opened_by)
     VALUES ($1, $2, $3, $4, $5)`,
    [row.caseId, row.transactionId, row.accountId, row.anopodId, row.openedBy],
  );
}

/**
 * The attestors' list (spec 13.4.3): the trade cases in `statuses`, newest
 * first, each with the sender pod's username and names and the opening
 * attestor's username (null when a pod's row is gone) and `signOffs`, the
 * count of distinct pods with an attestationSigned event.
 */
export async function listByStatus(statuses, db = pool) {
  const { rows } = await db.query(
    `SELECT c.case_id, c.transaction_id, c.account_id, c.anopod_id, c.opened_by, c.lookup_id, c.status, c.created_at, c.updated_at,
            a.username, a.first_name, a.last_name, o.username AS opened_by_username,
            (SELECT count(DISTINCT e.anopod_id) FROM attestor_events e
             WHERE e.case_id = c.case_id AND e.kind = 'attestationSigned')::int AS sign_offs
     FROM assisted_trades c
     LEFT JOIN anopods a ON a.anopod_id = c.anopod_id
     LEFT JOIN anopods o ON o.anopod_id = c.opened_by
     WHERE c.status = ANY ($1::text[])
     ORDER BY c.created_at DESC, c.case_id`,
    [statuses],
  );
  return rows.map((row) => ({
    ...tradeRow(row),
    username: row.username,
    firstName: row.first_name,
    lastName: row.last_name,
    openedByUsername: row.opened_by_username,
    signOffs: row.sign_offs,
  }));
}

/** The person's trade cases (spec 13.4.5): those whose sender pod is `anopodId`, newest first. */
export async function listForPod(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${COLUMNS} FROM assisted_trades WHERE anopod_id = $1 ORDER BY created_at DESC, case_id`,
    [anopodId],
  );
  return rows.map(tradeRow);
}

/** Moves the case to `status` on `client` (spec 13.5); the trigger stamps updated_at. */
export async function updateStatus(client, caseId, status) {
  await client.query('UPDATE assisted_trades SET status = $2 WHERE case_id = $1', [caseId, status]);
}

/** Sets lookup_id on `client`: the 32 bytes the person shared, or null to clear it when the case is decided or dismissed. */
export async function setLookupId(client, caseId, lookupId) {
  await client.query('UPDATE assisted_trades SET lookup_id = $2 WHERE case_id = $1', [caseId, lookupId]);
}
