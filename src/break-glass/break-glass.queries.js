import { pool } from '../db/pool.js';

/**
 * SQL for the break_glass_cases and break_glass_moves tables (spec 14.3): a
 * recovery case as the attestors see it, keyed by the recovery case's own
 * id, and its moves, one per breakGlassTransfer the finish filed,
 * append-only. Ids are Buffers of raw bytes, matching the BYTEA columns.
 * Reads take an optional `db` (a client inside a transaction; the pool by
 * default); writes take the transaction's client first. The two lists
 * aggregate a case's moves as JSON in the database, so those moves' ids
 * come back as lowercase hex already (encode(..., 'hex'), the wire form)
 * and their createdAt as the database's ISO 8601 text.
 */

const CASE_COLUMNS = 'case_id, anopod_id, status, created_at, updated_at';
const MOVE_COLUMNS = 'transaction_id, case_id, account_id, account_id_to, account_type, created_at';

/** A break_glass_cases row in camelCase. Byte columns stay Buffers. */
export function caseRow(row) {
  return {
    caseId: row.case_id,
    anopodId: row.anopod_id,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** A break_glass_moves row in camelCase. Byte columns stay Buffers. */
export function moveRow(row) {
  return {
    transactionId: row.transaction_id,
    caseId: row.case_id,
    accountId: row.account_id,
    accountIdTo: row.account_id_to,
    accountType: row.account_type,
    createdAt: row.created_at,
  };
}

/** The break-glass case with this id (a 32-byte Buffer, the recovery case's), or null. */
export async function findCase(caseId, db = pool) {
  const { rows } = await db.query(`SELECT ${CASE_COLUMNS} FROM break_glass_cases WHERE case_id = $1`, [caseId]);
  return rows.length === 0 ? null : caseRow(rows[0]);
}

/**
 * The break-glass case with this id, locked for the rest of the transaction
 * on `client` (SELECT ... FOR UPDATE), or null. Every write to a case locks
 * it first, so two second sign-offs, a dismissal racing a sign-off, or a
 * filing racing either, see each other's status.
 */
export async function lockCase(client, caseId) {
  const { rows } = await client.query(`SELECT ${CASE_COLUMNS} FROM break_glass_cases WHERE case_id = $1 FOR UPDATE`, [caseId]);
  return rows.length === 0 ? null : caseRow(rows[0]);
}

/**
 * Inserts the case row on `client` with status open, when there is none:
 * ON CONFLICT DO NOTHING, since the wallet files once per finish and again
 * on Retry for the moves that failed. Returns true when the row was
 * inserted, false when it was already there.
 */
export async function insertCase(client, caseId, anopodId) {
  const { rowCount } = await client.query(
    'INSERT INTO break_glass_cases (case_id, anopod_id) VALUES ($1, $2) ON CONFLICT (case_id) DO NOTHING',
    [caseId, anopodId],
  );
  return rowCount === 1;
}

/** Moves the case to `status` on `client` (spec 14.5); the trigger stamps updated_at. */
export async function updateStatus(client, caseId, status) {
  await client.query('UPDATE break_glass_cases SET status = $2 WHERE case_id = $1', [caseId, status]);
}

/**
 * A case's moves as one JSON array, in account order, each { accountId,
 * accountIdTo, transactionId, accountType, createdAt }, the ids lowercase
 * hex and createdAt the database's ISO 8601 text; [] when the case has
 * none. A column of the select both lists share.
 */
const MOVES_JSON = `COALESCE((SELECT json_agg(json_build_object(
                                 'accountId', encode(m.account_id, 'hex'),
                                 'accountIdTo', encode(m.account_id_to, 'hex'),
                                 'transactionId', encode(m.transaction_id, 'hex'),
                                 'accountType', m.account_type,
                                 'createdAt', m.created_at)
                               ORDER BY m.account_id, m.transaction_id)
                      FROM break_glass_moves m WHERE m.case_id = c.case_id), '[]'::json)`;

/**
 * The select both lists share: the case, its pod's username and names
 * (null when the pod's row is gone), its moves as MOVES_JSON and
 * `signOffs`, the count of distinct pods with an attestationSigned event,
 * as assisted-trades.queries.js listByStatus counts a trade's.
 */
const LIST_SELECT = `SELECT c.case_id, c.anopod_id, c.status, c.created_at, c.updated_at,
            a.username, a.first_name, a.last_name,
            ${MOVES_JSON} AS moves,
            (SELECT count(DISTINCT e.anopod_id) FROM attestor_events e
             WHERE e.case_id = c.case_id AND e.kind = 'attestationSigned')::int AS sign_offs
     FROM break_glass_cases c
     LEFT JOIN anopods a ON a.anopod_id = c.anopod_id`;

/** A row of LIST_SELECT: the case row with the pod's names, the moves (already hex) and the sign-off count. */
function listItem(row) {
  return {
    ...caseRow(row),
    username: row.username,
    firstName: row.first_name,
    lastName: row.last_name,
    moves: row.moves,
    signOffs: row.sign_offs,
  };
}

/** The attestors' list (spec 14.4.2): the cases in `statuses`, newest first, each as listItem. */
export async function listCasesByStatus(statuses, db = pool) {
  const { rows } = await db.query(
    `${LIST_SELECT}
     WHERE c.status = ANY ($1::text[])
     ORDER BY c.created_at DESC, c.case_id`,
    [statuses],
  );
  return rows.map(listItem);
}

/** The person's list (spec 14.4.1): the cases of the pod `anopodId`, newest first, each as listItem. */
export async function listCasesForPod(anopodId, db = pool) {
  const { rows } = await db.query(
    `${LIST_SELECT}
     WHERE c.anopod_id = $1
     ORDER BY c.created_at DESC, c.case_id`,
    [anopodId],
  );
  return rows.map(listItem);
}

/** The move with this transaction id (a 32-byte Buffer), or null: the filing's "no move with this transactionId yet". */
export async function findMove(transactionId, db = pool) {
  const { rows } = await db.query(`SELECT ${MOVE_COLUMNS} FROM break_glass_moves WHERE transaction_id = $1`, [transactionId]);
  return rows.length === 0 ? null : moveRow(rows[0]);
}

/**
 * Inserts a move on `client`: { transactionId, caseId, accountId,
 * accountIdTo, accountType }. A second move for the transaction throws a
 * unique violation on the primary key (db/transaction.js isUniqueViolation).
 */
export async function insertMove(client, move) {
  await client.query(
    `INSERT INTO break_glass_moves (transaction_id, case_id, account_id, account_id_to, account_type)
     VALUES ($1, $2, $3, $4, $5)`,
    [move.transactionId, move.caseId, move.accountId, move.accountIdTo, move.accountType],
  );
}

/** The moves of a case, account order (the old account's id, then the transaction id). */
export async function listMoves(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${MOVE_COLUMNS} FROM break_glass_moves WHERE case_id = $1 ORDER BY account_id, transaction_id`,
    [caseId],
  );
  return rows.map(moveRow);
}
