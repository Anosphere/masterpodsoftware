import { pool } from '../db/pool.js';

/**
 * SQL for the recovery_cases table (spec 12.3): one row per case. Ids are
 * Buffers of raw bytes, matching the BYTEA columns. Reads take an optional
 * `db` (a client inside a transaction; the pool by default); writes take
 * the transaction's client first.
 */

/** The statuses of spec 12.5, in order; the last two are final. */
export const CASE_STATUSES = ['open', 'inReview', 'approved', 'delivering', 'completed', 'dismissed'];

/** A case in one of these statuses is closed: another case may be opened for its lookup id. */
export const FINAL_STATUSES = ['completed', 'dismissed'];

const COLUMNS = 'case_id, lookup_id, anopod_id, contact_email, contact_phone, status, created_at, updated_at';

/**
 * A recovery_cases row in camelCase, as requireRecoverySession puts it on
 * req.recoveryCase. Byte columns stay Buffers; contactEmail and
 * contactPhone are each a string or null, at least one of them a string.
 */
export function caseRow(row) {
  return {
    caseId: row.case_id,
    lookupId: row.lookup_id,
    anopodId: row.anopod_id,
    contactEmail: row.contact_email,
    contactPhone: row.contact_phone,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** The case with this id (a 32-byte Buffer), or null. */
export async function findById(caseId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM recovery_cases WHERE case_id = $1`, [caseId]);
  return rows.length === 0 ? null : caseRow(rows[0]);
}

/** True when a case for this lookup id is open (status not completed or dismissed): the one-open-case rule. */
export async function openCaseExists(lookupId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM recovery_cases WHERE lookup_id = $1 AND status <> ALL ($2::text[])) AS open`,
    [lookupId, FINAL_STATUSES],
  );
  return rows[0].open;
}

/**
 * Inserts a case on `client` with status open. `row` is { caseId, lookupId,
 * anopodId, contactEmail, contactPhone }, the last two each a string or
 * null, null for the one the person did not give. A second open case for
 * the lookup id throws a unique violation on
 * recovery_cases_one_open_per_lookup_id.
 */
export async function insertCase(client, row) {
  await client.query(
    `INSERT INTO recovery_cases (case_id, lookup_id, anopod_id, contact_email, contact_phone)
     VALUES ($1, $2, $3, $4, $5)`,
    [row.caseId, row.lookupId, row.anopodId, row.contactEmail, row.contactPhone],
  );
}

/** The statuses /list-recovery-cases shows by default: the cases still in progress (spec 12.4.4). */
export const DEFAULT_LIST_STATUSES = ['open', 'inReview', 'approved', 'delivering'];

/**
 * The case with this id, locked for the rest of the transaction on `client`
 * (SELECT ... FOR UPDATE), or null. The moderator writes lock the case first,
 * so two sign-offs racing for the second approval, or a dismissal racing a
 * sign-off, see each other's status.
 */
export async function lockById(client, caseId) {
  const { rows } = await client.query(`SELECT ${COLUMNS} FROM recovery_cases WHERE case_id = $1 FOR UPDATE`, [caseId]);
  return rows.length === 0 ? null : caseRow(rows[0]);
}

/**
 * The moderators' list (spec 12.4.4): the cases in `statuses`, newest first,
 * each with its pod's username and names (null when the pod's row is gone)
 * and `approvals`, the count of distinct pods with an approvalSigned event.
 */
export async function listByStatus(statuses, db = pool) {
  const { rows } = await db.query(
    `SELECT c.case_id, c.lookup_id, c.anopod_id, c.contact_email, c.contact_phone, c.status, c.created_at, c.updated_at,
            a.username, a.first_name, a.last_name,
            (SELECT count(DISTINCT e.anopod_id) FROM recovery_events e
             WHERE e.case_id = c.case_id AND e.kind = 'approvalSigned')::int AS approvals
     FROM recovery_cases c
     LEFT JOIN anopods a ON a.anopod_id = c.anopod_id
     WHERE c.status = ANY ($1::text[])
     ORDER BY c.created_at DESC, c.case_id`,
    [statuses],
  );
  return rows.map((row) => ({
    ...caseRow(row),
    username: row.username,
    firstName: row.first_name,
    lastName: row.last_name,
    approvals: row.approvals,
  }));
}

/** Moves the case to `status` on `client` (spec 12.5); the trigger stamps updated_at. */
export async function updateStatus(client, caseId, status) {
  await client.query('UPDATE recovery_cases SET status = $2 WHERE case_id = $1', [caseId, status]);
}
