import { pool } from '../db/pool.js';
import { REVIEW_STATUSES } from './assisted-trades.queries.js';

/**
 * SQL for the escrow_disputes table (spec 13.3): one case per disputed
 * escrow. Ids and keys are Buffers of raw bytes, matching the BYTEA columns.
 * Reads take an optional `db`; writes take the transaction's client first.
 * The statuses are assisted-trades.queries.js's: both kinds share them.
 */

const COLUMNS = `case_id, transaction_id, account_id, account_id_to, anopod_id, anopod_id_to, disputed_by, opened_by,
       case_key_x25519, case_key_mlkem, status, created_at, updated_at`;

/** An escrow_disputes row in camelCase. Byte columns stay Buffers. */
export function disputeRow(row) {
  return {
    caseId: row.case_id,
    transactionId: row.transaction_id,
    accountId: row.account_id,
    accountIdTo: row.account_id_to,
    anopodId: row.anopod_id,
    anopodIdTo: row.anopod_id_to,
    disputedBy: row.disputed_by,
    openedBy: row.opened_by,
    caseKeyX25519: row.case_key_x25519,
    caseKeyMlkem: row.case_key_mlkem,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** The dispute case with this id (a 32-byte Buffer), or null. */
export async function findById(caseId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM escrow_disputes WHERE case_id = $1`, [caseId]);
  return rows.length === 0 ? null : disputeRow(rows[0]);
}

/** The dispute case with this id, locked for the rest of the transaction on `client` (SELECT ... FOR UPDATE), or null. */
export async function lockById(client, caseId) {
  const { rows } = await client.query(`SELECT ${COLUMNS} FROM escrow_disputes WHERE case_id = $1 FOR UPDATE`, [caseId]);
  return rows.length === 0 ? null : disputeRow(rows[0]);
}

/** True when a case for this escrow is open or inReview: the one-open-case-per-escrow rule. */
export async function openDisputeExists(transactionId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM escrow_disputes WHERE transaction_id = $1 AND status = ANY ($2::text[])) AS open`,
    [transactionId, REVIEW_STATUSES],
  );
  return rows[0].open;
}

/**
 * Inserts a dispute case on `client` with status open. `row` is { caseId,
 * transactionId, accountId, accountIdTo, anopodId, anopodIdTo, disputedBy,
 * openedBy, caseKeyX25519, caseKeyMlkem }. A second open case for the
 * transaction throws a unique violation on
 * escrow_disputes_one_open_per_transaction.
 */
export async function insertDispute(client, row) {
  await client.query(
    `INSERT INTO escrow_disputes (case_id, transaction_id, account_id, account_id_to, anopod_id, anopod_id_to,
                                  disputed_by, opened_by, case_key_x25519, case_key_mlkem)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      row.caseId,
      row.transactionId,
      row.accountId,
      row.accountIdTo,
      row.anopodId,
      row.anopodIdTo,
      row.disputedBy,
      row.openedBy,
      row.caseKeyX25519,
      row.caseKeyMlkem,
    ],
  );
}

/**
 * The attestors' list (spec 13.4.3): the dispute cases in `statuses`,
 * newest first, each with the seller's and the buyer's username and names
 * and the opening attestor's username (null when a pod's row is gone),
 * `signOffs`, the count of distinct pods with a verdictSigned event, and
 * `evidenceCount`, the rows of escrow_dispute_evidence on the case.
 */
export async function listByStatus(statuses, db = pool) {
  const { rows } = await db.query(
    `SELECT c.case_id, c.transaction_id, c.account_id, c.account_id_to, c.anopod_id, c.anopod_id_to, c.disputed_by, c.opened_by,
            c.case_key_x25519, c.case_key_mlkem, c.status, c.created_at, c.updated_at,
            s.username AS seller_username, s.first_name AS seller_first_name, s.last_name AS seller_last_name,
            b.username AS buyer_username, b.first_name AS buyer_first_name, b.last_name AS buyer_last_name,
            o.username AS opened_by_username,
            (SELECT count(DISTINCT e.anopod_id) FROM attestor_events e
             WHERE e.case_id = c.case_id AND e.kind = 'verdictSigned')::int AS sign_offs,
            (SELECT count(*) FROM escrow_dispute_evidence v WHERE v.case_id = c.case_id)::int AS evidence_count
     FROM escrow_disputes c
     LEFT JOIN anopods s ON s.anopod_id = c.anopod_id
     LEFT JOIN anopods b ON b.anopod_id = c.anopod_id_to
     LEFT JOIN anopods o ON o.anopod_id = c.opened_by
     WHERE c.status = ANY ($1::text[])
     ORDER BY c.created_at DESC, c.case_id`,
    [statuses],
  );
  return rows.map((row) => ({
    ...disputeRow(row),
    seller: { username: row.seller_username, firstName: row.seller_first_name, lastName: row.seller_last_name },
    buyer: { username: row.buyer_username, firstName: row.buyer_first_name, lastName: row.buyer_last_name },
    openedByUsername: row.opened_by_username,
    signOffs: row.sign_offs,
    evidenceCount: row.evidence_count,
  }));
}

/** The person's dispute cases (spec 13.4.5): those where `anopodId` is the seller's or the buyer's pod, newest first. */
export async function listForPod(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${COLUMNS} FROM escrow_disputes WHERE anopod_id = $1 OR anopod_id_to = $1 ORDER BY created_at DESC, case_id`,
    [anopodId],
  );
  return rows.map(disputeRow);
}

/** Moves the case to `status` on `client` (spec 13.5); the trigger stamps updated_at. */
export async function updateStatus(client, caseId, status) {
  await client.query('UPDATE escrow_disputes SET status = $2 WHERE case_id = $1', [caseId, status]);
}
