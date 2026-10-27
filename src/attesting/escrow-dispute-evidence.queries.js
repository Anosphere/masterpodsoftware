import { pool } from '../db/pool.js';

/**
 * SQL for the escrow_dispute_evidence table (spec 13.3): one row per file a
 * party uploaded to a dispute case, the file under its content key and that
 * key twice, under the uploader's pod encryption key (stays) and encrypted
 * to the case key (nulled when the case is decided or dismissed). Ids and
 * bytes are Buffers.
 */

const COLUMNS = 'evidence_id, case_id, anopod_id, content_type, file, key_for_me, key_for_case, created_at, updated_at';

/** An escrow_dispute_evidence row in camelCase. Byte columns stay Buffers; keyForCase is null after the end of the case. */
export function evidenceRow(row) {
  return {
    evidenceId: row.evidence_id,
    caseId: row.case_id,
    anopodId: row.anopod_id,
    contentType: row.content_type,
    file: row.file,
    keyForMe: row.key_for_me,
    keyForCase: row.key_for_case,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Writes one row on `client`: `row` is { evidenceId, caseId, anopodId,
 * contentType, file, keyForMe, keyForCase }, the byte fields Buffers.
 */
export async function insertEvidence(client, row) {
  await client.query(
    `INSERT INTO escrow_dispute_evidence (evidence_id, case_id, anopod_id, content_type, file, key_for_me, key_for_case)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [row.evidenceId, row.caseId, row.anopodId, row.contentType, row.file, row.keyForMe, row.keyForCase],
  );
}

/**
 * Supplies a file to another case on `client` (spec 13.4.5, `existing`): a
 * new row for `caseId` copying content_type, file and key_for_me from the
 * row `fromEvidenceId`, which must be `anopodId`'s, with the new
 * `keyForCase`. The server copies; nothing is re-sent. Returns true when
 * the row was written, false when the source row is not the pod's.
 */
export async function copyEvidence(client, { evidenceId, caseId, anopodId, fromEvidenceId, keyForCase }) {
  const { rowCount } = await client.query(
    `INSERT INTO escrow_dispute_evidence (evidence_id, case_id, anopod_id, content_type, file, key_for_me, key_for_case)
     SELECT $1, $2, $3, content_type, file, key_for_me, $4
     FROM escrow_dispute_evidence WHERE evidence_id = $5 AND anopod_id = $3`,
    [evidenceId, caseId, anopodId, keyForCase, fromEvidenceId],
  );
  return rowCount === 1;
}

/** The row with this id without its bytes, { evidenceId, caseId, anopodId, contentType, createdAt }, or null: the check that an `existing` entry names the caller's row. */
export async function findById(evidenceId, db = pool) {
  const { rows } = await db.query(
    'SELECT evidence_id, case_id, anopod_id, content_type, created_at FROM escrow_dispute_evidence WHERE evidence_id = $1',
    [evidenceId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return { evidenceId: row.evidence_id, caseId: row.case_id, anopodId: row.anopod_id, contentType: row.content_type, createdAt: row.created_at };
}

/** Every row of the case with the uploader's username (null when the pod's row is gone), oldest first: what /get-dispute-case shows the attestors. */
export async function listForCase(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT e.evidence_id, e.case_id, e.anopod_id, e.content_type, e.file, e.key_for_me, e.key_for_case, e.created_at, e.updated_at, a.username
     FROM escrow_dispute_evidence e
     LEFT JOIN anopods a ON a.anopod_id = e.anopod_id
     WHERE e.case_id = $1
     ORDER BY e.created_at, e.evidence_id`,
    [caseId],
  );
  return rows.map((row) => ({ ...evidenceRow(row), username: row.username }));
}

/** The rows `anopodId` uploaded to the case, oldest first: what /get-my-case shows a party. */
export async function listForCaseAndPod(caseId, anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${COLUMNS} FROM escrow_dispute_evidence WHERE case_id = $1 AND anopod_id = $2 ORDER BY created_at, evidence_id`,
    [caseId, anopodId],
  );
  return rows.map(evidenceRow);
}

/** Removes the case-key copy from every row of the case on `client` (the case decided or dismissed). Returns how many rows lost one. */
export async function clearCaseKeys(client, caseId) {
  const { rowCount } = await client.query(
    'UPDATE escrow_dispute_evidence SET key_for_case = NULL WHERE case_id = $1 AND key_for_case IS NOT NULL',
    [caseId],
  );
  return rowCount;
}
