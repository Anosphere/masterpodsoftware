import { pool } from '../db/pool.js';

/**
 * SQL for the escrow_dispute_keys table (spec 13.3): a dispute case's
 * private key wrapped to each attestor pod's chat public key, as chat_hpke
 * holds a room key for a member. Written at open and by /share-case-key;
 * every row of a case is deleted when the case is decided or dismissed.
 * Ids and keys are Buffers.
 */

/** Writes the key wrapped to `anopodId` on `client`. A second row for the pod throws a unique violation on the primary key. */
export async function insertKey(client, caseId, anopodId, wrappedKey) {
  await client.query(
    'INSERT INTO escrow_dispute_keys (case_id, anopod_id, wrapped_key) VALUES ($1, $2, $3)',
    [caseId, anopodId, wrappedKey],
  );
}

/** The key wrapped to `anopodId` for the case, a Buffer, or null when the pod holds none. */
export async function findKey(caseId, anopodId, db = pool) {
  const { rows } = await db.query(
    'SELECT wrapped_key FROM escrow_dispute_keys WHERE case_id = $1 AND anopod_id = $2',
    [caseId, anopodId],
  );
  return rows.length === 0 ? null : rows[0].wrapped_key;
}

/** True when `anopodId` holds a key row for the case. */
export async function keyExists(caseId, anopodId, db = pool) {
  const { rows } = await db.query(
    'SELECT EXISTS (SELECT 1 FROM escrow_dispute_keys WHERE case_id = $1 AND anopod_id = $2) AS found',
    [caseId, anopodId],
  );
  return rows[0].found;
}

/** The pods holding a key row for the case (Buffers), oldest row first: who can share the key with a later appointee. */
export async function listHolders(caseId, db = pool) {
  const { rows } = await db.query(
    'SELECT anopod_id FROM escrow_dispute_keys WHERE case_id = $1 ORDER BY created_at, anopod_id',
    [caseId],
  );
  return rows.map((row) => row.anopod_id);
}

/** Deletes every key row of the case on `client` (the case decided or dismissed). Returns how many rows went. */
export async function deleteForCase(client, caseId) {
  const { rowCount } = await client.query('DELETE FROM escrow_dispute_keys WHERE case_id = $1', [caseId]);
  return rowCount;
}
