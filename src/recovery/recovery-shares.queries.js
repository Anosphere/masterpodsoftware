import { pool } from '../db/pool.js';

/**
 * SQL for the recovery_shares table (spec 12.3): what the keyholders posted
 * to a case's recovery pod, as posted. The insert is /receive-recovery-share's
 * (build 3); the reads serve the person and the moderators.
 */


/** A recovery_shares row in camelCase. Byte columns stay Buffers. */
export function shareRow(row) {
  return {
    shareId: row.share_id,
    caseId: row.case_id,
    keyholderId: row.keyholder_id,
    lookupId: row.lookup_id,
    shareType: row.share_type,
    keyId: row.key_id,
    share: row.share,
    createdAt: row.created_at,
  };
}

/** Every share posted to a case, oldest first. */
export async function listForCase(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT share_id, case_id, keyholder_id, lookup_id, share_type, key_id, share, created_at
     FROM recovery_shares WHERE case_id = $1
     ORDER BY created_at, share_id`,
    [caseId],
  );
  return rows.map(shareRow);
}

/**
 * Inserts a share on `client`: `row` is { shareId, caseId, keyholderId,
 * lookupId, shareType, keyId, share }, the byte fields Buffers. A banker's
 * second send of the same share (the same case, type, key id and keyholder)
 * is a no-op on the unique key: returns true when the row was inserted,
 * false when it was already there.
 */
export async function insertShare(client, row) {
  const { rowCount } = await client.query(
    `INSERT INTO recovery_shares (share_id, case_id, keyholder_id, lookup_id, share_type, key_id, share)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (case_id, share_type, key_id, keyholder_id) DO NOTHING`,
    [row.shareId, row.caseId, row.keyholderId, row.lookupId, row.shareType, row.keyId, row.share],
  );
  return rowCount === 1;
}
