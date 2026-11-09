import { pool } from '../db/pool.js';

/**
 * SQL for the appointments table (spec section 16): the pods that are
 * moderators or attestors. A pod holds a role while it has a row with no
 * revoked_at, at most one such row per pod (the partial unique index
 * appointments_one_live_per_pod). Only scripts/appoint.js and
 * scripts/revoke.js write the table; no route does. The gates in
 * src/auth/require-moderator.js and require-attestor.js read it, and so do
 * the two answers that carry a pod's role (/get-anos-account,
 * /check-anopod-status).
 */

/** The pod's live role: 'moderator', 'attestor' or null. */
export async function findLiveRole(anopodId, db = pool) {
  const { rows } = await db.query('SELECT role FROM appointments WHERE anopod_id = $1 AND revoked_at IS NULL', [
    anopodId,
  ]);
  return rows.length === 0 ? null : rows[0].role;
}

/** True when the pod holds a live appointment for this role ('moderator' or 'attestor'). */
export async function isAppointed(anopodId, role, db = pool) {
  const { rows } = await db.query(
    'SELECT EXISTS (SELECT 1 FROM appointments WHERE anopod_id = $1 AND role = $2 AND revoked_at IS NULL) AS found',
    [anopodId, role],
  );
  return rows[0].found;
}

/**
 * The pods with a live appointment for this role whose setup is complete
 * (so they have chat keys a case key can be wrapped to), username order:
 * [ { anopodId, username, firstName, lastName } ], the id a Buffer.
 */
export async function listAppointedPods(role, db = pool) {
  const { rows } = await db.query(
    `SELECT a.anopod_id, a.username, a.first_name, a.last_name
     FROM appointments p
     JOIN anopods a ON a.anopod_id = p.anopod_id
     WHERE p.role = $1 AND p.revoked_at IS NULL AND a.anopod_encryption_key_blob_2 IS NOT NULL
     ORDER BY a.username`,
    [role],
  );
  return rows.map((row) => ({ anopodId: row.anopod_id, username: row.username, firstName: row.first_name, lastName: row.last_name }));
}

/**
 * Appoints the pod on `client`: a new row, appointed_at now(). `appointedBy`
 * is 'operator' for the scripts, otherwise the hex id of the pod that
 * appointed. A pod that already holds a live appointment throws a unique
 * violation on appointments_one_live_per_pod.
 */
export async function insertAppointment(client, anopodId, role, appointedBy) {
  await client.query('INSERT INTO appointments (anopod_id, role, appointed_by) VALUES ($1, $2, $3)', [
    anopodId,
    role,
    appointedBy,
  ]);
}

/**
 * Ends the pod's live appointment on `client`, if it has one: revoked_at =
 * now(); the row stays. Returns the row count, 1 or 0.
 */
export async function revokeAppointment(client, anopodId) {
  const { rowCount } = await client.query(
    'UPDATE appointments SET revoked_at = now() WHERE anopod_id = $1 AND revoked_at IS NULL',
    [anopodId],
  );
  return rowCount;
}
