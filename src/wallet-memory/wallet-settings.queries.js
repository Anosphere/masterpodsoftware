import { pool, query } from '../db/pool.js';

/**
 * SQL for the wallet_settings table (wallet spec 4.7): one row per pod,
 * replaced in place. The pod id and the blob are Buffers of raw bytes,
 * matching the BYTEA columns.
 */

/** The pod's row as { settingsBlob, updatedAt } (a Buffer and a Date), or null before the first set. */
export async function findSettings(anopodId, db = pool) {
  const { rows } = await db.query('SELECT settings_blob, updated_at FROM wallet_settings WHERE anopod_id = $1', [anopodId]);
  return rows.length === 0 ? null : { settingsBlob: rows[0].settings_blob, updatedAt: rows[0].updated_at };
}

/**
 * Writes the pod's one row whole: an INSERT, or an UPDATE of the blob when
 * the row exists (the trigger stamps updated_at on that path). Returns the
 * row's updated_at Date.
 */
export async function upsertSettings(anopodId, settingsBlob) {
  const { rows } = await query(
    `INSERT INTO wallet_settings (anopod_id, settings_blob) VALUES ($1, $2)
     ON CONFLICT (anopod_id) DO UPDATE SET settings_blob = EXCLUDED.settings_blob
     RETURNING updated_at`,
    [anopodId, settingsBlob],
  );
  return rows[0].updated_at;
}
