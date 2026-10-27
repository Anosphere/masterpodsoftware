import { pool } from '../db/pool.js';

/**
 * SQL for the seeds and super_seeds tables. anopods.queries.js seedStatus
 * reads both flags in one query; these are the single checks and the one
 * write the approve flow needs. Super seeds are only ever written by
 * scripts/make-super-seed.js.
 */

/** True when the pod is in seeds. */
export async function isSeed(anopodId, db = pool) {
  const { rows } = await db.query('SELECT EXISTS (SELECT 1 FROM seeds WHERE anopod_id = $1) AS found', [anopodId]);
  return rows[0].found;
}

/** True when the pod is in super_seeds. */
export async function isSuperSeed(anopodId, db = pool) {
  const { rows } = await db.query('SELECT EXISTS (SELECT 1 FROM super_seeds WHERE anopod_id = $1) AS found', [
    anopodId,
  ]);
  return rows[0].found;
}

/**
 * Makes the pod a seed on `client`: `vouchedBy` is the hex id of the super
 * seed whose approval did it. trust_score starts at its default, 0.
 */
export async function insertSeed(client, anopodId, vouchedBy) {
  await client.query('INSERT INTO seeds (anopod_id, vouched_by) VALUES ($1, $2)', [anopodId, vouchedBy]);
}
