import { query } from '../db/pool.js';

/**
 * SQL for the nonces table, the replay cache of signed session requests
 * (spec section 3, step 7).
 */

/**
 * Records that `nonce` was seen on a request signed by `anopodId`, kept
 * until `expiresAt`. One round trip: the sweep of expired nonces, then the
 * insert. Returns true when the nonce was new, false when the same pod
 * already used it: a replay.
 */
export async function insertNonce(anopodId, nonce, expiresAt) {
  const { rowCount } = await query(
    `WITH swept AS (DELETE FROM nonces WHERE expires_at < now())
     INSERT INTO nonces (anopod_id, nonce, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT DO NOTHING`,
    [anopodId, nonce, expiresAt],
  );
  return rowCount === 1;
}
