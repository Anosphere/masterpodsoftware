import { randomBytes } from 'node:crypto';
import { env } from '../config/env.js';
import { query } from '../db/pool.js';

/**
 * SQL for the challenges table: the single-use WebAuthn challenges that
 * /challenge hands out and /create-anopod and /unlock consume.
 */

/**
 * Issues a challenge for `purpose` (create, unlock, openCase, unlockCase or
 * recover), bound to `anopodId`: the id minted for a sign-up, the pod the
 * username named for openCase, or null for the others. One round trip: the
 * sweep of expired challenges, then the insert. Returns { challenge,
 * expiresAt } with the challenge as a 32-byte Buffer.
 */
export async function issue(purpose, anopodId) {
  const challenge = randomBytes(32);
  const { rows } = await query(
    `WITH swept AS (DELETE FROM challenges WHERE expires_at < now())
     INSERT INTO challenges (challenge, purpose, anopod_id, expires_at)
     VALUES ($1, $2, $3, now() + ($4::int * interval '1 second'))
     RETURNING expires_at`,
    [challenge, purpose, anopodId, env.challengeSeconds],
  );
  return { challenge, expiresAt: rows[0].expires_at };
}

/**
 * Looks a challenge up without consuming it: { anopodId } when a row with
 * this challenge and purpose exists and has not expired, else null. The
 * checks of /create-anopod, /unlock and the recovery routes run against
 * this; the write then calls take().
 */
export async function find(challenge, purpose) {
  const { rows } = await query(
    `SELECT anopod_id FROM challenges
     WHERE challenge = $1 AND purpose = $2 AND expires_at > now()`,
    [challenge, purpose],
  );
  return rows.length === 0 ? null : { anopodId: rows[0].anopod_id };
}

/**
 * Consumes a challenge inside the caller's transaction: locks and deletes
 * the row with this challenge and purpose if it is there and unexpired
 * (DELETE ... RETURNING is the select-for-update and the delete in one
 * statement) and returns { anopodId }; null when it is missing or expired.
 * Two writes racing for one challenge: one gets the row, the other null.
 * A transaction that rolls back afterwards gives the challenge back.
 */
export async function take(client, challenge, purpose) {
  const { rows } = await client.query(
    `DELETE FROM challenges
     WHERE challenge = $1 AND purpose = $2 AND expires_at > now()
     RETURNING anopod_id`,
    [challenge, purpose],
  );
  return rows.length === 0 ? null : { anopodId: rows[0].anopod_id };
}
