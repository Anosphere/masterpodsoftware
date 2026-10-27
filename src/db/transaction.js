import { pool } from './pool.js';

/**
 * Runs `fn(client)` inside one database transaction on a client from the
 * pool: BEGIN, fn, COMMIT; ROLLBACK when fn throws, and the client always
 * goes back to the pool. Returns what fn returns. Every multi-row write in
 * this server goes through here, so each lands whole or not at all.
 */
export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** PostgreSQL's error code for a UNIQUE or PRIMARY KEY violation. */
export const UNIQUE_VIOLATION = '23505';

/** True when `err` is PostgreSQL refusing a duplicate key. */
export function isUniqueViolation(err) {
  return err?.code === UNIQUE_VIOLATION;
}
