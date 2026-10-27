import pg from 'pg';
import { env } from '../config/env.js';

const { Pool } = pg;

/**
 * One shared connection pool for the whole process. PostgreSQL runs on the
 * same machine as this server, so the pool connects over TCP to
 * 127.0.0.1:5432.
 */
export const pool = new Pool({
  ...env.db,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

// An idle client can emit an error (for example when PostgreSQL restarts).
// Without this listener that error is unhandled and crashes the process.
pool.on('error', (err) => {
  console.error('Unexpected error on idle PostgreSQL client', err);
});

/** Runs a single query using a pooled connection. */
export function query(text, params) {
  return pool.query(text, params);
}

/** Drains the pool. Called once during graceful shutdown. */
export function closePool() {
  return pool.end();
}
