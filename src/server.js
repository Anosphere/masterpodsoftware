import { createApp } from './app.js';
import { env } from './config/env.js';
import { startDaoClock, stopDaoClock } from './dao/dao-clock.js';
import { closePool, query } from './db/pool.js';

// Verify the database connection before accepting traffic, so a bad
// configuration fails loudly at boot instead of on the first request.
try {
  const { rows } = await query('SHOW server_version');
  console.log(
    `Connected to PostgreSQL ${rows[0].server_version} ` +
      `at ${env.db.host}:${env.db.port}/${env.db.database}`,
  );
} catch (err) {
  console.error('Could not connect to PostgreSQL:', err.message);
  process.exit(1);
}

const app = createApp();

const server = app.listen(env.port, () => {
  console.log(`masterpodsoftware listening on http://localhost:${env.port}`);
  // And the DAO clock (src/dao/dao-clock.js): once now, then every minute,
  // the expiry, the flip and the close of the DAO proposals (spec 15.5).
  startDaoClock();
});

let shuttingDown = false;

/** Stop accepting connections, let in-flight requests finish, drain the pool. */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  stopDaoClock();
  console.log(`\n${signal} received, shutting down...`);

  // Safety net: never hang forever if a connection refuses to close.
  setTimeout(() => {
    console.error('Shutdown timed out, forcing exit');
    process.exit(1);
  }, 10_000).unref();

  try {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await closePool();
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
