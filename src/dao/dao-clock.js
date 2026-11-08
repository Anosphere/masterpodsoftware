import { env } from '../config/env.js';
import { pool } from '../db/pool.js';
import { withTransaction } from '../db/transaction.js';
import { toHex } from '../util/ids.js';
import { deleteSnapshot, expirePending, findPendingReached, lockClosable, setDecided, sumVotes } from './dao.queries.js';
import { flipIfReached } from './dao.service.js';

/**
 * The DAO clock (spec 15.5), in the shape of anossoftware's
 * src/held-transactions/unapproved-sweep.js: one tick at boot, then every
 * CLOCK_EVERY_MS, started from src/server.js after listen and stopped in
 * its shutdown. A tick runs, in order:
 *
 *   1. The expiry: every pending proposal whose pending_until has passed
 *      becomes expired (one idempotent statement) and loses its snapshot
 *      rows; it stays in the table, hidden from the lists.
 *   2. The flip: every pending proposal whose support has reached `needed`
 *      goes through flipIfReached (dao.service.js), the retry for a flip
 *      that found the validators unreachable when the support arrived.
 *   3. The close, one transaction: every open proposal whose vote_closes_at
 *      has passed is locked (SKIP LOCKED), its official votes summed,
 *      accepted when for * 100 > DAO_PASS_PERCENT * (for + against) else
 *      rejected (so a tie, or no vote at all, is rejected), the results
 *      written with decided_at, the snapshot rows deleted.
 *
 * Three masterpods run the clock at once on prod1, prod2 and prod3: the
 * expiry is one idempotent statement, the flip locks the row and re-checks
 * the status, the close skips the rows another box holds. A tick that
 * throws logs the error and the next tick runs.
 */

/** How often the clock ticks, in milliseconds. */
const CLOCK_EVERY_MS = 60_000;

let timer = null;

/** 1. The expiry: the statement, then each expired proposal's snapshot rows go, one log line each. */
async function expire() {
  for (const proposalId of await expirePending()) {
    await deleteSnapshot(pool, proposalId);
    console.log(`dao: proposal ${toHex(proposalId)} expired, its support under needed at pending_until`);
  }
}

/** 2. The flip: every pending proposal whose support has reached needed, through the service's flip. */
async function flip() {
  for (const proposalId of await findPendingReached()) {
    await flipIfReached(proposalId);
  }
}

/** 3. The close: one transaction over the open proposals past vote_closes_at that no other box holds. */
async function close() {
  await withTransaction(async (client) => {
    for (const { proposalId } of await lockClosable(client)) {
      const { for: votesFor, against } = await sumVotes(client, proposalId, 'official');
      const accepted = votesFor * 100n > BigInt(env.dao.passPercent) * (votesFor + against);
      const status = accepted ? 'accepted' : 'rejected';
      await setDecided(client, proposalId, status, votesFor.toString(), against.toString());
      await deleteSnapshot(client, proposalId);
      console.log(`dao: proposal ${toHex(proposalId)} ${status}, ${votesFor} for and ${against} against`);
    }
  });
}

/** One tick: the expiry, the flip, the close. An error is logged, not thrown: the next tick runs. */
export async function tick() {
  try {
    await expire();
    await flip();
    await close();
  } catch (err) {
    console.error(`dao clock tick failed: ${err.message}`);
  }
}

/** Starts the clock: once now, then every CLOCK_EVERY_MS. Starting it twice does nothing. */
export function startDaoClock() {
  if (timer !== null) return;
  timer = setInterval(tick, CLOCK_EVERY_MS);
  timer.unref();
  void tick();
}

/** Stops the clock; a tick already running finishes on its own. */
export function stopDaoClock() {
  if (timer === null) return;
  clearInterval(timer);
  timer = null;
}
