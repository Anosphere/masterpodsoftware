import { closePool, pool } from '../src/db/pool.js';
import { decodeId, toHex } from '../src/util/ids.js';

/**
 * Genesis (spec section 9): makes an existing pod a super seed, so vouching
 * can begin. The pod is created through the web app like any other, then
 *
 *   npm run make-super-seed -- <anopod id, 64 hex characters>
 *
 * sets vouched = true and inserts the super_seeds row with vouched_by
 * 'genesis', in one transaction. Idempotent: running it again changes
 * nothing and says so. Exits 1 on an unknown id, 2 on a malformed one.
 * There is no route for this.
 */

const anopodId = decodeId(process.argv[2]);
if (anopodId === null) {
  console.error('usage: npm run make-super-seed -- <anopod id, 64 hex characters>');
  process.exit(2);
}
const hex = toHex(anopodId);

const client = await pool.connect();
let exitCode = 0;
try {
  await client.query('BEGIN');
  const vouched = await client.query('UPDATE anopods SET vouched = true WHERE anopod_id = $1', [anopodId]);
  if (vouched.rowCount === 0) {
    await client.query('ROLLBACK');
    console.error(`${hex}: no anopod with this id`);
    exitCode = 1;
  } else {
    const inserted = await client.query(
      `INSERT INTO super_seeds (anopod_id, vouched_by) VALUES ($1, 'genesis') ON CONFLICT DO NOTHING`,
      [anopodId],
    );
    await client.query('COMMIT');
    console.log(
      inserted.rowCount === 1
        ? `${hex}: vouched = true, super seed made (vouched_by genesis)`
        : `${hex}: vouched = true, already a super seed`,
    );
  }
} catch (err) {
  await client.query('ROLLBACK');
  console.error(err.message);
  exitCode = 1;
} finally {
  client.release();
  await closePool();
}
process.exit(exitCode);
