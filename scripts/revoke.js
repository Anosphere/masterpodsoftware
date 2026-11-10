import { findLiveRole, revokeAppointment } from '../src/appointments/appointments.queries.js';
import { closePool, pool } from '../src/db/pool.js';
import { decodeId, toHex } from '../src/util/ids.js';

/**
 * Ends a pod's appointment, whichever of the four roles it holds (spec
 * section 16; validator and masterPod since 2026-11-10, 16.7):
 *
 *   npm run revoke -- <anopod id, 64 hex characters>
 *
 * sets revoked_at on the pod's live appointments row, in one transaction.
 * The row stays, so who held what when is on record. The role is gone at
 * once: the masterpod refuses a revoked moderator or attestor, and
 * /get-anos-account and /check-anopod-status answer null for the pod's
 * role, whichever of the four it was. The stake the pod holds at the
 * validators comes back through the guardians' fund proposal payout. A pod
 * with no live appointment is said so (exit 0). Exits 1 on an unknown id,
 * 2 on a malformed one. There is no route for this.
 */

const anopodId = decodeId(process.argv[2]);
if (anopodId === null) {
  console.error('usage: npm run revoke -- <anopod id, 64 hex characters>');
  process.exit(2);
}
const hex = toHex(anopodId);

const client = await pool.connect();
let exitCode = 0;
try {
  await client.query('BEGIN');
  const { rows } = await client.query('SELECT username FROM anopods WHERE anopod_id = $1', [anopodId]);
  if (rows.length === 0) {
    await client.query('ROLLBACK');
    console.error(`${hex}: no anopod with this id`);
    exitCode = 1;
  } else {
    const { username } = rows[0];
    const live = await findLiveRole(anopodId, client);
    if (live === null) {
      await client.query('ROLLBACK');
      console.log(`${username} (${hex}): holds no appointment`);
    } else {
      await revokeAppointment(client, anopodId);
      await client.query('COMMIT');
      console.log(`${username} (${hex}): revoked as ${live}`);
    }
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
