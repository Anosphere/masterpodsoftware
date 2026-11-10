import { findLiveRole, insertAppointment } from '../src/appointments/appointments.queries.js';
import { closePool, pool } from '../src/db/pool.js';
import { decodeId, toHex } from '../src/util/ids.js';

/**
 * Appoints a pod for one of four roles (spec section 16). moderator and
 * attestor open the moderator and the attestor routes. validator and
 * masterPod (2026-11-10, spec 16.7) open nothing on this server: they only
 * let the pod stake for that purpose at the validators. The pod is created
 * through the web app like any other, then
 *
 *   npm run appoint -- <anopod id, 64 hex characters> <moderator|attestor|validator|masterPod>
 *
 * inserts the appointments row with appointed_by 'operator', in one
 * transaction. The pod must exist and nothing else: not vouched, not set
 * up; the operator appoints whom they choose, and the stake the pod will
 * hold needs a vouched pod anyway. A pod already appointed for the role is
 * left alone and said so (exit 0); a pod holding another role is refused
 * (exit 1): revoke first, then appoint. Exits 1 on an unknown id, 2 on a
 * malformed id or role. There is no route for this.
 */

const ROLES = ['moderator', 'attestor', 'validator', 'masterPod'];

const anopodId = decodeId(process.argv[2]);
const role = process.argv[3];
if (anopodId === null || !ROLES.includes(role)) {
  console.error('usage: npm run appoint -- <anopod id, 64 hex characters> <moderator|attestor|validator|masterPod>');
  process.exit(2);
}
const hex = toHex(anopodId);

/** "a moderator" or "an attestor". */
const withArticle = (name) => `${name === 'attestor' ? 'an' : 'a'} ${name}`;

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
    if (live === role) {
      await client.query('ROLLBACK');
      console.log(`${username} (${hex}): already appointed as ${role}`);
    } else if (live !== null) {
      await client.query('ROLLBACK');
      console.error(`${username} (${hex}): is ${withArticle(live)}; revoke first`);
      exitCode = 1;
    } else {
      await insertAppointment(client, anopodId, role, 'operator');
      await client.query('COMMIT');
      console.log(`${username} (${hex}): appointed as ${role}`);
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
