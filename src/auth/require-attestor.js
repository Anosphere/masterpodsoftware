import { pool } from '../db/pool.js';
import { answer, refuse } from '../util/result.js';
import { vouchedBySuperSeed } from './require-moderator.js';
import { requireSession } from './require-session.js';

/**
 * An attestor's username starts with this (spec 13.2). A username has one
 * prefix, so a pod is a moderator or an attestor, never both.
 */
export const ATTESTOR_PREFIX = 'attestor';

/**
 * After requireSession: the caller's username starts with "attestor" and a
 * super seed vouched for it (the moderator rule of 12.2 with the other
 * prefix, the same query, imported from require-moderator.js); else 403 not
 * an attestor. The prefix is checked first, so a pod that is no attestor
 * costs no query. The stake is not checked here: the validators check it on
 * every read and every follow-up, the keyholders on every bucket key
 * request.
 */
export async function mustBeAttestor(req, res, next) {
  if (!req.anopod.username.startsWith(ATTESTOR_PREFIX) || !(await vouchedBySuperSeed(req.anopod.anopodId))) {
    return answer(res, refuse(403, 'not an attestor'));
  }
  next();
}

/**
 * Level "attestor" of spec 13.2: a signed session request from a pod named
 * attestor... that a super seed vouched for. An array, so a route lists it
 * like one middleware: router.post('/x', requireAttestor, handler). The
 * fourteen attestor routes of 13.4.3 and 13.4.4.
 */
export const requireAttestor = [requireSession, mustBeAttestor];

/**
 * True when the pod with this id (a 32-byte Buffer) is an attestor as above:
 * the prefix and the super-seed vouch in one query. /open-dispute-case and
 * /share-case-key check the pods a case key is wrapped to with it.
 */
export async function isAttestorPod(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM anopods a
                    WHERE a.anopod_id = $1 AND starts_with(a.username, $2)
                      AND EXISTS (SELECT 1 FROM vouches v
                                  JOIN super_seeds s ON s.anopod_id = v.anopod_id_vouched_by
                                  WHERE v.anopod_id_vouched_for = a.anopod_id)) AS found`,
    [anopodId, ATTESTOR_PREFIX],
  );
  return rows[0].found;
}

/**
 * Every attestor pod whose setup is complete (so it has chat keys a case key
 * can be wrapped to), username order: { anopodId, username, firstName,
 * lastName }, the id a Buffer. What /list-attestors answers, the chat keys
 * added from chat.queries.js findChatPublicKeys.
 */
export async function listAttestorPods(db = pool) {
  const { rows } = await db.query(
    `SELECT a.anopod_id, a.username, a.first_name, a.last_name
     FROM anopods a
     WHERE starts_with(a.username, $1) AND a.anopod_encryption_key_blob_2 IS NOT NULL
       AND EXISTS (SELECT 1 FROM vouches v
                   JOIN super_seeds s ON s.anopod_id = v.anopod_id_vouched_by
                   WHERE v.anopod_id_vouched_for = a.anopod_id)
     ORDER BY a.username`,
    [ATTESTOR_PREFIX],
  );
  return rows.map((row) => ({ anopodId: row.anopod_id, username: row.username, firstName: row.first_name, lastName: row.last_name }));
}
