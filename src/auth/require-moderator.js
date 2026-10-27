import { pool } from '../db/pool.js';
import { answer, refuse } from '../util/result.js';
import { requireSession } from './require-session.js';

/** A moderator's username starts with this (spec 12.2). */
export const MODERATOR_PREFIX = 'moderator';

/**
 * True when a super seed has vouched for the pod: the appointment of spec
 * 12.2. There is no table of moderators and no script; the operator's vouch
 * is it (and makes the pod a seed, as every super-seed vouch does). The
 * stake is not checked here: the keyholders check it, where the secrets
 * are, on every bucket key request.
 */
export async function vouchedBySuperSeed(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM vouches v
                    JOIN super_seeds s ON s.anopod_id = v.anopod_id_vouched_by
                    WHERE v.anopod_id_vouched_for = $1) AS found`,
    [anopodId],
  );
  return rows[0].found;
}

/**
 * After requireSession: the caller's username starts with "moderator" and a
 * super seed vouched for it; else 403 not a moderator. The prefix is checked
 * first, so a pod that is no moderator costs no query.
 */
export async function mustBeModerator(req, res, next) {
  if (!req.anopod.username.startsWith(MODERATOR_PREFIX) || !(await vouchedBySuperSeed(req.anopod.anopodId))) {
    return answer(res, refuse(403, 'not a moderator'));
  }
  next();
}

/**
 * Level "moderator" of spec 12.2: a signed session request from a pod named
 * moderator... that a super seed vouched for. An array, so a route lists it
 * like one middleware: router.post('/x', requireModerator, handler). The six
 * moderation routes of 12.4.4.
 */
export const requireModerator = [requireSession, mustBeModerator];
