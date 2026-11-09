import { isAppointed } from '../appointments/appointments.queries.js';
import { answer, refuse } from '../util/result.js';
import { requireSession } from './require-session.js';

/**
 * After requireSession: the caller holds a live appointment as a moderator
 * (an appointments row with role moderator and no revoked_at, spec 12.2
 * and section 16); else 403 not a moderator. The appointment is the rule:
 * the username says nothing, and a super seed's vouch appoints nobody. The
 * stake is not checked here: the keyholders check it, where the secrets
 * are, on every bucket key request.
 */
export async function mustBeModerator(req, res, next) {
  if (!(await isAppointed(req.anopod.anopodId, 'moderator'))) {
    return answer(res, refuse(403, 'not a moderator'));
  }
  next();
}

/**
 * Level "moderator" of spec 12.2: a signed session request from a pod
 * appointed as a moderator (section 16). An array, so a route lists it like
 * one middleware: router.post('/x', requireModerator, handler). The six
 * moderation routes of 12.4.4.
 */
export const requireModerator = [requireSession, mustBeModerator];
