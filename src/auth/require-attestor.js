import { isAppointed, listAppointedPods } from '../appointments/appointments.queries.js';
import { answer, refuse } from '../util/result.js';
import { requireSession } from './require-session.js';

/**
 * After requireSession: the caller holds a live appointment as an attestor
 * (an appointments row with role attestor and no revoked_at, spec 13.2 and
 * section 16); else 403 not an attestor. The appointment is the rule: the
 * username says nothing, and a super seed's vouch appoints nobody. The
 * stake is not checked here: the validators check it on every read and
 * every follow-up, the keyholders on every bucket key request.
 */
export async function mustBeAttestor(req, res, next) {
  if (!(await isAppointed(req.anopod.anopodId, 'attestor'))) {
    return answer(res, refuse(403, 'not an attestor'));
  }
  next();
}

/**
 * Level "attestor" of spec 13.2: a signed session request from a pod
 * appointed as an attestor (section 16). An array, so a route lists it like
 * one middleware: router.post('/x', requireAttestor, handler). The
 * fourteen attestor routes of 13.4.3 and 13.4.4, and the seven break-glass
 * routes of 14.4.2.
 */
export const requireAttestor = [requireSession, mustBeAttestor];

/**
 * True when the pod with this id (a 32-byte Buffer) is an attestor as
 * above: a live appointment for the role (section 16). /open-dispute-case
 * and /share-case-key check the pods a case key is wrapped to with it.
 */
export function isAttestorPod(anopodId, db) {
  return isAppointed(anopodId, 'attestor', db);
}

/**
 * Every appointed attestor pod whose setup is complete (so it has chat keys
 * a case key can be wrapped to), username order: { anopodId, username,
 * firstName, lastName }, the id a Buffer. What /list-attestors answers, the
 * chat keys added from chat.queries.js findChatPublicKeys.
 */
export function listAttestorPods(db) {
  return listAppointedPods('attestor', db);
}
