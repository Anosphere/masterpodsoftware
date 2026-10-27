import { answer, refuse } from '../util/result.js';
import { requireSession } from './require-session.js';

/** After requireSession: the caller must be vouched. */
export function mustBeVouched(req, res, next) {
  if (!req.anopod.vouched) return answer(res, refuse(403, 'anopod not vouched'));
  next();
}

/**
 * Level "vouched" of spec section 2: a signed session request from a pod
 * whose anopods.vouched is true. An array, so a route lists it like one
 * middleware: router.post('/x', requireVouched, handler).
 */
export const requireVouched = [requireSession, mustBeVouched];
