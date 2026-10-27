import { answer, refuse } from '../util/result.js';
import { requireSession } from './require-session.js';
import { mustBeVouched } from './require-vouched.js';

/** After mustBeVouched: the caller must have completed setup, so it has chat keys. */
export function mustHaveSetup(req, res, next) {
  if (!req.anopod.setupComplete) return answer(res, refuse(403, 'setup not complete'));
  next();
}

/**
 * Level "setup" of spec section 2: vouched, and /complete-setup done
 * (anopod_encryption_key_blob_2 is set). Every chat and marketplace route.
 */
export const requireSetup = [requireSession, mustBeVouched, mustHaveSetup];
