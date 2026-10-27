import { Router } from 'express';
import { requireSession } from '../auth/require-session.js';
import { requireVouched } from '../auth/require-vouched.js';
import {
  approveVouchRequest,
  declineVouchRequest,
  listVouchRequests,
  searchUsernamesHandler,
  sendVouchRequest,
} from './vouching.handlers.js';

/**
 * Vouching feature router.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case. Searching and asking are level
 * "session" (the caller is not vouched yet); the seed's inbox is "vouched".
 */
export const vouchingRouter = Router();

vouchingRouter.post('/search-usernames', requireSession, searchUsernamesHandler);
vouchingRouter.post('/send-vouch-request', requireSession, sendVouchRequest);
vouchingRouter.post('/list-vouch-requests', requireVouched, listVouchRequests);
vouchingRouter.post('/approve-vouch-request', requireVouched, approveVouchRequest);
vouchingRouter.post('/decline-vouch-request', requireVouched, declineVouchRequest);
