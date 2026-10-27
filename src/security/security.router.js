import { Router } from 'express';
import { requireVouched } from '../auth/require-vouched.js';
import { addToSecurityBucketOne, addToSecurityBucketTwo, listSecurityRecords } from './security.handlers.js';

/**
 * Security buckets feature router. All three routes are level "vouched".
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const securityRouter = Router();

securityRouter.post('/add-to-security-bucket-one', requireVouched, addToSecurityBucketOne);
securityRouter.post('/add-to-security-bucket-two', requireVouched, addToSecurityBucketTwo);
securityRouter.post('/list-security-records', requireVouched, listSecurityRecords);
