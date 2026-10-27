import { answer } from '../util/result.js';
import { addToBucketOne, addToBucketTwo, listRecords } from './security.service.js';

/**
 * Route handlers for the security buckets. HTTP in and out only: the caller
 * is req.anopod, the route's object is req.body; the service checks and
 * answers.
 */

/** POST /add-to-security-bucket-one */
export async function addToSecurityBucketOne(req, res) {
  answer(res, await addToBucketOne(req.anopod, req.body));
}

/** POST /add-to-security-bucket-two */
export async function addToSecurityBucketTwo(req, res) {
  answer(res, await addToBucketTwo(req.anopod, req.body));
}

/** POST /list-security-records */
export async function listSecurityRecords(req, res) {
  answer(res, await listRecords(req.anopod));
}
