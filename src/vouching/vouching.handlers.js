import { answer } from '../util/result.js';
import { approve, decline, listRequests, searchUsernames, sendRequest } from './vouching.service.js';

/**
 * Route handlers for the vouching feature. HTTP in and out only: the caller
 * is req.anopod, the route's object is req.body; the service checks and
 * answers.
 */

/** POST /search-usernames */
export async function searchUsernamesHandler(req, res) {
  answer(res, await searchUsernames(req.body));
}

/** POST /send-vouch-request */
export async function sendVouchRequest(req, res) {
  answer(res, await sendRequest(req.anopod, req.body));
}

/** POST /list-vouch-requests */
export async function listVouchRequests(req, res) {
  answer(res, await listRequests(req.anopod));
}

/** POST /approve-vouch-request */
export async function approveVouchRequest(req, res) {
  answer(res, await approve(req.anopod, req.body));
}

/** POST /decline-vouch-request */
export async function declineVouchRequest(req, res) {
  answer(res, await decline(req.anopod, req.body));
}
