import { answer } from '../util/result.js';
import { createAnosAccount, getAnosAccount, listAnosAccounts, markAnosAccountSubmitted } from './anos-accounts.service.js';

/**
 * Route handlers for the anos accounts feature. HTTP in and out only: on
 * the setup-level routes the caller is req.anopod and req.body is the
 * route's own object; /get-anos-account has no caller. The checking and
 * storing lives in anos-accounts.service.js.
 */

/** POST /create-anos-account */
export async function createAnosAccountHandler(req, res) {
  answer(res, await createAnosAccount(req.anopod, req.body));
}

/** POST /mark-anos-account-submitted */
export async function markAnosAccountSubmittedHandler(req, res) {
  answer(res, await markAnosAccountSubmitted(req.anopod, req.body));
}

/** POST /list-anos-accounts */
export async function listAnosAccountsHandler(req, res) {
  answer(res, await listAnosAccounts(req.anopod));
}

/** POST /get-anos-account */
export async function getAnosAccountHandler(req, res) {
  answer(res, await getAnosAccount(req.body));
}
