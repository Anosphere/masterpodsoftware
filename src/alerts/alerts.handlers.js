import { answer } from '../util/result.js';
import {
  addAlertEmail,
  addAlertPhone,
  confirmAlertEmail,
  keepAlertEmail,
  keepAlertPhone,
  listAlertSettings,
  removeAlertEmail,
  removeAlertPhone,
} from './alerts.service.js';
import { reportWaitingTransfers } from './validator-reports.js';

/**
 * Route handlers for the security alerts (spec section 25). HTTP in and
 * out only: read the request, call the service, send the answer. The
 * eight routes of a pod's list are behind requireSetup, so the caller is
 * req.anopod and req.body is the route's own object;
 * /report-waiting-transfers has no caller; the checking and storing lives
 * in alerts.service.js and validator-reports.js.
 */

/** POST /list-alert-settings */
export async function listAlertSettingsHandler(req, res) {
  answer(res, await listAlertSettings(req.anopod));
}

/** POST /add-alert-email */
export async function addAlertEmailHandler(req, res) {
  answer(res, await addAlertEmail(req.anopod, req.body));
}

/** POST /confirm-alert-email */
export async function confirmAlertEmailHandler(req, res) {
  answer(res, await confirmAlertEmail(req.anopod, req.body));
}

/** POST /remove-alert-email */
export async function removeAlertEmailHandler(req, res) {
  answer(res, await removeAlertEmail(req.anopod, req.body));
}

/** POST /keep-alert-email */
export async function keepAlertEmailHandler(req, res) {
  answer(res, await keepAlertEmail(req.anopod, req.body));
}

/**
 * POST /add-alert-phone. A phone on a delivery service that is not on the
 * list gets one log line of its own, which names the service's host and
 * nothing else of the phone's delivery address.
 */
export async function addAlertPhoneHandler(req, res) {
  const result = await addAlertPhone(req.anopod, req.body);
  if (!result.ok && result.host !== undefined) console.log(`alert phone refused, delivery service not on the list: ${result.host}`);
  answer(res, result);
}

/** POST /remove-alert-phone */
export async function removeAlertPhoneHandler(req, res) {
  answer(res, await removeAlertPhone(req.anopod, req.body));
}

/** POST /keep-alert-phone */
export async function keepAlertPhoneHandler(req, res) {
  answer(res, await keepAlertPhone(req.anopod, req.body));
}

/** POST /report-waiting-transfers: no caller; req.body is the plain JSON body, signed by a validator's key. */
export async function reportWaitingTransfersHandler(req, res) {
  answer(res, await reportWaitingTransfers(req.body));
}
