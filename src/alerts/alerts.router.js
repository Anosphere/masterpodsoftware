import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import {
  addAlertEmailHandler,
  addAlertPhoneHandler,
  confirmAlertEmailHandler,
  keepAlertEmailHandler,
  keepAlertPhoneHandler,
  listAlertSettingsHandler,
  removeAlertEmailHandler,
  removeAlertPhoneHandler,
  reportWaitingTransfersHandler,
} from './alerts.handlers.js';

/**
 * Security alerts feature router (spec section 25): an email and a
 * notification on the phone when a transfer starts to wait in a guarded, a
 * vault or an assisted account, when a recovery is started for a pod, and
 * when a pod's alert list changes. Eight routes at level setup, for the
 * pod whose list it is, and one at level none,
 * /report-waiting-transfers, for the validators, whose message is signed
 * by the validator's own key.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const alertsRouter = Router();

alertsRouter.post('/list-alert-settings', requireSetup, listAlertSettingsHandler);
alertsRouter.post('/add-alert-email', requireSetup, addAlertEmailHandler);
alertsRouter.post('/confirm-alert-email', requireSetup, confirmAlertEmailHandler);
alertsRouter.post('/remove-alert-email', requireSetup, removeAlertEmailHandler);
alertsRouter.post('/keep-alert-email', requireSetup, keepAlertEmailHandler);
alertsRouter.post('/add-alert-phone', requireSetup, addAlertPhoneHandler);
alertsRouter.post('/remove-alert-phone', requireSetup, removeAlertPhoneHandler);
alertsRouter.post('/keep-alert-phone', requireSetup, keepAlertPhoneHandler);
alertsRouter.post('/report-waiting-transfers', reportWaitingTransfersHandler);
