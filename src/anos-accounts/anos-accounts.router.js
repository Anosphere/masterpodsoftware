import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import {
  createAnosAccountHandler,
  getAnosAccountHandler,
  listAnosAccountsHandler,
  markAnosAccountSubmittedHandler,
} from './anos-accounts.handlers.js';

/**
 * anos accounts feature router (wallet spec 4.4). Three routes at level
 * setup, for the pod that made the account; one at level none, for the
 * validators' binding check.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const anosAccountsRouter = Router();

anosAccountsRouter.post('/create-anos-account', requireSetup, createAnosAccountHandler);
anosAccountsRouter.post('/mark-anos-account-submitted', requireSetup, markAnosAccountSubmittedHandler);
anosAccountsRouter.post('/list-anos-accounts', requireSetup, listAnosAccountsHandler);
anosAccountsRouter.post('/get-anos-account', getAnosAccountHandler);
