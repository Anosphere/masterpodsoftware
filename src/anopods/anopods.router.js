import { Router } from 'express';
import { requireSession } from '../auth/require-session.js';
import { requireVouched } from '../auth/require-vouched.js';
import {
  checkAnopodStatus,
  checkUsernameHandler,
  completeSetupHandler,
  createAnopodHandler,
  getAnopodProfile,
  getAnopodSessionKeys,
  unlockHandler,
} from './anopods.handlers.js';

/**
 * anoPods feature router.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case. The level of each route is the
 * middleware in front of it (spec section 2): none, session or vouched.
 */
export const anopodsRouter = Router();

anopodsRouter.post('/create-anopod', createAnopodHandler);
anopodsRouter.post('/unlock', unlockHandler);
anopodsRouter.post('/check-username', checkUsernameHandler);
anopodsRouter.post('/check-anopod-status', requireSession, checkAnopodStatus);
anopodsRouter.post('/get-anopod-profile', requireSession, getAnopodProfile);
anopodsRouter.post('/get-anopod-session-keys', getAnopodSessionKeys);
anopodsRouter.post('/complete-setup', requireVouched, completeSetupHandler);
