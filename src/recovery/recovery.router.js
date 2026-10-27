import { Router } from 'express';
import { requireModerator } from '../auth/require-moderator.js';
import { requireRecoverySession } from '../auth/require-recovery-session.js';
import { requireSetup } from '../auth/require-setup.js';
import {
  completeRecoveryCaseHandler,
  dismissRecoveryCaseHandler,
  getRecoveryCaseHandler,
  getRecoveryPodHandler,
  listCaseSecurityRecordsHandler,
  listRecoveryCasesHandler,
  openRecoveryCaseHandler,
  receiveRecoveryShareHandler,
  recoverWithBackupCodeHandler,
  rotateBackupCodeHandler,
  scheduleRecoveryCaseHandler,
  signOffRecoveryCaseHandler,
  storeBreakGlassBlobHandler,
  unlockRecoveryPodHandler,
} from './recovery.handlers.js';

/**
 * Recovery feature router (spec 12.4). The person's side: three routes at
 * level none, signed by the keys inside them (/open-recovery-case and
 * /unlock-recovery-pod by the ephemeral keys, like /create-anopod and
 * /unlock; /recover-with-backup-code by the backup code keys), and two at
 * level recovery, signed by the recovery pod's session keys. The
 * keyholders' side: the unsigned share route, the case id in the path. The
 * moderator's side: six routes at level moderator (12.2,
 * src/auth/require-moderator.js). After the finish, two routes at level
 * setup: the backup code rotation and the break-glass blobs (12.4.5).
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const recoveryRouter = Router();

recoveryRouter.post('/open-recovery-case', openRecoveryCaseHandler);
recoveryRouter.post('/unlock-recovery-pod', unlockRecoveryPodHandler);
recoveryRouter.post('/receive-recovery-share/:caseId', receiveRecoveryShareHandler);
recoveryRouter.post('/recover-with-backup-code', recoverWithBackupCodeHandler);
recoveryRouter.post('/get-recovery-pod', requireRecoverySession, getRecoveryPodHandler);
recoveryRouter.post('/complete-recovery-case', requireRecoverySession, completeRecoveryCaseHandler);

recoveryRouter.post('/list-recovery-cases', requireModerator, listRecoveryCasesHandler);
recoveryRouter.post('/get-recovery-case', requireModerator, getRecoveryCaseHandler);
recoveryRouter.post('/list-case-security-records', requireModerator, listCaseSecurityRecordsHandler);
recoveryRouter.post('/schedule-recovery-case', requireModerator, scheduleRecoveryCaseHandler);
recoveryRouter.post('/sign-off-recovery-case', requireModerator, signOffRecoveryCaseHandler);
recoveryRouter.post('/dismiss-recovery-case', requireModerator, dismissRecoveryCaseHandler);

recoveryRouter.post('/rotate-backup-code', requireSetup, rotateBackupCodeHandler);
recoveryRouter.post('/store-break-glass-blob', requireSetup, storeBreakGlassBlobHandler);
