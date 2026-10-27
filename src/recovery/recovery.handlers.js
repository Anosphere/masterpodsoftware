import { answer } from '../util/result.js';
import {
  completeRecoveryCase,
  dismissRecoveryCase,
  getRecoveryCase,
  getRecoveryPod,
  listCaseSecurityRecords,
  listRecoveryCases,
  openRecoveryCase,
  receiveRecoveryShare,
  recoverWithBackupCode,
  rotateBackupCode,
  scheduleRecoveryCase,
  signOffRecoveryCase,
  storeBreakGlassBlob,
  unlockRecoveryPod,
} from './recovery.service.js';

/**
 * Route handlers for the recovery feature. HTTP in and out only: read the
 * request, call the service, send the answer. On the routes behind
 * requireRecoverySession the caller's pod is req.recoveryPod, its case
 * req.recoveryCase and req.body the route's own object; on the routes
 * behind requireModerator or requireSetup the caller is req.anopod and
 * req.body the route's own object; the keyholders' share route takes the
 * case id from the path and the body as posted; the checking and storing
 * lives in recovery.service.js.
 */


/** POST /open-recovery-case */
export async function openRecoveryCaseHandler(req, res) {
  answer(res, await openRecoveryCase(req.body));
}

/** POST /unlock-recovery-pod */
export async function unlockRecoveryPodHandler(req, res) {
  answer(res, await unlockRecoveryPod(req.body));
}

/** POST /get-recovery-pod */
export async function getRecoveryPodHandler(req, res) {
  answer(res, await getRecoveryPod(req.recoveryPod, req.recoveryCase));
}

/** POST /list-recovery-cases */
export async function listRecoveryCasesHandler(req, res) {
  answer(res, await listRecoveryCases(req.body));
}

/** POST /get-recovery-case */
export async function getRecoveryCaseHandler(req, res) {
  answer(res, await getRecoveryCase(req.body));
}

/** POST /list-case-security-records */
export async function listCaseSecurityRecordsHandler(req, res) {
  answer(res, await listCaseSecurityRecords(req.anopod, req.body));
}

/** POST /schedule-recovery-case */
export async function scheduleRecoveryCaseHandler(req, res) {
  answer(res, await scheduleRecoveryCase(req.anopod, req.body));
}

/** POST /sign-off-recovery-case */
export async function signOffRecoveryCaseHandler(req, res) {
  answer(res, await signOffRecoveryCase(req.anopod, req.body));
}

/** POST /dismiss-recovery-case */
export async function dismissRecoveryCaseHandler(req, res) {
  answer(res, await dismissRecoveryCase(req.anopod, req.body));
}

/** POST /receive-recovery-share/:caseId */
export async function receiveRecoveryShareHandler(req, res) {
  answer(res, await receiveRecoveryShare(req.params.caseId, req.body));
}

/** POST /recover-with-backup-code */
export async function recoverWithBackupCodeHandler(req, res) {
  answer(res, await recoverWithBackupCode(req.body));
}

/** POST /complete-recovery-case */
export async function completeRecoveryCaseHandler(req, res) {
  answer(res, await completeRecoveryCase(req.recoveryCase));
}

/** POST /rotate-backup-code */
export async function rotateBackupCodeHandler(req, res) {
  answer(res, await rotateBackupCode(req.anopod, req.body));
}

/** POST /store-break-glass-blob */
export async function storeBreakGlassBlobHandler(req, res) {
  answer(res, await storeBreakGlassBlob(req.anopod, req.body));
}
