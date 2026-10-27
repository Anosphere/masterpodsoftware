import { Router } from 'express';
import { requireAttestor } from '../auth/require-attestor.js';
import { requireSetup } from '../auth/require-setup.js';
import {
  addDisputeEvidenceHandler,
  dismissAttestorCaseHandler,
  getDisputeCaseHandler,
  getMyCaseHandler,
  getTradeCaseHandler,
  listAnosAccountProfilesHandler,
  listAttestorCasesHandler,
  listAttestorsHandler,
  listMyCasesHandler,
  listTradeCaseSecurityRecordsHandler,
  markAttestorCaseSentHandler,
  openDisputeCaseHandler,
  openTradeCaseHandler,
  scheduleAttestorCaseHandler,
  shareCaseKeyHandler,
  shareLookupIdHandler,
  signOffDisputeCaseHandler,
  signOffTradeCaseHandler,
} from './attesting.handlers.js';

/**
 * Attestation feature router (spec 13.4). The attestors' side: fourteen
 * routes at level attestor (13.2, src/auth/require-attestor.js), the six
 * reads of 13.4.3 and the eight writes of 13.4.4 on the two kinds of case.
 * The person's side: four routes at level setup (13.4.5), their cases, the
 * lookup id of a trade case and the evidence of a dispute case.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const attestingRouter = Router();

attestingRouter.post('/list-attestors', requireAttestor, listAttestorsHandler);
attestingRouter.post('/list-anos-account-profiles', requireAttestor, listAnosAccountProfilesHandler);
attestingRouter.post('/list-attestor-cases', requireAttestor, listAttestorCasesHandler);
attestingRouter.post('/get-trade-case', requireAttestor, getTradeCaseHandler);
attestingRouter.post('/get-dispute-case', requireAttestor, getDisputeCaseHandler);
attestingRouter.post('/list-trade-case-security-records', requireAttestor, listTradeCaseSecurityRecordsHandler);

attestingRouter.post('/open-trade-case', requireAttestor, openTradeCaseHandler);
attestingRouter.post('/open-dispute-case', requireAttestor, openDisputeCaseHandler);
attestingRouter.post('/schedule-attestor-case', requireAttestor, scheduleAttestorCaseHandler);
attestingRouter.post('/share-case-key', requireAttestor, shareCaseKeyHandler);
attestingRouter.post('/sign-off-trade-case', requireAttestor, signOffTradeCaseHandler);
attestingRouter.post('/sign-off-dispute-case', requireAttestor, signOffDisputeCaseHandler);
attestingRouter.post('/mark-attestor-case-sent', requireAttestor, markAttestorCaseSentHandler);
attestingRouter.post('/dismiss-attestor-case', requireAttestor, dismissAttestorCaseHandler);

attestingRouter.post('/list-my-cases', requireSetup, listMyCasesHandler);
attestingRouter.post('/get-my-case', requireSetup, getMyCaseHandler);
attestingRouter.post('/share-lookup-id', requireSetup, shareLookupIdHandler);
attestingRouter.post('/add-dispute-evidence', requireSetup, addDisputeEvidenceHandler);
