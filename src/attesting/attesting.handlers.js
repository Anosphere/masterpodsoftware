import { answer } from '../util/result.js';
import {
  addDisputeEvidence,
  dismissAttestorCase,
  getDisputeCase,
  getMyCase,
  getTradeCase,
  listAnosAccountProfiles,
  listAttestorCases,
  listAttestors,
  listMyCases,
  listTradeCaseSecurityRecords,
  markAttestorCaseSent,
  openDisputeCase,
  openTradeCase,
  scheduleAttestorCase,
  shareCaseKey,
  shareLookupId,
  signOffDisputeCase,
  signOffTradeCase,
} from './attesting.service.js';

/**
 * Route handlers for the attestation feature. HTTP in and out only: read
 * the request, call the service, send the answer. Behind requireAttestor
 * and requireSetup alike the caller is req.anopod and req.body the route's
 * own object; the checking and storing lives in attesting.service.js.
 */

/** POST /list-attestors */
export async function listAttestorsHandler(req, res) {
  answer(res, await listAttestors());
}

/** POST /list-anos-account-profiles */
export async function listAnosAccountProfilesHandler(req, res) {
  answer(res, await listAnosAccountProfiles(req.body));
}

/** POST /list-attestor-cases */
export async function listAttestorCasesHandler(req, res) {
  answer(res, await listAttestorCases(req.body));
}

/** POST /get-trade-case */
export async function getTradeCaseHandler(req, res) {
  answer(res, await getTradeCase(req.body));
}

/** POST /get-dispute-case */
export async function getDisputeCaseHandler(req, res) {
  answer(res, await getDisputeCase(req.anopod, req.body));
}

/** POST /list-trade-case-security-records */
export async function listTradeCaseSecurityRecordsHandler(req, res) {
  answer(res, await listTradeCaseSecurityRecords(req.anopod, req.body));
}

/** POST /open-trade-case */
export async function openTradeCaseHandler(req, res) {
  answer(res, await openTradeCase(req.anopod, req.body));
}

/** POST /open-dispute-case */
export async function openDisputeCaseHandler(req, res) {
  answer(res, await openDisputeCase(req.anopod, req.body));
}

/** POST /schedule-attestor-case */
export async function scheduleAttestorCaseHandler(req, res) {
  answer(res, await scheduleAttestorCase(req.anopod, req.body));
}

/** POST /share-case-key */
export async function shareCaseKeyHandler(req, res) {
  answer(res, await shareCaseKey(req.anopod, req.body));
}

/** POST /sign-off-trade-case */
export async function signOffTradeCaseHandler(req, res) {
  answer(res, await signOffTradeCase(req.anopod, req.body));
}

/** POST /sign-off-dispute-case */
export async function signOffDisputeCaseHandler(req, res) {
  answer(res, await signOffDisputeCase(req.anopod, req.body));
}

/** POST /mark-attestor-case-sent */
export async function markAttestorCaseSentHandler(req, res) {
  answer(res, await markAttestorCaseSent(req.anopod, req.body));
}

/** POST /dismiss-attestor-case */
export async function dismissAttestorCaseHandler(req, res) {
  answer(res, await dismissAttestorCase(req.anopod, req.body));
}

/** POST /list-my-cases */
export async function listMyCasesHandler(req, res) {
  answer(res, await listMyCases(req.anopod));
}

/** POST /get-my-case */
export async function getMyCaseHandler(req, res) {
  answer(res, await getMyCase(req.anopod, req.body));
}

/** POST /share-lookup-id */
export async function shareLookupIdHandler(req, res) {
  answer(res, await shareLookupId(req.anopod, req.body));
}

/** POST /add-dispute-evidence */
export async function addDisputeEvidenceHandler(req, res) {
  answer(res, await addDisputeEvidence(req.anopod, req.body));
}
