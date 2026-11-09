import { answer } from '../util/result.js';
import {
  dismissBreakGlassCase,
  fileBreakGlassMoves,
  getBreakGlassCase,
  listBreakGlassCaseSecurityRecords,
  listBreakGlassCases,
  listMyBreakGlassMoves,
  markBreakGlassCaseSent,
  scheduleBreakGlassCase,
  signOffBreakGlassCase,
} from './break-glass.service.js';

/**
 * Route handlers for the break-glass feature. HTTP in and out only: read
 * the request, call the service, send the answer. Behind requireSetup and
 * requireAttestor alike the caller is req.anopod and req.body the route's
 * own object; the checking and storing lives in break-glass.service.js.
 */

/** POST /file-break-glass-moves */
export async function fileBreakGlassMovesHandler(req, res) {
  answer(res, await fileBreakGlassMoves(req.anopod, req.body));
}

/** POST /list-my-break-glass-moves */
export async function listMyBreakGlassMovesHandler(req, res) {
  answer(res, await listMyBreakGlassMoves(req.anopod));
}

/** POST /list-break-glass-cases */
export async function listBreakGlassCasesHandler(req, res) {
  answer(res, await listBreakGlassCases(req.body));
}

/** POST /get-break-glass-case */
export async function getBreakGlassCaseHandler(req, res) {
  answer(res, await getBreakGlassCase(req.body));
}

/** POST /list-break-glass-case-security-records */
export async function listBreakGlassCaseSecurityRecordsHandler(req, res) {
  answer(res, await listBreakGlassCaseSecurityRecords(req.anopod, req.body));
}

/** POST /schedule-break-glass-case */
export async function scheduleBreakGlassCaseHandler(req, res) {
  answer(res, await scheduleBreakGlassCase(req.anopod, req.body));
}

/** POST /sign-off-break-glass-case */
export async function signOffBreakGlassCaseHandler(req, res) {
  answer(res, await signOffBreakGlassCase(req.anopod, req.body));
}

/** POST /mark-break-glass-case-sent */
export async function markBreakGlassCaseSentHandler(req, res) {
  answer(res, await markBreakGlassCaseSent(req.anopod, req.body));
}

/** POST /dismiss-break-glass-case */
export async function dismissBreakGlassCaseHandler(req, res) {
  answer(res, await dismissBreakGlassCase(req.anopod, req.body));
}
