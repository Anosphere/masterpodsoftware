import { Router } from 'express';
import { requireAttestor } from '../auth/require-attestor.js';
import { requireSetup } from '../auth/require-setup.js';
import {
  dismissBreakGlassCaseHandler,
  fileBreakGlassMovesHandler,
  getBreakGlassCaseHandler,
  listBreakGlassCaseSecurityRecordsHandler,
  listBreakGlassCasesHandler,
  listMyBreakGlassMovesHandler,
  markBreakGlassCaseSentHandler,
  scheduleBreakGlassCaseHandler,
  signOffBreakGlassCaseHandler,
} from './break-glass.handlers.js';

/**
 * Break-glass feature router (spec 14.4). The person's side: two routes at
 * level setup (14.4.1), the finish of a recovery filing its moves and the
 * wallet reading the case's progress. The attestors' side: seven routes at
 * level attestor (13.2, src/auth/require-attestor.js; 14.4.2), the cases
 * beside the trades, one case, its buckets, the appointment, the sign-off
 * of every move in one pass, the posting and the dismissal.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const breakGlassRouter = Router();

breakGlassRouter.post('/file-break-glass-moves', requireSetup, fileBreakGlassMovesHandler);
breakGlassRouter.post('/list-my-break-glass-moves', requireSetup, listMyBreakGlassMovesHandler);

breakGlassRouter.post('/list-break-glass-cases', requireAttestor, listBreakGlassCasesHandler);
breakGlassRouter.post('/get-break-glass-case', requireAttestor, getBreakGlassCaseHandler);
breakGlassRouter.post('/list-break-glass-case-security-records', requireAttestor, listBreakGlassCaseSecurityRecordsHandler);
breakGlassRouter.post('/schedule-break-glass-case', requireAttestor, scheduleBreakGlassCaseHandler);
breakGlassRouter.post('/sign-off-break-glass-case', requireAttestor, signOffBreakGlassCaseHandler);
breakGlassRouter.post('/mark-break-glass-case-sent', requireAttestor, markBreakGlassCaseSentHandler);
breakGlassRouter.post('/dismiss-break-glass-case', requireAttestor, dismissBreakGlassCaseHandler);
