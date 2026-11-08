import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import {
  createDaoProposalHandler,
  getDaoProposalHandler,
  listDaoProposalsHandler,
  listDaoVotesHandler,
  supportDaoProposalHandler,
  voteDaoProposalHandler,
} from './dao.handlers.js';

/**
 * DAO voting feature router (spec 15.4): six routes at level setup. The
 * three writes, a proposal posted, supported and voted on; the three
 * reads, the lists of proposals and of votes and one proposal.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const daoRouter = Router();

daoRouter.post('/create-dao-proposal', requireSetup, createDaoProposalHandler);
daoRouter.post('/support-dao-proposal', requireSetup, supportDaoProposalHandler);
daoRouter.post('/vote-dao-proposal', requireSetup, voteDaoProposalHandler);
daoRouter.post('/list-dao-proposals', requireSetup, listDaoProposalsHandler);
daoRouter.post('/get-dao-proposal', requireSetup, getDaoProposalHandler);
daoRouter.post('/list-dao-votes', requireSetup, listDaoVotesHandler);
