import { answer } from '../util/result.js';
import {
  createDaoProposal,
  getDaoProposal,
  listDaoProposals,
  listDaoVotes,
  supportDaoProposal,
  voteDaoProposal,
} from './dao.service.js';

/**
 * Route handlers for the DAO voting feature. HTTP in and out only: read
 * the request, call the service, send the answer. Behind requireSetup the
 * caller is req.anopod and req.body the route's own object; the checking
 * and storing lives in dao.service.js.
 */

/** POST /create-dao-proposal */
export async function createDaoProposalHandler(req, res) {
  answer(res, await createDaoProposal(req.anopod, req.body));
}

/** POST /support-dao-proposal */
export async function supportDaoProposalHandler(req, res) {
  answer(res, await supportDaoProposal(req.anopod, req.body));
}

/** POST /vote-dao-proposal */
export async function voteDaoProposalHandler(req, res) {
  answer(res, await voteDaoProposal(req.anopod, req.body));
}

/** POST /list-dao-proposals */
export async function listDaoProposalsHandler(req, res) {
  answer(res, await listDaoProposals(req.anopod, req.body));
}

/** POST /get-dao-proposal */
export async function getDaoProposalHandler(req, res) {
  answer(res, await getDaoProposal(req.anopod, req.body));
}

/** POST /list-dao-votes */
export async function listDaoVotesHandler(req, res) {
  answer(res, await listDaoVotes(req.anopod, req.body));
}
