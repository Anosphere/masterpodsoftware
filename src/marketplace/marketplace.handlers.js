import { answer } from '../util/result.js';
import { close, createListing, list } from './marketplace.service.js';

/**
 * Route handlers for the marketplace. HTTP in and out only: the caller is
 * req.anopod (requireSetup), the route's object is req.body; the service
 * checks and answers.
 */

/** POST /create-listing */
export async function createListingHandler(req, res) {
  answer(res, await createListing(req.anopod, req.body));
}

/** POST /close-listing */
export async function closeListingHandler(req, res) {
  answer(res, await close(req.anopod, req.body));
}

/** POST /list-listings */
export async function listListingsHandler(req, res) {
  answer(res, await list(req.body));
}
