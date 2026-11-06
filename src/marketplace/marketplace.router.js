import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import {
  closeListingHandler,
  createListingHandler,
  getListingHandler,
  listListingsHandler,
} from './marketplace.handlers.js';

/**
 * Marketplace feature router. All four routes are level "setup".
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const marketplaceRouter = Router();

marketplaceRouter.post('/create-listing', requireSetup, createListingHandler);
marketplaceRouter.post('/close-listing', requireSetup, closeListingHandler);
marketplaceRouter.post('/list-listings', requireSetup, listListingsHandler);
marketplaceRouter.post('/get-listing', requireSetup, getListingHandler);
