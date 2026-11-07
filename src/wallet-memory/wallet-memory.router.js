import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import {
  addNotedTransactionHandler,
  getWalletSettingsHandler,
  listNotedTransactionsHandler,
  removeNotedTransactionHandler,
  setWalletSettingsHandler,
  updateNotedTransactionHandler,
} from './wallet-memory.handlers.js';

/**
 * Wallet memory feature router (wallet spec 4.6 and 4.7): the six routes,
 * all at level setup, for the pod whose rows they are: the four noted
 * transaction routes and the two wallet settings routes.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const walletMemoryRouter = Router();

walletMemoryRouter.post('/add-noted-transaction', requireSetup, addNotedTransactionHandler);
walletMemoryRouter.post('/update-noted-transaction', requireSetup, updateNotedTransactionHandler);
walletMemoryRouter.post('/remove-noted-transaction', requireSetup, removeNotedTransactionHandler);
walletMemoryRouter.post('/list-noted-transactions', requireSetup, listNotedTransactionsHandler);
walletMemoryRouter.post('/get-wallet-settings', requireSetup, getWalletSettingsHandler);
walletMemoryRouter.post('/set-wallet-settings', requireSetup, setWalletSettingsHandler);
