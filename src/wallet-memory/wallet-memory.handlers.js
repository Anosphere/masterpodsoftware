import { answer } from '../util/result.js';
import {
  addNotedTransaction,
  getWalletSettings,
  listNotedTransactions,
  removeNotedTransaction,
  setWalletSettings,
  updateNotedTransaction,
} from './wallet-memory.service.js';

/**
 * Route handlers for the wallet memory feature. HTTP in and out only: the
 * caller is req.anopod and req.body is the route's own object. The checking
 * and storing lives in wallet-memory.service.js.
 */

/** POST /add-noted-transaction */
export async function addNotedTransactionHandler(req, res) {
  answer(res, await addNotedTransaction(req.anopod, req.body));
}

/** POST /update-noted-transaction */
export async function updateNotedTransactionHandler(req, res) {
  answer(res, await updateNotedTransaction(req.anopod, req.body));
}

/** POST /remove-noted-transaction */
export async function removeNotedTransactionHandler(req, res) {
  answer(res, await removeNotedTransaction(req.anopod, req.body));
}

/** POST /list-noted-transactions */
export async function listNotedTransactionsHandler(req, res) {
  answer(res, await listNotedTransactions(req.anopod, req.body));
}

/** POST /get-wallet-settings */
export async function getWalletSettingsHandler(req, res) {
  answer(res, await getWalletSettings(req.anopod));
}

/** POST /set-wallet-settings */
export async function setWalletSettingsHandler(req, res) {
  answer(res, await setWalletSettings(req.anopod, req.body));
}
