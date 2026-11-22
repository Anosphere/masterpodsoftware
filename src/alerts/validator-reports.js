import { findAccount } from '../anos-accounts/anos-accounts.queries.js';
import { canonicalHash, canonicalize } from '../crypto/canonical.js';
import { ECDSA_P256, decodeSignature, verifySignature } from '../crypto/signatures.js';
import { withTransaction } from '../db/transaction.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { raiseAlert } from './alert-events.js';
import { kickAlertSender } from './alert-sender.js';
import { insertTransfer, recentReports } from './alerts.queries.js';
import { validatorKeys } from './validator-keys.js';

/**
 * The validators' reports of waiting transfers (spec 25.4). A transfer out
 * of a guarded, a vault or an assisted account, and a recovery's
 * break-glass move, wait on the validators before they are written. Each
 * validator that holds one tells this server, about five minutes after it
 * was sent, with one message signed by its own key like a message to
 * another validator (anossoftware/docs/schemas.md section 34). This server
 * then tells the pod that made the account, so that a transfer that is not
 * the owner's can be cancelled in time.
 *
 * One report is enough to set an alert off: the first validator's. The
 * others that report the same transfer with the same facts add nothing. A
 * report that says something else about the same transfer is a report of
 * its own and makes an alert of its own, so one validator cannot keep a
 * true report from counting by sending a false one first. Nothing is used
 * up and no time is checked: the same message sent again finds its rows
 * and writes nothing.
 */

const BAD_SHAPE = 'bad request shape';

/** How many alert_transfers rows one validator's reports may write in 24 hours. */
const REPORTS_A_DAY = 1000;

/** How many transfers one message carries at most. */
const TRANSFERS_A_MESSAGE = 100;

/** The kinds of transfer that wait, as a validator names them. */
const TRANSFER_TYPES = ['guardedAnosTransfer', 'vaultAnosTransfer', 'assistedAnosTransfer', 'breakGlassTransfer'];

/** An amount in millionths of an anos: a decimal string of 1 to 39 digits that does not begin with 0. */
const AMOUNT_PATTERN = /^[1-9][0-9]{0,38}$/;

/**
 * One reported transfer, checked: { transactionId, accountId (Buffers),
 * transactionType, amount, writesAt (a Date or null) }, or null when an
 * entry is not what a validator's job sends.
 */
function transferOf(entry) {
  const transactionId = decodeId(entry.transactionId);
  const accountId = decodeId(entry.accountId);
  if (transactionId === null || accountId === null) return null;
  if (!TRANSFER_TYPES.includes(entry.transactionType)) return null;
  if (typeof entry.amount !== 'string' || !AMOUNT_PATTERN.test(entry.amount)) return null;
  let writesAt = null;
  if (entry.writesAt !== null) {
    if (typeof entry.writesAt !== 'string' || Number.isNaN(Date.parse(entry.writesAt))) return null;
    writesAt = new Date(Date.parse(entry.writesAt));
  }
  return { transactionId, accountId, transactionType: entry.transactionType, amount: entry.amount, writesAt };
}

/**
 * POST /report-waiting-transfers (none). Body { payload: { validatorId,
 * transfers }, signature: { key } }; `transfers` is a list of 1 to 100
 * entries { transactionId, accountId, transactionType, amount, writesAt }.
 * The six checks of spec 25.4, then one transaction: for each transfer, in
 * the order of the list, the pod that made the account, the
 * alert_transfers row under the hash of the report's facts, and, when the
 * row was written and the account has a pod, the alert.
 */
export async function reportWaitingTransfers(body) {
  // 1. The validators' keys are loaded.
  if (validatorKeys === null) return refuse(503, 'validator keys not loaded');

  // 2. Shape.
  if (!isObject(body) || !isObject(body.payload) || !isObject(body.signature)) return refuse(400, BAD_SHAPE);
  const { payload, signature } = body;
  const { validatorId, transfers } = payload;
  if (!Number.isInteger(validatorId) || validatorId < 1 || !Array.isArray(transfers) || transfers.length < 1
    || transfers.length > TRANSFERS_A_MESSAGE || !transfers.every(isObject) || typeof signature.key !== 'string') {
    return refuse(400, BAD_SHAPE);
  }

  // 3. The validator is one of the keys' file.
  const publicKey = validatorKeys.get(validatorId);
  if (publicKey === undefined) return refuse(401, 'unknown validator');

  // 4. The signature, over the canonical bytes of the payload, by that
  //    validator's key. canonicalize throws on a string that is not well
  //    formed, and the route is open to anybody: a throw is a bad
  //    signature too.
  let verified = false;
  try {
    const signed = decodeSignature(ECDSA_P256, signature.key);
    verified = signed !== null && verifySignature(ECDSA_P256, publicKey, Buffer.from(canonicalize(payload), 'utf8'), signed);
  } catch {
    verified = false;
  }
  if (!verified) return refuse(401, 'bad signature');

  // 5. Every transfer. One bad entry refuses the whole message: the
  //    entries are made by our own code.
  const reported = transfers.map(transferOf);
  if (reported.includes(null)) return refuse(400, 'invalid transfer');

  // 6. What this validator's reports have written in the last 24 hours.
  if ((await recentReports(validatorId)) >= REPORTS_A_DAY) return refuse(429, 'too many reports today');

  const { taken, messages } = await withTransaction(async (client) => {
    let rows = 0;
    let written = 0;
    for (const transfer of reported) {
      // 7. The pod that made the account and the account's type, or nothing.
      const account = await findAccount(transfer.accountId, client);

      // 8. The row, under the hash of the report's facts. When no row was
      //    written, the same facts were reported before.
      const accountId = toHex(transfer.accountId);
      const writesAt = transfer.writesAt === null ? null : transfer.writesAt.toISOString();
      const reportId = canonicalHash({
        transactionId: toHex(transfer.transactionId),
        accountId,
        transactionType: transfer.transactionType,
        amount: transfer.amount,
        writesAt,
      });
      const inserted = await insertTransfer(client, {
        reportId,
        transactionId: transfer.transactionId,
        accountId: transfer.accountId,
        anopodId: account === null ? null : account.anopodId,
        transactionType: transfer.transactionType,
        amount: transfer.amount,
        writesAt: transfer.writesAt,
        validatorId,
      });
      if (!inserted) continue;
      rows += 1;

      // 9. The alert, to the pod that made the account. An account no pod
      //    made has nobody to tell.
      if (account === null) continue;
      written += await raiseAlert(client, {
        anopodId: account.anopodId,
        kind: transfer.transactionType === 'breakGlassTransfer' ? 'recoveryMoveWaiting' : 'transferWaiting',
        details: { accountId, accountType: account.accountType, amount: transfer.amount, writesAt },
        reference: transfer.accountId,
      });
    }
    return { taken: rows, messages: written };
  });

  if (messages > 0) kickAlertSender();
  console.log(`validator ${validatorId} reported ${transfers.length} waiting transfers, ${taken} new`);
  return ok(200, { taken });
}
