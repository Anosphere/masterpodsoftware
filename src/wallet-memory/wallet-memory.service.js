import { findAccount } from '../anos-accounts/anos-accounts.queries.js';
import { decodeBytes } from '../crypto/bytes.js';
import { isUniqueViolation } from '../db/transaction.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { deleteNote, findNoteByTransaction, insertNote, listNotes, updateNoteBlob } from './noted-transactions.queries.js';
import { findSettings, upsertSettings } from './wallet-settings.queries.js';

/**
 * The wallet memory feature (wallet spec 4.6 and 4.7): what a wallet
 * remembers for its pod, kept here under the pod's encryption key, which
 * this server cannot open. Two tables: noted_transactions, one row per
 * ledger transaction the person noted for their tax records, the ledger's
 * facts in the clear and the private part (the kind, the money, the
 * currency, the memo, the tag) in one blob; and wallet_settings, one row per
 * pod holding one blob of the small things the wallet remembers (the
 * Protect your passkey answer first). A caller sees and changes its own
 * rows only. Each function runs its route's checks in the spec's order and
 * returns ok(status, body) or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

/** The blobs' ceilings, the columns' checks. */
const NOTE_BLOB_MAX = 4096;
const SETTINGS_BLOB_MAX = 16384;

/** /list-noted-transactions answers this many notes at most, and says when more exist. */
const LIST_LIMIT = 1000;

/** amount: millionths of an anos as digits only, zero allowed, that fit a BIGINT. */
const AMOUNT_PATTERN = /^(0|[1-9][0-9]*)$/;
const MAX_BIGINT = 2n ** 63n - 1n;

/** noteBlob is 1 to 4096 bytes; settingsBlob 1 to 16384. */
const noteBlobLength = (n) => n >= 1 && n <= NOTE_BLOB_MAX;
const settingsBlobLength = (n) => n >= 1 && n <= SETTINGS_BLOB_MAX;

/** True for an amount string the column accepts. */
function isAmount(value) {
  return typeof value === 'string' && AMOUNT_PATTERN.test(value) && BigInt(value) <= MAX_BIGINT;
}

/** `value` as an ISO 8601 string when it is a string that parses to a time (Date.parse, as the session's timestamp check), else null. */
function timeOf(value) {
  if (typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

/** A row in wire form, as /list-noted-transactions answers it: ids and the blob hex (otherAccountId null when there is none), position a number, the times ISO 8601, amount a decimal string. */
function noteOf(row) {
  return {
    noteId: toHex(row.noteId),
    transactionId: toHex(row.transactionId),
    accountId: toHex(row.accountId),
    otherAccountId: toHex(row.otherAccountId),
    position: Number(row.position),
    transactedAt: row.transactedAt.toISOString(),
    amount: row.amount,
    sent: row.sent,
    noteBlob: toHex(row.noteBlob),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/**
 * POST /add-noted-transaction (setup). Body { transactionId, accountId,
 * otherAccountId, position, transactedAt, amount, sent, noteBlob }. The
 * checks, in order: the shape; transactionId 32 bytes; accountId 32 bytes;
 * otherAccountId 32 bytes when not null; position an integer of 0 or more;
 * transactedAt parses; amount digits only that fit a BIGINT; noteBlob 1 to
 * 4096 bytes; an anos_accounts row with this accountId and this pod; no note
 * of this pod for this transaction, the unique rule as the backstop.
 */
export async function addNotedTransaction(anopod, body) {
  if (!isObject(body) || typeof body.transactionId !== 'string' || typeof body.accountId !== 'string'
    || (body.otherAccountId !== null && typeof body.otherAccountId !== 'string')
    || typeof body.position !== 'number' || typeof body.transactedAt !== 'string'
    || typeof body.amount !== 'string' || typeof body.sent !== 'boolean' || typeof body.noteBlob !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const transactionId = decodeId(body.transactionId);
  if (transactionId === null) return refuse(400, 'invalid transactionId');
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  const otherAccountId = body.otherAccountId === null ? null : decodeId(body.otherAccountId);
  if (body.otherAccountId !== null && otherAccountId === null) return refuse(400, 'invalid otherAccountId');
  if (!Number.isInteger(body.position) || body.position < 0) return refuse(400, 'invalid position');
  const transactedAt = timeOf(body.transactedAt);
  if (transactedAt === null) return refuse(400, 'invalid transactedAt');
  if (!isAmount(body.amount)) return refuse(400, 'invalid amount');
  const noteBlob = decodeBytes(body.noteBlob, noteBlobLength);
  if (noteBlob === null) return refuse(400, 'invalid noteBlob');

  const account = await findAccount(accountId);
  if (account === null || !account.anopodId.equals(anopod.anopodId)) return refuse(403, 'not your account');
  if ((await findNoteByTransaction(anopod.anopodId, transactionId)) !== null) return refuse(409, 'already noted');

  const noteId = randomId();
  try {
    await insertNote({
      noteId,
      anopodId: anopod.anopodId,
      transactionId,
      accountId,
      otherAccountId,
      position: body.position,
      transactedAt,
      amount: body.amount,
      sent: body.sent,
      noteBlob,
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'already noted');
    throw err;
  }
  return ok(201, { noteId: toHex(noteId) });
}

/**
 * POST /update-noted-transaction (setup). Body { noteId, noteBlob }. The
 * row must be this pod's; only the blob changes, the ledger facts never.
 */
export async function updateNotedTransaction(anopod, body) {
  if (!isObject(body) || typeof body.noteId !== 'string' || typeof body.noteBlob !== 'string') return refuse(400, BAD_SHAPE);
  const noteId = decodeId(body.noteId);
  if (noteId === null) return refuse(400, 'invalid noteId');
  const noteBlob = decodeBytes(body.noteBlob, noteBlobLength);
  if (noteBlob === null) return refuse(400, 'invalid noteBlob');
  const updatedAt = await updateNoteBlob(noteId, anopod.anopodId, noteBlob);
  if (updatedAt === null) return refuse(404, 'note not found');
  return ok(200, { noteId: toHex(noteId), updatedAt: updatedAt.toISOString() });
}

/** POST /remove-noted-transaction (setup). Body { noteId }. The row must be this pod's. */
export async function removeNotedTransaction(anopod, body) {
  if (!isObject(body) || typeof body.noteId !== 'string') return refuse(400, BAD_SHAPE);
  const noteId = decodeId(body.noteId);
  if (noteId === null) return refuse(400, 'invalid noteId');
  if (!(await deleteNote(noteId, anopod.anopodId))) return refuse(404, 'note not found');
  return ok(200, { noteId: toHex(noteId), removed: true });
}

/**
 * POST /list-noted-transactions (setup). Body { from?, to? }, ISO 8601,
 * null counting as absent: the pod's notes with transacted_at at or after
 * from and before to, newest first, the first LIST_LIMIT of them, and
 * `more` true when a further row exists.
 */
export async function listNotedTransactions(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const from = body.from === undefined || body.from === null ? null : timeOf(body.from);
  if (from === null && body.from !== undefined && body.from !== null) return refuse(400, 'invalid from');
  const to = body.to === undefined || body.to === null ? null : timeOf(body.to);
  if (to === null && body.to !== undefined && body.to !== null) return refuse(400, 'invalid to');
  const rows = await listNotes(anopod.anopodId, from, to, LIST_LIMIT + 1);
  return ok(200, { notes: rows.slice(0, LIST_LIMIT).map(noteOf), more: rows.length > LIST_LIMIT });
}

/** POST /get-wallet-settings (setup). Body { }. The pod's blob and when it was last set, both null before the first set. */
export async function getWalletSettings(anopod) {
  const found = await findSettings(anopod.anopodId);
  if (found === null) return ok(200, { settingsBlob: null, updatedAt: null });
  return ok(200, { settingsBlob: toHex(found.settingsBlob), updatedAt: found.updatedAt.toISOString() });
}

/** POST /set-wallet-settings (setup). Body { settingsBlob }. The pod's one row, written whole: inserted, or its blob replaced. */
export async function setWalletSettings(anopod, body) {
  if (!isObject(body) || typeof body.settingsBlob !== 'string') return refuse(400, BAD_SHAPE);
  const settingsBlob = decodeBytes(body.settingsBlob, settingsBlobLength);
  if (settingsBlob === null) return refuse(400, 'invalid settingsBlob');
  const updatedAt = await upsertSettings(anopod.anopodId, settingsBlob);
  return ok(200, { updatedAt: updatedAt.toISOString() });
}
