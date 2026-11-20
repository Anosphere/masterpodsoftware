import { findLiveRole } from '../appointments/appointments.queries.js';
import { decodeBytes } from '../crypto/bytes.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  countAccountsSince,
  findAccount,
  findAccountOf,
  insertAccount,
  listAccountsOf,
  lockPod,
  markSubmitted,
  setFirstKeyBlob,
} from './anos-accounts.queries.js';

/**
 * The anos accounts feature (wallet spec 4.4): one row per anos account a
 * pod made, holding the private halves for the pod (both pairs in
 * key_blob and, since 2026-11-20, pair one alone in first_key_blob,
 * spec section 22; both under the pod's key blob key, which this
 * server cannot open), the signed creation, and when a
 * validator answered it. The validators ask /get-anos-account whether an
 * account was made by a vouched pod before accepting its creation. The
 * masterpod never verifies anos signatures; the validators do. Each function
 * runs its route's checks in the spec's order and returns ok(status, body)
 * or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

/** The four account types a wallet may make, as the validators name them. */
export const ACCOUNT_TYPES = ['spending', 'guarded', 'vault', 'assisted'];

/** The eight signatures a creation carries, in the validators' order. */
const CREATION_SIGNATURES = [
  'key1', 'postQuantumKey1', 'key2', 'postQuantumKey2',
  'breakGlassKey', 'breakGlassPostQuantumKey', 'walletKey', 'walletPostQuantumKey',
];

/** The transactionType of a creation. */
const ACCOUNT_CREATION = 'accountCreation';

/** keyBlob is 1 to 1024 bytes (156 in practice); firstKeyBlob too (92 in practice). */
const keyBlobLength = (n) => n >= 1 && n <= 1024;

/**
 * The account limit (spec section 17): a pod may make at most ACCOUNT_LIMIT
 * new anos accounts in the last ACCOUNT_LIMIT_DAYS days, counted back from
 * the moment of the request.
 */
const ACCOUNT_LIMIT = 20;
const ACCOUNT_LIMIT_DAYS = 30;

/** A row in wire form, as /list-anos-accounts answers it. keyBlob is the row's first key blob, pair one alone, once it has one, and until then the blob with both pairs; firstKeyOnly says which (spec section 22). breakGlassBlob is hex, or null until a recovery's finish stored it (spec 12.4.5). */
function accountOf(row) {
  return {
    accountId: toHex(row.accountId),
    accountType: row.accountType,
    keyBlob: toHex(row.firstKeyBlob ?? row.keyBlob),
    firstKeyOnly: row.firstKeyBlob !== null,
    creation: row.creation,
    submittedAt: row.submittedAt === null ? null : row.submittedAt.toISOString(),
    breakGlassBlob: toHex(row.breakGlassBlob),
    createdAt: row.createdAt.toISOString(),
  };
}


/**
 * POST /create-anos-account (setup). Body { accountId, accountType, keyBlob,
 * firstKeyBlob, creation: { payload, signatures } }. firstKeyBlob (spec
 * section 22) is pair one's private halves alone; a wallet page loaded
 * before 2026-11-20 sends none, and the row then has none until that pod's
 * next login. The checks, in order: the shape;
 * accountId 32 bytes; accountType one of the four; keyBlob 1 to 1024 bytes;
 * firstKeyBlob, when there, 1 to 1024 bytes;
 * the creation names the same account, type and transactionType and
 * carries the eight signature strings; no row with this accountId; last,
 * the account limit (spec section 17): in one transaction, with the pod's
 * row locked, the pod's rows of the last ACCOUNT_LIMIT_DAYS days are
 * counted, and at ACCOUNT_LIMIT or more nothing is inserted and the answer
 * is 403 account limit reached. The insert runs in that transaction.
 */
export async function createAnosAccount(anopod, body) {
  if (!isObject(body) || typeof body.accountId !== 'string' || typeof body.accountType !== 'string'
    || typeof body.keyBlob !== 'string' || !isObject(body.creation)
    || !isObject(body.creation.payload) || !isObject(body.creation.signatures)) {
    return refuse(400, BAD_SHAPE);
  }
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  if (!ACCOUNT_TYPES.includes(body.accountType)) return refuse(400, 'invalid accountType');
  const keyBlob = decodeBytes(body.keyBlob, keyBlobLength);
  if (keyBlob === null) return refuse(400, 'invalid keyBlob');
  let firstKeyBlob = null;
  if (body.firstKeyBlob !== undefined) {
    firstKeyBlob = decodeBytes(body.firstKeyBlob, keyBlobLength);
    if (firstKeyBlob === null) return refuse(400, 'invalid firstKeyBlob');
  }

  const { payload, signatures } = body.creation;
  const payloadAccountId = decodeId(payload.accountId);
  if (payloadAccountId === null || !payloadAccountId.equals(accountId)
    || payload.accountType !== body.accountType
    || payload.transactionType !== ACCOUNT_CREATION
    || !CREATION_SIGNATURES.every((name) => typeof signatures[name] === 'string')) {
    return refuse(400, 'invalid creation');
  }

  if ((await findAccount(accountId)) !== null) return refuse(409, 'account already registered');
  try {
    const written = await withTransaction(async (client) => {
      await lockPod(client, anopod.anopodId);
      if ((await countAccountsSince(client, anopod.anopodId, ACCOUNT_LIMIT_DAYS)) >= ACCOUNT_LIMIT) return false;
      await insertAccount({ accountId, anopodId: anopod.anopodId, accountType: body.accountType, keyBlob, firstKeyBlob, creation: body.creation }, client);
      return true;
    });
    if (!written) return refuse(403, 'account limit reached');
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'account already registered');
    throw err;
  }
  return ok(201, { accountId: toHex(accountId) });
}

/**
 * POST /mark-anos-account-submitted (setup). Body { accountId }. The row
 * must be this pod's. submitted_at is set once; a second call keeps the
 * first time.
 */
export async function markAnosAccountSubmitted(anopod, body) {
  if (!isObject(body) || typeof body.accountId !== 'string') return refuse(400, BAD_SHAPE);
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  const submittedAt = await markSubmitted(accountId, anopod.anopodId);
  if (submittedAt === null) return refuse(404, 'account not found');
  return ok(200, { accountId: toHex(accountId), submittedAt: submittedAt.toISOString() });
}

/**
 * POST /list-anos-accounts (setup). Body { firstKeyBlobs }. The caller's
 * rows, oldest first, each with its breakGlassBlob (hex or null). Since
 * 2026-11-20 (spec section 22) a row that has a first key blob is answered
 * with that blob as keyBlob and firstKeyOnly true, and the blob with both
 * pairs is answered to nobody; a row without one is answered as before,
 * with firstKeyOnly false. The old page guard: a wallet page loaded before
 * 2026-11-20 cannot open a first key blob, and it sends no firstKeyBlobs:
 * true. Once one of the pod's rows has a first key blob, a call without it
 * is refused, 409 reload the wallet.
 */
export async function listAnosAccounts(anopod, body) {
  const rows = await listAccountsOf(anopod.anopodId);
  if (body.firstKeyBlobs !== true && rows.some((row) => row.firstKeyBlob !== null)) return refuse(409, 'reload the wallet');
  return ok(200, { accounts: rows.map(accountOf) });
}

/**
 * POST /store-first-key-blob (setup). Body { accountId, firstKeyBlob }: the
 * first key blob of one of the caller's accounts, pair one's private halves
 * alone under the pod's key blob key (spec section 22). The wallet sends it
 * at a login for each account that has none. The checks, in order: the
 * shape; accountId 32 bytes; firstKeyBlob 1 to 1024 bytes; the row is this
 * pod's (404 account not found); the row has none yet (409 first key blob
 * already stored). Written once: the UPDATE writes only where the column is
 * null, so of two calls at the same moment one writes and the other gets
 * the 409. key_blob is not touched.
 */
export async function storeFirstKeyBlob(anopod, body) {
  if (!isObject(body) || typeof body.accountId !== 'string' || typeof body.firstKeyBlob !== 'string') return refuse(400, BAD_SHAPE);
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, 'invalid accountId');
  const firstKeyBlob = decodeBytes(body.firstKeyBlob, keyBlobLength);
  if (firstKeyBlob === null) return refuse(400, 'invalid firstKeyBlob');
  const account = await findAccount(accountId);
  if (account === null || !account.anopodId.equals(anopod.anopodId)) return refuse(404, 'account not found');
  if (account.firstKeyBlob !== null || !(await setFirstKeyBlob(accountId, anopod.anopodId, firstKeyBlob))) {
    return refuse(409, 'first key blob already stored');
  }
  return ok(200, { accountId: toHex(accountId) });
}

/**
 * POST /get-anos-account (none). Body { accountId }. For the validators'
 * binding check at create-account and their appointment check at a
 * moderator, attestor, validator or masterPod stake (spec section 16, the
 * last two since 2026-11-10, 16.7): the pod that made the account, whether
 * it is vouched, read from the pod's row, and its live role, "moderator",
 * "attestor", "validator", "masterPod" or null, read from appointments.
 * Unsigned, like /get-anopod-session-keys.
 */
export async function getAnosAccount(body) {
  if (!isObject(body) || typeof body.accountId !== 'string') return refuse(400, BAD_SHAPE);
  const accountId = decodeId(body.accountId);
  if (accountId === null) return refuse(400, BAD_SHAPE);
  const found = await findAccountOf(accountId);
  if (found === null) return refuse(404, 'unknown account');
  const role = await findLiveRole(found.anopodId);
  return ok(200, { accountId: toHex(accountId), anopodId: toHex(found.anopodId), vouched: found.vouched, role });
}
