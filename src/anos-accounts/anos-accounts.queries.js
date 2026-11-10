import { pool, query } from '../db/pool.js';

/**
 * SQL for the anos_accounts table. Ids and blobs are Buffers of raw bytes,
 * matching the BYTEA columns; pg sends a Buffer parameter as bytea. The
 * creation is stored as JSONB, sent as JSON text; JSONB keeps the value, not
 * the key order, which is fine because the validators rebuild the signed
 * bytes canonically.
 */

/** An anos_accounts row in camelCase. Byte columns stay Buffers. */
function accountRow(row) {
  return {
    accountId: row.account_id,
    anopodId: row.anopod_id,
    accountType: row.account_type,
    keyBlob: row.key_blob,
    creation: row.creation,
    submittedAt: row.submitted_at,
    breakGlassBlob: row.break_glass_blob,
    createdAt: row.created_at,
  };
}

const COLUMNS = 'account_id, anopod_id, account_type, key_blob, creation, submitted_at, break_glass_blob, created_at';


/** The row with this account id (a 32-byte Buffer), or null. */
export async function findAccount(accountId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM anos_accounts WHERE account_id = $1`, [accountId]);
  return rows.length === 0 ? null : accountRow(rows[0]);
}

/**
 * For /get-anos-account: the pod that made the account and the pod's
 * vouched flag, { anopodId, vouched }, or null when there is no such
 * account. A pod row that vanished reads as vouched false.
 */
export async function findAccountOf(accountId, db = pool) {
  const { rows } = await db.query(
    `SELECT x.anopod_id, COALESCE(a.vouched, false) AS vouched
     FROM anos_accounts x
     LEFT JOIN anopods a ON a.anopod_id = x.anopod_id
     WHERE x.account_id = $1`,
    [accountId],
  );
  return rows.length === 0 ? null : { anopodId: rows[0].anopod_id, vouched: rows[0].vouched };
}

/**
 * Locks this pod's row in anopods for the rest of the transaction on
 * `client` (SELECT ... FOR UPDATE). /create-anos-account locks it before it
 * counts, so two creations of one pod sent at the same moment wait for each
 * other and cannot both pass on the same count (spec section 17).
 */
export async function lockPod(client, anopodId) {
  await client.query('SELECT 1 FROM anopods WHERE anopod_id = $1 FOR UPDATE', [anopodId]);
}

/**
 * How many anos_accounts rows this pod made in the last `days` days, counted
 * back from now(), on `client`: the number the account limit reads (spec
 * section 17). Every row of the pod's counts, also one whose creation never
 * reached a validator.
 */
export async function countAccountsSince(client, anopodId, days) {
  const { rows } = await client.query(
    'SELECT count(*)::int AS count FROM anos_accounts WHERE anopod_id = $1 AND created_at > now() - make_interval(days => $2)',
    [anopodId, days],
  );
  return rows[0].count;
}

/**
 * Inserts one account: { accountId, anopodId, accountType, keyBlob,
 * creation }, submitted_at null. A duplicate account id throws a unique
 * violation (db/transaction.js isUniqueViolation).
 */
export async function insertAccount({ accountId, anopodId, accountType, keyBlob, creation }, db = pool) {
  await db.query(
    `INSERT INTO anos_accounts (account_id, anopod_id, account_type, key_blob, creation)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [accountId, anopodId, accountType, keyBlob, JSON.stringify(creation)],
  );
}

/**
 * Sets submitted_at on this pod's account, once: COALESCE keeps the first
 * time. Returns the submitted_at Date, or null when the row is not this
 * pod's or does not exist.
 */
export async function markSubmitted(accountId, anopodId) {
  const { rows } = await query(
    `UPDATE anos_accounts SET submitted_at = COALESCE(submitted_at, now())
     WHERE account_id = $1 AND anopod_id = $2
     RETURNING submitted_at`,
    [accountId, anopodId],
  );
  return rows.length === 0 ? null : rows[0].submitted_at;
}

/** The pod's accounts, oldest first. */
export async function listAccountsOf(anopodId) {
  const { rows } = await query(
    `SELECT ${COLUMNS} FROM anos_accounts WHERE anopod_id = $1 ORDER BY created_at, account_id`,
    [anopodId],
  );
  return rows.map(accountRow);
}

/**
 * Stores the break-glass blob on this pod's account (spec 12.4.5,
 * /store-break-glass-blob): the account's break-glass seed under the pod's
 * encryption key, written at the finish of a recovery; a second call
 * replaces it. Returns true when the row is this pod's and was written,
 * false when there is no such account of the pod's.
 */
export async function setBreakGlassBlob(accountId, anopodId, blob) {
  const { rowCount } = await query(
    'UPDATE anos_accounts SET break_glass_blob = $3 WHERE account_id = $1 AND anopod_id = $2',
    [accountId, anopodId, blob],
  );
  return rowCount === 1;
}

/**
 * For the DAO snapshot (spec 15.6): the pod of each of these accounts
 * (32-byte Buffers), as a Map from the account id in lowercase hex to the
 * pod's id as a Buffer. An account the masterpod does not know has no
 * entry.
 */
export async function findPodsForAccounts(accountIds, db = pool) {
  const { rows } = await db.query(
    'SELECT account_id, anopod_id FROM anos_accounts WHERE account_id = ANY ($1::bytea[])',
    [accountIds],
  );
  return new Map(rows.map((row) => [row.account_id.toString('hex'), row.anopod_id]));
}
