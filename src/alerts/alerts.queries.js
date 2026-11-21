import { pool } from '../db/pool.js';

/**
 * SQL for the four tables of the security alerts (spec section 25):
 * alert_emails, alert_phones, alert_transfers and alert_messages, and the
 * two counts the feature reads from notifications. Ids, keys and secrets
 * are Buffers of raw bytes, matching the BYTEA columns; pg sends a Buffer
 * parameter as bytea.
 *
 * Reads take an optional `db` (a client inside a transaction; the pool by
 * default). Writes take the transaction's client first.
 */

/**
 * An alert_emails row in camelCase. The id stays a Buffer. A column the
 * statement did not read is undefined: the list reads neither the pod nor
 * the code.
 */
function emailRow(row) {
  return {
    emailId: row.email_id,
    anopodId: row.anopod_id,
    email: row.email,
    language: row.language,
    code: row.code,
    codeExpiresAt: row.code_expires_at,
    codeTries: row.code_tries,
    verifiedAt: row.verified_at,
    removesAt: row.removes_at,
    createdAt: row.created_at,
  };
}

/** An alert_phones row in camelCase. Byte columns stay Buffers. The list does not read the pod. */
function phoneRow(row) {
  return {
    phoneId: row.phone_id,
    anopodId: row.anopod_id,
    endpoint: row.endpoint,
    p256dh: row.p256dh,
    auth: row.auth,
    label: row.label,
    removesAt: row.removes_at,
    createdAt: row.created_at,
  };
}

/** An alert_messages row in camelCase, as the sender takes it. `details` is the JSONB value, parsed. */
function messageRow(row) {
  return {
    messageId: row.message_id,
    anopodId: row.anopod_id,
    kind: row.kind,
    emailId: row.email_id,
    phoneId: row.phone_id,
    details: row.details,
    tries: row.tries,
    createdAt: row.created_at,
  };
}

/** What the list reads of an email: everything but the pod and the code. */
const EMAIL_LIST_COLUMNS = 'email_id, email, language, code_expires_at, code_tries, verified_at, removes_at, created_at';

/** What a read of one email takes: the pod and the code too. */
const EMAIL_COLUMNS = `anopod_id, ${EMAIL_LIST_COLUMNS}, code`;

/** What the list reads of a phone: everything but the pod. */
const PHONE_LIST_COLUMNS = 'phone_id, endpoint, p256dh, auth, label, removes_at, created_at';

/** What a read of one phone takes: the pod too. */
const PHONE_COLUMNS = `anopod_id, ${PHONE_LIST_COLUMNS}`;

/** The pod's emails, oldest first: the confirmed ones, the ones that are coming off and the ones not confirmed yet. */
export async function listEmails(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${EMAIL_LIST_COLUMNS} FROM alert_emails WHERE anopod_id = $1 ORDER BY created_at, email_id`,
    [anopodId],
  );
  return rows.map(emailRow);
}

/** The pod's phones, oldest first, the ones that are coming off too. */
export async function listPhones(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${PHONE_LIST_COLUMNS} FROM alert_phones WHERE anopod_id = $1 ORDER BY created_at, phone_id`,
    [anopodId],
  );
  return rows.map(phoneRow);
}

/**
 * The pod's row for this address on `client`, compared in lower case and
 * locked for the rest of the transaction, or null.
 */
export async function findEmailByAddress(client, anopodId, email) {
  const { rows } = await client.query(
    `SELECT ${EMAIL_COLUMNS} FROM alert_emails WHERE anopod_id = $1 AND lower(email) = lower($2) FOR UPDATE`,
    [anopodId, email],
  );
  return rows.length === 0 ? null : emailRow(rows[0]);
}

/** The email with this id on `client`, locked for the rest of the transaction, or null. Reads the code too. */
export async function lockEmail(client, emailId) {
  const { rows } = await client.query(`SELECT ${EMAIL_COLUMNS} FROM alert_emails WHERE email_id = $1 FOR UPDATE`, [emailId]);
  return rows.length === 0 ? null : emailRow(rows[0]);
}

/** The phone with this id on `client`, locked for the rest of the transaction, or null. */
export async function lockPhone(client, phoneId) {
  const { rows } = await client.query(`SELECT ${PHONE_COLUMNS} FROM alert_phones WHERE phone_id = $1 FOR UPDATE`, [phoneId]);
  return rows.length === 0 ? null : phoneRow(rows[0]);
}

/** The email with this id, with no lock, or null: for the sender. Reads the code too. */
export async function findEmail(emailId, db = pool) {
  const { rows } = await db.query(`SELECT ${EMAIL_COLUMNS} FROM alert_emails WHERE email_id = $1`, [emailId]);
  return rows.length === 0 ? null : emailRow(rows[0]);
}

/** The phone with this id, with no lock, or null: for the sender. */
export async function findPhone(phoneId, db = pool) {
  const { rows } = await db.query(`SELECT ${PHONE_COLUMNS} FROM alert_phones WHERE phone_id = $1`, [phoneId]);
  return rows.length === 0 ? null : phoneRow(rows[0]);
}

/** The pod's row with this delivery address on `client`, or null. */
export async function findPhoneByEndpoint(client, anopodId, endpoint) {
  const { rows } = await client.query(
    `SELECT ${PHONE_COLUMNS} FROM alert_phones WHERE anopod_id = $1 AND endpoint = $2`,
    [anopodId, endpoint],
  );
  return rows.length === 0 ? null : phoneRow(rows[0]);
}

/** How many alert_emails rows the pod has on `client`, the unconfirmed ones and the ones coming off too: what the limit of 3 reads. */
export async function countEmails(client, anopodId) {
  const { rows } = await client.query('SELECT count(*)::int AS count FROM alert_emails WHERE anopod_id = $1', [anopodId]);
  return rows[0].count;
}

/** How many alert_phones rows the pod has on `client`, the ones coming off too: what the limit of 5 reads. */
export async function countPhones(client, anopodId) {
  const { rows } = await client.query('SELECT count(*)::int AS count FROM alert_phones WHERE anopod_id = $1', [anopodId]);
  return rows[0].count;
}

/** Inserts one email on `client`, not confirmed and with no code yet: { emailId, anopodId, email, language }. */
export async function insertEmail(client, { emailId, anopodId, email, language }) {
  await client.query(
    'INSERT INTO alert_emails (email_id, anopod_id, email, language) VALUES ($1, $2, $3, $4)',
    [emailId, anopodId, email, language],
  );
}

/**
 * Gives the email a new code on `client`, good for ten minutes, with no
 * wrong tries yet, and the language the wallet shows now.
 */
export async function setCode(client, emailId, code, language) {
  await client.query(
    `UPDATE alert_emails SET code = $2, code_expires_at = now() + interval '10 minutes', code_tries = 0, language = $3 WHERE email_id = $1`,
    [emailId, code, language],
  );
}

/** Counts one wrong code against the email's current code on `client`. */
export async function countWrongCode(client, emailId) {
  await client.query('UPDATE alert_emails SET code_tries = code_tries + 1 WHERE email_id = $1', [emailId]);
}

/** Confirms the email on `client`: verified now, the code gone. A row that is confirmed already is left as it is. */
export async function confirmEmail(client, emailId) {
  await client.query(
    'UPDATE alert_emails SET verified_at = now(), code = NULL, code_expires_at = NULL, code_tries = 0 WHERE email_id = $1 AND verified_at IS NULL',
    [emailId],
  );
}

/** Deletes the email on `client`, only while it is not confirmed. */
export async function deleteEmail(client, emailId) {
  await client.query('DELETE FROM alert_emails WHERE email_id = $1 AND verified_at IS NULL', [emailId]);
}

/** Sets the email to come off `minutes` from now on `client`. Returns that moment, a Date. */
export async function setEmailRemoval(client, emailId, minutes) {
  const { rows } = await client.query(
    'UPDATE alert_emails SET removes_at = now() + make_interval(mins => $2) WHERE email_id = $1 RETURNING removes_at',
    [emailId, minutes],
  );
  return rows[0].removes_at;
}

/** The email stays on `client`: its removal is cleared. */
export async function clearEmailRemoval(client, emailId) {
  await client.query('UPDATE alert_emails SET removes_at = NULL WHERE email_id = $1', [emailId]);
}

/** Sets the phone to come off `minutes` from now on `client`. Returns that moment, a Date. */
export async function setPhoneRemoval(client, phoneId, minutes) {
  const { rows } = await client.query(
    'UPDATE alert_phones SET removes_at = now() + make_interval(mins => $2) WHERE phone_id = $1 RETURNING removes_at',
    [phoneId, minutes],
  );
  return rows[0].removes_at;
}

/** The phone stays on `client`: its removal is cleared. */
export async function clearPhoneRemoval(client, phoneId) {
  await client.query('UPDATE alert_phones SET removes_at = NULL WHERE phone_id = $1', [phoneId]);
}

/** Inserts one phone on `client`: { phoneId, anopodId, endpoint, p256dh, auth, label }. */
export async function insertPhone(client, { phoneId, anopodId, endpoint, p256dh, auth, label }) {
  await client.query(
    'INSERT INTO alert_phones (phone_id, anopod_id, endpoint, p256dh, auth, label) VALUES ($1, $2, $3, $4, $5, $6)',
    [phoneId, anopodId, endpoint, p256dh, auth, label],
  );
}

/**
 * The codes the pod was sent in the last 24 hours on `client`: { count,
 * latest }, `latest` the Date of the newest one or null when there is none.
 */
export async function recentCodes(client, anopodId) {
  const { rows } = await client.query(
    `SELECT count(*)::int AS count, max(created_at) AS latest FROM alert_messages WHERE anopod_id = $1 AND kind = 'emailCode' AND created_at > now() - interval '24 hours'`,
    [anopodId],
  );
  return { count: rows[0].count, latest: rows[0].latest };
}

/**
 * Where an alert of the pod goes, on `client`: { emailIds, phoneIds }, the
 * ids of its confirmed emails and of its phones, the ones that are coming
 * off too.
 */
export async function destinations(client, anopodId) {
  const emails = await client.query('SELECT email_id FROM alert_emails WHERE anopod_id = $1 AND verified_at IS NOT NULL', [anopodId]);
  const phones = await client.query('SELECT phone_id FROM alert_phones WHERE anopod_id = $1', [anopodId]);
  return {
    emailIds: emails.rows.map((row) => row.email_id),
    phoneIds: phones.rows.map((row) => row.phone_id),
  };
}

/**
 * Inserts one message on `client`: { messageId, anopodId, kind, emailId,
 * phoneId, details }, one of emailId and phoneId null. It is due at once.
 */
export async function insertMessage(client, { messageId, anopodId, kind, emailId, phoneId, details }) {
  await client.query(
    'INSERT INTO alert_messages (message_id, anopod_id, kind, email_id, phone_id, details) VALUES ($1, $2, $3, $4, $5, $6::jsonb)',
    [messageId, anopodId, kind, emailId, phoneId, JSON.stringify(details)],
  );
}

/** How many notifications of `kind` the pod got in the last 24 hours, on `client`. */
async function recentNotifications(client, anopodId, kind) {
  const { rows } = await client.query(
    `SELECT count(*)::int AS count FROM notifications WHERE anopod_id = $1 AND kind = $2 AND created_at > now() - interval '24 hours'`,
    [anopodId, kind],
  );
  return rows[0].count;
}

/** How many changes of its list the pod made in the last 24 hours, on `client`: its alertSettingsChanged notifications. */
export function recentChanges(client, anopodId) {
  return recentNotifications(client, anopodId, 'alertSettingsChanged');
}

/** How many alerts about a recovery case the pod got in the last 24 hours, on `client`: its recoveryCaseOpened notifications. */
export function recentRecoveryAlerts(client, anopodId) {
  return recentNotifications(client, anopodId, 'recoveryCaseOpened');
}

/** How many alert_transfers rows this validator's reports wrote in the last 24 hours. */
export async function recentReports(validatorId, db = pool) {
  const { rows } = await db.query(
    `SELECT count(*)::int AS count FROM alert_transfers WHERE validator_id = $1 AND created_at > now() - interval '24 hours'`,
    [validatorId],
  );
  return rows[0].count;
}

/**
 * Inserts one reported transfer on `client`: { reportId, transactionId,
 * accountId, anopodId (or null), transactionType, amount, writesAt (a Date
 * or null), validatorId }. Returns true when the row was written, false
 * when a report with the same facts wrote it before.
 */
export async function insertTransfer(client, row) {
  const { rowCount } = await client.query(
    `INSERT INTO alert_transfers (report_id, transaction_id, account_id, anopod_id, transaction_type, amount, writes_at, validator_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (report_id) DO NOTHING`,
    [row.reportId, row.transactionId, row.accountId, row.anopodId, row.transactionType, row.amount, row.writesAt, row.validatorId],
  );
  return rowCount === 1;
}

/**
 * Takes up to `limit` messages that are due on `client`, the oldest due
 * first, and holds them for the rest of the transaction; rows another
 * server holds are skipped. Messages to an email are taken only when
 * `emailOn`, messages to a phone only when `phonesOn`.
 */
export async function claimDue(client, limit, emailOn, phonesOn) {
  const { rows } = await client.query(
    `SELECT message_id, anopod_id, kind, email_id, phone_id, details, tries, created_at
     FROM alert_messages
     WHERE sent_at IS NULL AND gave_up_at IS NULL AND next_try_at <= now()
       AND ($2 OR email_id IS NULL) AND ($3 OR phone_id IS NULL)
     ORDER BY next_try_at, message_id
     LIMIT $1
     FOR UPDATE SKIP LOCKED`,
    [limit, emailOn, phonesOn],
  );
  return rows.map(messageRow);
}

/** The message went out, on `client`. */
export async function markSent(client, messageId) {
  await client.query('UPDATE alert_messages SET sent_at = now(), last_error = NULL WHERE message_id = $1', [messageId]);
}

/**
 * A send failed, on `client`: one more try counted, `error` kept, and the
 * next try after 1, 2, 4, 8, 16 and 32 minutes, then every 60. A message
 * that is more than three days old is given up.
 */
export async function markFailed(client, messageId, error) {
  await client.query(
    `UPDATE alert_messages
     SET tries = tries + 1,
         last_error = $2,
         next_try_at = now() + make_interval(mins => LEAST(power(2, LEAST(tries, 6)), 60)::int),
         gave_up_at = CASE WHEN created_at < now() - interval '3 days' THEN now() END
     WHERE message_id = $1`,
    [messageId, error],
  );
}

/** The message is given up, on `client`, with `error` as the reason. */
export async function markGaveUp(client, messageId, error) {
  await client.query('UPDATE alert_messages SET gave_up_at = now(), last_error = $2 WHERE message_id = $1', [messageId, error]);
}

/**
 * Deletes every phone with this delivery address on `client`, whichever
 * pod's: the phone can no longer be reached. Returns the rows that went,
 * each { phoneId, anopodId, label }.
 */
export async function deletePhonesByEndpoint(client, endpoint) {
  const { rows } = await client.query(
    'DELETE FROM alert_phones WHERE endpoint = $1 RETURNING phone_id, anopod_id, label',
    [endpoint],
  );
  return rows.map((row) => ({ phoneId: row.phone_id, anopodId: row.anopod_id, label: row.label }));
}

/**
 * What is due to come off, comes off: the emails and the phones whose
 * removes_at has passed, and the emails that were not confirmed within a
 * day. Returns { emails, phones }, how many rows of each went.
 */
export async function removeDue(db = pool) {
  const emails = await db.query('DELETE FROM alert_emails WHERE removes_at <= now()');
  const phones = await db.query('DELETE FROM alert_phones WHERE removes_at <= now()');
  const unconfirmed = await db.query(`DELETE FROM alert_emails WHERE verified_at IS NULL AND created_at < now() - interval '1 day'`);
  return { emails: emails.rowCount + unconfirmed.rowCount, phones: phones.rowCount };
}
