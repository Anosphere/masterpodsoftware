import { pool } from '../db/pool.js';
import { toHex } from '../util/ids.js';

/**
 * SQL for the anopods table. Ids and keys are Buffers of raw bytes,
 * matching the BYTEA columns; pg sends a Buffer parameter as bytea.
 *
 * Reads take an optional `db` (a client inside a transaction; the pool by
 * default). Writes take the transaction's client first.
 */

const COLUMNS = `anopod_id, first_name, last_name, username,
       pass_key_credential_id, pass_key_public_key,
       ephemeral_auth_key, ephemeral_auth_key_pq, ephemeral_expires_at, vouched,
       anopod_encryption_key_blob_1, anopod_encryption_key_blob_2,
       backup_code_public_key, backup_code_public_key_pq,
       chat_public_key, chat_public_key_pq, chat_private_key_blob, identity_blob,
       created_at, updated_at`;

/**
 * An anopods row in camelCase, as requireSession puts it on req.anopod.
 * Byte columns stay Buffers; setupComplete is the spec's definition,
 * anopod_encryption_key_blob_2 being set.
 */
export function anopodRow(row) {
  return {
    anopodId: row.anopod_id,
    firstName: row.first_name,
    lastName: row.last_name,
    username: row.username,
    passKeyCredentialId: row.pass_key_credential_id,
    passKeyPublicKey: row.pass_key_public_key,
    ephemeralAuthKey: row.ephemeral_auth_key,
    ephemeralAuthKeyPq: row.ephemeral_auth_key_pq,
    ephemeralExpiresAt: row.ephemeral_expires_at,
    vouched: row.vouched,
    encryptionKeyBlob1: row.anopod_encryption_key_blob_1,
    encryptionKeyBlob2: row.anopod_encryption_key_blob_2,
    backupCodePublicKey: row.backup_code_public_key,
    backupCodePublicKeyPq: row.backup_code_public_key_pq,
    chatPublicKey: row.chat_public_key,
    chatPublicKeyPq: row.chat_public_key_pq,
    chatPrivateKeyBlob: row.chat_private_key_blob,
    identityBlob: row.identity_blob,
    setupComplete: row.anopod_encryption_key_blob_2 !== null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function findOne(where, params, db) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM anopods WHERE ${where}`, params);
  return rows.length === 0 ? null : anopodRow(rows[0]);
}

/** The row with this id (a 32-byte Buffer), or null. */
export function findById(anopodId, db = pool) {
  return findOne('anopod_id = $1', [anopodId], db);
}

/** The row whose passkey has this credential id (a Buffer), or null. */
export function findByCredentialId(credentialId, db = pool) {
  return findOne('pass_key_credential_id = $1', [credentialId], db);
}

/** The row with this username (already lowercased), or null. */
export function findByUsername(username, db = pool) {
  return findOne('username = $1', [username], db);
}

/** True when a pod already has this username. */
export async function usernameTaken(username, db = pool) {
  const { rows } = await db.query('SELECT EXISTS (SELECT 1 FROM anopods WHERE username = $1) AS taken', [
    username,
  ]);
  return rows[0].taken;
}

/**
 * Inserts a new pod on `client`: the profile, the passkey, the first
 * session's keys and their expiry; vouched false, the setup columns null.
 * `row` is { anopodId, firstName, lastName, username, passKeyCredentialId,
 * passKeyPublicKey, ephemeralAuthKey, ephemeralAuthKeyPq,
 * ephemeralExpiresAt }. A duplicate key column throws a unique violation
 * (db/transaction.js isUniqueViolation).
 */
export async function insertAnopod(client, row) {
  await client.query(
    `INSERT INTO anopods (anopod_id, first_name, last_name, username,
                          pass_key_credential_id, pass_key_public_key,
                          ephemeral_auth_key, ephemeral_auth_key_pq, ephemeral_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      row.anopodId,
      row.firstName,
      row.lastName,
      row.username,
      row.passKeyCredentialId,
      row.passKeyPublicKey,
      row.ephemeralAuthKey,
      row.ephemeralAuthKeyPq,
      row.ephemeralExpiresAt,
    ],
  );
}

/**
 * Opens a new session on `client`: replaces the pod's ephemeral keys
 * (`keys` is { ephemeralAuthKey, ephemeralAuthKeyPq }, Buffers) and sets
 * their expiry. The previous session stops verifying at once.
 */
export async function replaceEphemeralKeys(client, anopodId, keys, expiresAt) {
  await client.query(
    `UPDATE anopods
     SET ephemeral_auth_key = $2, ephemeral_auth_key_pq = $3, ephemeral_expires_at = $4
     WHERE anopod_id = $1`,
    [anopodId, keys.ephemeralAuthKey, keys.ephemeralAuthKeyPq, expiresAt],
  );
}

/**
 * Writes the eight setup columns on `client`. `fields` is { blob1, blob2,
 * backupCodePublicKey, backupCodePublicKeyPq, chatPublicKey,
 * chatPublicKeyPq, chatPrivateKeyBlob, identityBlob }, all Buffers.
 */
export async function completeSetup(client, anopodId, fields) {
  await client.query(
    `UPDATE anopods
     SET anopod_encryption_key_blob_1 = $2, anopod_encryption_key_blob_2 = $3,
         backup_code_public_key = $4, backup_code_public_key_pq = $5,
         chat_public_key = $6, chat_public_key_pq = $7, chat_private_key_blob = $8,
         identity_blob = $9
     WHERE anopod_id = $1`,
    [
      anopodId,
      fields.blob1,
      fields.blob2,
      fields.backupCodePublicKey,
      fields.backupCodePublicKeyPq,
      fields.chatPublicKey,
      fields.chatPublicKeyPq,
      fields.chatPrivateKeyBlob,
      fields.identityBlob,
    ],
  );
}

/**
 * The pod's rows in the security buckets, for /check-anopod-status:
 * { bucketOneImages, bucketTwoImages, bucketTwoInfos }, integers.
 */
export async function countBucketRows(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT
       (SELECT count(*) FROM security_images WHERE anopod_id = $1 AND type = 1)::int AS bucket_one_images,
       (SELECT count(*) FROM security_images WHERE anopod_id = $1 AND type = 2)::int AS bucket_two_images,
       (SELECT count(*) FROM security_info   WHERE anopod_id = $1 AND type = 2)::int AS bucket_two_infos`,
    [anopodId],
  );
  return {
    bucketOneImages: rows[0].bucket_one_images,
    bucketTwoImages: rows[0].bucket_two_images,
    bucketTwoInfos: rows[0].bucket_two_infos,
  };
}

/**
 * Marks the pod vouched on `client`. Returns true when this call flipped it,
 * false when it already was.
 */
export async function setVouched(client, anopodId) {
  const { rowCount } = await client.query(
    'UPDATE anopods SET vouched = true WHERE anopod_id = $1 AND vouched = false',
    [anopodId],
  );
  return rowCount === 1;
}

/** How many vouches rows name this pod as the one vouched for. */
export async function countVouches(anopodId, db = pool) {
  const { rows } = await db.query(
    'SELECT count(*)::int AS count FROM vouches WHERE anopod_id_vouched_for = $1',
    [anopodId],
  );
  return rows[0].count;
}

/** Whether the pod is in seeds and whether it is in super_seeds: { isSeed, isSuperSeed }. */
export async function seedStatus(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM seeds WHERE anopod_id = $1) AS is_seed,
            EXISTS (SELECT 1 FROM super_seeds WHERE anopod_id = $1) AS is_super_seed`,
    [anopodId],
  );
  return { isSeed: rows[0].is_seed, isSuperSeed: rows[0].is_super_seed };
}

/**
 * The profile of spec section 5 for a mapped row and its seedStatus:
 * { anopodId, username, firstName, lastName, vouched, isSeed, isSuperSeed }.
 */
export function profileOf(anopod, status) {
  return {
    anopodId: toHex(anopod.anopodId),
    username: anopod.username,
    firstName: anopod.firstName,
    lastName: anopod.lastName,
    vouched: anopod.vouched,
    isSeed: status.isSeed,
    isSuperSeed: status.isSuperSeed,
  };
}

/**
 * The SELECT list of a profile for an anopods row aliased `a`: the five
 * public columns and the two seed flags, each prefixed p_, so a list query
 * that shows the other party (vouch requests, invites, join requests, public
 * rooms, listings) joins anopods a and maps the row with profileFromRow.
 */
export const PROFILE_COLUMNS = `
       a.anopod_id AS p_anopod_id, a.username AS p_username,
       a.first_name AS p_first_name, a.last_name AS p_last_name, a.vouched AS p_vouched,
       EXISTS (SELECT 1 FROM seeds s WHERE s.anopod_id = a.anopod_id) AS p_is_seed,
       EXISTS (SELECT 1 FROM super_seeds ss WHERE ss.anopod_id = a.anopod_id) AS p_is_super_seed`;

/** The profile object from a row selected with PROFILE_COLUMNS. */
export function profileFromRow(row) {
  return {
    anopodId: toHex(row.p_anopod_id),
    username: row.p_username,
    firstName: row.p_first_name,
    lastName: row.p_last_name,
    vouched: row.p_vouched,
    isSeed: row.p_is_seed,
    isSuperSeed: row.p_is_super_seed,
  };
}

/**
 * The finish of a recovery on `client` (spec 12.4.2,
 * /recover-with-backup-code): the recovery passkey becomes the pod's
 * passkey, blob1 is replaced by the one the person made under that
 * passkey's KEK_prf, and the live session ends now, so the lost device's
 * keys stop verifying. `fields` is { passKeyCredentialId, passKeyPublicKey,
 * blob1 }, Buffers. A duplicate credential id or COSE key throws a unique
 * violation.
 */
export async function adoptRecoveryPasskey(client, anopodId, fields) {
  await client.query(
    `UPDATE anopods
     SET pass_key_credential_id = $2, pass_key_public_key = $3,
         anopod_encryption_key_blob_1 = $4, ephemeral_expires_at = now()
     WHERE anopod_id = $1`,
    [anopodId, fields.passKeyCredentialId, fields.passKeyPublicKey, fields.blob1],
  );
}

/**
 * A backup code rotation on `client` (spec 12.4.5, /rotate-backup-code):
 * replaces the three backup code columns with the new code's. `fields` is
 * { newBlob2, newBackupCodePublicKey, newBackupCodePublicKeyPq }, Buffers.
 * A duplicate key throws a unique violation.
 */
export async function replaceBackupCode(client, anopodId, fields) {
  await client.query(
    `UPDATE anopods
     SET anopod_encryption_key_blob_2 = $2, backup_code_public_key = $3, backup_code_public_key_pq = $4
     WHERE anopod_id = $1`,
    [anopodId, fields.newBlob2, fields.newBackupCodePublicKey, fields.newBackupCodePublicKeyPq],
  );
}
