import { pool } from '../db/pool.js';

/**
 * SQL for the added_passkeys table (spec section 19): the passkeys a pod
 * added after its first one. Ids, keys and blobs are Buffers of raw bytes,
 * matching the BYTEA columns; pg sends a Buffer parameter as bytea.
 *
 * Reads take an optional `db` (a client inside a transaction; the pool by
 * default). Writes take the transaction's client first.
 */

/** An added_passkeys row in camelCase. Byte columns stay Buffers. */
function addedPasskeyRow(row) {
  return {
    passkeyId: row.passkey_id,
    anopodId: row.anopod_id,
    passKeyCredentialId: row.pass_key_credential_id,
    passKeyPublicKey: row.pass_key_public_key,
    encryptionKeyBlob1: row.anopod_encryption_key_blob_1,
    wrappedKeyBlobKey: row.wrapped_key_blob_key,
    createdAt: row.created_at,
  };
}

const COLUMNS = 'passkey_id, anopod_id, pass_key_credential_id, pass_key_public_key, anopod_encryption_key_blob_1, wrapped_key_blob_key, created_at';

/** The row of the added passkey with this credential id (a Buffer), or null. */
export async function findAddedByCredentialId(credentialId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM added_passkeys WHERE pass_key_credential_id = $1`, [credentialId]);
  return rows.length === 0 ? null : addedPasskeyRow(rows[0]);
}

/** The pod's added passkeys, oldest first. */
export async function listAdded(anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT ${COLUMNS} FROM added_passkeys WHERE anopod_id = $1 ORDER BY created_at, passkey_id`,
    [anopodId],
  );
  return rows.map(addedPasskeyRow);
}

/**
 * Inserts one added passkey on `client`. `row` is { passkeyId, anopodId,
 * passKeyCredentialId, passKeyPublicKey, encryptionKeyBlob1,
 * wrappedKeyBlobKey }, all Buffers. Returns the row's created_at Date. A
 * duplicate credential id or COSE key throws a unique violation
 * (db/transaction.js isUniqueViolation).
 */
export async function insertAdded(client, row) {
  const { rows } = await client.query(
    `INSERT INTO added_passkeys (passkey_id, anopod_id, pass_key_credential_id, pass_key_public_key,
                                 anopod_encryption_key_blob_1, wrapped_key_blob_key)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING created_at`,
    [
      row.passkeyId,
      row.anopodId,
      row.passKeyCredentialId,
      row.passKeyPublicKey,
      row.encryptionKeyBlob1,
      row.wrappedKeyBlobKey,
    ],
  );
  return rows[0].created_at;
}

/**
 * Deletes every added passkey of this pod on `client`: the finish of a
 * recovery (spec 19.3, /recover-with-backup-code). Returns how many rows
 * went.
 */
export async function deleteAddedOf(client, anopodId) {
  const { rowCount } = await client.query('DELETE FROM added_passkeys WHERE anopod_id = $1', [anopodId]);
  return rowCount;
}
