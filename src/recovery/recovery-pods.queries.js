import { pool } from '../db/pool.js';

/**
 * SQL for the recovery_pods table (spec 12.3): one per case, keyed like the
 * case. The recovery passkey, the recovery session's ephemeral keys, the
 * hybrid public key and the wrapped private halves. Byte columns are
 * Buffers. Reads take an optional `db`; writes take the client first.
 */

const COLUMNS = `case_id, anopod_id, pass_key_credential_id, pass_key_public_key,
       ephemeral_auth_key, ephemeral_auth_key_pq, ephemeral_expires_at,
       hybrid_key_x25519, hybrid_key_mlkem, hybrid_key_blob, created_at, updated_at`;

/** A recovery_pods row in camelCase, as requireRecoverySession puts it on req.recoveryPod. */
export function podRow(row) {
  return {
    caseId: row.case_id,
    anopodId: row.anopod_id,
    passKeyCredentialId: row.pass_key_credential_id,
    passKeyPublicKey: row.pass_key_public_key,
    ephemeralAuthKey: row.ephemeral_auth_key,
    ephemeralAuthKeyPq: row.ephemeral_auth_key_pq,
    ephemeralExpiresAt: row.ephemeral_expires_at,
    hybridKeyX25519: row.hybrid_key_x25519,
    hybridKeyMlkem: row.hybrid_key_mlkem,
    hybridKeyBlob: row.hybrid_key_blob,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function findOne(where, params, db) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM recovery_pods WHERE ${where}`, params);
  return rows.length === 0 ? null : podRow(rows[0]);
}

/** The recovery pod of this case (a 32-byte Buffer), or null. */
export function findByCaseId(caseId, db = pool) {
  return findOne('case_id = $1', [caseId], db);
}

/** The recovery pod whose passkey has this credential id (a Buffer), or null. */
export function findByCredentialId(credentialId, db = pool) {
  return findOne('pass_key_credential_id = $1', [credentialId], db);
}

/**
 * Inserts a recovery pod on `client`, with the case. `row` is { caseId,
 * anopodId, passKeyCredentialId, passKeyPublicKey, ephemeralAuthKey,
 * ephemeralAuthKeyPq, ephemeralExpiresAt, hybridKeyX25519, hybridKeyMlkem,
 * hybridKeyBlob }. A duplicate key column throws a unique violation.
 */
export async function insertPod(client, row) {
  await client.query(
    `INSERT INTO recovery_pods (case_id, anopod_id, pass_key_credential_id, pass_key_public_key,
                                ephemeral_auth_key, ephemeral_auth_key_pq, ephemeral_expires_at,
                                hybrid_key_x25519, hybrid_key_mlkem, hybrid_key_blob)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      row.caseId,
      row.anopodId,
      row.passKeyCredentialId,
      row.passKeyPublicKey,
      row.ephemeralAuthKey,
      row.ephemeralAuthKeyPq,
      row.ephemeralExpiresAt,
      row.hybridKeyX25519,
      row.hybridKeyMlkem,
      row.hybridKeyBlob,
    ],
  );
}

/**
 * Opens a new recovery session on `client`: replaces the pod's ephemeral
 * keys (`keys` is { ephemeralAuthKey, ephemeralAuthKeyPq }, Buffers) and
 * sets their expiry. The previous recovery session stops verifying at once.
 */
export async function replaceEphemeralKeys(client, caseId, keys, expiresAt) {
  await client.query(
    `UPDATE recovery_pods
     SET ephemeral_auth_key = $2, ephemeral_auth_key_pq = $3, ephemeral_expires_at = $4
     WHERE case_id = $1`,
    [caseId, keys.ephemeralAuthKey, keys.ephemeralAuthKeyPq, expiresAt],
  );
}
