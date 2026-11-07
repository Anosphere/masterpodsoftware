import { pool, query } from '../db/pool.js';

/**
 * SQL for the noted_transactions table (wallet spec 4.6). Ids and the blob
 * are Buffers of raw bytes, matching the BYTEA columns; pg sends a Buffer
 * parameter as bytea. position and amount are BIGINTs, which pg hands over
 * as decimal strings so nothing is lost; transacted_at is a TIMESTAMPTZ, a
 * Date on the way out.
 */

/** A noted_transactions row in camelCase. Byte columns stay Buffers. */
function noteRow(row) {
  return {
    noteId: row.note_id,
    anopodId: row.anopod_id,
    transactionId: row.transaction_id,
    accountId: row.account_id,
    otherAccountId: row.other_account_id,
    position: row.position,
    transactedAt: row.transacted_at,
    amount: row.amount,
    sent: row.sent,
    noteBlob: row.note_blob,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const COLUMNS = 'note_id, anopod_id, transaction_id, account_id, other_account_id, position, transacted_at, amount, sent, note_blob, created_at, updated_at';

/** The row with this note id and this pod (32-byte Buffers), or null. */
export async function findNote(noteId, anopodId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM noted_transactions WHERE note_id = $1 AND anopod_id = $2`, [noteId, anopodId]);
  return rows.length === 0 ? null : noteRow(rows[0]);
}

/** The pod's row for this transaction, or null. */
export async function findNoteByTransaction(anopodId, transactionId, db = pool) {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM noted_transactions WHERE anopod_id = $1 AND transaction_id = $2`, [anopodId, transactionId]);
  return rows.length === 0 ? null : noteRow(rows[0]);
}

/**
 * Inserts one note: { noteId, anopodId, transactionId, accountId,
 * otherAccountId, position, transactedAt, amount, sent, noteBlob };
 * transactedAt an ISO string pg casts to the column, amount a decimal
 * string cast to BIGINT. A second note of the pod on the same transaction
 * throws a unique violation (db/transaction.js isUniqueViolation).
 */
export async function insertNote({ noteId, anopodId, transactionId, accountId, otherAccountId, position, transactedAt, amount, sent, noteBlob }) {
  await query(
    `INSERT INTO noted_transactions (note_id, anopod_id, transaction_id, account_id, other_account_id, position, transacted_at, amount, sent, note_blob)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [noteId, anopodId, transactionId, accountId, otherAccountId, position, transactedAt, amount, sent, noteBlob],
  );
}

/**
 * Replaces the private part of this pod's note; the ledger facts never
 * change. Returns the row's updated_at Date, or null when the row is not
 * this pod's or does not exist.
 */
export async function updateNoteBlob(noteId, anopodId, noteBlob) {
  const { rows } = await query(
    `UPDATE noted_transactions SET note_blob = $3 WHERE note_id = $1 AND anopod_id = $2 RETURNING updated_at`,
    [noteId, anopodId, noteBlob],
  );
  return rows.length === 0 ? null : rows[0].updated_at;
}

/** Deletes this pod's note. True when a row went, false when there was none of the pod's. */
export async function deleteNote(noteId, anopodId) {
  const { rowCount } = await query('DELETE FROM noted_transactions WHERE note_id = $1 AND anopod_id = $2', [noteId, anopodId]);
  return rowCount === 1;
}

/**
 * The pod's notes with transacted_at at or after `from` and before `to`
 * (ISO strings, either null for no bound), newest transacted_at first and
 * the highest position first within a moment, `limit` rows at most. The
 * bounds are typed in the SQL, as the listings query types its filters.
 */
export async function listNotes(anopodId, from, to, limit) {
  const { rows } = await query(
    `SELECT ${COLUMNS} FROM noted_transactions
     WHERE anopod_id = $1
       AND ($2::timestamptz IS NULL OR transacted_at >= $2)
       AND ($3::timestamptz IS NULL OR transacted_at < $3)
     ORDER BY transacted_at DESC, position DESC
     LIMIT $4`,
    [anopodId, from, to, limit],
  );
  return rows.map(noteRow);
}
