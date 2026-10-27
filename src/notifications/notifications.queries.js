import { query } from '../db/pool.js';
import { randomId, toHex } from '../util/ids.js';

/**
 * SQL for the notifications table. Ids are 32-byte Buffers, matching the
 * BYTEA columns; pg sends a Buffer parameter as bytea.
 */

/**
 * Writes one notification for `anopodId` on `client`, inside the
 * transaction of the event it reports: `kind` is one of the ten kinds of
 * spec section 6, `referenceId` the thing it is about.
 */
export async function notify(client, anopodId, kind, referenceId) {
  await client.query(
    `INSERT INTO notifications (notification_number, anopod_id, kind, reference_id)
     VALUES ($1, $2, $3, $4)`,
    [randomId(), anopodId, kind, referenceId],
  );
}

/**
 * The newest `limit` notifications of `anopodId`, newest first, only the
 * unread ones when `unreadOnly`. Each in its wire form:
 * { notificationNumber, kind, referenceId, read, createdAt }.
 */
export async function listFor(anopodId, unreadOnly, limit) {
  const { rows } = await query(
    `SELECT notification_number, kind, reference_id, read_at, created_at
     FROM notifications
     WHERE anopod_id = $1 AND (NOT $2::boolean OR read_at IS NULL)
     ORDER BY created_at DESC, notification_number
     LIMIT $3`,
    [anopodId, unreadOnly, limit],
  );
  return rows.map((row) => ({
    notificationNumber: toHex(row.notification_number),
    kind: row.kind,
    referenceId: toHex(row.reference_id),
    read: row.read_at !== null,
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * Marks the given notifications of `anopodId` read, those that were unread.
 * `numbers` are 32-byte Buffers. Returns how many rows changed.
 */
export async function markRead(anopodId, numbers) {
  const { rowCount } = await query(
    `UPDATE notifications SET read_at = now()
     WHERE anopod_id = $1 AND notification_number = ANY($2::bytea[]) AND read_at IS NULL`,
    [anopodId, numbers],
  );
  return rowCount;
}
