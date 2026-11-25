import { query } from '../db/pool.js';
import { randomId, toHex } from '../util/ids.js';

/**
 * SQL for the notifications table. Ids are 32-byte Buffers, matching the
 * BYTEA columns; pg sends a Buffer parameter as bytea.
 */

/**
 * Writes one notification for `anopodId` on `client`, inside the
 * transaction of the event it reports: `kind` is one of the twenty-one kinds
 * of spec section 6, `referenceId` the thing it is about.
 */
export async function notify(client, anopodId, kind, referenceId) {
  await client.query(
    `INSERT INTO notifications (notification_number, anopod_id, kind, reference_id)
     VALUES ($1, $2, $3, $4)`,
    [randomId(), anopodId, kind, referenceId],
  );
}

/**
 * The three numbers of `anopodId` that every answer of /list-notifications
 * carries (2026-11-25, spec section 34): { seq, count, unread }. `seq` is
 * the highest `seq` of the pod's rows, 0 when it has none, and never the
 * counter's own value; `count` is how many notifications the pod has, and
 * `unread` how many of them are unread. One statement, so the three are
 * the pod's rows at one moment.
 */
export async function numbersFor(anopodId) {
  const { rows } = await query(
    `SELECT coalesce(max(seq), 0) AS seq, count(*) AS count, count(*) FILTER (WHERE read_at IS NULL) AS unread
     FROM notifications
     WHERE anopod_id = $1`,
    [anopodId],
  );
  return { seq: Number(rows[0].seq), count: Number(rows[0].count), unread: Number(rows[0].unread) };
}

/**
 * At most `limit` notifications of `anopodId` in the order of `seq`, the
 * highest first, only the unread ones when `unreadOnly`, and none with a
 * `seq` above `highest`, the `seq` that numbersFor read before. `since`,
 * `before` and `kinds` are null, or keep only the rows with a `seq` above
 * `since`, with a `seq` below `before`, and of one of the `kinds`
 * (2026-11-25, spec section 34). For the rows of before that day the order
 * of `seq` is the order of before, created_at DESC and then the id. Each
 * in its wire form:
 * { notificationNumber, kind, referenceId, read, createdAt, seq }.
 */
export async function listFor(anopodId, { unreadOnly, limit, highest, since, before, kinds }) {
  const { rows } = await query(
    `SELECT notification_number, kind, reference_id, read_at, created_at, seq
     FROM notifications
     WHERE anopod_id = $1 AND seq <= $2 AND (NOT $3::boolean OR read_at IS NULL)
       AND ($4::bigint IS NULL OR seq > $4::bigint)
       AND ($5::bigint IS NULL OR seq < $5::bigint)
       AND ($6::text[] IS NULL OR kind = ANY($6::text[]))
     ORDER BY seq DESC
     LIMIT $7`,
    [anopodId, highest, unreadOnly, since, before, kinds, limit],
  );
  return rows.map((row) => ({
    notificationNumber: toHex(row.notification_number),
    kind: row.kind,
    referenceId: toHex(row.reference_id),
    read: row.read_at !== null,
    createdAt: row.created_at.toISOString(),
    seq: Number(row.seq),
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

/**
 * Marks every unread notification of `anopodId` read whose `seq` is `upTo`
 * or lower (2026-11-25, spec section 34). Returns how many rows changed.
 */
export async function markReadUpTo(anopodId, upTo) {
  const { rowCount } = await query(
    `UPDATE notifications SET read_at = now()
     WHERE anopod_id = $1 AND seq <= $2 AND read_at IS NULL`,
    [anopodId, upTo],
  );
  return rowCount;
}
