import { PROFILE_COLUMNS, profileFromRow } from '../anopods/anopods.queries.js';
import { pool } from '../db/pool.js';
import { trimDecimal } from '../marketplace/listings.queries.js';
import { toHex } from '../util/ids.js';
import { encodeImage } from '../util/images.js';

/**
 * SQL for the chat tables: chat_rooms, chat_room_pictures (since
 * 2026-11-22), chat_room_members with chat_hpke, chat_room_invites,
 * chat_room_join_requests and chat_room_messages. Ids and keys are
 * Buffers, matching the BYTEA columns. Reads take an optional `db` (a
 * client inside a transaction; the pool by default); writes take the
 * transaction's client first.
 */

// ---------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------

/**
 * Writes a room on `client`: `name` is null unless `type` is 'public';
 * `listingId` is the listing a private room is about, null when absent;
 * `caseId` and `caseKind` are the attestor case a private room is about
 * and its kind ('trade', 'dispute' or 'recovery'), both null when absent.
 */
export async function insertRoom(
  client,
  { chatRoomId, creatorAnopodId, type, name, listingId = null, caseId = null, caseKind = null },
) {
  await client.query(
    `INSERT INTO chat_rooms (chat_room_id, creator_anopod_id, type, name, listing_id, case_id, case_kind)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [chatRoomId, creatorAnopodId, type, name, listingId, caseId, caseKind],
  );
}

/** The room with this id, as { chatRoomId, creatorAnopodId, type, name, listingId, caseId, caseKind, createdAt }, or null. */
export async function findRoom(chatRoomId, db = pool) {
  const { rows } = await db.query(
    `SELECT chat_room_id, creator_anopod_id, type, name, listing_id, case_id, case_kind, created_at
     FROM chat_rooms WHERE chat_room_id = $1`,
    [chatRoomId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    chatRoomId: row.chat_room_id,
    creatorAnopodId: row.creator_anopod_id,
    type: row.type,
    name: row.name,
    listingId: row.listing_id,
    caseId: row.case_id,
    caseKind: row.case_kind,
    createdAt: row.created_at,
  };
}

/**
 * The room `creatorAnopodId` created about this listing (its listing_id),
 * in findRoom's form, or null: whether the person has connected with the
 * listing already.
 */
export async function roomAboutListingBy(listingId, creatorAnopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT chat_room_id, creator_anopod_id, type, name, listing_id, created_at
     FROM chat_rooms
     WHERE listing_id = $1 AND creator_anopod_id = $2
     ORDER BY created_at, chat_room_id
     LIMIT 1`,
    [listingId, creatorAnopodId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    chatRoomId: row.chat_room_id,
    creatorAnopodId: row.creator_anopod_id,
    type: row.type,
    name: row.name,
    listingId: row.listing_id,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// Room pictures
// ---------------------------------------------------------------------------

/**
 * Writes a public room's picture on `client` (2026-11-22, spec section 27):
 * its first one, or another in place of the one it has. Returns when the
 * row last changed, which the room lists hand out as pictureAt.
 */
export async function upsertRoomPicture(client, chatRoomId, contentType, bytes) {
  const { rows } = await client.query(
    `INSERT INTO chat_room_pictures (chat_room_id, content_type, image) VALUES ($1, $2, $3)
     ON CONFLICT (chat_room_id) DO UPDATE SET content_type = EXCLUDED.content_type, image = EXCLUDED.image
     RETURNING updated_at`,
    [chatRoomId, contentType, bytes],
  );
  return rows[0].updated_at;
}

/** A room's picture as { picture: { contentType, image }, pictureAt }, or null when it has none (2026-11-22, spec section 27). */
export async function findRoomPicture(chatRoomId, db = pool) {
  const { rows } = await db.query(
    'SELECT content_type, image, updated_at FROM chat_room_pictures WHERE chat_room_id = $1',
    [chatRoomId],
  );
  return rows.length === 0 ? null : { picture: encodeImage(rows[0]), pictureAt: rows[0].updated_at.toISOString() };
}

// ---------------------------------------------------------------------------
// Members and their wrapped keys. A member row and its chat_hpke row are
// always written and deleted together, so both tables are touched here only.
// ---------------------------------------------------------------------------

/** Adds `anopodId` to the room on `client`, with `hpkeKey`, the room key wrapped to it. */
export async function insertMember(client, chatRoomId, anopodId, hpkeKey) {
  await client.query('INSERT INTO chat_room_members (chat_room_id, anopod_id) VALUES ($1, $2)', [
    chatRoomId,
    anopodId,
  ]);
  await client.query('INSERT INTO chat_hpke (chat_room_id, anopod_id, hpke_key) VALUES ($1, $2, $3)', [
    chatRoomId,
    anopodId,
    hpkeKey,
  ]);
}

/** Removes `anopodId` from the room on `client`: the member row and its wrapped key. */
export async function deleteMember(client, chatRoomId, anopodId) {
  await client.query('DELETE FROM chat_hpke WHERE chat_room_id = $1 AND anopod_id = $2', [chatRoomId, anopodId]);
  await client.query('DELETE FROM chat_room_members WHERE chat_room_id = $1 AND anopod_id = $2', [
    chatRoomId,
    anopodId,
  ]);
}

/** True when `anopodId` is in the room. */
export async function isMember(chatRoomId, anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM chat_room_members WHERE chat_room_id = $1 AND anopod_id = $2) AS member`,
    [chatRoomId, anopodId],
  );
  return rows[0].member;
}

/**
 * Raises `anopodId`'s seen position in the room on `client` to
 * `position`, never above the room's newest message and never below
 * what the row holds, and returns what the row holds afterwards, as a
 * number; null when `anopodId` is not in the room. The room's newest
 * message here is its newest row: since spec section 31 that can be an
 * edit or a delete of a message.
 */
export async function raiseSeenPosition(client, chatRoomId, anopodId, position) {
  const { rows } = await client.query(
    `UPDATE chat_room_members
        SET seen_position = GREATEST(seen_position,
                                     LEAST($3::bigint,
                                           (SELECT COALESCE(max(position), 0)
                                              FROM chat_room_messages
                                             WHERE chat_room_id = $1)))
      WHERE chat_room_id = $1 AND anopod_id = $2
      RETURNING seen_position`,
    [chatRoomId, anopodId, position],
  );
  return rows.length === 0 ? null : Number(rows[0].seen_position);
}

/** The highest message position in the room, 0 when it has none. */
export async function lastPosition(chatRoomId, db = pool) {
  const { rows } = await db.query(
    'SELECT COALESCE(max(position), 0) AS last FROM chat_room_messages WHERE chat_room_id = $1',
    [chatRoomId],
  );
  return Number(rows[0].last);
}

/**
 * The seen positions of the room that changed after `seenSince`
 * (2026-11-24, spec section 29): { seen, seenSeq }. `seen` is the members
 * whose seen_seq is above `seenSince`, in the order of a room's members,
 * each as { anopodId, seenPosition }. `seenSeq` is the highest seen_seq of
 * the room's members, 0 when no member has seen anything: what a wallet
 * sends as its next `seenSince`. One statement reads both, so they are the
 * room at one moment. With `seenSince` 0 it is every member who has seen
 * anything.
 */
export async function listSeenSince(chatRoomId, seenSince) {
  const { rows } = await pool.query(
    `SELECT m.anopod_id, m.seen_position, t.seen_seq
     FROM (SELECT COALESCE(max(seen_seq), 0) AS seen_seq
             FROM chat_room_members
            WHERE chat_room_id = $1) t
     LEFT JOIN chat_room_members m ON m.chat_room_id = $1 AND m.seen_seq > $2::bigint
     ORDER BY m.created_at, m.anopod_id`,
    [chatRoomId, seenSince],
  );
  return {
    seen: rows
      .filter((row) => row.anopod_id !== null)
      .map((row) => ({ anopodId: toHex(row.anopod_id), seenPosition: Number(row.seen_position) })),
    seenSeq: Number(rows[0].seen_seq),
  };
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

/** Writes an open invite on `client`, carrying the room key wrapped to the invitee. */
export async function insertInvite(client, { inviteId, chatRoomId, anopodIdFrom, anopodIdTo, hpkeKey }) {
  await client.query(
    `INSERT INTO chat_room_invites (invite_id, chat_room_id, anopod_id_from, anopod_id_to, hpke_key)
     VALUES ($1, $2, $3, $4, $5)`,
    [inviteId, chatRoomId, anopodIdFrom, anopodIdTo, hpkeKey],
  );
}

/** The open invite with this id, with its wrapped key, or null. */
export async function findInvite(inviteId, db = pool) {
  const { rows } = await db.query(
    `SELECT invite_id, chat_room_id, anopod_id_from, anopod_id_to, hpke_key, created_at
     FROM chat_room_invites WHERE invite_id = $1`,
    [inviteId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    inviteId: row.invite_id,
    chatRoomId: row.chat_room_id,
    anopodIdFrom: row.anopod_id_from,
    anopodIdTo: row.anopod_id_to,
    hpkeKey: row.hpke_key,
    createdAt: row.created_at,
  };
}

/** True when `anopodIdTo` already has an open invite to the room. */
export async function inviteOpen(chatRoomId, anopodIdTo, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM chat_room_invites WHERE chat_room_id = $1 AND anopod_id_to = $2) AS open`,
    [chatRoomId, anopodIdTo],
  );
  return rows[0].open;
}

/** Deletes the invite on `client`: accept and decline both end here. */
export async function deleteInvite(client, inviteId) {
  await client.query('DELETE FROM chat_room_invites WHERE invite_id = $1', [inviteId]);
}

// ---------------------------------------------------------------------------
// Join requests
// ---------------------------------------------------------------------------

/** Writes an open join request on `client`. */
export async function insertJoinRequest(client, { joinRequestId, chatRoomId, anopodId }) {
  await client.query(
    `INSERT INTO chat_room_join_requests (join_request_id, chat_room_id, anopod_id) VALUES ($1, $2, $3)`,
    [joinRequestId, chatRoomId, anopodId],
  );
}

/** The open join request with this id, as { joinRequestId, chatRoomId, anopodId, createdAt }, or null. */
export async function findJoinRequest(joinRequestId, db = pool) {
  const { rows } = await db.query(
    `SELECT join_request_id, chat_room_id, anopod_id, created_at
     FROM chat_room_join_requests WHERE join_request_id = $1`,
    [joinRequestId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    joinRequestId: row.join_request_id,
    chatRoomId: row.chat_room_id,
    anopodId: row.anopod_id,
    createdAt: row.created_at,
  };
}

/** True when `anopodId` already has an open join request on the room. */
export async function joinRequestOpen(chatRoomId, anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM chat_room_join_requests WHERE chat_room_id = $1 AND anopod_id = $2) AS open`,
    [chatRoomId, anopodId],
  );
  return rows[0].open;
}

/** Deletes the join request on `client`: approve and decline both end here. */
export async function deleteJoinRequest(client, joinRequestId) {
  await client.query('DELETE FROM chat_room_join_requests WHERE join_request_id = $1', [joinRequestId]);
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/** Writes a message on `client` and returns its position, as a number. */
export async function insertMessage(client, { messageId, chatRoomId, senderAnopodId, message }) {
  const { rows } = await client.query(
    `INSERT INTO chat_room_messages (message_id, chat_room_id, sender_anopod_id, message)
     VALUES ($1, $2, $3, $4)
     RETURNING position`,
    [messageId, chatRoomId, senderAnopodId, message],
  );
  return Number(rows[0].position);
}

/**
 * The message `messageId` of the room, locked for the rest of the
 * transaction on `client` (SELECT ... FOR UPDATE), or null (2026-11-24,
 * spec section 31): { senderAnopodId, editTimeOver }. Only a message is
 * found, a row with no kind: an edit and a delete are not. `editTimeOver`
 * is true when the database's clock, the one that stamped the message's
 * created_at, is more than `editMinutes` minutes past it. /edit-message
 * and /delete-message lock the message before they look for a delete of
 * it, so two requests about one message go one after the other.
 */
export async function lockMessage(client, chatRoomId, messageId, editMinutes) {
  const { rows } = await client.query(
    `SELECT sender_anopod_id, now() > created_at + make_interval(mins => $3::int) AS edit_time_over
     FROM chat_room_messages
     WHERE message_id = $2 AND chat_room_id = $1 AND kind IS NULL
     FOR UPDATE`,
    [chatRoomId, messageId, editMinutes],
  );
  return rows.length === 0 ? null : { senderAnopodId: rows[0].sender_anopod_id, editTimeOver: rows[0].edit_time_over };
}

/** True when a delete of the room names the message `messageId` (2026-11-24, spec section 31). */
export async function messageDeleted(chatRoomId, messageId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM chat_room_messages
                     WHERE target_message_id = $2 AND chat_room_id = $1 AND kind = 'delete') AS deleted`,
    [chatRoomId, messageId],
  );
  return rows[0].deleted;
}

/**
 * Writes an edit or a delete of a message on `client` and returns its
 * position, as a number (2026-11-24, spec section 31). It is a row of its
 * own: `kind` is 'edit' or 'delete', `targetMessageId` the message it is
 * about, and `message` the new text's ciphertext for an edit and null for
 * a delete. The message's own row is not changed.
 */
export async function insertMessageChange(
  client,
  { messageId, chatRoomId, senderAnopodId, kind, targetMessageId, message },
) {
  const { rows } = await client.query(
    `INSERT INTO chat_room_messages (message_id, chat_room_id, sender_anopod_id, message, kind, target_message_id)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING position`,
    [messageId, chatRoomId, senderAnopodId, message, kind, targetMessageId],
  );
  return Number(rows[0].position);
}

/**
 * The columns of a row of a room, read from chat_room_messages as `m`, and
 * the wire form they make: { messageId, position, senderAnopodId, message,
 * createdAt, kind, targetMessageId }. `kind` and `targetMessageId` are
 * there since 2026-11-24 (spec section 31): `kind` is null on a message and
 * 'edit' or 'delete' on a row about one, and `targetMessageId` is the
 * message such a row is about, null on a message. `message` is the
 * ciphertext base64, or null: a row goes out without it once a later row
 * of the room names the same message (a message is named by its own id, an
 * edit and a delete name their target), and a delete has none.
 */
const MESSAGE_ROW_COLUMNS = `m.message_id, m.position, m.sender_anopod_id, m.created_at, m.kind, m.target_message_id,
            CASE WHEN EXISTS (SELECT 1 FROM chat_room_messages later
                               WHERE later.target_message_id = COALESCE(m.target_message_id, m.message_id)
                                 AND later.chat_room_id = m.chat_room_id
                                 AND later.position > m.position)
                 THEN NULL ELSE m.message END AS message`;

function messageFromRow(row) {
  return {
    messageId: toHex(row.message_id),
    position: Number(row.position),
    senderAnopodId: toHex(row.sender_anopod_id),
    message: row.message === null ? null : row.message.toString('base64'),
    createdAt: row.created_at.toISOString(),
    kind: row.kind,
    targetMessageId: toHex(row.target_message_id),
  };
}

/**
 * The room's rows after `afterPosition`, ascending, at most `limit`, each
 * in the wire form of messageFromRow: the messages and, since 2026-11-24
 * (spec section 31), the edits and the deletes.
 */
export async function listMessages(chatRoomId, afterPosition, limit) {
  const { rows } = await pool.query(
    `SELECT ${MESSAGE_ROW_COLUMNS}
     FROM chat_room_messages m
     WHERE m.chat_room_id = $1 AND m.position > $2
     ORDER BY m.position
     LIMIT $3`,
    [chatRoomId, afterPosition, limit],
  );
  return rows.map(messageFromRow);
}

/**
 * The room's newest rows below `beforePosition`, at most `limit`, in
 * ascending order, each in the wire form of listMessages: how a room opens
 * at its newest messages and loads older ones.
 */
export async function listMessagesBefore(chatRoomId, beforePosition, limit) {
  const { rows } = await pool.query(
    `SELECT ${MESSAGE_ROW_COLUMNS}
     FROM chat_room_messages m
     WHERE m.chat_room_id = $1 AND m.position < $2
     ORDER BY m.position DESC
     LIMIT $3`,
    [chatRoomId, beforePosition, limit],
  );
  return rows.reverse().map(messageFromRow);
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

/**
 * The columns of the listing a room is about, joined as `l` with its owner
 * as `la`, and the listing object they make: { listingId, side, quantity,
 * currency, country, price, status, owner: { anopodId, username } }, the
 * quantity a decimal string of millionths and the price a decimal string
 * without trailing zeros, as /list-listings gives them; null for a room
 * without a listing.
 */
const ROOM_LISTING_COLUMNS = `l.side, l.quantity, l.currency, l.country, l.price, l.status,
            l.anopod_id AS owner_anopod_id, la.username AS owner_username`;

function listingFromRow(row) {
  if (row.listing_id === null) return null;
  return {
    listingId: toHex(row.listing_id),
    side: row.side,
    quantity: row.quantity,
    currency: row.currency,
    country: row.country,
    price: trimDecimal(row.price),
    status: row.status,
    owner: { anopodId: toHex(row.owner_anopod_id), username: row.owner_username },
  };
}

/**
 * The columns and the joins that make a room's `lastMessage` and
 * `lastPosition`, for a statement that has the room's member row as `cm`,
 * and the object they make (2026-11-24, spec section 31; until then
 * `lastMessage` was the room's newest row). `lastMessage` is the room's
 * newest message as it stands now, never an edit or a delete: { messageId,
 * position, senderAnopodId, message, createdAt, editPosition, deleted },
 * null for a room without a message. The first three and `createdAt` are
 * the message's own. `message` is the ciphertext base64 of the newest edit
 * when the message was edited, its own when it was not, and null when it
 * was deleted. `editPosition` is the position of the newest edit, null for
 * a message that was never edited; `deleted` is true when a delete names
 * it. `last_position` is the highest position of any row of the room, null
 * when it has none: listRoomsFor and listNewestMessagesFor hand it out as
 * `lastPosition`.
 */
const LAST_MESSAGE_COLUMNS = `lm.message_id AS last_message_id, lm.position AS last_message_position,
            lm.sender_anopod_id AS last_sender_anopod_id, lm.created_at AS last_created_at,
            CASE WHEN ld.deleted THEN NULL ELSE COALESCE(le.message, lm.message) END AS last_message,
            le.position AS last_edit_position, ld.deleted AS last_deleted, hp.position AS last_position`;

const LAST_MESSAGE_JOINS = `LEFT JOIN LATERAL (SELECT max(any_row.position) AS position
                          FROM chat_room_messages any_row
                         WHERE any_row.chat_room_id = cm.chat_room_id) hp ON true
     LEFT JOIN LATERAL (SELECT msg.message_id, msg.position, msg.sender_anopod_id, msg.message, msg.created_at
                          FROM chat_room_messages msg
                         WHERE msg.chat_room_id = cm.chat_room_id AND msg.kind IS NULL
                         ORDER BY msg.position DESC
                         LIMIT 1) lm ON true
     LEFT JOIN LATERAL (SELECT edit.position, edit.message
                          FROM chat_room_messages edit
                         WHERE edit.target_message_id = lm.message_id
                           AND edit.chat_room_id = cm.chat_room_id AND edit.kind = 'edit'
                         ORDER BY edit.position DESC
                         LIMIT 1) le ON true
     LEFT JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM chat_room_messages del
                                        WHERE del.target_message_id = lm.message_id
                                          AND del.chat_room_id = cm.chat_room_id AND del.kind = 'delete') AS deleted) ld ON true`;

function lastMessageFromRow(row) {
  if (row.last_message_id === null) return null;
  return {
    messageId: toHex(row.last_message_id),
    position: Number(row.last_message_position),
    senderAnopodId: toHex(row.last_sender_anopod_id),
    message: row.last_message === null ? null : row.last_message.toString('base64'),
    createdAt: row.last_created_at.toISOString(),
    editPosition: row.last_edit_position === null ? null : Number(row.last_edit_position),
    deleted: row.last_deleted,
  };
}

/**
 * The change numbers of everything in `anopodId`'s chat list (2026-11-24,
 * spec section 29), read by one statement, so they are the list at one
 * moment: { rooms, invites, joinRequests }. `rooms` is the rooms the pod is
 * a member of, in the order of listRoomsFor, each as { chatRoomId,
 * messageSeq, peopleSeq }; `invites` the open invites to the pod, each as
 * { inviteId, changeSeq }; `joinRequests` the open join requests on rooms
 * the pod created, each as { joinRequestId, changeSeq }. The ids are
 * Buffers and the numbers are numbers. Each of the three selects has the
 * joins of its list (listRoomsFor, listInvitesFor,
 * listJoinRequestsForCreator), so it counts the rows that list hands out.
 */
export async function listChangeNumbersFor(anopodId) {
  const { rows } = await pool.query(
    `SELECT n.kind, n.id, n.message_seq, n.people_seq, n.change_seq
     FROM (SELECT 'room' AS kind, r.chat_room_id AS id, r.message_seq, r.people_seq, 0::bigint AS change_seq, r.created_at
             FROM chat_room_members cm
             JOIN chat_rooms r ON r.chat_room_id = cm.chat_room_id
             JOIN chat_hpke h ON h.chat_room_id = cm.chat_room_id AND h.anopod_id = cm.anopod_id
            WHERE cm.anopod_id = $1
           UNION ALL
           SELECT 'invite', i.invite_id, 0, 0, i.change_seq, i.created_at
             FROM chat_room_invites i
             JOIN chat_rooms r ON r.chat_room_id = i.chat_room_id
             JOIN anopods a ON a.anopod_id = i.anopod_id_from
            WHERE i.anopod_id_to = $1
           UNION ALL
           SELECT 'joinRequest', j.join_request_id, 0, 0, j.change_seq, j.created_at
             FROM chat_room_join_requests j
             JOIN chat_rooms r ON r.chat_room_id = j.chat_room_id
             JOIN anopods a ON a.anopod_id = j.anopod_id
            WHERE r.creator_anopod_id = $1) n
     ORDER BY n.kind, n.created_at DESC, n.id`,
    [anopodId],
  );
  const ofKind = (kind) => rows.filter((row) => row.kind === kind);
  return {
    rooms: ofKind('room').map((row) => ({
      chatRoomId: row.id,
      messageSeq: Number(row.message_seq),
      peopleSeq: Number(row.people_seq),
    })),
    invites: ofKind('invite').map((row) => ({ inviteId: row.id, changeSeq: Number(row.change_seq) })),
    joinRequests: ofKind('joinRequest').map((row) => ({ joinRequestId: row.id, changeSeq: Number(row.change_seq) })),
  };
}

/**
 * The rooms `anopodId` is a member of, newest first, each with the caller's
 * own wrapped key, the members (id, username and, since 2026-11-19,
 * `seenPosition`), the people invited who have not answered yet (oldest
 * first), the newest message as it stands now (lastMessageFromRow; null
 * when the room has none; since 2026-11-24, spec section 31, never an edit
 * or a delete) with the highest position of any row of the room as
 * lastPosition (0 when none)
 * and, for a room about a listing
 * (chat_rooms.listing_id: a private room made with a listingId, or an old
 * marketplace room), its listing id and the listing as listingFromRow
 * gives it, and, for a room about an attestor case (chat_rooms.case_id: a
 * private room made with a caseId), the case's id and its kind ('trade',
 * 'dispute' or 'recovery'), both null on any other room: { chatRoomId,
 * type, name, pictureAt, listingId, listing, caseId, caseKind,
 * creatorAnopodId, hpkeKey, members, invited, lastMessage, lastPosition,
 * createdAt }. `pictureAt` is when the room's picture was last set, null
 * for a room without one (2026-11-22). `chatRoomIds`, when it is not null,
 * keeps the rooms with one of these ids (Buffers) and leaves the others
 * out (2026-11-24, spec section 29).
 */
export async function listRoomsFor(anopodId, chatRoomIds = null) {
  const { rows } = await pool.query(
    `SELECT r.chat_room_id, r.type, r.name, r.creator_anopod_id, r.created_at, h.hpke_key,
            r.listing_id, ${ROOM_LISTING_COLUMNS}, r.case_id, r.case_kind, rp.updated_at AS picture_at,
            ${LAST_MESSAGE_COLUMNS},
            (SELECT COALESCE(json_agg(json_build_object('anopodId', encode(m.anopod_id, 'hex'),
                                                         'username', ma.username,
                                                         'seenPosition', m.seen_position)
                                      ORDER BY m.created_at, m.anopod_id), '[]'::json)
               FROM chat_room_members m
               JOIN anopods ma ON ma.anopod_id = m.anopod_id
              WHERE m.chat_room_id = r.chat_room_id) AS members,
            (SELECT COALESCE(json_agg(json_build_object('anopodId', encode(i.anopod_id_to, 'hex'),
                                                         'username', ia.username)
                                      ORDER BY i.created_at, i.invite_id), '[]'::json)
               FROM chat_room_invites i
               JOIN anopods ia ON ia.anopod_id = i.anopod_id_to
              WHERE i.chat_room_id = r.chat_room_id) AS invited
     FROM chat_room_members cm
     JOIN chat_rooms r ON r.chat_room_id = cm.chat_room_id
     JOIN chat_hpke h ON h.chat_room_id = cm.chat_room_id AND h.anopod_id = cm.anopod_id
     LEFT JOIN listings l ON l.listing_id = r.listing_id
     LEFT JOIN anopods la ON la.anopod_id = l.anopod_id
     LEFT JOIN chat_room_pictures rp ON rp.chat_room_id = r.chat_room_id
     ${LAST_MESSAGE_JOINS}
     WHERE cm.anopod_id = $1
       AND ($2::bytea[] IS NULL OR r.chat_room_id = ANY($2::bytea[]))
     ORDER BY r.created_at DESC, r.chat_room_id`,
    [anopodId, chatRoomIds],
  );
  return rows.map((row) => ({
    chatRoomId: toHex(row.chat_room_id),
    type: row.type,
    name: row.name,
    pictureAt: row.picture_at === null ? null : row.picture_at.toISOString(),
    listingId: toHex(row.listing_id),
    listing: listingFromRow(row),
    caseId: toHex(row.case_id),
    caseKind: row.case_kind,
    creatorAnopodId: toHex(row.creator_anopod_id),
    hpkeKey: toHex(row.hpke_key),
    members: row.members,
    invited: row.invited,
    lastMessage: lastMessageFromRow(row),
    lastPosition: row.last_position === null ? 0 : Number(row.last_position),
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * The newest message of each of the given rooms (ids as Buffers) that
 * `anopodId` is a member of (2026-11-24, spec section 29): { chatRoomId,
 * lastMessage, lastPosition }, the three fields of listRoomsFor that a
 * message changes, in its forms, and, since spec section 31, an edit and a
 * delete too. A room the pod is not in is left out.
 */
export async function listNewestMessagesFor(anopodId, chatRoomIds) {
  const { rows } = await pool.query(
    `SELECT cm.chat_room_id,
            ${LAST_MESSAGE_COLUMNS}
     FROM chat_room_members cm
     ${LAST_MESSAGE_JOINS}
     WHERE cm.anopod_id = $1 AND cm.chat_room_id = ANY($2::bytea[])`,
    [anopodId, chatRoomIds],
  );
  return rows.map((row) => ({
    chatRoomId: toHex(row.chat_room_id),
    lastMessage: lastMessageFromRow(row),
    lastPosition: row.last_position === null ? 0 : Number(row.last_position),
  }));
}

/**
 * The open invites to `anopodId`, oldest first, each with the listing its
 * room is about (listingFromRow; null without one) and the attestor case
 * its room is about (the case's id and kind; both null without one):
 * { inviteId, chatRoomId, type, name, listingId, listing, caseId, caseKind,
 * from: profile, createdAt }. `inviteIds`, when it is not null, keeps the
 * invites with one of these ids (Buffers) and leaves the others out
 * (2026-11-24, spec section 29).
 */
export async function listInvitesFor(anopodId, inviteIds = null) {
  const { rows } = await pool.query(
    `SELECT i.invite_id, i.chat_room_id, i.created_at, r.type, r.name, r.listing_id, ${ROOM_LISTING_COLUMNS},
            r.case_id, r.case_kind,
            ${PROFILE_COLUMNS}
     FROM chat_room_invites i
     JOIN chat_rooms r ON r.chat_room_id = i.chat_room_id
     JOIN anopods a ON a.anopod_id = i.anopod_id_from
     LEFT JOIN listings l ON l.listing_id = r.listing_id
     LEFT JOIN anopods la ON la.anopod_id = l.anopod_id
     WHERE i.anopod_id_to = $1
       AND ($2::bytea[] IS NULL OR i.invite_id = ANY($2::bytea[]))
     ORDER BY i.created_at, i.invite_id`,
    [anopodId, inviteIds],
  );
  return rows.map((row) => ({
    inviteId: toHex(row.invite_id),
    chatRoomId: toHex(row.chat_room_id),
    type: row.type,
    name: row.name,
    listingId: toHex(row.listing_id),
    listing: listingFromRow(row),
    caseId: toHex(row.case_id),
    caseKind: row.case_kind,
    from: profileFromRow(row),
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * The open join requests on rooms `creatorAnopodId` created, oldest first:
 * { joinRequestId, chatRoomId, from: profile, createdAt }.
 * `joinRequestIds`, when it is not null, keeps the requests with one of
 * these ids (Buffers) and leaves the others out (2026-11-24, spec section
 * 29).
 */
export async function listJoinRequestsForCreator(creatorAnopodId, joinRequestIds = null) {
  const { rows } = await pool.query(
    `SELECT j.join_request_id, j.chat_room_id, j.created_at, ${PROFILE_COLUMNS}
     FROM chat_room_join_requests j
     JOIN chat_rooms r ON r.chat_room_id = j.chat_room_id
     JOIN anopods a ON a.anopod_id = j.anopod_id
     WHERE r.creator_anopod_id = $1
       AND ($2::bytea[] IS NULL OR j.join_request_id = ANY($2::bytea[]))
     ORDER BY j.created_at, j.join_request_id`,
    [creatorAnopodId, joinRequestIds],
  );
  return rows.map((row) => ({
    joinRequestId: toHex(row.join_request_id),
    chatRoomId: toHex(row.chat_room_id),
    from: profileFromRow(row),
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * Public rooms, the ones with the most members first, then the newest
 * (2026-11-22, spec section 26; newest first until then): { chatRoomId,
 * name, pictureAt, creator: profile, memberCount, createdAt }. `search`,
 * when it is not null, keeps the rooms whose name holds it anywhere,
 * capital and small letters alike. It is compared as text, so % and _
 * mean themselves. `pictureAt` is when the room's picture was last set,
 * null for a room without one (2026-11-22, spec section 27).
 */
export async function listPublicRooms(limit, offset, search = null) {
  const { rows } = await pool.query(
    `SELECT r.chat_room_id, r.name, r.created_at, rp.updated_at AS picture_at,
            (SELECT count(*)::int FROM chat_room_members m WHERE m.chat_room_id = r.chat_room_id) AS member_count,
            ${PROFILE_COLUMNS}
     FROM chat_rooms r
     JOIN anopods a ON a.anopod_id = r.creator_anopod_id
     LEFT JOIN chat_room_pictures rp ON rp.chat_room_id = r.chat_room_id
     WHERE r.type = 'public'
       AND ($3::text IS NULL OR strpos(lower(r.name), lower($3::text)) > 0)
     ORDER BY member_count DESC, r.created_at DESC, r.chat_room_id
     LIMIT $1 OFFSET $2`,
    [limit, offset, search],
  );
  return rows.map((row) => ({
    chatRoomId: toHex(row.chat_room_id),
    name: row.name,
    pictureAt: row.picture_at === null ? null : row.picture_at.toISOString(),
    creator: profileFromRow(row),
    memberCount: row.member_count,
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * The chat public keys of the given pods (32-byte Buffers), only those whose
 * setup is complete: { anopodId, chatPublicKey, chatPublicKeyPq } in hex.
 */
export async function findChatPublicKeys(anopodIds) {
  const { rows } = await pool.query(
    `SELECT anopod_id, chat_public_key, chat_public_key_pq
     FROM anopods
     WHERE anopod_id = ANY($1::bytea[]) AND anopod_encryption_key_blob_2 IS NOT NULL
     ORDER BY anopod_id`,
    [anopodIds],
  );
  return rows.map((row) => ({
    anopodId: toHex(row.anopod_id),
    chatPublicKey: toHex(row.chat_public_key),
    chatPublicKeyPq: toHex(row.chat_public_key_pq),
  }));
}
