import { PROFILE_COLUMNS, profileFromRow } from '../anopods/anopods.queries.js';
import { pool } from '../db/pool.js';
import { toHex } from '../util/ids.js';

/**
 * SQL for the chat tables: chat_rooms, chat_room_members with chat_hpke,
 * chat_room_invites, chat_room_join_requests and chat_room_messages. Ids
 * and keys are Buffers, matching the BYTEA columns. Reads take an optional
 * `db` (a client inside a transaction; the pool by default); writes take
 * the transaction's client first.
 */

// ---------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------

/** Writes a room on `client`: `name` is null unless `type` is 'public'. */
export async function insertRoom(client, { chatRoomId, creatorAnopodId, type, name }) {
  await client.query(
    `INSERT INTO chat_rooms (chat_room_id, creator_anopod_id, type, name) VALUES ($1, $2, $3, $4)`,
    [chatRoomId, creatorAnopodId, type, name],
  );
}

/** The room with this id, as { chatRoomId, creatorAnopodId, type, name, createdAt }, or null. */
export async function findRoom(chatRoomId, db = pool) {
  const { rows } = await db.query(
    `SELECT chat_room_id, creator_anopod_id, type, name, created_at FROM chat_rooms WHERE chat_room_id = $1`,
    [chatRoomId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    chatRoomId: row.chat_room_id,
    creatorAnopodId: row.creator_anopod_id,
    type: row.type,
    name: row.name,
    createdAt: row.created_at,
  };
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

/** The highest message position in the room, 0 when it has none. */
export async function lastPosition(chatRoomId, db = pool) {
  const { rows } = await db.query(
    'SELECT COALESCE(max(position), 0) AS last FROM chat_room_messages WHERE chat_room_id = $1',
    [chatRoomId],
  );
  return Number(rows[0].last);
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
 * The room's messages after `afterPosition`, ascending, at most `limit`,
 * each in wire form: { messageId, position, senderAnopodId, message, createdAt }
 * with the ciphertext base64.
 */
export async function listMessages(chatRoomId, afterPosition, limit) {
  const { rows } = await pool.query(
    `SELECT message_id, position, sender_anopod_id, message, created_at
     FROM chat_room_messages
     WHERE chat_room_id = $1 AND position > $2
     ORDER BY position
     LIMIT $3`,
    [chatRoomId, afterPosition, limit],
  );
  return rows.map((row) => ({
    messageId: toHex(row.message_id),
    position: Number(row.position),
    senderAnopodId: toHex(row.sender_anopod_id),
    message: row.message.toString('base64'),
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * The room's newest messages below `beforePosition`, at most `limit`, in
 * ascending order, each in the wire form of listMessages: how a room opens
 * at its newest messages and loads older ones.
 */
export async function listMessagesBefore(chatRoomId, beforePosition, limit) {
  const { rows } = await pool.query(
    `SELECT message_id, position, sender_anopod_id, message, created_at
     FROM chat_room_messages
     WHERE chat_room_id = $1 AND position < $2
     ORDER BY position DESC
     LIMIT $3`,
    [chatRoomId, beforePosition, limit],
  );
  return rows.reverse().map((row) => ({
    messageId: toHex(row.message_id),
    position: Number(row.position),
    senderAnopodId: toHex(row.sender_anopod_id),
    message: row.message.toString('base64'),
    createdAt: row.created_at.toISOString(),
  }));
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

/**
 * The rooms `anopodId` is a member of, newest first, each with the caller's
 * own wrapped key, the members (id and username), the people invited who
 * have not answered yet (oldest first), the newest message in the wire form
 * of listMessages (null when the room has none) with its position as
 * lastPosition (0 when none) and, for a marketplace room, its listing id
 * and the listing's side, quantity (millionths, a decimal string) and
 * currency: { chatRoomId, type, name, listingId, listing, creatorAnopodId,
 * hpkeKey, members, invited, lastMessage, lastPosition, createdAt }.
 */
export async function listRoomsFor(anopodId) {
  const { rows } = await pool.query(
    `SELECT r.chat_room_id, r.type, r.name, r.creator_anopod_id, r.created_at, h.hpke_key,
            l.listing_id, l.side, l.quantity, l.currency,
            lm.message_id AS last_message_id, lm.position AS last_position,
            lm.sender_anopod_id AS last_sender_anopod_id, lm.message AS last_message,
            lm.created_at AS last_created_at,
            (SELECT COALESCE(json_agg(json_build_object('anopodId', encode(m.anopod_id, 'hex'),
                                                         'username', ma.username)
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
     LEFT JOIN listings l ON l.chat_room_id = r.chat_room_id
     LEFT JOIN LATERAL (SELECT msg.message_id, msg.position, msg.sender_anopod_id, msg.message, msg.created_at
                          FROM chat_room_messages msg
                         WHERE msg.chat_room_id = r.chat_room_id
                         ORDER BY msg.position DESC
                         LIMIT 1) lm ON true
     WHERE cm.anopod_id = $1
     ORDER BY r.created_at DESC, r.chat_room_id`,
    [anopodId],
  );
  return rows.map((row) => ({
    chatRoomId: toHex(row.chat_room_id),
    type: row.type,
    name: row.name,
    listingId: toHex(row.listing_id),
    listing: row.listing_id === null ? null : { side: row.side, quantity: row.quantity, currency: row.currency },
    creatorAnopodId: toHex(row.creator_anopod_id),
    hpkeKey: toHex(row.hpke_key),
    members: row.members,
    invited: row.invited,
    lastMessage:
      row.last_message_id === null
        ? null
        : {
            messageId: toHex(row.last_message_id),
            position: Number(row.last_position),
            senderAnopodId: toHex(row.last_sender_anopod_id),
            message: row.last_message.toString('base64'),
            createdAt: row.last_created_at.toISOString(),
          },
    lastPosition: row.last_position === null ? 0 : Number(row.last_position),
    createdAt: row.created_at.toISOString(),
  }));
}

/** The open invites to `anopodId`, oldest first: { inviteId, chatRoomId, type, name, from: profile, createdAt }. */
export async function listInvitesFor(anopodId) {
  const { rows } = await pool.query(
    `SELECT i.invite_id, i.chat_room_id, i.created_at, r.type, r.name, ${PROFILE_COLUMNS}
     FROM chat_room_invites i
     JOIN chat_rooms r ON r.chat_room_id = i.chat_room_id
     JOIN anopods a ON a.anopod_id = i.anopod_id_from
     WHERE i.anopod_id_to = $1
     ORDER BY i.created_at, i.invite_id`,
    [anopodId],
  );
  return rows.map((row) => ({
    inviteId: toHex(row.invite_id),
    chatRoomId: toHex(row.chat_room_id),
    type: row.type,
    name: row.name,
    from: profileFromRow(row),
    createdAt: row.created_at.toISOString(),
  }));
}

/** The open join requests on rooms `creatorAnopodId` created, oldest first: { joinRequestId, chatRoomId, from: profile, createdAt }. */
export async function listJoinRequestsForCreator(creatorAnopodId) {
  const { rows } = await pool.query(
    `SELECT j.join_request_id, j.chat_room_id, j.created_at, ${PROFILE_COLUMNS}
     FROM chat_room_join_requests j
     JOIN chat_rooms r ON r.chat_room_id = j.chat_room_id
     JOIN anopods a ON a.anopod_id = j.anopod_id
     WHERE r.creator_anopod_id = $1
     ORDER BY j.created_at, j.join_request_id`,
    [creatorAnopodId],
  );
  return rows.map((row) => ({
    joinRequestId: toHex(row.join_request_id),
    chatRoomId: toHex(row.chat_room_id),
    from: profileFromRow(row),
    createdAt: row.created_at.toISOString(),
  }));
}

/** Public rooms, newest first: { chatRoomId, name, creator: profile, memberCount, createdAt }. */
export async function listPublicRooms(limit, offset) {
  const { rows } = await pool.query(
    `SELECT r.chat_room_id, r.name, r.created_at,
            (SELECT count(*)::int FROM chat_room_members m WHERE m.chat_room_id = r.chat_room_id) AS member_count,
            ${PROFILE_COLUMNS}
     FROM chat_rooms r
     JOIN anopods a ON a.anopod_id = r.creator_anopod_id
     WHERE r.type = 'public'
     ORDER BY r.created_at DESC, r.chat_room_id
     LIMIT $1 OFFSET $2`,
    [limit, offset],
  );
  return rows.map((row) => ({
    chatRoomId: toHex(row.chat_room_id),
    name: row.name,
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
