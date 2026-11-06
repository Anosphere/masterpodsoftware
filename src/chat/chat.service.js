import { findById } from '../anopods/anopods.queries.js';
import { decodeBytes } from '../crypto/bytes.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { findListingByRoom } from '../marketplace/listings.queries.js';
import { notify } from '../notifications/notifications.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { decodeBase64 } from '../util/images.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  deleteInvite,
  deleteJoinRequest,
  deleteMember,
  findChatPublicKeys,
  findInvite,
  findJoinRequest,
  findRoom,
  insertInvite,
  insertJoinRequest,
  insertMember,
  insertMessage,
  insertRoom,
  inviteOpen,
  isMember,
  joinRequestOpen,
  listInvitesFor,
  listJoinRequestsForCreator,
  listMessages,
  listMessagesBefore,
  listPublicRooms as listPublicRoomsQuery,
  listRoomsFor,
} from './chat.queries.js';

/**
 * The chat feature: rooms, invites, join requests, membership, messages and
 * the chat public keys. The server never opens a wrapped room key or a
 * message; it checks who may do what and stores bytes. Each function runs
 * its route's checks in the spec's order (section 5) and returns
 * ok(status, body) or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

/** A room name is 1 to 100 characters. */
const NAME_MAX_CHARS = 100;

/** A wrapped room key is 1661 bytes (spec section 7); the column takes up to 4096. */
const hpkeKeyLength = (n) => n >= 1 && n <= 4096;

/** A message is at most 65536 bytes of ciphertext. */
const MESSAGE_MAX_BYTES = 65536;

/** Defaults and ceilings of the paged lists. */
const PUBLIC_ROOMS_DEFAULT_LIMIT = 50;
const PUBLIC_ROOMS_MAX_LIMIT = 200;
const MESSAGES_DEFAULT_LIMIT = 100;
const MESSAGES_MAX_LIMIT = 200;

/** /get-chat-public-keys takes 1 to 50 ids. */
const MAX_KEY_LOOKUPS = 50;

/** Decodes a wrapped room key from hex or base64; null when it is not one. */
function decodeHpkeKey(value) {
  return decodeBytes(value, hpkeKeyLength);
}

/** A whole number from `value` within [min, max], `fallback` when absent; undefined when invalid. */
function integerOption(value, fallback, min, max) {
  if (value === undefined || value === null) return fallback;
  return Number.isInteger(value) && value >= min && value <= max ? value : undefined;
}

/** POST /create-chat-room. Body { type, name, hpkeKey }. */
export async function createRoom(anopod, body) {
  if (!isObject(body) || typeof body.type !== 'string' || typeof body.hpkeKey !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const { type, name } = body;
  if (type !== 'private' && type !== 'public') return refuse(400, 'type must be private or public');
  if (type === 'public') {
    const chars = typeof name === 'string' ? Array.from(name).length : 0;
    if (chars < 1 || chars > NAME_MAX_CHARS) return refuse(400, 'invalid name');
  } else if (name !== undefined && name !== null) {
    return refuse(400, 'private rooms have no name');
  }
  const hpkeKey = decodeHpkeKey(body.hpkeKey);
  if (hpkeKey === null) return refuse(400, 'invalid hpkeKey');

  const chatRoomId = randomId();
  await withTransaction(async (client) => {
    await insertRoom(client, {
      chatRoomId,
      creatorAnopodId: anopod.anopodId,
      type,
      name: type === 'public' ? name : null,
    });
    await insertMember(client, chatRoomId, anopod.anopodId, hpkeKey);
  });
  return ok(201, { chatRoomId: toHex(chatRoomId) });
}

/** POST /invite-to-chat-room. Body { chatRoomId, anopodIdTo, hpkeKey }. */
export async function invite(anopod, body) {
  if (
    !isObject(body) ||
    typeof body.chatRoomId !== 'string' ||
    typeof body.anopodIdTo !== 'string' ||
    typeof body.hpkeKey !== 'string'
  ) {
    return refuse(400, BAD_SHAPE);
  }
  const chatRoomId = decodeId(body.chatRoomId);
  const room = chatRoomId === null ? null : await findRoom(chatRoomId);
  if (room === null || !room.creatorAnopodId.equals(anopod.anopodId)) {
    return refuse(403, 'only the creator invites');
  }
  if (room.type === 'marketplace') return refuse(400, 'marketplace rooms take join requests');
  const anopodIdTo = decodeId(body.anopodIdTo);
  if (anopodIdTo === null) return refuse(400, 'invalid anopodIdTo');
  const target = await findById(anopodIdTo);
  if (target === null || !target.setupComplete) return refuse(409, 'invitee has no chat key');
  if (await isMember(chatRoomId, anopodIdTo)) return refuse(409, 'already a member');
  if (await inviteOpen(chatRoomId, anopodIdTo)) return refuse(409, 'invite already open');
  const hpkeKey = decodeHpkeKey(body.hpkeKey);
  if (hpkeKey === null) return refuse(400, 'invalid hpkeKey');

  const inviteId = randomId();
  try {
    await withTransaction(async (client) => {
      await insertInvite(client, { inviteId, chatRoomId, anopodIdFrom: anopod.anopodId, anopodIdTo, hpkeKey });
      await notify(client, anopodIdTo, 'chatInvite', inviteId);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'invite already open');
    throw err;
  }
  return ok(201, { inviteId: toHex(inviteId) });
}

/** The invite named in `body`, checked to exist and to be addressed to the caller: { invite } or { result }. */
async function ownInvite(anopod, body) {
  if (!isObject(body) || typeof body.inviteId !== 'string') return { result: refuse(400, BAD_SHAPE) };
  const inviteId = decodeId(body.inviteId);
  const found = inviteId === null ? null : await findInvite(inviteId);
  if (found === null || !found.anopodIdTo.equals(anopod.anopodId)) return { result: refuse(404, 'invite not found') };
  return { invite: found };
}

/** POST /accept-invite. Body { inviteId }. The wrapped key moves from the invite into chat_hpke. */
export async function acceptInvite(anopod, body) {
  const { invite: found, result } = await ownInvite(anopod, body);
  if (result) return result;

  try {
    await withTransaction(async (client) => {
      await insertMember(client, found.chatRoomId, anopod.anopodId, found.hpkeKey);
      await deleteInvite(client, found.inviteId);
      await notify(client, found.anopodIdFrom, 'inviteAccepted', found.chatRoomId);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'already a member');
    throw err;
  }
  return ok(200, { chatRoomId: toHex(found.chatRoomId) });
}

/** POST /decline-invite. Body { inviteId }. */
export async function declineInvite(anopod, body) {
  const { invite: found, result } = await ownInvite(anopod, body);
  if (result) return result;

  await withTransaction(async (client) => {
    await deleteInvite(client, found.inviteId);
    await notify(client, found.anopodIdFrom, 'inviteDeclined', found.chatRoomId);
  });
  return ok(200, { chatRoomId: toHex(found.chatRoomId) });
}

/**
 * POST /request-to-join. Body { chatRoomId }. Public and marketplace rooms
 * only; a marketplace room takes requests while its listing is open.
 */
export async function requestToJoin(anopod, body) {
  if (!isObject(body) || typeof body.chatRoomId !== 'string') return refuse(400, BAD_SHAPE);
  const chatRoomId = decodeId(body.chatRoomId);
  const room = chatRoomId === null ? null : await findRoom(chatRoomId);
  if (room === null) return refuse(404, 'room not found');
  if (room.type === 'private') return refuse(403, 'room is private');
  if (room.type === 'marketplace') {
    const listing = await findListingByRoom(chatRoomId);
    if (listing === null || listing.status !== 'open') return refuse(409, 'listing closed');
  }
  if (await isMember(chatRoomId, anopod.anopodId)) return refuse(409, 'already a member');
  if (await joinRequestOpen(chatRoomId, anopod.anopodId)) return refuse(409, 'request already open');

  const joinRequestId = randomId();
  try {
    await withTransaction(async (client) => {
      await insertJoinRequest(client, { joinRequestId, chatRoomId, anopodId: anopod.anopodId });
      await notify(client, room.creatorAnopodId, 'joinRequest', joinRequestId);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'request already open');
    throw err;
  }
  return ok(201, { joinRequestId: toHex(joinRequestId) });
}

/**
 * The join request named in `body`, checked to exist and to be on a room the
 * caller created: { request } or { result }.
 */
async function ownJoinRequest(anopod, body) {
  if (!isObject(body) || typeof body.joinRequestId !== 'string') return { result: refuse(400, BAD_SHAPE) };
  const joinRequestId = decodeId(body.joinRequestId);
  const request = joinRequestId === null ? null : await findJoinRequest(joinRequestId);
  if (request === null) return { result: refuse(404, 'join request not found') };
  const room = await findRoom(request.chatRoomId);
  if (room === null || !room.creatorAnopodId.equals(anopod.anopodId)) {
    return { result: refuse(403, 'only the creator approves') };
  }
  return { request };
}

/** POST /approve-join. Body { joinRequestId, hpkeKey }, the room key wrapped to the requester. */
export async function approveJoin(anopod, body) {
  const { request, result } = await ownJoinRequest(anopod, body);
  if (result) return result;
  const hpkeKey = isObject(body) ? decodeHpkeKey(body.hpkeKey) : null;
  if (hpkeKey === null) return refuse(400, 'invalid hpkeKey');

  try {
    await withTransaction(async (client) => {
      await insertMember(client, request.chatRoomId, request.anopodId, hpkeKey);
      await deleteJoinRequest(client, request.joinRequestId);
      await notify(client, request.anopodId, 'joinApproved', request.chatRoomId);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'already a member');
    throw err;
  }
  return ok(200, { chatRoomId: toHex(request.chatRoomId), anopodId: toHex(request.anopodId) });
}

/** POST /decline-join. Body { joinRequestId }. */
export async function declineJoin(anopod, body) {
  const { request, result } = await ownJoinRequest(anopod, body);
  if (result) return result;

  await withTransaction(async (client) => {
    await deleteJoinRequest(client, request.joinRequestId);
    await notify(client, request.anopodId, 'joinDeclined', request.chatRoomId);
  });
  return ok(200, { chatRoomId: toHex(request.chatRoomId), anopodId: toHex(request.anopodId) });
}

/** POST /leave-chat-room. Body { chatRoomId }. The creator stays. */
export async function leave(anopod, body) {
  if (!isObject(body) || typeof body.chatRoomId !== 'string') return refuse(400, BAD_SHAPE);
  const chatRoomId = decodeId(body.chatRoomId);
  if (chatRoomId === null || !(await isMember(chatRoomId, anopod.anopodId))) return refuse(404, 'not a member');
  const room = await findRoom(chatRoomId);
  if (room !== null && room.creatorAnopodId.equals(anopod.anopodId)) return refuse(409, 'the creator cannot leave');

  await withTransaction((client) => deleteMember(client, chatRoomId, anopod.anopodId));
  return ok(200, { chatRoomId: toHex(chatRoomId) });
}

/** POST /list-chat-rooms. The caller's rooms, open invites, and the join requests on rooms it created. */
export async function listRooms(anopod) {
  const [rooms, invites, joinRequests] = await Promise.all([
    listRoomsFor(anopod.anopodId),
    listInvitesFor(anopod.anopodId),
    listJoinRequestsForCreator(anopod.anopodId),
  ]);
  return ok(200, { rooms, invites, joinRequests });
}

/** POST /list-public-chat-rooms. Body { limit, offset }, optional. */
export async function listPublicRooms(body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const limit = integerOption(body.limit, PUBLIC_ROOMS_DEFAULT_LIMIT, 1, PUBLIC_ROOMS_MAX_LIMIT);
  if (limit === undefined) return refuse(400, 'invalid limit');
  const offset = integerOption(body.offset, 0, 0, Number.MAX_SAFE_INTEGER);
  if (offset === undefined) return refuse(400, 'invalid offset');

  return ok(200, { rooms: await listPublicRoomsQuery(limit, offset) });
}

/**
 * POST /list-messages. Body { chatRoomId, afterPosition, beforePosition,
 * limit }. Members only. With `beforePosition` the answer is the newest
 * `limit` messages below it and `afterPosition` is ignored.
 */
export async function listRoomMessages(anopod, body) {
  if (!isObject(body) || typeof body.chatRoomId !== 'string') return refuse(400, BAD_SHAPE);
  const chatRoomId = decodeId(body.chatRoomId);
  if (chatRoomId === null) return refuse(400, 'invalid chatRoomId');
  const afterPosition = integerOption(body.afterPosition, 0, 0, Number.MAX_SAFE_INTEGER);
  if (afterPosition === undefined) return refuse(400, 'invalid afterPosition');
  const beforePosition = integerOption(body.beforePosition, null, 1, Number.MAX_SAFE_INTEGER);
  if (beforePosition === undefined) return refuse(400, 'invalid beforePosition');
  const limit = integerOption(body.limit, MESSAGES_DEFAULT_LIMIT, 1, MESSAGES_MAX_LIMIT);
  if (limit === undefined) return refuse(400, 'invalid limit');
  if (!(await isMember(chatRoomId, anopod.anopodId))) return refuse(403, 'not a member');

  const messages =
    beforePosition === null
      ? await listMessages(chatRoomId, afterPosition, limit)
      : await listMessagesBefore(chatRoomId, beforePosition, limit);
  return ok(200, { messages });
}

/** POST /send-message. Body { chatRoomId, message }, the ciphertext base64. Members only. */
export async function sendMessage(anopod, body) {
  if (!isObject(body) || typeof body.chatRoomId !== 'string' || typeof body.message !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const chatRoomId = decodeId(body.chatRoomId);
  if (chatRoomId === null) return refuse(400, 'invalid chatRoomId');
  const message = decodeBase64(body.message, MESSAGE_MAX_BYTES);
  if (message === null) return refuse(400, `message must be base64 of 1 to ${MESSAGE_MAX_BYTES} bytes`);
  if (!(await isMember(chatRoomId, anopod.anopodId))) return refuse(403, 'not a member');

  const messageId = randomId();
  const position = await withTransaction((client) =>
    insertMessage(client, { messageId, chatRoomId, senderAnopodId: anopod.anopodId, message }),
  );
  return ok(201, { messageId: toHex(messageId), position });
}

/** POST /get-chat-public-keys. Body { anopodIds }, 1 to 50; pods without setup are left out. */
export async function getChatPublicKeys(body) {
  if (!isObject(body) || !Array.isArray(body.anopodIds)) return refuse(400, BAD_SHAPE);
  if (body.anopodIds.length < 1 || body.anopodIds.length > MAX_KEY_LOOKUPS) return refuse(400, 'invalid anopodIds');
  const anopodIds = body.anopodIds.map(decodeId);
  if (anopodIds.includes(null)) return refuse(400, 'invalid anopodIds');

  return ok(200, { keys: await findChatPublicKeys(anopodIds) });
}
