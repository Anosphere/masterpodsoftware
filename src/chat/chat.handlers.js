import { answer } from '../util/result.js';
import {
  acceptInvite,
  approveJoin,
  createRoom,
  declineInvite,
  declineJoin,
  deleteMessage,
  editMessage,
  getChatPublicKeys,
  getRoomPicture,
  invite,
  leave,
  listPublicRooms,
  listRoomMessages,
  listRooms,
  markSeen,
  requestToJoin,
  sendMessage,
  setRoomPicture,
} from './chat.service.js';

/**
 * Route handlers for the chat feature. HTTP in and out only: the caller is
 * req.anopod (requireSetup), the route's object is req.body; the service
 * checks and answers.
 */

/** POST /create-chat-room */
export async function createChatRoom(req, res) {
  answer(res, await createRoom(req.anopod, req.body));
}

/** POST /invite-to-chat-room */
export async function inviteToChatRoom(req, res) {
  answer(res, await invite(req.anopod, req.body));
}

/** POST /accept-invite */
export async function acceptInviteHandler(req, res) {
  answer(res, await acceptInvite(req.anopod, req.body));
}

/** POST /decline-invite */
export async function declineInviteHandler(req, res) {
  answer(res, await declineInvite(req.anopod, req.body));
}

/** POST /request-to-join */
export async function requestToJoinHandler(req, res) {
  answer(res, await requestToJoin(req.anopod, req.body));
}

/** POST /approve-join */
export async function approveJoinHandler(req, res) {
  answer(res, await approveJoin(req.anopod, req.body));
}

/** POST /decline-join */
export async function declineJoinHandler(req, res) {
  answer(res, await declineJoin(req.anopod, req.body));
}

/** POST /leave-chat-room */
export async function leaveChatRoom(req, res) {
  answer(res, await leave(req.anopod, req.body));
}

/** POST /list-chat-rooms */
export async function listChatRooms(req, res) {
  answer(res, await listRooms(req.anopod, req.body));
}

/** POST /list-public-chat-rooms */
export async function listPublicChatRooms(req, res) {
  answer(res, await listPublicRooms(req.body));
}

/** POST /set-chat-room-picture */
export async function setChatRoomPicture(req, res) {
  answer(res, await setRoomPicture(req.anopod, req.body));
}

/** POST /get-chat-room-picture */
export async function getChatRoomPicture(req, res) {
  answer(res, await getRoomPicture(req.body));
}

/** POST /list-messages */
export async function listMessagesHandler(req, res) {
  answer(res, await listRoomMessages(req.anopod, req.body));
}

/** POST /send-message */
export async function sendMessageHandler(req, res) {
  answer(res, await sendMessage(req.anopod, req.body));
}

/** POST /edit-message */
export async function editMessageHandler(req, res) {
  answer(res, await editMessage(req.anopod, req.body));
}

/** POST /delete-message */
export async function deleteMessageHandler(req, res) {
  answer(res, await deleteMessage(req.anopod, req.body));
}

/** POST /mark-messages-seen */
export async function markSeenHandler(req, res) {
  answer(res, await markSeen(req.anopod, req.body));
}

/** POST /get-chat-public-keys */
export async function getChatPublicKeysHandler(req, res) {
  answer(res, await getChatPublicKeys(req.body));
}
