import { Router } from 'express';
import { requireSetup } from '../auth/require-setup.js';
import {
  acceptInviteHandler,
  approveJoinHandler,
  createChatRoom,
  declineInviteHandler,
  declineJoinHandler,
  getChatPublicKeysHandler,
  inviteToChatRoom,
  leaveChatRoom,
  listChatRooms,
  listMessagesHandler,
  listPublicChatRooms,
  requestToJoinHandler,
  sendMessageHandler,
} from './chat.handlers.js';

/**
 * Chat feature router. All thirteen routes are level "setup": a vouched pod
 * with chat keys.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const chatRouter = Router();

chatRouter.post('/create-chat-room', requireSetup, createChatRoom);
chatRouter.post('/invite-to-chat-room', requireSetup, inviteToChatRoom);
chatRouter.post('/accept-invite', requireSetup, acceptInviteHandler);
chatRouter.post('/decline-invite', requireSetup, declineInviteHandler);
chatRouter.post('/request-to-join', requireSetup, requestToJoinHandler);
chatRouter.post('/approve-join', requireSetup, approveJoinHandler);
chatRouter.post('/decline-join', requireSetup, declineJoinHandler);
chatRouter.post('/leave-chat-room', requireSetup, leaveChatRoom);
chatRouter.post('/list-chat-rooms', requireSetup, listChatRooms);
chatRouter.post('/list-public-chat-rooms', requireSetup, listPublicChatRooms);
chatRouter.post('/list-messages', requireSetup, listMessagesHandler);
chatRouter.post('/send-message', requireSetup, sendMessageHandler);
chatRouter.post('/get-chat-public-keys', requireSetup, getChatPublicKeysHandler);
