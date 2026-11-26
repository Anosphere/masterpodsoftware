import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { toHex } from '../util/ids.js';
import { decodeImage, pictureProblem } from '../util/images.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { joyIsOn } from './joy.answer.js';
import { MEMORY_MAX_BYTES } from './joy.memory.js';
import { addTokens, countMessage, countUpload, findMemory, upsertMemory } from './joy.queries.js';

/**
 * Joy, the wallet's AI (spec section 30). A member writes to her in the
 * wallet, and a model of one of two companies writes her answers:
 * Anthropic's or OpenAI's, by the setting JOY_PROVIDER (joy.answer.js,
 * spec section 36).
 *
 * What this server keeps: the member's memory file, as one blob under the
 * pod's encryption key, which this server cannot open (joy_memories); and
 * a count of messages, tokens, web searches, pictures that Joy had made
 * and, since spec section 37, pictures that the pod sent her, for each
 * pod and day (joy_usage); and, since spec section 35, the two files
 * that Joy reads with her tool read_file, the same for every member
 * (joy_files).
 * It keeps nothing of a conversation. The wallet sends
 * the conversation and the opened memory file with every message; both
 * pass through this server's memory on their way to the company that
 * answers and are written nowhere. Nothing of a web search is written
 * either: no query, no page and no source (spec section 32). And nothing
 * of a picture that Joy has made: no picture and no description (spec
 * section 33). A picture's description, which Joy writes from the
 * conversation, goes on to OpenAI's image model, whoever answers.
 *
 * Since spec section 37 a member can send Joy one picture with a
 * message. It passes through this server's memory too, on its way to the
 * company that answers, with that one message, and is written nowhere:
 * not into a table and not into the log.
 *
 * Each function runs its route's checks in the spec's order and returns
 * ok(status, body) or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

/** The most messages of a conversation one request may carry. */
const MAX_MESSAGES = 200;

/**
 * The most bytes (UTF-8) the texts of one request's messages may have
 * together. It keeps one request far under the 100,000 tokens above which
 * Anthropic's price for its model is five times as high.
 */
const MAX_CONVERSATION_BYTES = 120_000;

/**
 * The most pixels a picture that a member sends Joy may be wide and may
 * be high (spec section 37). The wallet makes a picture smaller before
 * it sends it, its longer side to this number at most.
 */
const UPLOAD_MAX_SIDE = 1568;

/** The blob's ceiling, the column's check. */
const MEMORY_BLOB_MAX = 32_768;

/** memoryBlob is 1 to 32768 bytes. */
const memoryBlobLength = (n) => n >= 1 && n <= MEMORY_BLOB_MAX;

/** POST /get-joy-memory (setup). Body { }. The pod's blob and when it was last set, both null before the first set. */
export async function getJoyMemory(anopod) {
  const found = await findMemory(anopod.anopodId);
  if (found === null) return ok(200, { memoryBlob: null, updatedAt: null });
  return ok(200, { memoryBlob: toHex(found.memoryBlob), updatedAt: found.updatedAt.toISOString() });
}

/** POST /set-joy-memory (setup). Body { memoryBlob }. The pod's one row, written whole: inserted, or its blob replaced. */
export async function setJoyMemory(anopod, body) {
  if (!isObject(body) || typeof body.memoryBlob !== 'string') return refuse(400, BAD_SHAPE);
  const memoryBlob = decodeBytes(body.memoryBlob, memoryBlobLength);
  if (memoryBlob === null) return refuse(400, 'invalid memoryBlob');
  const updatedAt = await upsertMemory(anopod.anopodId, memoryBlob);
  return ok(200, { updatedAt: updatedAt.toISOString() });
}

/**
 * Whether a message may search the web (spec section 32), from the web
 * searches the pod's row of the day held when the message was counted:
 * 'off' when JOY_MAX_SEARCHES or JOY_DAILY_SEARCHES is 0; 'used' when
 * the row has reached JOY_DAILY_SEARCHES; 'on' otherwise. The row is
 * read before the message's own searches, so a pod can end a day over
 * the number: by up to 2 when one message may make 3 searches. With
 * OpenAI's model answering, by up to 11: the 3 are then the most steps
 * of its search tool for one request, and one message can take four
 * requests (spec 36.5).
 */
function searchFor(searches) {
  if (env.joy.maxSearches === 0 || env.joy.dailySearches === 0) return 'off';
  return searches >= env.joy.dailySearches ? 'used' : 'on';
}

/**
 * Whether Joy may have a picture made for a message (spec section 33),
 * from the pictures the pod's row of the day held when the message was
 * counted: 'off' when this server holds no OPENAI_API_KEY or
 * JOY_DAILY_PICTURES is 0; 'used' when the row has reached
 * JOY_DAILY_PICTURES; 'on' otherwise. The row is read before the
 * message's own picture, so a pod that writes from two devices at the
 * same moment can end a day one over the number.
 */
function pictureFor(pictures) {
  if (env.joy.openaiApiKey === null || env.joy.dailyPictures === 0) return 'off';
  return pictures >= env.joy.dailyPictures ? 'used' : 'on';
}

/**
 * The checks of POST /ask-joy (setup), before anything is sent to the
 * company that answers. Body { messages, memory }: `messages` is the
 * conversation, oldest first, each { role: 'user' | 'assistant', text },
 * the member's new message last; `memory` is the member's memory file as
 * text. Since spec section 37 the last message, and no other, may carry
 * `upload`, one picture as { contentType, image }: the form in which a
 * selfie and a chat room's picture travel (src/util/images.js). On any
 * other message `upload` is passed over, as every field is that this
 * server does not know.
 *
 * In order: the shape; the messages (1 to 200, each with a role and a
 * text that is not empty, the first and the last the member's); their
 * texts together at most 120,000 bytes; the picture, when the last
 * message carries one (one of the three types, base64 of at most
 * MAX_IMAGE_BYTES, bytes that begin as a picture of that type, at most
 * 1,568 pixels wide and high); the memory at most 10,240 bytes; Joy is
 * on; with a picture, uploads are on (JOY_DAILY_UPLOADS is not 0); the
 * pod's count of the day, which this call raises by one unless it has
 * reached JOY_DAILY_MESSAGES; and, with a picture, the pictures that the
 * pod's row of the day holds, which this call raises by one unless they
 * have reached JOY_DAILY_UPLOADS.
 *
 * The message is counted before the day's pictures are looked at. So a
 * message that is refused for the day's pictures has been counted as one
 * of the day's messages. The row's pictures are read before this
 * message's own picture is counted, which a statement of its own does,
 * so a pod that writes from two devices at the same moment can end a day
 * one over the number, and from more devices at the same moment further
 * over: the day's number of pictures is no hard stop, as the day's
 * number of messages is. A message with no picture is never refused for
 * the pictures: not when the row has reached the number, and not when
 * uploads are off.
 *
 * Returns ok(200, { history, memory, day, search, picture }) for the
 * handler, which answers as a stream, or a refusal. `history` is the
 * conversation as [{ role, text }]. Its last message also holds
 * `upload`, { contentType, data }, when the member's new message came
 * with a picture: the bytes that were checked here, encoded anew as
 * base64. `day` is the row of joy_usage the message was counted on.
 * `search` is whether the message may search the web: 'on', 'off' or
 * 'used' (searchFor). It is never a refusal: a message that may not
 * search is answered without searching. `picture` is the same for a
 * picture that Joy has made (pictureFor): a message that may not have
 * one made is answered without one.
 */
export async function prepareAsk(anopod, body) {
  if (!isObject(body) || !Array.isArray(body.messages) || typeof body.memory !== 'string') return refuse(400, BAD_SHAPE);
  if (body.messages.length === 0 || body.messages.length > MAX_MESSAGES) return refuse(400, 'invalid messages');

  const history = [];
  let bytes = 0;
  for (const message of body.messages) {
    if (!isObject(message) || (message.role !== 'user' && message.role !== 'assistant')) return refuse(400, 'invalid messages');
    if (typeof message.text !== 'string' || message.text.trim() === '') return refuse(400, 'invalid messages');
    bytes += Buffer.byteLength(message.text, 'utf8');
    history.push({ role: message.role, text: message.text });
  }
  if (history[0].role !== 'user' || history[history.length - 1].role !== 'user') return refuse(400, 'invalid messages');
  if (bytes > MAX_CONVERSATION_BYTES) return refuse(400, 'conversation too long');

  // The picture of the member's new message, checked as a chat room's
  // picture is. Null when the message carries none.
  const sent = body.messages[body.messages.length - 1].upload;
  let upload = null;
  if (sent !== undefined) {
    upload = decodeImage(sent);
    if (upload.reason) return refuse(400, `invalid upload: ${upload.reason}`);
    const problem = pictureProblem(upload, UPLOAD_MAX_SIDE);
    if (problem) return refuse(400, `invalid upload: ${problem}`);
  }
  if (Buffer.byteLength(body.memory, 'utf8') > MEMORY_MAX_BYTES) return refuse(400, 'memory too long');

  if (!joyIsOn()) return refuse(503, 'joy is off');
  if (upload !== null && env.joy.dailyUploads === 0) return refuse(503, 'uploads are off');

  const counted = await countMessage(anopod.anopodId, env.joy.dailyMessages);
  if (counted === null) return refuse(429, 'daily limit reached');
  if (upload !== null) {
    if (counted.uploads >= env.joy.dailyUploads) return refuse(429, 'daily upload limit reached');
    await countUpload(anopod.anopodId, counted.day);
    history[history.length - 1].upload = { contentType: upload.contentType, data: upload.bytes.toString('base64') };
  }
  return ok(200, { history, memory: body.memory, day: counted.day, search: searchFor(counted.searches), picture: pictureFor(counted.pictures) });
}

/** Writes the tokens, the web searches and the pictures of one message onto the pod's row of `day`. Nothing is written when the company that answers counted none and OpenAI made no picture. */
export async function recordTokens(anopod, day, tokens) {
  if (tokens.input + tokens.output + tokens.cacheRead + tokens.cacheWrite + tokens.searches + tokens.pictures === 0) return;
  await addTokens(anopod.anopodId, day, tokens);
}
