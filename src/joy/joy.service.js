import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { joyIsOn } from './joy.anthropic.js';
import { MEMORY_MAX_BYTES } from './joy.memory.js';
import { addTokens, countMessage, findMemory, upsertMemory } from './joy.queries.js';

/**
 * Joy, the wallet's AI (spec section 30). A member writes to her in the
 * wallet, and a model of the company Anthropic writes her answers.
 *
 * What this server keeps: the member's memory file, as one blob under the
 * pod's encryption key, which this server cannot open (joy_memories); and
 * a count of messages, tokens and web searches for each pod and day
 * (joy_usage). It keeps nothing of a conversation. The wallet sends the
 * conversation and the opened memory file with every message; both pass
 * through this server's memory on their way to Anthropic and are written
 * nowhere. Nothing of a web search is written either: no query, no page
 * and no source (spec section 32).
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
 * Anthropic's price for the model is five times as high.
 */
const MAX_CONVERSATION_BYTES = 120_000;

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
 * the number: by up to 2 when one message may make 3 searches.
 */
function searchFor(searches) {
  if (env.joy.maxSearches === 0 || env.joy.dailySearches === 0) return 'off';
  return searches >= env.joy.dailySearches ? 'used' : 'on';
}

/**
 * The checks of POST /ask-joy (setup), before anything is sent to
 * Anthropic. Body { messages, memory }: `messages` is the conversation,
 * oldest first, each { role: 'user' | 'assistant', text }, the member's
 * new message last; `memory` is the member's memory file as text.
 *
 * In order: the shape; the messages (1 to 200, each with a role and a
 * text that is not empty, the first and the last the member's); their
 * texts together at most 120,000 bytes; the memory at most 10,240 bytes;
 * Joy is on; and the pod's count of the day, which this call raises by
 * one unless it has reached JOY_DAILY_MESSAGES.
 *
 * Returns ok(200, { history, memory, day, search }) for the handler,
 * which answers as a stream, or a refusal. `day` is the row of joy_usage
 * the message was counted on. `search` is whether the message may search
 * the web: 'on', 'off' or 'used' (searchFor). It is never a refusal: a
 * message that may not search is answered without searching.
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
  if (Buffer.byteLength(body.memory, 'utf8') > MEMORY_MAX_BYTES) return refuse(400, 'memory too long');

  if (!joyIsOn()) return refuse(503, 'joy is off');

  const counted = await countMessage(anopod.anopodId, env.joy.dailyMessages);
  if (counted === null) return refuse(429, 'daily limit reached');
  return ok(200, { history, memory: body.memory, day: counted.day, search: searchFor(counted.searches) });
}

/** Writes the tokens and the web searches of one message onto the pod's row of `day`. Nothing is written when Anthropic counted none. */
export async function recordTokens(anopod, day, tokens) {
  if (tokens.input + tokens.output + tokens.cacheRead + tokens.cacheWrite + tokens.searches === 0) return;
  await addTokens(anopod.anopodId, day, tokens);
}
