import { env } from '../config/env.js';
import { sha256 } from '../crypto/hash.js';
import { toHex } from '../util/ids.js';
import { IMAGE_CONTENT_TYPES, imageSize } from '../util/images.js';
import { isObject } from '../util/is-object.js';

/**
 * Joy's pictures (spec section 33). Joy does not draw. She calls her
 * tool make_picture with a description, and this server has a
 * model of the company OpenAI make the picture from it. This file holds
 * the tool, the few words Joy is told of a call's outcome, and the one
 * request to OpenAI. No package: fetch, Node's own.
 *
 * What leaves for OpenAI in this request is the description that Joy
 * wrote and a hash of the pod's id. Not the conversation, not the memory
 * file, not the pod's id. When OpenAI's model also writes Joy's answers
 * (spec section 36), the conversation and the memory file go to OpenAI
 * in the request for her answer (joy.openai.js), not in this one, and so
 * does a picture that a member sends her (spec section 37). This server
 * keeps no picture and no description: neither is written into a table
 * or into the log.
 */

/** Where a picture is asked for. */
const OPENAI_URL = 'https://api.openai.com/v1/images/generations';

/**
 * How long OpenAI gets to answer, in milliseconds. In the real call of
 * 2026-11-25 a picture took 8 to 9 seconds. OpenAI's page names two
 * minutes as the longest case.
 */
const TIMEOUT_MS = 150_000;

/** The longest description, in characters. */
const DESCRIPTION_MAX_CHARS = 1000;

/**
 * Joy's tool make_picture, as Anthropic's API takes it. Its input is
 * checked here, in makePicture.
 */
export const MAKE_PICTURE_TOOL = Object.freeze({
  name: 'make_picture',
  description:
    "Make one picture for this member and show it in the chat. Call it when the member asks for a picture, a drawing, an illustration or the like, and when they ask you to change a picture you made before. A picture service makes the picture from your description alone and knows nothing of this chat. So describe the whole picture: what it shows, where, the style, the colours, the light, and any words that must stand in it, written exactly. For a changed picture, write the whole description again with the change in it. Put nothing from the member's memory file into a description unless the member asks for it in the picture. One call for each message of the member.",
  input_schema: {
    type: 'object',
    properties: {
      description: { type: 'string', description: 'The whole picture in words, as one paragraph of at most 1000 characters.' },
    },
    required: ['description'],
  },
});

/** What make_picture answers Joy. Every one but `made` is handed over as a refusal. */
const OUTCOMES = Object.freeze({
  made: 'made',
  refused: 'refused: the picture service does not make this picture',
  failed: 'failed: the picture could not be made right now',
  second: 'one picture for each message: this one was not made',
  empty: 'the description is empty',
  long: `a description is at most ${DESCRIPTION_MAX_CHARS} characters`,
});

/** A call that brought no picture: the few words for Joy, as a refusal, and whether a request went to OpenAI for it. */
function noPicture(result, asked) {
  return { result, isError: true, picture: null, asked };
}

/**
 * The one request to OpenAI for one picture. Returns { type, data } when
 * OpenAI made it: the picture's content type, told by its first bytes,
 * and its bytes as base64. Returns 'refused' when OpenAI's safety check
 * does not take the description, and 'failed' for everything else: a
 * refused key, no credit, a spend limit, too many requests in a minute,
 * a failure at OpenAI, no answer in TIMEOUT_MS, an answer with no
 * picture in it.
 *
 * A failure writes one line into the log: the status and OpenAI's own
 * code for it, or what went wrong on the way. Never the key and never
 * the description. Never OpenAI's message either: for a refused key it
 * holds a part of the key. A refusal writes nothing.
 *
 * `leaving` stops the request when the wallet has gone away. That is
 * answered 'failed' too, with no line in the log: the caller looks at
 * `leaving` itself. A redirect is not followed.
 */
async function askOpenAI(description, anopodId, leaving) {
  const failed = (why) => {
    console.log('joy picture failed:', why);
    return 'failed';
  };

  let response;
  let answer = null;
  try {
    response = await fetch(OPENAI_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.joy.openaiApiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: env.joy.pictureModel,
        prompt: description,
        size: env.joy.pictureSize,
        quality: env.joy.pictureQuality,
        output_format: env.joy.pictureFormat,
        n: 1,
        safety_identifier: toHex(sha256(anopodId)),
      }),
      redirect: 'manual',
      signal: AbortSignal.any([leaving, AbortSignal.timeout(TIMEOUT_MS)]),
    });
    // The time limit covers the answer's body too. An answer that is no
    // JSON is told by its status alone.
    const text = await response.text();
    try {
      answer = JSON.parse(text);
    } catch {
      answer = null;
    }
  } catch (err) {
    if (leaving.aborted) return 'failed';
    if (err.name === 'TimeoutError') return failed(`no answer in ${TIMEOUT_MS / 1000} seconds`);
    const code = typeof err.cause?.code === 'string' ? ` ${err.cause.code}` : '';
    return failed(`${String(err.message).slice(0, 100)}${code}`);
  }

  if (response.status < 200 || response.status > 299) {
    const error = isObject(answer) && isObject(answer.error) ? answer.error : {};
    if (response.status === 400 && error.code === 'moderation_blocked') return 'refused';
    // OpenAI names a failure by a code, such as invalid_api_key or
    // credit_balance_exhausted, and where it gives none, by a type.
    const name = [error.code, error.type].find((word) => typeof word === 'string' && word !== '');
    return failed(name === undefined ? `status ${response.status}` : `status ${response.status} ${name.slice(0, 60)}`);
  }

  // The picture is in the answer as base64. It is taken for a picture
  // when its bytes begin as a JPEG, a PNG or a WebP file does and name a
  // width and a height.
  const encoded = isObject(answer) && Array.isArray(answer.data) && isObject(answer.data[0]) ? answer.data[0].b64_json : null;
  const bytes = typeof encoded === 'string' ? Buffer.from(encoded, 'base64') : Buffer.alloc(0);
  const type = IMAGE_CONTENT_TYPES.find((candidate) => imageSize(candidate, bytes) !== null);
  if (type === undefined) return failed(`status ${response.status} with no picture in the answer`);
  return { type, data: bytes.toString('base64') };
}

/**
 * Carries out one call of make_picture.
 *
 *   input     the call's input, as the model wrote it
 *   used      whether a request has gone to OpenAI for this message
 *             already
 *   anopodId  the pod's id, a Buffer. Only its SHA-256 hash leaves
 *   leaving   an AbortSignal that fires when the wallet has gone away
 *
 * Returns { result, isError, picture, asked }: the few words Joy is told
 * and whether they are a refusal; the picture as { type, data,
 * description } when OpenAI made one, otherwise null; and whether a
 * request went to OpenAI.
 *
 * One message gets one request to OpenAI, whatever came of it. A call
 * after it is answered without one. So is a call whose description is
 * empty or longer than DESCRIPTION_MAX_CHARS: such a call does not use
 * the message's one request up, and Joy may call again. Never throws.
 */
export async function makePicture({ input, used, anopodId, leaving }) {
  if (used) return noPicture(OUTCOMES.second, false);
  const description = isObject(input) && typeof input.description === 'string' ? input.description.trim() : '';
  if (description === '') return noPicture(OUTCOMES.empty, false);
  if (description.length > DESCRIPTION_MAX_CHARS) return noPicture(OUTCOMES.long, false);

  const made = await askOpenAI(description, anopodId, leaving);
  if (made === 'refused') return noPicture(OUTCOMES.refused, true);
  if (made === 'failed') return noPicture(OUTCOMES.failed, true);
  return { result: OUTCOMES.made, isError: false, picture: { type: made.type, data: made.data, description }, asked: true };
}
