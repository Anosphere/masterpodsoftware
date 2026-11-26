import { env } from '../config/env.js';
import { sha256 } from '../crypto/hash.js';
import { toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { MAX_ROUNDS, MAX_SOURCES, SHARED_MEMORY, TITLE_MAX_CHARS, memberPart } from './joy.common.js';
import { READ_FILE_TOOL, readJoyFile } from './joy.files.js';
import { MEMORY_TOOLS, applyMemoryTool } from './joy.memory.js';
import { MAKE_PICTURE_TOOL, makePicture } from './joy.pictures.js';

/**
 * The call to OpenAI, one of the two companies whose model can write
 * Joy's answers (spec section 36). joy.answer.js hands a message here
 * when JOY_PROVIDER is openai. No package: fetch, Node's own, to OpenAI's
 * Responses API, as the request for a picture is (joy.pictures.js).
 *
 * One message to Joy is one request to OpenAI, and one more after each
 * round in which Joy called a tool of her own (a change of the memory
 * file, a read of one of her files, a picture). Every request carries, in
 * this order: the shared memory file, today's date and the member's
 * memory file, and the conversation. The answer is read as a stream, and
 * its text is handed on while it is being written.
 *
 * What Joy is told and what she can do is what joy.anthropic.js has: the
 * same two texts, her four tools with their names, words and inputs, and
 * a web search that the company runs inside the request. The four tools
 * are carried out by the same functions. Only their form in the request
 * is OpenAI's.
 *
 * OpenAI keeps no answer for later reading: `store` is false. So after a
 * round of her tools the answer's items go back as they came, the
 * model's thinking among them in its encrypted form.
 *
 * Joy can see a picture that a member sends her (spec section 37). The
 * member's new message then goes to OpenAI as one message of two parts,
 * the member's words and the picture, in every request that the message
 * takes. No other message carries a picture, and this server keeps none.
 */

/** Where an answer is asked for. */
const OPENAI_URL = 'https://api.openai.com/v1/responses';

/**
 * How long OpenAI may send nothing while a request is under way, in
 * milliseconds, before the request is given up. It runs from the moment
 * a request goes out and begins anew with every piece of the stream.
 * None runs between two requests. The empty lines that this server
 * writes keep the wallet's side waiting meanwhile.
 */
const SILENCE_MS = 120_000;

/**
 * A request that failed before its stream began is sent again, twice at
 * most: after half a second, and then after one second. Anthropic's
 * package does the same for a request to Anthropic.
 */
const RETRY_WAITS_MS = Object.freeze([500, 1000]);

/** A wait that OpenAI names in its Retry-After header is kept when it is under this many milliseconds. */
const RETRY_AFTER_MAX_MS = 60_000;

/**
 * OpenAI's words for a 429 that is the account's and not the minute's:
 * the credit is used up, or a limit on what the account may spend or use
 * is reached. They stand in the answer's `code` or in its `type`. Such a
 * request is not sent again.
 */
const ACCOUNT_CODES = Object.freeze(['credit_balance_exhausted', 'organization_spend_limit_exceeded', 'project_spend_limit_exceeded', 'organization_usage_limit_exceeded', 'insufficient_quota']);

/** The longest piece that is held back while it may still become a cited place, in characters. */
const HOLD_MAX_CHARS = 1000;

/** How the address of a cited place begins: one of these, the longer one first. */
const ADDRESS_STARTS = Object.freeze(['https://', 'http://']);

/** True when this server holds a key for OpenAI. */
export function joyIsOn() {
  return env.joy.openaiApiKey !== null;
}

/**
 * One of Joy's own tools in OpenAI's form, a function tool, made from
 * the definition that is there in Anthropic's form. `strict` makes
 * OpenAI hold an input to the shape that the tool asks for, and wants
 * `additionalProperties: false` on it. `eager_input_streaming` is
 * Anthropic's and is not sent.
 */
function asFunction(tool) {
  return Object.freeze({ type: 'function', name: tool.name, description: tool.description, parameters: { ...tool.input_schema, additionalProperties: false }, strict: true });
}

/** Her two memory tools and read_file: in every request, in this order. */
const OWN_TOOLS = Object.freeze([...MEMORY_TOOLS, READ_FILE_TOOL].map(asFunction));

/**
 * OpenAI's web search tool. OpenAI runs the searches itself, inside the
 * request. Nothing is sent with it: no country, so OpenAI's search takes
 * its own default.
 */
const WEB_SEARCH_TOOL = Object.freeze({ type: 'web_search' });

/** make_picture, the last tool of a request that may have a picture made. */
const PICTURE_TOOL = asFunction(MAKE_PICTURE_TOOL);

/** The wallet went away and the call was stopped here: nobody is left to tell. */
class WalletLeft extends Error {
  constructor() {
    super('the wallet went away');
    this.name = 'WalletLeft';
  }
}

/**
 * A call that failed. `reason` is what the wallet is told: 'joy busy',
 * 'joy unavailable' or 'joy was cut off'. The message is the log's line:
 * the status, OpenAI's own code for the failure or, where it gives none,
 * its type, and the part of the request that it names. Never OpenAI's
 * message, which for a refused key holds a part of the key, and never a
 * member's text. `again` says that the request may be sent once more,
 * and `retryAfter` is OpenAI's Retry-After header for it.
 */
class JoyFailure extends Error {
  constructor(reason, words, { again = false, retryAfter = null } = {}) {
    super(words);
    this.name = 'JoyFailure';
    this.reason = reason;
    this.again = again;
    this.retryAfter = retryAfter;
  }
}

/** A word of OpenAI's for the log, or null when it is none: a text that is not empty, cut at `most` characters. */
function word(value, most) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim().slice(0, most) : null;
}

/** How a request broke on the way, for the log: the error's name and Node's code for it. */
function breakOf(err) {
  const code = typeof err?.cause?.code === 'string' ? err.cause.code : typeof err?.code === 'string' ? err.code : null;
  return [word(err?.name, 40) ?? 'Error', code === null ? null : code.slice(0, 40)].filter((one) => one !== null).join(' ');
}

/**
 * `utm_source=openai` taken off an address where it is the address's
 * last parameter: at the address's end, or right before the part that a
 * # sign begins. OpenAI ends each cited address with it: a tag that
 * tells the page's site where the visit came from.
 */
export function withoutTag(address) {
  return address.replace(/[?&]utm_source=openai(?=#|$)/, '');
}

/**
 * A reader of one piece of text that began with a round bracket. It is
 * handed the piece's further letters one at a time, and says after each
 * whether the piece is now a whole cited place ('whole'), can still
 * become one with more letters ('open'), or cannot ('none'). A cited
 * place is ([words](address)): the words hold no line break and no
 * square bracket that closes, the address begins http:// or https:// and
 * holds no space, and round brackets inside the address count in pairs,
 * as Wikipedia's addresses have them, so the address ends at the bracket
 * that closes the link. A piece of more than HOLD_MAX_CHARS characters
 * is none.
 *
 * The reader keeps where it stands in the piece, so each letter is
 * looked at once. To read the whole piece again for every new letter
 * would hold this server for seconds on a long text of brackets.
 */
function readPlace() {
  // What the next letter is: the bracket that opens the words ('start'),
  // the words, the bracket that opens the address ('link'), the address,
  // or the bracket after the link ('closed').
  let part = 'start';
  let size = 1; // the piece's length so far, its first bracket counted
  let begun = ''; // the address's first letters, until they show its beginning whole
  let depth = 0; // round brackets that are open inside the address
  return (letter) => {
    size += letter.length;
    if (size > HOLD_MAX_CHARS) return 'none';
    if (part === 'start') {
      if (letter !== '[') return 'none';
      part = 'words';
    } else if (part === 'words') {
      if (letter === '\n' || letter === '\r') return 'none';
      if (letter === ']') part = 'link';
    } else if (part === 'link') {
      if (letter !== '(') return 'none';
      part = 'address';
    } else if (part === 'address') {
      if (begun.length < ADDRESS_STARTS[0].length) {
        begun += letter;
        if (!ADDRESS_STARTS.some((start) => (begun.length >= start.length ? begun.startsWith(start) : start.startsWith(begun)))) return 'none';
      }
      if (/\s/.test(letter)) return 'none';
      if (letter === '(') depth += 1;
      else if (letter === ')') {
        if (depth > 0) depth -= 1;
        // The link is closed. The place is whole when the next letter
        // closes the round brackets around it.
        else part = 'closed';
      }
    } else {
      return letter === ')' ? 'whole' : 'none';
    }
    return 'open';
  };
}

/**
 * The cut of the cited places out of Joy's text, while the text streams
 * (spec section 36). OpenAI's model writes each page that it cites into
 * its text, as a link in round brackets with a space before it:
 *
 *   ... about 34 baht. ([bot.or.th](https://www.bot.or.th/x?utm_source=openai))
 *
 * The wallet shows Joy's words as she wrote them and lists the pages
 * under her answer, so such a place is taken out here. OpenAI's own mark
 * for a place comes after the place's letters, so the cut cannot wait
 * for it: it works by the form of a place (readPlace). When OpenAI
 * changes that form, this function and readPlace are the two to change.
 *
 * `onText` gets the text that goes on. Returns { push, end }: `push`
 * takes each piece of the model's text as it comes, and `end` is called
 * when no more text follows what was pushed.
 *
 * A piece is handed on at once, but for two things that are held back
 * until it can be told: the spaces at a piece's end, and everything from
 * a round bracket on for as long as that can still become a cited place.
 * A whole place is dropped, with the spaces before it. What turns out to
 * be none goes on as it is. So does a held piece of more than
 * HOLD_MAX_CHARS characters. At the end what is held goes on as it is,
 * except spaces, which are dropped.
 */
export function makeCut(onText) {
  let spaces = ''; // spaces that are held back
  let held = ''; // a piece from a round bracket on that may still become a cited place
  let place = null; // the reader of that piece
  let out = '';

  const take = (letter) => {
    if (held !== '') {
      held += letter;
      const state = place(letter);
      if (state === 'open') return;
      const was = held;
      held = '';
      if (state === 'whole') {
        spaces = '';
        return;
      }
      // Not a place: its first bracket goes on, and the rest is looked at
      // again, since a place can begin inside it.
      out += spaces + was[0];
      spaces = '';
      for (const next of was.slice(1)) take(next);
      return;
    }
    if (letter === ' ') spaces += letter;
    else if (letter === '(') {
      held = letter;
      place = readPlace();
    } else {
      out += spaces + letter;
      spaces = '';
    }
  };
  const flush = () => {
    if (out !== '') onText(out);
    out = '';
  };
  return {
    push(piece) {
      for (const letter of piece) take(letter);
      flush();
    },
    end() {
      if (held !== '') out += spaces + held;
      held = '';
      spaces = '';
      flush();
    },
  };
}

/** A count of OpenAI's as a number of 0 or more: a missing one, and anything that is no whole number above 0, is 0. */
function count(value) {
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

/**
 * Adds one answer's token counts and its count of web searches to
 * `tokens`, with the meaning that the columns of joy_usage have. OpenAI's
 * `input_tokens` holds the tokens read from its cache and the tokens
 * written to it, where Anthropic's count leaves both out. So `input`
 * gets what is left without the two: the tokens at the full price. It is
 * never less than 0: the table refuses a number below 0, and the
 * message's counts would be lost. The searches are the steps of the
 * search tool that are a search, which are the ones OpenAI charges: a
 * page that the tool opens, or a look inside a page, is none.
 */
function addUsage(tokens, usage, items) {
  const all = count(usage?.input_tokens);
  const read = count(usage?.input_tokens_details?.cached_tokens);
  const written = count(usage?.input_tokens_details?.cache_write_tokens);
  tokens.input += Math.max(0, all - read - written);
  tokens.output += count(usage?.output_tokens);
  tokens.cacheRead += read;
  tokens.cacheWrite += written;
  tokens.searches += items.filter((item) => item.type === 'web_search_call' && item.action?.type === 'search').length;
}

/**
 * Adds the web pages that one answer of OpenAI's cites to `sources`,
 * each as { title, url }. OpenAI marks each cited place of a text: a
 * part of a message carries `annotations`, and a mark of the type
 * url_citation holds the page's address and its title. Taken in their
 * order, each address once, MAX_SOURCES at most, and only an address
 * that begins with https:// or http://. An address goes on without
 * OpenAI's tag (withoutTag). A title is cut at TITLE_MAX_CHARS, and a
 * page without one gets an empty title. The pages come from the marks
 * and not from the text, so they are listed also when the cut did not
 * know a place's form. An answer from one of OpenAI's own services,
 * such as its weather service, has no mark and so no source.
 */
function addSources(sources, items) {
  for (const item of items) {
    if (item.type !== 'message' || !Array.isArray(item.content)) continue;
    for (const part of item.content) {
      if (!isObject(part) || !Array.isArray(part.annotations)) continue;
      for (const mark of part.annotations) {
        if (sources.length === MAX_SOURCES) return;
        if (!isObject(mark) || mark.type !== 'url_citation' || typeof mark.url !== 'string') continue;
        if (!mark.url.startsWith('https://') && !mark.url.startsWith('http://')) continue;
        const url = withoutTag(mark.url);
        if (sources.some((source) => source.url === url)) continue;
        const title = typeof mark.title === 'string' ? mark.title.trim().slice(0, TITLE_MAX_CHARS) : '';
        sources.push({ title, url });
      }
    }
  }
}

/** An item of an answer as it goes back in the next request: as it came, without the one field that OpenAI does not take back, `created_by`. */
function backOf(item) {
  const { created_by: _maker, ...rest } = item;
  return rest;
}

/** Waits `ms` milliseconds. Ends at once, with WalletLeft, when the wallet goes away meanwhile. */
function pause(ms, leaving) {
  return new Promise((resolve, reject) => {
    if (leaving.aborted) {
      reject(new WalletLeft());
      return;
    }
    const left = () => {
      clearTimeout(timer);
      reject(new WalletLeft());
    };
    const timer = setTimeout(() => {
      leaving.removeEventListener('abort', left);
      resolve();
    }, ms);
    leaving.addEventListener('abort', left, { once: true });
  });
}

/** The wait before a request is sent again: the one that OpenAI's Retry-After names, in seconds or as a date, when that is above 0 and under RETRY_AFTER_MAX_MS; otherwise `fallback`. */
function waitOf(retryAfter, fallback) {
  if (typeof retryAfter !== 'string' || retryAfter.trim() === '') return fallback;
  const seconds = Number(retryAfter);
  const ms = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(retryAfter) - Date.now();
  return ms > 0 && ms < RETRY_AFTER_MAX_MS ? ms : fallback;
}

/**
 * One request to OpenAI, sent once, and its answer read to the end.
 *
 *   body      the request, as JSON text
 *   leaving   the caller's signal for a wallet that has gone away
 *   onStream  called with an object whose abort() stops this request
 *   onEvent   called with each event of the stream, and with `seen`
 *
 * The answer is a stream of blocks with an empty line between them. A
 * block's data lines hold one JSON object with a `type`. The stream is
 * read as bytes and made text only where a whole character has come: a
 * piece can end in the middle of a Thai letter.
 *
 * Returns `seen`: { done, final, error, refusal }, which onEvent fills.
 * `final` is the response of the stream's last event.
 *
 * Throws WalletLeft when the request was stopped for the wallet. Throws
 * a JoyFailure for everything else. One that failed before the stream
 * began, in a way that a second try can mend, says so (`again`): a 408,
 * a 409, a 429 that is not the account's, a status from 500 on, and
 * OpenAI out of reach. Whatever goes wrong once the stream has begun is
 * 'joy was cut off'. So is SILENCE_MS with nothing from OpenAI, wherever
 * the request stands then: before any answer, in the body of an answer
 * that is not a 200, or in the stream. Such a request is not sent again.
 */
async function sendOnce(body, leaving, onStream, onEvent) {
  const own = new AbortController(); // stops this request: the watch on silence, and the caller through onStream
  let silent = false; // the watch on silence ran out
  let unread = true; // the answer's body is not read to its end yet
  let watch = null;
  const heard = () => {
    clearTimeout(watch);
    watch = setTimeout(() => {
      silent = true;
      own.abort();
    }, SILENCE_MS);
  };
  // The request was stopped for the wallet: the caller's signal fired,
  // or the caller stopped this request, which it does for nothing else.
  const left = () => leaving.aborted || (own.signal.aborted && !silent);
  const quiet = (before) => new JoyFailure('joy was cut off', `${before}OpenAI sent nothing for ${SILENCE_MS / 1000} seconds`);

  onStream({ abort: () => own.abort() });
  heard();
  try {
    let response;
    try {
      response = await fetch(OPENAI_URL, {
        method: 'POST',
        headers: { Authorization: `Bearer ${env.joy.openaiApiKey}`, 'Content-Type': 'application/json', Accept: 'text/event-stream' },
        body,
        redirect: 'manual',
        signal: AbortSignal.any([leaving, own.signal]),
      });
    } catch (err) {
      if (silent) throw quiet('');
      if (left()) throw new WalletLeft();
      throw new JoyFailure('joy unavailable', `OpenAI out of reach: ${breakOf(err)}`, { again: true });
    }

    // OpenAI does not take the request, or cannot answer it now. Its
    // answer names the failure: { error: { code, type, param, message } }.
    // An answer that is no JSON is told by its status alone.
    if (response.status !== 200) {
      let text = '';
      try {
        text = await response.text();
        unread = false;
      } catch {
        // The answer's body did not come whole. When the watch on
        // silence stopped it, that is silence, and the request is not
        // sent again. Otherwise the status alone tells the failure.
        if (silent) throw quiet(`${response.status}, then `);
        if (left()) throw new WalletLeft();
      }
      let error = {};
      try {
        const answer = JSON.parse(text);
        if (isObject(answer) && isObject(answer.error)) error = answer.error;
      } catch {
        error = {};
      }
      const { status } = response;
      const account = status === 429 && [error.code, error.type].some((one) => ACCOUNT_CODES.includes(one));
      const busy = (status === 429 && !account) || status >= 500;
      const words = [String(status), word(error.code, 60) ?? word(error.type, 60), word(error.param, 100)].filter((one) => one !== null).join(' ');
      throw new JoyFailure(busy ? 'joy busy' : 'joy unavailable', words, { again: busy || status === 408 || status === 409, retryAfter: response.headers.get('retry-after') });
    }

    const seen = { done: [], final: null, error: null, refusal: false };
    const decoder = new TextDecoder();
    let rest = '';
    const takeBlocks = () => {
      for (;;) {
        const found = /\r?\n\r?\n/.exec(rest);
        if (found === null) return;
        const block = rest.slice(0, found.index);
        rest = rest.slice(found.index + found[0].length);
        const data = block
          .split(/\r?\n/)
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).replace(/^ /, ''))
          .join('\n');
        if (data === '' || data === '[DONE]') continue;
        let event = null;
        try {
          event = JSON.parse(data);
        } catch {
          event = null;
        }
        if (isObject(event) && typeof event.type === 'string') onEvent(event, seen);
      }
    };
    if (response.body === null) throw new JoyFailure('joy was cut off', '200, then the stream ended with no last event');
    const reader = response.body.getReader();
    for (;;) {
      let piece;
      try {
        piece = await reader.read();
      } catch (err) {
        // The answer is whole once its last event has come: what breaks
        // after it changes nothing.
        if (seen.final !== null) break;
        if (silent) throw quiet('200, then ');
        if (left()) throw new WalletLeft();
        throw new JoyFailure('joy was cut off', `200, then the connection broke: ${breakOf(err)}`);
      }
      if (piece.done) {
        unread = false;
        break;
      }
      heard();
      rest += decoder.decode(piece.value, { stream: true });
      takeBlocks();
    }
    rest += `${decoder.decode()}\n\n`;
    takeBlocks();

    if (seen.final === null) {
      if (seen.error === null) throw new JoyFailure('joy was cut off', '200, then the stream ended with no last event');
      throw new JoyFailure('joy was cut off', ['200, then an error in the stream:', word(seen.error.code, 60) ?? word(seen.error.type, 60), word(seen.error.param, 100)].filter((one) => one !== null).join(' '));
    }
    return seen;
  } finally {
    clearTimeout(watch);
    // A request that ends here with its answer not read to the end is
    // let go, so that its connection does not stay open.
    if (unread) own.abort();
  }
}

/**
 * One request to OpenAI with what a service needs around it: a request
 * that failed before its stream began is sent again, twice at most,
 * after a short wait (RETRY_WAITS_MS, or the wait that OpenAI names).
 * Not when the wallet has gone away. The failure that is thrown in the
 * end says how often the request was sent.
 */
async function send(body, leaving, onStream, onEvent) {
  for (let sent = 1; ; sent += 1) {
    if (leaving.aborted) throw new WalletLeft();
    try {
      return await sendOnce(body, leaving, onStream, onEvent);
    } catch (err) {
      if (!(err instanceof JoyFailure) || !err.again) throw err;
      if (sent > RETRY_WAITS_MS.length) throw new JoyFailure(err.reason, `${err.message}, sent ${sent} times`);
      await pause(waitOf(err.retryAfter, RETRY_WAITS_MS[sent - 1]), leaving);
    }
  }
}

/**
 * Sends one message to Joy and reads her answer. The same function as
 * askAnthropic() of joy.anthropic.js: the same things in, the same
 * things out and the same calls back.
 *
 *   history   the conversation, oldest first, the new message last:
 *             [{ role: 'user' | 'assistant', text }]. The last message
 *             also holds `upload`, { contentType, data }, when the
 *             member sent a picture with it (spec section 37): the
 *             picture's type and its bytes as base64
 *   memory    the member's memory file as the wallet sent it
 *   search    whether Joy may search the web for this message: 'on';
 *             'off' when web search is switched off by a setting; 'used'
 *             when the pod has used its searches of the day. Only with
 *             'on' the web search tool is in the request; with the other
 *             two a sentence tells Joy why she cannot search
 *   picture   whether Joy may have a picture made for this message, in
 *             the same three words. Only with 'on' make_picture is in
 *             the request
 *   anopodId  the pod's id, a Buffer. Its hash goes to OpenAI with every
 *             request, as `safety_identifier`, and nothing else of it.
 *             It is handed to makePicture() too, which sends the same
 *             hash
 *   tokens    { input, output, cacheRead, cacheWrite, searches,
 *             pictures }: each request's token counts and its count of
 *             web searches are added to it as it ends, and a picture
 *             when OpenAI made it, so the caller holds what was used
 *             even when a later request fails
 *   leaving   an AbortSignal that the caller fires when the wallet has
 *             gone away: a request that is under way is stopped by it,
 *             the one for an answer and the one for a picture, and
 *             after a read of a file no further request goes out
 *   onText    called with each piece of the answer's text as it comes
 *   onSearch  called each time a step of a web search starts
 *   onDrawing called each time Joy starts a call of make_picture
 *   onPicture called with a picture that OpenAI made, as { type, data,
 *             description }
 *   onStream  called with each request as it goes out, as an object
 *             with abort(), so the caller can stop it when the wallet
 *             has gone away
 *
 * Returns { stop, memory, sources }: how the answer ended, 'end',
 * 'length' (the model reached JOY_OPENAI_MAX_TOKENS) or 'refused'
 * (OpenAI's filter stopped it, or the model refused); the memory file
 * after Joy's changes, or null when she changed nothing; and the web
 * pages Joy cited, as addSources() gathers them, an empty list when she
 * cited none.
 *
 * Throws WalletLeft or a JoyFailure. failureOf() turns that into a
 * reason.
 */
export async function askOpenAI({ history, memory, search, picture, anopodId, tokens, leaving, onText, onSearch, onDrawing, onPicture, onStream }) {
  // The same tools stand in every request of one message, and what Joy
  // is told is made once for it. So is the code that stands for the pod.
  // OpenAI drops the thinking of an earlier round when the request's
  // beginning or that code differs between two requests.
  const tools = [...OWN_TOOLS, ...(search === 'on' ? [WEB_SEARCH_TOOL] : []), ...(picture === 'on' ? [PICTURE_TOOL] : [])];
  const head = [
    // The shared memory file carries a mark for OpenAI's prompt cache by
    // itself: it is the same for every member, so one member's request
    // keeps it ready for the next. OpenAI's field `instructions` is not
    // used: for this model OpenAI puts it behind the conversation and
    // bills it in full with every request.
    { role: 'developer', content: [{ type: 'input_text', text: SHARED_MEMORY, prompt_cache_breakpoint: { mode: 'explicit' } }] },
    { role: 'developer', content: [{ type: 'input_text', text: memberPart(memory, search, picture) }] },
  ];
  const who = toHex(sha256(anopodId));
  // The conversation, and after it what each round of her tools adds:
  // the answer's items as they came, then each tool's outcome. A message
  // goes as its words. The one message that came with a picture goes as
  // two parts, its words first and then the picture, as an address that
  // holds the picture itself (spec section 37). The picture's detail is
  // not set, so OpenAI's default holds. The list is built once for a
  // message, so the picture is in every request that the message takes.
  const items = history.map(({ role, text, upload }) => ({
    role,
    content: upload === undefined ? text : [{ type: 'input_text', text }, { type: 'input_image', image_url: `data:${upload.contentType};base64,${upload.data}` }],
  }));
  const sources = [];
  let file = memory;
  let asked = false; // whether this message's one request for a picture has gone out
  let wrote = false; // whether any text has gone to the caller yet
  // Whether the next text starts a new paragraph: the first text after a
  // round of her own tools, and the first text after a web search.
  let newParagraph = false;
  let searched = false; // whether a web search has started for this message
  const result = (stop) => ({ stop, memory: file === memory ? null : file, sources });

  const hand = (text) => {
    onText(newParagraph && wrote ? `\n\n${text}` : text);
    newParagraph = false;
    wrote = true;
  };
  // From the message's first web search on, her text goes through the
  // cut of the cited places. An answer for which she did not search is
  // handed on as it comes.
  const cut = makeCut(hand);
  const say = (text) => {
    if (searched) cut.push(text);
    else hand(text);
  };

  const onEvent = (event, seen) => {
    if (event.type === 'response.output_text.delta') {
      if (typeof event.delta === 'string' && event.delta !== '') say(event.delta);
    } else if (event.type === 'response.output_item.added') {
      if (!isObject(event.item)) return;
      if (event.item.type === 'web_search_call') {
        // A step of a web search starts: a search, a page that the tool
        // opens, a look inside a page. What it asks for is not read here.
        cut.end();
        searched = true;
        newParagraph = true;
        onSearch();
      } else if (picture === 'on' && event.item.type === 'function_call' && event.item.name === MAKE_PICTURE_TOOL.name) {
        // Joy starts a call of make_picture. The call is carried out
        // below, when this request has ended.
        onDrawing();
      }
    } else if (event.type === 'response.refusal.delta') {
      // The model refuses in its own words: they go on as her text, and
      // the answer ends as refused.
      seen.refusal = true;
      if (typeof event.delta === 'string' && event.delta !== '') say(event.delta);
    } else if (event.type === 'response.output_item.done') {
      if (isObject(event.item)) seen.done.push(event.item);
    } else if (event.type === 'response.completed' || event.type === 'response.incomplete' || event.type === 'response.failed') {
      if (isObject(event.response)) seen.final = event.response;
    } else if (event.type === 'error') {
      // OpenAI ends the stream with an error: its code and the part of
      // the request that it names, on the event itself or one level down.
      const error = isObject(event.error) ? event.error : event;
      seen.error = { code: error.code, type: isObject(event.error) ? error.type : null, param: error.param };
    }
  };

  for (let round = 1; round <= MAX_ROUNDS; round += 1) {
    const seen = await send(
      JSON.stringify({
        model: env.joy.openaiModel,
        store: false,
        stream: true,
        reasoning: { effort: env.joy.openaiEffort },
        max_output_tokens: env.joy.openaiMaxTokens,
        // The most steps of the web search tool in one request. OpenAI
        // counts it for a request, and it counts every step.
        ...(search === 'on' ? { max_tool_calls: env.joy.maxSearches } : {}),
        safety_identifier: who,
        include: ['reasoning.encrypted_content'],
        tools,
        input: [...head, ...items],
      }),
      leaving,
      onStream,
      onEvent,
    );
    const response = seen.final;

    // The answer's items: those of the stream's last event, and where
    // that lists none, the items as the stream finished them. An item of
    // thinking is taken with its encrypted content: from the stream's
    // own copy when the last event's has none.
    const listed = Array.isArray(response.output) && response.output.length > 0 ? response.output : seen.done;
    const output = listed.filter(isObject).map((item) => (item.type === 'reasoning' && typeof item.encrypted_content !== 'string' ? (seen.done.find((other) => other.id === item.id && typeof other.encrypted_content === 'string') ?? item) : item));
    addUsage(tokens, response.usage, output);
    addSources(sources, output);

    // A refusal in OpenAI's own form is a part of a message. Its words
    // went on as text while they came. When none came, they go on now.
    const refusals = output.filter((item) => item.type === 'message' && Array.isArray(item.content)).flatMap((item) => item.content.filter((part) => isObject(part) && part.type === 'refusal'));
    if (!seen.refusal) for (const part of refusals) if (typeof part.refusal === 'string' && part.refusal !== '') say(part.refusal);
    // No more text follows in this request: what the cut still holds
    // goes on.
    cut.end();

    if (response.status === 'failed') {
      throw new JoyFailure('joy was cut off', ['200, then the answer failed:', word(response.error?.code, 60) ?? word(response.error?.type, 60)].filter((one) => one !== null).join(' '));
    }
    // A refused or a cut-off answer can end in the middle of a tool's
    // input, so the tools of such an answer are never carried out.
    if (seen.refusal || refusals.length > 0) return result('refused');
    if (response.status === 'incomplete') return result(response.incomplete_details?.reason === 'content_filter' ? 'refused' : 'length');
    if (response.status !== 'completed') throw new JoyFailure('joy was cut off', `200, then the answer ended as ${word(response.status, 40) ?? 'nothing known'}`);

    const calls = output.filter((item) => item.type === 'function_call');
    if (calls.length === 0) return result('end');

    // The answer's items go back as they came, in their order, and after
    // them each tool's outcome, in the order of the calls. OpenAI has no
    // mark for a refusal: the outcome's words say it.
    const outcomes = [];
    for (const call of calls) {
      // A call's input comes as JSON text. One that is no JSON is handed
      // to the tool as it came, an input that is no object, which every
      // tool answers.
      let input;
      try {
        input = JSON.parse(call.arguments);
      } catch {
        input = call.arguments;
      }
      let done;
      if (picture === 'on' && call.name === MAKE_PICTURE_TOOL.name) {
        // A call of make_picture is carried out here, between two
        // requests for an answer, with one request to OpenAI's image
        // model. No watch on silence runs meanwhile: that request has a
        // time limit of its own. One message gets one such request. A
        // picture that OpenAI made is counted and handed to the caller
        // at once, before Joy's words about it are asked for.
        done = await makePicture({ input, used: asked, anopodId, leaving });
        asked = asked || done.asked;
        if (done.picture !== null) {
          tokens.pictures += 1;
          onPicture(done.picture);
        }
        // The wallet went away meanwhile: nobody is left to tell, so no
        // further request goes out.
        if (leaving.aborted) throw new WalletLeft();
      } else if (call.name === READ_FILE_TOOL.name) {
        // A call of read_file is carried out here too: one read of the
        // file's row from this server's database, at this moment. The
        // file's text is the tool's outcome, whole and alone.
        done = await readJoyFile(input);
        if (leaving.aborted) throw new WalletLeft();
      } else {
        done = applyMemoryTool(file, call.name, input);
        file = done.text;
      }
      outcomes.push({ type: 'function_call_output', call_id: call.call_id, output: done.result });
    }
    items.push(...output.map(backOf), ...outcomes);
    newParagraph = true;
  }
  return result('end');
}

/**
 * The reason a failed call is answered with, or null when there is
 * nobody to tell: the wallet went away and the call was stopped here.
 *
 *   'joy busy'         too many requests in a minute, or OpenAI fails
 *                      or is overloaded: a 429 that is not the
 *                      account's, and every status from 500 on
 *   'joy unavailable'  OpenAI is out of reach, the key is refused, the
 *                      credit or a limit of the account is used up, or
 *                      the request is one that OpenAI does not take:
 *                      every other status that is not 200
 *   'joy was cut off'  whatever goes wrong once the stream has begun,
 *                      and 120 seconds with nothing from OpenAI
 */
export function failureOf(err) {
  if (err instanceof WalletLeft) return null;
  if (err instanceof JoyFailure) return err.reason;
  return 'joy was cut off';
}

/** A failed call in a few words for the log: the status, OpenAI's code for the failure and the part of the request that it names. Never the key, never OpenAI's message, never a member's text. */
export function describeFailure(err) {
  if (err instanceof JoyFailure) return err.message;
  return `${err.name || 'Error'}: ${String(err.message).slice(0, 200)}`;
}
