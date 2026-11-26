import { answer } from '../util/result.js';
import { askJoy, describeFailure, failureOf } from './joy.answer.js';
import { getJoyMemory, prepareAsk, recordTokens, setJoyMemory } from './joy.service.js';

/**
 * Route handlers for Joy (spec section 30). HTTP in and out only: the
 * caller is req.anopod and req.body is the route's own object. The
 * checking and storing lives in joy.service.js. The call to the company
 * whose model writes her answers goes through joy.answer.js, which picks
 * Anthropic or OpenAI (spec section 36).
 */

/**
 * How often an empty line goes out while an answer is awaited, in
 * milliseconds. The doormen in front of this server end a request that
 * carries no byte for 30 seconds.
 */
const BEAT_MS = 10_000;

/** POST /get-joy-memory */
export async function getJoyMemoryHandler(req, res) {
  answer(res, await getJoyMemory(req.anopod));
}

/** POST /set-joy-memory */
export async function setJoyMemoryHandler(req, res) {
  answer(res, await setJoyMemory(req.anopod, req.body));
}

/**
 * POST /ask-joy. A refusal of the checks is answered as every route
 * answers one, { error } with its status. Past the checks the answer is
 * a stream with status 200, lines of JSON with a line break after each
 * (application/x-ndjson):
 *
 *   { "text": "..." }      a piece of Joy's answer, as she writes it
 *   { "searching": true }  Joy starts a web search (spec section 32)
 *   { "drawing": true }    Joy starts on a picture (spec section 33)
 *   { "picture": { "type", "data", "description" } }
 *                          a picture that OpenAI made for her: its content
 *                          type, its bytes as base64, and the description
 *                          she wrote for it. One long line
 *   { "done": true, "stop": "end" | "length" | "refused", "memory": "<the file>" | null, "sources": [{ "title", "url" }] }
 *                          the last line of an answer that ended
 *   { "error": "<reason>" }  the last line of an answer that failed
 *
 * An empty line may come between them and means nothing. `memory` is the
 * member's whole memory file after Joy changed it, or null when she did
 * not. `sources` are the web pages Joy cited, ten at most, and an empty
 * list when she cited none.
 *
 * When the wallet goes away before the end, the call to the company
 * that answers is stopped, and so is a request for a picture that is
 * under way. The tokens and the web searches that the company counted,
 * and a picture that OpenAI made, are written either way.
 */
export async function askJoyHandler(req, res) {
  const prepared = await prepareAsk(req.anopod, req.body);
  if (!prepared.ok) return answer(res, prepared);
  const { history, memory, day, search, picture } = prepared.body;

  let stream = null; // the request to the company that answers, while one is under way
  const leaving = new AbortController(); // stops a request for a picture that is under way, and tells the call that the wallet has gone
  let gone = false; // the wallet's connection closed before the answer ended
  let ended = false;
  res.on('close', () => {
    if (ended) return;
    gone = true;
    leaving.abort();
    if (stream !== null) stream.abort();
  });

  res.status(200).set({ 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store' });
  res.flushHeaders();
  const write = (text) => {
    if (!gone) res.write(text);
  };
  const beat = setInterval(() => write('\n'), BEAT_MS);

  const tokens = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, searches: 0, pictures: 0 };
  try {
    const out = await askJoy({
      history,
      memory,
      search,
      picture,
      anopodId: req.anopod.anopodId,
      tokens,
      leaving: leaving.signal,
      onText: (text) => write(`${JSON.stringify({ text })}\n`),
      onSearch: () => write(`${JSON.stringify({ searching: true })}\n`),
      onDrawing: () => write(`${JSON.stringify({ drawing: true })}\n`),
      onPicture: (made) => write(`${JSON.stringify({ picture: made })}\n`),
      onStream: (started) => {
        stream = started;
        if (gone) started.abort();
      },
    });
    write(`${JSON.stringify({ done: true, stop: out.stop, memory: out.memory, sources: out.sources })}\n`);
  } catch (err) {
    const reason = failureOf(err);
    if (reason !== null) {
      console.log('joy failed:', describeFailure(err));
      write(`${JSON.stringify({ error: reason })}\n`);
    }
  } finally {
    clearInterval(beat);
    ended = true;
    res.end();
  }

  try {
    await recordTokens(req.anopod, day, tokens);
  } catch (err) {
    console.error('joy: the tokens, the web searches and the pictures of a message were not written:', err.message);
  }
}
