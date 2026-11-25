import { answer } from '../util/result.js';
import { askAnthropic, describeFailure, failureOf } from './joy.anthropic.js';
import { getJoyMemory, prepareAsk, recordTokens, setJoyMemory } from './joy.service.js';

/**
 * Route handlers for Joy (spec section 30). HTTP in and out only: the
 * caller is req.anopod and req.body is the route's own object. The
 * checking and storing lives in joy.service.js, the call to Anthropic in
 * joy.anthropic.js.
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
 *   { "done": true, "stop": "end" | "length" | "refused", "memory": "<the file>" | null, "sources": [{ "title", "url" }] }
 *                          the last line of an answer that ended
 *   { "error": "<reason>" }  the last line of an answer that failed
 *
 * An empty line may come between them and means nothing. `memory` is the
 * member's whole memory file after Joy changed it, or null when she did
 * not. `sources` are the web pages Joy cited, ten at most, and an empty
 * list when she cited none.
 *
 * When the wallet goes away before the end, the call to Anthropic is
 * stopped. The tokens and the web searches Anthropic counted are written
 * either way.
 */
export async function askJoyHandler(req, res) {
  const prepared = await prepareAsk(req.anopod, req.body);
  if (!prepared.ok) return answer(res, prepared);
  const { history, memory, day, search } = prepared.body;

  let stream = null; // the request to Anthropic that is under way
  let gone = false; // the wallet's connection closed before the answer ended
  let ended = false;
  res.on('close', () => {
    if (ended) return;
    gone = true;
    if (stream !== null) stream.abort();
  });

  res.status(200).set({ 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store' });
  res.flushHeaders();
  const write = (text) => {
    if (!gone) res.write(text);
  };
  const beat = setInterval(() => write('\n'), BEAT_MS);

  const tokens = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, searches: 0 };
  try {
    const out = await askAnthropic({
      history,
      memory,
      search,
      tokens,
      onText: (text) => write(`${JSON.stringify({ text })}\n`),
      onSearch: () => write(`${JSON.stringify({ searching: true })}\n`),
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
    console.error('joy: the tokens and the web searches of a message were not written:', err.message);
  }
}
