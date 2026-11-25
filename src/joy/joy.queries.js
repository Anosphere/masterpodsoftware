import { pool, query } from '../db/pool.js';

/**
 * SQL for Joy's two tables (spec section 30): joy_memories, one row per
 * pod, replaced in place; and joy_usage, one row per pod and day, which
 * since spec section 32 also counts the day's web searches and since
 * spec section 33 the day's pictures. The pod id and the blob are
 * Buffers of raw bytes, matching the BYTEA columns.
 */

/** The pod's row as { memoryBlob, updatedAt } (a Buffer and a Date), or null before the first set. */
export async function findMemory(anopodId, db = pool) {
  const { rows } = await db.query('SELECT memory_blob, updated_at FROM joy_memories WHERE anopod_id = $1', [anopodId]);
  return rows.length === 0 ? null : { memoryBlob: rows[0].memory_blob, updatedAt: rows[0].updated_at };
}

/**
 * Writes the pod's one row whole: an INSERT, or an UPDATE of the blob when
 * the row exists (the trigger stamps updated_at on that path). Returns the
 * row's updated_at Date.
 */
export async function upsertMemory(anopodId, memoryBlob) {
  const { rows } = await query(
    `INSERT INTO joy_memories (anopod_id, memory_blob) VALUES ($1, $2)
     ON CONFLICT (anopod_id) DO UPDATE SET memory_blob = EXCLUDED.memory_blob
     RETURNING updated_at`,
    [anopodId, memoryBlob],
  );
  return rows[0].updated_at;
}

/**
 * Counts one message for the pod on today's row (the day in UTC), unless
 * the row already holds `limit` messages. One statement, so two requests
 * at the same instant cannot both take the last place. Returns
 * { day, searches, pictures }: the row's day as text (YYYY-MM-DD), and
 * the web searches and the pictures the row holds, which are those of
 * the pod's earlier messages of the day (spec sections 32 and 33); or
 * null when the limit is reached.
 */
export async function countMessage(anopodId, limit) {
  const { rows } = await query(
    `INSERT INTO joy_usage (anopod_id, day, messages) VALUES ($1, (now() AT TIME ZONE 'UTC')::date, 1)
     ON CONFLICT (anopod_id, day) DO UPDATE SET messages = joy_usage.messages + 1
       WHERE joy_usage.messages < $2
     RETURNING day::text AS day, searches, pictures`,
    [anopodId, limit],
  );
  return rows.length === 0 ? null : { day: rows[0].day, searches: rows[0].searches, pictures: rows[0].pictures };
}

/**
 * Adds the tokens and the web searches Anthropic counted for one message,
 * and the pictures OpenAI made for it, to the pod's row of `day` (the
 * text countMessage returned). `tokens` is { input, output, cacheRead,
 * cacheWrite, searches, pictures }, each a number of 0 or more.
 */
export async function addTokens(anopodId, day, tokens) {
  await query(
    `UPDATE joy_usage
        SET input_tokens = input_tokens + $3,
            output_tokens = output_tokens + $4,
            cache_read_tokens = cache_read_tokens + $5,
            cache_write_tokens = cache_write_tokens + $6,
            searches = searches + $7,
            pictures = pictures + $8
      WHERE anopod_id = $1 AND day = $2::date`,
    [anopodId, day, tokens.input, tokens.output, tokens.cacheRead, tokens.cacheWrite, tokens.searches, tokens.pictures],
  );
}
