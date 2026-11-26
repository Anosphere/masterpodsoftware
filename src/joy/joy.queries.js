import { pool, query } from '../db/pool.js';

/**
 * SQL for Joy's two tables (spec section 30): joy_memories, one row per
 * pod, replaced in place; and joy_usage, one row per pod and day, which
 * since spec section 32 also counts the day's web searches and since
 * spec section 33 the day's pictures. The pod id and the blob are
 * Buffers of raw bytes, matching the BYTEA columns.
 *
 * And, since spec section 35, for her third table: joy_files, one row
 * for each file that Joy reads with her tool read_file. The server reads
 * a row. scripts/joy-files.js alone writes the table; no route does.
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

/**
 * The text of one of Joy's files (spec section 35), by its name, or null
 * when the table holds no row of that name. One row is read at each
 * call, and nothing of it is kept in this process.
 */
export async function findFile(fileName) {
  const { rows } = await query('SELECT content FROM joy_files WHERE file_name = $1', [fileName]);
  return rows.length === 0 ? null : rows[0].content;
}

/**
 * For scripts/joy-files.js: what the table holds of the files named in
 * `fileNames`, as [ { name, content } ]. A name with no row is not in
 * the answer. `db` is the pool, or the client of the script's
 * transaction.
 */
export async function listStoredFiles(fileNames, db = pool) {
  const { rows } = await db.query('SELECT file_name, content FROM joy_files WHERE file_name = ANY($1::text[]) ORDER BY file_name', [fileNames]);
  return rows.map((row) => ({ name: row.file_name, content: row.content }));
}

/**
 * For scripts/joy-files.js: writes one file's row whole, on the client
 * of the script's transaction: an INSERT, or an UPDATE of the text when
 * the row exists (the trigger stamps updated_at on that path).
 */
export async function upsertFile(client, fileName, content) {
  await client.query(
    `INSERT INTO joy_files (file_name, content) VALUES ($1, $2)
     ON CONFLICT (file_name) DO UPDATE SET content = EXCLUDED.content`,
    [fileName, content],
  );
}
