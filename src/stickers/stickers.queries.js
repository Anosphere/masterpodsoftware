import { pool } from '../db/pool.js';

/**
 * SQL for the three sticker tables (2026-11-23, spec section 28):
 * sticker_sets, stickers and sticker_tags. The first two functions serve
 * the two routes. The rest serves scripts/stickers.js, the only writer of
 * the tables; no route writes them. A picture is a Buffer, matching the
 * BYTEA column. Reads take an optional `db` (a client inside a
 * transaction; the pool by default); writes take the transaction's client
 * first.
 */

// ---------------------------------------------------------------------------
// The two reads of the routes
// ---------------------------------------------------------------------------

/**
 * Every set in the order of the row, each with its stickers in their
 * order: [ { name, stickers: [ { number, tags: [ ... ] } ] } ]. One
 * statement, so the answer is the database at one moment, also while the
 * script writes. No picture is read. A set with no sticker is left out. A
 * sticker's tags come in the order of their bytes.
 */
export async function listStickerSets(db = pool) {
  const { rows } = await db.query(
    `SELECT s.set_name, t.number,
            COALESCE(array_agg(g.tag ORDER BY g.tag COLLATE "C") FILTER (WHERE g.tag IS NOT NULL), '{}') AS tags
     FROM sticker_sets s
     JOIN stickers t ON t.set_name = s.set_name
     LEFT JOIN sticker_tags g ON g.set_name = t.set_name AND g.number = t.number
     GROUP BY s.place, s.set_name, t.place, t.number
     ORDER BY s.place, s.set_name, t.place, t.number`,
  );
  const sets = [];
  for (const row of rows) {
    let set = sets.at(-1);
    if (set === undefined || set.name !== row.set_name) {
      set = { name: row.set_name, stickers: [] };
      sets.push(set);
    }
    set.stickers.push({ number: row.number, tags: row.tags });
  }
  return sets;
}

/** A sticker's picture, the WebP's bytes as a Buffer, or null when there is no such sticker. */
export async function findStickerPicture(setName, number, db = pool) {
  const { rows } = await db.query('SELECT image FROM stickers WHERE set_name = $1 AND number = $2', [setName, number]);
  return rows.length === 0 ? null : rows[0].image;
}

// ---------------------------------------------------------------------------
// The script's reads and writes
// ---------------------------------------------------------------------------

/** The row of sets as the database holds it, in its order: [ { name, place } ]. */
export async function listSetPlaces(db = pool) {
  const { rows } = await db.query('SELECT set_name, place FROM sticker_sets ORDER BY place, set_name');
  return rows.map((row) => ({ name: row.set_name, place: row.place }));
}

/**
 * What the database holds of one set's stickers, by number:
 * [ { number, place, imageHash, tags } ]. `imageHash` is the SHA-256 of
 * the stored picture, a Buffer, worked out by the database, so no picture
 * travels.
 */
export async function listStoredStickers(setName, db = pool) {
  const { rows } = await db.query(
    `SELECT t.number, t.place, sha256(t.image) AS image_hash,
            COALESCE(array_agg(g.tag) FILTER (WHERE g.tag IS NOT NULL), '{}') AS tags
     FROM stickers t
     LEFT JOIN sticker_tags g ON g.set_name = t.set_name AND g.number = t.number
     WHERE t.set_name = $1
     GROUP BY t.set_name, t.number
     ORDER BY t.number`,
    [setName],
  );
  return rows.map((row) => ({ number: row.number, place: row.place, imageHash: row.image_hash, tags: row.tags }));
}

/** Adds a set on `client`, at `place` in the row. */
export async function insertStickerSet(client, setName, place) {
  await client.query('INSERT INTO sticker_sets (set_name, place) VALUES ($1, $2)', [setName, place]);
}

/** Adds a sticker on `client`: its number, its place in the set and its picture. A number that is there throws a unique violation. */
export async function insertSticker(client, setName, number, place, image) {
  await client.query('INSERT INTO stickers (set_name, number, place, image) VALUES ($1, $2, $3, $4)', [
    setName,
    number,
    place,
    image,
  ]);
}

/** Gives a sticker another place in its set, on `client`. */
export async function updateStickerPlace(client, setName, number, place) {
  await client.query('UPDATE stickers SET place = $3 WHERE set_name = $1 AND number = $2', [setName, number, place]);
}

/** Adds tags to a sticker on `client`: `tags` is an array of strings, none of them the sticker's already. */
export async function insertStickerTags(client, setName, number, tags) {
  await client.query('INSERT INTO sticker_tags (set_name, number, tag) SELECT $1, $2, unnest($3::text[])', [
    setName,
    number,
    tags,
  ]);
}

/** Takes tags off a sticker on `client`: `tags` is an array of strings. */
export async function deleteStickerTags(client, setName, number, tags) {
  await client.query('DELETE FROM sticker_tags WHERE set_name = $1 AND number = $2 AND tag = ANY($3::text[])', [
    setName,
    number,
    tags,
  ]);
}
