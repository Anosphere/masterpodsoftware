import { PROFILE_COLUMNS, profileFromRow } from '../anopods/anopods.queries.js';
import { pool } from '../db/pool.js';
import { toHex } from '../util/ids.js';

/**
 * SQL for the listings table. quantity is a BIGINT and price a
 * NUMERIC(24, 8); pg hands both over as decimal strings so nothing is lost,
 * and they stay strings on the wire.
 */

/** The sort keys /list-listings accepts, each mapped to its column. Nothing else reaches the SQL. */
const SORT_COLUMNS = { createdAt: 'created_at', price: 'price', quantity: 'quantity' };
const SORT_DIRECTIONS = { asc: 'ASC', desc: 'DESC' };

/** The sort keys and directions, for the service's validation. */
export const SORT_KEYS = Object.keys(SORT_COLUMNS);
export const DIRECTIONS = Object.keys(SORT_DIRECTIONS);

/**
 * A NUMERIC as pg returns it ('1.50000000') without its trailing zeros
 * ('1.5'; '2.00000000' is '2'). Integers pass through.
 */
export function trimDecimal(text) {
  return text.includes('.') ? text.replace(/0+$/, '').replace(/\.$/, '') : text;
}

/**
 * Writes a listing on `client`. quantity and price are decimal strings;
 * chatRoomId is null since 2026-11-06 (a listing no longer gets a room of
 * its own).
 */
export async function insertListing(client, { listingId, chatRoomId, anopodId, side, quantity, currency, country, price }) {
  await client.query(
    `INSERT INTO listings (listing_id, chat_room_id, anopod_id, side, quantity, currency, country, price)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [listingId, chatRoomId, anopodId, side, quantity, currency, country, price],
  );
}

function listingRow(row) {
  return {
    listingId: row.listing_id,
    chatRoomId: row.chat_room_id,
    anopodId: row.anopod_id,
    side: row.side,
    quantity: row.quantity,
    currency: row.currency,
    country: row.country,
    price: trimDecimal(row.price),
    status: row.status,
    createdAt: row.created_at,
  };
}

const LISTING_COLUMNS = 'listing_id, chat_room_id, anopod_id, side, quantity, currency, country, price, status, created_at';

/** The listing with this id (a Buffer), ids as Buffers, or null. */
export async function findListing(listingId, db = pool) {
  const { rows } = await db.query(`SELECT ${LISTING_COLUMNS} FROM listings WHERE listing_id = $1`, [listingId]);
  return rows.length === 0 ? null : listingRow(rows[0]);
}

/** The listing that owns this marketplace room, or null. */
export async function findListingByRoom(chatRoomId, db = pool) {
  const { rows } = await db.query(`SELECT ${LISTING_COLUMNS} FROM listings WHERE chat_room_id = $1`, [chatRoomId]);
  return rows.length === 0 ? null : listingRow(rows[0]);
}

/** Closes the listing on `client`. Returns true when it was open, false when it already was closed. */
export async function closeListing(client, listingId) {
  const { rowCount } = await client.query(
    `UPDATE listings SET status = 'closed' WHERE listing_id = $1 AND status = 'open'`,
    [listingId],
  );
  return rowCount === 1;
}

/**
 * The listings matching the filters, sorted and paged, each in wire form
 * with the owner's profile. `filters` is { status, side, currency, country,
 * anopodId } (status, side, currency and country null for "any"; anopodId
 * the owner as a Buffer, null for everyone's); `page` is { sortBy,
 * sortDirection, limit, offset }, sortBy one of SORT_KEYS and sortDirection
 * one of DIRECTIONS, already validated by the service. The filters are
 * parameters; only the whitelisted column and direction reach the SQL text.
 */
export async function listListings(filters, page) {
  const column = SORT_COLUMNS[page.sortBy];
  const direction = SORT_DIRECTIONS[page.sortDirection];
  if (column === undefined || direction === undefined) throw new TypeError('unknown sort');

  const { rows } = await pool.query(
    `SELECT l.listing_id, l.chat_room_id, l.side, l.quantity, l.currency, l.country, l.price, l.status, l.created_at,
            ${PROFILE_COLUMNS}
     FROM listings l
     JOIN anopods a ON a.anopod_id = l.anopod_id
     WHERE ($1::text IS NULL OR l.status = $1)
       AND ($2::text IS NULL OR l.side = $2)
       AND ($3::text IS NULL OR l.currency = $3)
       AND ($4::text IS NULL OR l.country = $4)
       AND ($7::bytea IS NULL OR l.anopod_id = $7)
     ORDER BY l.${column} ${direction}, l.listing_id
     LIMIT $5 OFFSET $6`,
    [filters.status, filters.side, filters.currency, filters.country, page.limit, page.offset, filters.anopodId],
  );
  return rows.map((row) => ({
    listingId: toHex(row.listing_id),
    chatRoomId: toHex(row.chat_room_id),
    owner: profileFromRow(row),
    side: row.side,
    quantity: row.quantity,
    currency: row.currency,
    country: row.country,
    price: trimDecimal(row.price),
    status: row.status,
    createdAt: row.created_at.toISOString(),
  }));
}

/**
 * One listing by id (a Buffer), open or closed, in the wire form of
 * listListings with the owner's profile, or null: the /list-listings select
 * for one id, for /get-listing (2026-11-06).
 */
export async function findListingItem(listingId) {
  const { rows } = await pool.query(
    `SELECT l.listing_id, l.chat_room_id, l.side, l.quantity, l.currency, l.country, l.price, l.status, l.created_at,
            ${PROFILE_COLUMNS}
     FROM listings l
     JOIN anopods a ON a.anopod_id = l.anopod_id
     WHERE l.listing_id = $1`,
    [listingId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    listingId: toHex(row.listing_id),
    chatRoomId: toHex(row.chat_room_id),
    owner: profileFromRow(row),
    side: row.side,
    quantity: row.quantity,
    currency: row.currency,
    country: row.country,
    price: trimDecimal(row.price),
    status: row.status,
    createdAt: row.created_at.toISOString(),
  };
}
