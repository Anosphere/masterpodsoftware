import { insertMember, insertRoom } from '../chat/chat.queries.js';
import { decodeBytes } from '../crypto/bytes.js';
import { withTransaction } from '../db/transaction.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { DIRECTIONS, SORT_KEYS, closeListing, findListing, insertListing, listListings } from './listings.queries.js';

/**
 * The marketplace: listings of anos for a fiat currency, each with its own
 * marketplace chat room where the owner meets whoever asks to join. Each
 * function runs its route's checks in the spec's order (section 5) and
 * returns ok(status, body) or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

const SIDES = ['buy', 'sell'];
const STATUSES = ['open', 'closed'];
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const COUNTRY_PATTERN = /^[A-Z]{2}$/;

/** quantity: a positive integer of millionths that fits a BIGINT. */
const QUANTITY_PATTERN = /^[1-9][0-9]*$/;
const MAX_BIGINT = 2n ** 63n - 1n;

/** price: a decimal string with at most 8 decimals; NUMERIC(24, 8) leaves 16 digits before the point. */
const PRICE_PATTERN = /^(0|[1-9][0-9]{0,15})(\.[0-9]{1,8})?$/;

/** A wrapped room key is 1661 bytes; the column takes up to 4096. */
const hpkeKeyLength = (n) => n >= 1 && n <= 4096;

/** Defaults and ceiling of the list. */
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

/** True for a quantity string the column accepts. */
function isQuantity(value) {
  return typeof value === 'string' && QUANTITY_PATTERN.test(value) && BigInt(value) <= MAX_BIGINT;
}

/** True for a price string above zero that the column accepts. */
function isPrice(value) {
  return typeof value === 'string' && PRICE_PATTERN.test(value) && /[1-9]/.test(value);
}

/** `value` when it is one of `allowed`, `fallback` when absent, undefined otherwise. */
function oneOf(value, allowed, fallback) {
  if (value === undefined || value === null) return fallback;
  return allowed.includes(value) ? value : undefined;
}

/** A whole number from `value` within [min, max], `fallback` when absent; undefined when invalid. */
function integerOption(value, fallback, min, max) {
  if (value === undefined || value === null) return fallback;
  return Number.isInteger(value) && value >= min && value <= max ? value : undefined;
}

/**
 * POST /create-listing. Body { side, quantity, currency, country, price,
 * hpkeKey }. The room, the owner's membership and key, and the listing in
 * one transaction.
 */
export async function createListing(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  for (const field of ['side', 'quantity', 'currency', 'country', 'price', 'hpkeKey']) {
    if (typeof body[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  const { side, quantity, currency, country, price } = body;
  if (!SIDES.includes(side)) return refuse(400, 'side must be buy or sell');
  if (!isQuantity(quantity)) return refuse(400, 'invalid quantity');
  if (!CURRENCY_PATTERN.test(currency)) return refuse(400, 'invalid currency');
  if (!COUNTRY_PATTERN.test(country)) return refuse(400, 'invalid country');
  if (!isPrice(price)) return refuse(400, 'invalid price');
  const hpkeKey = decodeBytes(body.hpkeKey, hpkeKeyLength);
  if (hpkeKey === null) return refuse(400, 'invalid hpkeKey');

  const listingId = randomId();
  const chatRoomId = randomId();
  await withTransaction(async (client) => {
    await insertRoom(client, { chatRoomId, creatorAnopodId: anopod.anopodId, type: 'marketplace', name: null });
    await insertMember(client, chatRoomId, anopod.anopodId, hpkeKey);
    await insertListing(client, {
      listingId,
      chatRoomId,
      anopodId: anopod.anopodId,
      side,
      quantity,
      currency,
      country,
      price,
    });
  });
  return ok(201, { listingId: toHex(listingId), chatRoomId: toHex(chatRoomId) });
}

/** POST /close-listing. Body { listingId }. The room and its members stay. */
export async function close(anopod, body) {
  if (!isObject(body) || typeof body.listingId !== 'string') return refuse(400, BAD_SHAPE);
  const listingId = decodeId(body.listingId);
  const listing = listingId === null ? null : await findListing(listingId);
  if (listing === null) return refuse(404, 'listing not found');
  if (!listing.anopodId.equals(anopod.anopodId)) return refuse(403, 'not your listing');
  if (listing.status !== 'open') return refuse(409, 'already closed');

  const closed = await withTransaction((client) => closeListing(client, listingId));
  if (!closed) return refuse(409, 'already closed');
  return ok(200, { listingId: toHex(listingId), status: 'closed' });
}

/**
 * POST /list-listings. Body, all optional: { side, currency, country,
 * status, sortBy, sortDirection, limit, offset }.
 */
export async function list(body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const side = oneOf(body.side, SIDES, null);
  if (side === undefined) return refuse(400, 'invalid side');
  const status = oneOf(body.status, STATUSES, 'open');
  if (status === undefined) return refuse(400, 'invalid status');
  const currency = body.currency ?? null;
  if (currency !== null && !(typeof currency === 'string' && CURRENCY_PATTERN.test(currency))) {
    return refuse(400, 'invalid currency');
  }
  const country = body.country ?? null;
  if (country !== null && !(typeof country === 'string' && COUNTRY_PATTERN.test(country))) {
    return refuse(400, 'invalid country');
  }
  const sortBy = oneOf(body.sortBy, SORT_KEYS, 'createdAt');
  if (sortBy === undefined) return refuse(400, 'invalid sortBy');
  const sortDirection = oneOf(body.sortDirection, DIRECTIONS, 'desc');
  if (sortDirection === undefined) return refuse(400, 'invalid sortDirection');
  const limit = integerOption(body.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  if (limit === undefined) return refuse(400, 'invalid limit');
  const offset = integerOption(body.offset, 0, 0, Number.MAX_SAFE_INTEGER);
  if (offset === undefined) return refuse(400, 'invalid offset');

  const listings = await listListings({ status, side, currency, country }, { sortBy, sortDirection, limit, offset });
  return ok(200, { listings });
}
