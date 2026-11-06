import { withTransaction } from '../db/transaction.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import {
  DIRECTIONS,
  SORT_KEYS,
  closeListing,
  findListing,
  findListingItem,
  insertListing,
  listListings,
} from './listings.queries.js';

/**
 * The marketplace: listings of anos for a fiat currency. Until 2026-11-06
 * each had its own marketplace chat room where the owner met whoever asked
 * to join; since then whoever connects opens a private room about the
 * listing (/create-chat-room with a listingId, in the chat feature) and the
 * listing has no room of its own. Each function runs its route's checks in
 * the spec's order (section 5) and returns ok(status, body) or
 * refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

const SIDES = ['buy', 'sell'];
const STATUSES = ['open', 'closed', 'any']; // the /list-listings filter; 'any' (2026-11-06) is both
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const COUNTRY_PATTERN = /^[A-Z]{2}$/;

/** quantity: a positive integer of millionths that fits a BIGINT. */
const QUANTITY_PATTERN = /^[1-9][0-9]*$/;
const MAX_BIGINT = 2n ** 63n - 1n;

/** price: a decimal string with at most 8 decimals; NUMERIC(24, 8) leaves 16 digits before the point. */
const PRICE_PATTERN = /^(0|[1-9][0-9]{0,15})(\.[0-9]{1,8})?$/;

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
 * POST /create-listing. Body { side, quantity, currency, country, price }.
 * The listing only, with no room (2026-11-06); `hpkeKey`, which an older
 * client still sends, is optional and ignored when it is a string.
 */
export async function createListing(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  for (const field of ['side', 'quantity', 'currency', 'country', 'price']) {
    if (typeof body[field] !== 'string') return refuse(400, BAD_SHAPE);
  }
  if (body.hpkeKey !== undefined && body.hpkeKey !== null && typeof body.hpkeKey !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const { side, quantity, currency, country, price } = body;
  if (!SIDES.includes(side)) return refuse(400, 'side must be buy or sell');
  if (!isQuantity(quantity)) return refuse(400, 'invalid quantity');
  if (!CURRENCY_PATTERN.test(currency)) return refuse(400, 'invalid currency');
  if (!COUNTRY_PATTERN.test(country)) return refuse(400, 'invalid country');
  if (!isPrice(price)) return refuse(400, 'invalid price');

  const listingId = randomId();
  await withTransaction((client) =>
    insertListing(client, {
      listingId,
      chatRoomId: null,
      anopodId: anopod.anopodId,
      side,
      quantity,
      currency,
      country,
      price,
    }),
  );
  return ok(201, { listingId: toHex(listingId), chatRoomId: null });
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

/** POST /get-listing. Body { listingId }. One listing, open or closed, in the form of /list-listings (2026-11-06). */
export async function get(body) {
  if (!isObject(body) || typeof body.listingId !== 'string') return refuse(400, BAD_SHAPE);
  const listingId = decodeId(body.listingId);
  const listing = listingId === null ? null : await findListingItem(listingId);
  if (listing === null) return refuse(404, 'listing not found');
  return ok(200, { listing });
}

/**
 * POST /list-listings. Body, all optional: { side, currency, country,
 * status, mine, sortBy, sortDirection, limit, offset }; `status` 'any' and
 * `mine` (true for the caller's own listings only) since 2026-11-06.
 */
export async function list(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const side = oneOf(body.side, SIDES, null);
  if (side === undefined) return refuse(400, 'invalid side');
  const status = oneOf(body.status, STATUSES, 'open');
  if (status === undefined) return refuse(400, 'invalid status');
  const mine = body.mine ?? false;
  if (typeof mine !== 'boolean') return refuse(400, 'invalid mine');
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

  const listings = await listListings(
    { status: status === 'any' ? null : status, side, currency, country, anopodId: mine ? anopod.anopodId : null },
    { sortBy, sortDirection, limit, offset },
  );
  return ok(200, { listings });
}
