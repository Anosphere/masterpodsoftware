import { decodeId } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { listFor, markRead, markReadUpTo, numbersFor } from './notifications.queries.js';

/** The default and the largest `limit` of /list-notifications. */
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

/** How many ids one /mark-notifications-read may carry. */
const MAX_MARK = 500;

/**
 * The twenty-one kinds of a notification: the names in the check on
 * notifications.kind (db/schema.sql; spec section 6). `kinds` of
 * /list-notifications takes these names and no other.
 */
const KINDS = [
  'vouchRequest', 'vouchApproved', 'vouchDeclined', 'vouched',
  'chatInvite', 'inviteAccepted', 'inviteDeclined',
  'joinRequest', 'joinApproved', 'joinDeclined',
  'tradeCaseOpened', 'disputeCaseOpened', 'caseScheduled',
  'caseDecided', 'caseDismissed', 'recoveryCaseScheduled',
  'passkeyAdded',
  'transferWaiting', 'recoveryMoveWaiting', 'recoveryCaseOpened',
  'alertSettingsChanged',
];

/** True when a body names a field: the value is there and not null. */
function named(value) {
  return value !== undefined && value !== null;
}

/** True for a whole number from `min` up to the largest one JavaScript keeps exact. */
function isNumberFrom(value, min) {
  return Number.isSafeInteger(value) && value >= min;
}

/** True for the `kinds` of /list-notifications: a list of 1 to 21 of the kinds, each of them once. */
function areKinds(value) {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= KINDS.length &&
    value.every((kind) => KINDS.includes(kind)) &&
    new Set(value).size === value.length
  );
}

/**
 * /list-notifications: body { unreadOnly, limit, since, before, kinds },
 * all optional. unreadOnly is false and limit 100 (at most 500) by
 * default. Since 2026-11-25 (spec section 34): `since` asks for the rows
 * with a `seq` above it, `before` for the rows with a `seq` below it (a
 * body names one of the two at most), and `kinds` for rows of these kinds
 * only. Every row carries its `seq`, and every answer `seq`, `count` and
 * `unread`: the highest `seq` of the caller's rows, how many notifications
 * the caller has, and how many of them are unread.
 */
export async function list(anopod, body) {
  if (!isObject(body) || (named(body.since) && named(body.before))) return refuse(400, 'bad request shape');
  const unreadOnly = body.unreadOnly ?? false;
  if (typeof unreadOnly !== 'boolean') return refuse(400, 'invalid unreadOnly');
  const limit = body.limit ?? DEFAULT_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) return refuse(400, 'invalid limit');
  const since = body.since ?? null;
  if (since !== null && !isNumberFrom(since, 0)) return refuse(400, 'invalid since');
  const before = body.before ?? null;
  if (before !== null && !isNumberFrom(before, 1)) return refuse(400, 'invalid before');
  const kinds = body.kinds ?? null;
  if (kinds !== null && !areKinds(kinds)) return refuse(400, 'invalid kinds');

  // The first statement decides: `seq`, `count` and `unread` come from one
  // state of the database, and the rows are read after it and never above
  // that `seq`. A row that is written between the two statements comes
  // with the next read. The other order could lose a row.
  const numbers = await numbersFor(anopod.anopodId);
  const notifications = await listFor(anopod.anopodId, {
    unreadOnly,
    limit,
    highest: numbers.seq,
    since,
    before,
    kinds,
  });
  return ok(200, { notifications, seq: numbers.seq, count: numbers.count, unread: numbers.unread });
}

/**
 * /mark-notifications-read: body { notificationNumbers }, 1 to 500 ids, or,
 * since 2026-11-25 (spec section 34), { upTo }, a number: every unread
 * notification of the caller with a `seq` of `upTo` or lower. A body names
 * one of the two, not both.
 */
export async function mark(anopod, body) {
  if (!isObject(body) || named(body.upTo) === named(body.notificationNumbers)) return refuse(400, 'bad request shape');
  if (named(body.upTo)) {
    if (!isNumberFrom(body.upTo, 0)) return refuse(400, 'invalid upTo');
    const marked = await markReadUpTo(anopod.anopodId, body.upTo);
    return ok(200, { marked });
  }
  if (!Array.isArray(body.notificationNumbers)) return refuse(400, 'bad request shape');
  const { notificationNumbers } = body;
  if (notificationNumbers.length < 1 || notificationNumbers.length > MAX_MARK) {
    return refuse(400, 'invalid notificationNumbers');
  }
  const numbers = notificationNumbers.map(decodeId);
  if (numbers.includes(null)) return refuse(400, 'invalid notificationNumbers');

  const marked = await markRead(anopod.anopodId, numbers);
  return ok(200, { marked });
}
