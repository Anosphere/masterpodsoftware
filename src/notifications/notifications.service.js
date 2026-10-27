import { decodeId } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { listFor, markRead } from './notifications.queries.js';

/** The default and the largest `limit` of /list-notifications. */
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

/** How many ids one /mark-notifications-read may carry. */
const MAX_MARK = 500;

/**
 * /list-notifications: body { unreadOnly, limit }, both optional,
 * unreadOnly false and limit 100 (at most 500) by default.
 */
export async function list(anopod, body) {
  if (!isObject(body)) return refuse(400, 'bad request shape');
  const unreadOnly = body.unreadOnly ?? false;
  if (typeof unreadOnly !== 'boolean') return refuse(400, 'invalid unreadOnly');
  const limit = body.limit ?? DEFAULT_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) return refuse(400, 'invalid limit');

  const notifications = await listFor(anopod.anopodId, unreadOnly, limit);
  return ok(200, { notifications });
}

/** /mark-notifications-read: body { notificationNumbers }, 1 to 500 ids. */
export async function mark(anopod, body) {
  if (!isObject(body) || !Array.isArray(body.notificationNumbers)) return refuse(400, 'bad request shape');
  const { notificationNumbers } = body;
  if (notificationNumbers.length < 1 || notificationNumbers.length > MAX_MARK) {
    return refuse(400, 'invalid notificationNumbers');
  }
  const numbers = notificationNumbers.map(decodeId);
  if (numbers.includes(null)) return refuse(400, 'invalid notificationNumbers');

  const marked = await markRead(anopod.anopodId, numbers);
  return ok(200, { marked });
}
