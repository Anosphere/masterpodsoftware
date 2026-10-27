import { answer } from '../util/result.js';
import { list, mark } from './notifications.service.js';

/**
 * Route handlers for the notifications feature. HTTP in and out only: the
 * caller comes from requireSession as req.anopod, the route's object is
 * req.body; the service checks and answers.
 */

/** POST /list-notifications */
export async function listNotifications(req, res) {
  answer(res, await list(req.anopod, req.body));
}

/** POST /mark-notifications-read */
export async function markNotificationsRead(req, res) {
  answer(res, await mark(req.anopod, req.body));
}
