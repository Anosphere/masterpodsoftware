import { Router } from 'express';
import { requireSession } from '../auth/require-session.js';
import { listNotifications, markNotificationsRead } from './notifications.handlers.js';

/**
 * Notifications feature router. Both routes are level "session".
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const notificationsRouter = Router();

notificationsRouter.post('/list-notifications', requireSession, listNotifications);
notificationsRouter.post('/mark-notifications-read', requireSession, markNotificationsRead);
