import { Router } from 'express';
import { challenge } from './auth.handlers.js';

/**
 * Auth feature router.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case.
 */
export const authRouter = Router();

authRouter.post('/challenge', challenge);
