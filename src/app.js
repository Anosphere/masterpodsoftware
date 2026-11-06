import cors from 'cors';
import express from 'express';
import { anopodsRouter } from './anopods/anopods.router.js';
import { anosAccountsRouter } from './anos-accounts/anos-accounts.router.js';
import { attestingRouter } from './attesting/attesting.router.js';
import { authRouter } from './auth/auth.router.js';
import { chatRouter } from './chat/chat.router.js';
import { env } from './config/env.js';
import { healthRouter } from './health/health.router.js';
import { marketplaceRouter } from './marketplace/marketplace.router.js';
import { errorHandler } from './middleware/error-handler.js';
import { notFound } from './middleware/not-found.js';
import { notificationsRouter } from './notifications/notifications.router.js';
import { recoveryRouter } from './recovery/recovery.router.js';
import { securityRouter } from './security/security.router.js';
import { vouchingRouter } from './vouching/vouching.router.js';

/**
 * The largest JSON body accepted: a security bucket request full of images,
 * each base64 (about 4/3 of its bytes, rounded up to 1.4), plus a megabyte
 * for everything else.
 */
const JSON_LIMIT_BYTES = Math.ceil(env.maxImagesPerRequest * env.maxImageBytes * 1.4) + 1024 * 1024;

/**
 * Builds and returns the Express application.
 * Kept separate from the server so it can be imported without opening a
 * network port.
 */
export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(cors({ origin: env.webOrigins }));
  app.use(express.json({ limit: JSON_LIMIT_BYTES }));

  app.get('/', (req, res) => {
    res.type('text/plain').send('masterpodsoftware');
  });

  // Feature routers. Each feature folder owns its router, service, etc.
  app.use('/health', healthRouter);
  app.use(authRouter); // owns /challenge
  app.use(notificationsRouter); // owns /list-notifications and /mark-notifications-read
  app.use(anopodsRouter); // owns /create-anopod, /unlock, /check-username, /check-anopod-status, /get-anopod-profile, /get-anopod-session-keys, /complete-setup
  app.use(vouchingRouter); // owns /search-usernames, /send-vouch-request, /list-vouch-requests, /approve-vouch-request, /decline-vouch-request
  app.use(securityRouter); // owns /add-to-security-bucket-one, /add-to-security-bucket-two, /list-security-records
  app.use(chatRouter); // owns the thirteen chat routes, /create-chat-room to /get-chat-public-keys
  app.use(marketplaceRouter); // owns /create-listing, /close-listing, /list-listings, /get-listing
  app.use(anosAccountsRouter); // owns /create-anos-account, /mark-anos-account-submitted, /list-anos-accounts, /get-anos-account
  app.use(recoveryRouter); // owns /open-recovery-case, /unlock-recovery-pod, /get-recovery-pod
  app.use(attestingRouter); // owns the fourteen attestor routes, /list-attestors to /dismiss-attestor-case, and the person's /list-my-cases, /get-my-case, /share-lookup-id, /add-dispute-evidence

  // Order matters: these must come after every router.
  app.use(notFound);
  app.use(errorHandler);

  return app;
}
