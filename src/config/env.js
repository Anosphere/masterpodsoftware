/**
 * Reads and validates environment variables once at startup.
 * Everything else imports `env` from here instead of touching process.env,
 * so a missing or malformed variable fails at boot rather than mid-request.
 */
function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

/**
 * An optional variable that must be a positive integer when set; `fallback`
 * when it is not set.
 */
function optionalInteger(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive integer, got "${value}"`);
  }
  return Number(value);
}

/**
 * An optional percent: a positive integer of at most `max` when set;
 * `fallback` when it is not set.
 */
function optionalPercent(name, fallback, max) {
  const value = optionalInteger(name, fallback);
  if (value > max) throw new Error(`${name} must be at most ${max}, got "${value}"`);
  return value;
}

/**
 * An optional comma-separated list; `fallback` when it is not set. Items are
 * trimmed and empty ones dropped; a value with no item at all is an error.
 */
function optionalList(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  const items = value.split(',').map((item) => item.trim()).filter((item) => item !== '');
  if (items.length === 0) throw new Error(`${name} must list at least one item, got "${value}"`);
  return Object.freeze(items);
}

/** The five local validators of a development machine, the default VALIDATOR_URLS. */
const LOCAL_VALIDATOR_URLS = Object.freeze([1, 2, 3, 4, 5].map((n) => `http://localhost:300${n}`));

export const env = Object.freeze({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: Number(process.env.PORT) || 3100,

  // Variable names follow libpq (PGHOST, PGUSER, ...), so psql and other
  // PostgreSQL tools read the same env file without any translation.
  db: Object.freeze({
    host: process.env.PGHOST ?? '127.0.0.1',
    port: Number(process.env.PGPORT) || 5432,
    database: required('PGDATABASE'),
    user: required('PGUSER'),
    password: required('PGPASSWORD'),
  }),

  // The web app's origins, a comma-separated list (one locally; the wallet
  // and the moderator wallet one day): the CORS allow-list (src/app.js) and
  // the origins WebAuthn registrations and assertions may come from
  // (src/auth/webauthn.js).
  webOrigins: optionalList('WEB_ORIGIN', Object.freeze(['http://localhost:4200'])),

  // This server as the keyholders reach it. The banker packet's URL,
  // RECOVERY_POD_URL_BASE + /receive-recovery-share/<caseId>, is built from
  // it (spec 12.4.4); a trailing slash is dropped.
  recoveryPodUrlBase: (process.env.RECOVERY_POD_URL_BASE ?? 'http://localhost:3100').replace(/\/+$/, ''),

  // The WebAuthn relying party id the passkeys are bound to.
  rpId: process.env.RP_ID ?? 'localhost',

  // How long a session's ephemeral keys verify after /create-anopod or
  // /unlock registered them.
  ephemeralKeyHours: optionalInteger('EPHEMERAL_KEY_HOURS', 12),

  // How long a challenge from /challenge may be used.
  challengeSeconds: optionalInteger('CHALLENGE_SECONDS', 120),

  // How far a signed request's timestamp may be from the server clock,
  // each way. Nonces are kept twice this long.
  timestampWindowSeconds: optionalInteger('TIMESTAMP_WINDOW_SECONDS', 120),

  // Images (src/util/images.js): the largest decoded image, and how many a
  // security bucket request may carry. Together they size the JSON body
  // limit in src/app.js.
  maxImageBytes: optionalInteger('MAX_IMAGE_BYTES', 10_485_760),
  maxImagesPerRequest: optionalInteger('MAX_IMAGES_PER_REQUEST', 5),

  // The validators asked for the DAO stake list (src/dao/validators.client.js,
  // spec 15.6), a comma-separated list tried in order: the five local
  // validators by default, the doormen's URLs on the servers (the wallet's
  // list). A trailing slash is dropped.
  validatorUrls: Object.freeze(
    optionalList('VALIDATOR_URLS', LOCAL_VALIDATOR_URLS).map((url) => url.replace(/\/+$/, '')),
  ),

  // The DAO's dials (spec 15.7), answered to the wallet as `settings` by
  // /list-dao-proposals: the least DAO votes (whole staked anos) a pod needs
  // in the snapshot to post; the percent of all DAO votes a pending proposal
  // needs in support to go to a vote; the percent of the votes cast that for
  // must exceed (at most 99, so a tie fails); how long a proposal may collect
  // support (a week); how long an open proposal takes votes (two weeks).
  dao: Object.freeze({
    proposeMinVotes: optionalInteger('DAO_PROPOSE_MIN_VOTES', 1),
    proposalPercent: optionalPercent('DAO_PROPOSAL_PERCENT', 15, 100),
    passPercent: optionalPercent('DAO_PASS_PERCENT', 50, 99),
    pendingMinutes: optionalInteger('DAO_PENDING_MINUTES', 10_080),
    voteMinutes: optionalInteger('DAO_VOTE_MINUTES', 20_160),
  }),
});
