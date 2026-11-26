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
 * An optional variable that must be 0 or a positive integer when set;
 * `fallback` when it is not set.
 */
function optionalCount(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be 0 or a positive integer, got "${value}"`);
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

/** An optional text: the value trimmed, or null when the variable is not set or empty. */
function optionalText(name) {
  const value = process.env[name];
  return value === undefined || value.trim() === '' ? null : value.trim();
}

/**
 * The settings of the security alerts (src/alerts/, spec section 25).
 * Each pair is all or nothing: with both lines the part is on, with
 * neither it is off, and one line without the other stops the boot. An
 * error names the variable and never its value.
 */
function readAlerts() {
  const resendApiKey = optionalText('RESEND_API_KEY');
  const emailFrom = optionalText('ALERT_EMAIL_FROM');
  if ((resendApiKey === null) !== (emailFrom === null)) {
    throw new Error('RESEND_API_KEY and ALERT_EMAIL_FROM go together: set both or neither');
  }
  const pushKeyText = optionalText('ALERT_PUSH_PRIVATE_KEY');
  const pushContact = optionalText('ALERT_PUSH_CONTACT');
  if ((pushKeyText === null) !== (pushContact === null)) {
    throw new Error('ALERT_PUSH_PRIVATE_KEY and ALERT_PUSH_CONTACT go together: set both or neither');
  }
  if (pushKeyText !== null && !/^[A-Za-z0-9_-]{43}$/.test(pushKeyText)) {
    throw new Error('ALERT_PUSH_PRIVATE_KEY must be 43 base64url characters (32 bytes)');
  }
  if (pushContact !== null && !/^(https:\/\/|mailto:)\S+$/.test(pushContact)) {
    throw new Error('ALERT_PUSH_CONTACT must be an https:// address or a mailto: address');
  }
  return Object.freeze({
    resendApiKey,
    emailFrom,
    pushPrivateKey: pushKeyText === null ? null : Buffer.from(pushKeyText, 'base64url'),
    pushContact,
    removeMinutes: optionalInteger('ALERT_REMOVE_MINUTES', 43_200),
    validatorKeysFile: optionalText('VALIDATOR_KEYS_FILE') ?? 'network/validators.json',
  });
}

/** An optional choice: the value when it is one of `choices`; `fallback` when the variable is not set. */
function optionalChoice(name, choices, fallback) {
  const value = optionalText(name);
  if (value === null) return fallback;
  if (!choices.includes(value)) throw new Error(`${name} must be one of ${choices.join(', ')}, got "${value}"`);
  return value;
}

/**
 * An optional picture size: a width and a height in pixels with an x
 * between them, such as 1024x1024, when set; `fallback` when the
 * variable is not set.
 */
function optionalSize(name, fallback) {
  const value = optionalText(name);
  if (value === null) return fallback;
  if (!/^[1-9][0-9]*x[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a width and a height in pixels, such as 1024x1024, got "${value}"`);
  }
  return value;
}

/**
 * The settings of Joy, the wallet's AI (src/joy/, spec section 30). With
 * ANTHROPIC_API_KEY set Joy is on. Without it Joy is off: /ask-joy says
 * so, and nothing is sent to Anthropic. No error ever prints the key.
 * The two after the first five are her web search's (spec section 32):
 * each may be 0, and 0 in either switches web search off. The six after
 * those are her pictures' (spec section 33). With OPENAI_API_KEY set Joy
 * can have a picture made. Without it she cannot, nothing is sent to
 * OpenAI, and everything else is as it was. JOY_DAILY_PICTURES may be 0,
 * which switches pictures off too. No error ever prints that key either.
 *
 * The last four are of spec section 36. JOY_PROVIDER picks the company
 * whose model writes Joy's answers: anthropic or openai, and anthropic
 * when it is not set. Any other word stops the boot. What the first
 * lines of this comment say holds for anthropic. With openai Joy is on
 * when OPENAI_API_KEY is set, which is the pictures' key too, and the
 * model, how hard it thinks and the most tokens of a request are the
 * three settings that begin JOY_OPENAI_. The first four settings are
 * Anthropic's and are then not used. The fifth, JOY_DAILY_MESSAGES, is
 * for both, as her web search's and her pictures' numbers are. One of
 * them counts another thing with openai: JOY_MAX_SEARCHES is then the
 * most steps of OpenAI's search tool for one request (spec 36.5).
 */
function readJoy() {
  return Object.freeze({
    apiKey: optionalText('ANTHROPIC_API_KEY'),
    model: optionalText('JOY_MODEL') ?? 'claude-haiku-5-5',
    effort: optionalChoice('JOY_EFFORT', ['low', 'medium', 'high'], 'medium'),
    maxTokens: optionalInteger('JOY_MAX_TOKENS', 16_000),
    dailyMessages: optionalInteger('JOY_DAILY_MESSAGES', 300),
    maxSearches: optionalCount('JOY_MAX_SEARCHES', 3),
    dailySearches: optionalCount('JOY_DAILY_SEARCHES', 100),
    openaiApiKey: optionalText('OPENAI_API_KEY'),
    pictureModel: optionalText('JOY_PICTURE_MODEL') ?? 'gpt-image-2.6-flare',
    pictureQuality: optionalChoice('JOY_PICTURE_QUALITY', ['low', 'medium', 'high'], 'low'),
    pictureSize: optionalSize('JOY_PICTURE_SIZE', '1024x1024'),
    pictureFormat: optionalChoice('JOY_PICTURE_FORMAT', ['jpeg', 'png', 'webp'], 'jpeg'),
    dailyPictures: optionalCount('JOY_DAILY_PICTURES', 30),
    provider: optionalChoice('JOY_PROVIDER', ['anthropic', 'openai'], 'anthropic'),
    openaiModel: optionalText('JOY_OPENAI_MODEL') ?? 'gpt-6.2-sol',
    openaiEffort: optionalChoice('JOY_OPENAI_EFFORT', ['low', 'medium', 'high'], 'medium'),
    openaiMaxTokens: optionalInteger('JOY_OPENAI_MAX_TOKENS', 16_000),
  });
}

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

  // How long a challenge for /add-passkey may be used. An add takes three
  // taps and maybe a new PIN on a security key, so it lives longer.
  addPasskeyChallengeSeconds: optionalInteger('ADD_PASSKEY_CHALLENGE_SECONDS', 600),

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

  // Security alerts (src/alerts/, spec section 25): the email company's
  // key and the sender's name and address; the private half of this
  // server's key for the phones' delivery services and the contact they
  // are given; how long an email or a phone that was taken off still
  // gets every alert, in minutes (a month); and the file with the
  // validators' public keys.
  alerts: readAlerts(),

  // Joy, the wallet's AI (src/joy/, spec section 30): Anthropic's API key
  // (without it Joy is off); the model that writes her answers; how hard
  // the model thinks before it answers (low, medium or high); the most
  // tokens one request to Anthropic may write, thinking included; and how
  // many messages one pod may send her in one day (UTC). Her web search
  // (spec section 32): the most web searches for one message; and from
  // how many web searches in one day (UTC) a pod's further messages go
  // out without web search. 0 in either switches web search off. Her
  // pictures (spec section 33): OpenAI's API key (without it Joy makes
  // no picture); OpenAI's image model; the quality of a picture (low,
  // medium or high), its width and height in pixels and its file format
  // (jpeg, png or webp); and from how many pictures in one day (UTC) a
  // pod's further messages go out without the picture tool. 0 switches
  // pictures off. Who answers (spec section 36): the company whose model
  // writes her answers, anthropic or openai (anthropic when not set);
  // and for openai, whose key is the pictures' key, its model, how hard
  // that model thinks (low, medium or high) and the most tokens one
  // request to OpenAI may write, thinking included. With openai the
  // first number of her web search is the most steps of OpenAI's search
  // tool for one request.
  joy: readJoy(),
});
