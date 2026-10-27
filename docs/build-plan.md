# Build plan: anoPods, vouching, security buckets, chat and marketplace

For a fresh chat. The specification is `docs/schemas.md`; this file says in
what order to build it, which files each step touches, and how to verify
it. The design was settled with the user on 2026-10-24 over four rounds of
questions; the answers are all folded into `schemas.md`, so nothing here
needs the old conversation. `~/Desktop/masterpod_auth_flow.txt` is an
earlier draft and is not an input to this build.

## Before starting

Read, in this order: `README.md`, `docs/schemas.md`, this file, then the
code under `src/` (the skeleton: `app.js`, `server.js`, `config/env.js`,
`db/pool.js`, `health/`, `middleware/`). Then, in `~/Desktop/Z/anossoftware`,
`src/crypto/` (copied verbatim here), `src/util/is-object.js`, and one
feature folder, `src/transfer/`, for the router / handlers / service /
queries pattern this project copies.

House rules, from the user:

- The user commits. Never commit. End the work with the list of changed and
  new files, what changed in each, and a suggested commit message per step
  below, so the user can commit step by step.
- No test suites, fixtures or smoke scripts in the repo. Verify on a
  throwaway rig (step 11) with scripts kept in the scratchpad, then the user
  tests by hand through the web app.
- The spec is the spec. The changes to existing code are listed under
  "Approved changes" below; anything else in existing code gets a one-line
  question first. New files are free. Where the spec leaves a detail open,
  pick the simplest thing and write it into `schemas.md` section 11.
- Node comes from nvm: `source ~/.nvm/nvm.sh` before `node` or `npm` in a
  shell. Node 24 has P-256 and ML-DSA-87 built in. PostgreSQL is Homebrew's
  `postgresql@17`; `scripts/find-psql.sh` locates `psql`.
- `.env` files cannot be written by Claude. Every new variable has a
  default, so the user's `.env` keeps working; give the user the lines for
  `.env.example` in the report.
- `npm run db:setup` adds the new tables, function and triggers to the live
  `masterpod` database without a reset; nothing here alters an existing
  table.
- The user runs their own server on port 3100 from the committed code and
  their own `ng serve` on 4200; do not start or stop either. The rig uses
  port 3200, database `masterpodrig` and role `masterpodrig`, so the user's
  role and password are untouched.
- Build straight through, all steps, then report. Keep the step boundaries
  visible in the report so the diff reads step by step.

## Approved changes to existing code

Everything else in the skeleton stays as it is. `server.js`, `db/pool.js`,
`health/`, `middleware/` and the three shell scripts are untouched.

1. `db/schema.sql`: the `refuse_change` function and the eighteen tables of
   spec section 4, after the `set_updated_at` function, replacing the "No
   tables yet" comment.
2. `src/config/env.js`: the seven variables of spec section 8, with
   defaults, as `env.webOrigin`, `env.rpId`, `env.ephemeralKeyHours`,
   `env.challengeSeconds`, `env.timestampWindowSeconds`,
   `env.maxImageBytes`, `env.maxImagesPerRequest`.
3. `src/app.js`: `cors({ origin: env.webOrigin })` before the JSON parser,
   as anossoftware does; the JSON limit computed from `env` instead of
   `'1mb'`; the eight feature routers mounted after `/health`, each with a
   one-line comment naming its paths.
4. `package.json`: dependencies `cors`, `canonicalize`,
   `@simplewebauthn/server` (14.x); the script `"make-super-seed": "node
   --env-file=.env scripts/make-super-seed.js"`.
5. `README.md`: everything built, as in step 9.

## Steps

### 1. Schema

`db/schema.sql`: `refuse_change()`, then the tables in the order of spec
section 4: `anopods`, `public_selfies`, `challenges`, `nonces`,
`vouch_requests`, `vouches`, `seeds`, `super_seeds`, `notifications`,
`security_images`, `security_info`, `chat_rooms`, `chat_room_members`,
`chat_hpke`, `chat_room_invites`, `chat_room_join_requests`,
`chat_room_messages`, `listings`. Each with its header comment, its
`set_updated_at` trigger where it has `updated_at`, the append-only
triggers on the two security tables, the indexes, and `COMMENT ON` for the
table and every column. Then `npm run db:setup` against the user's
`masterpod` database and check `\d anopods` and `\d+ security_images`.

Suggested commit: `anopods, vouching, security, chat and marketplace: schema`.

### 2. Configuration and dependencies

`src/config/env.js` (approved change 2), `package.json` (approved change
4), `npm install`. `src/app.js` gets the CORS line and the computed JSON
limit now; the routers are mounted as the steps below create them.

Suggested commit: `web origin, passkey and image settings; cors, canonicalize, simplewebauthn`.

### 3. Shared building blocks

All new files.

- `src/crypto/bytes.js`, `canonical.js`, `hash.js`, `signatures.js`: copied
  verbatim from anossoftware. `src/util/is-object.js` too.
- `src/util/ids.js`: `randomId()` (32 random bytes), `toHex(buffer)`,
  `decodeId(encoded)` (32 bytes or null, via `decodeBytes`).
- `src/util/images.js`: `decodeImage({ contentType, image })` returning
  `{ contentType, bytes }` or a reason: content type in the allowed three,
  base64 decodes, at most `env.maxImageBytes`. `encodeImage(row)` for
  answers.
- `src/db/transaction.js`: `withTransaction(fn)`: a client from the pool,
  `BEGIN`, `fn(client)`, `COMMIT`, `ROLLBACK` on throw, release always.
- `src/auth/challenges.queries.js`: `issue(purpose, anopodId)` (insert and
  sweep expired), `take(client, challenge, purpose)` (select for update
  and delete inside the caller's transaction, null if missing or
  expired).
- `src/auth/nonces.queries.js`: `insertNonce(anopodId, nonce, expiresAt)`
  returning false on a duplicate, plus the sweep.
- `src/auth/signed-request.js`: `parseSignedRequest(body)` (the envelope
  shape of spec section 3, or a reason), `verifySignatures(payload,
  signatures, ecdsaKey, mldsaKey)` (canonical bytes, both algorithms,
  through `signatures.js`).
- `src/auth/webauthn.js`: `verifyRegistration(passkeyJson, challenge)` and
  `verifyAuthentication(assertionJson, challenge, credentialId,
  publicKey)` wrapping `@simplewebauthn/server` with `env.rpId`,
  `env.webOrigin`, user verification required, counter ignored; both
  return `{ ok, ... }` or `{ ok: false, reason }`. `prfResultsPresent(json)`
  for the two checks that refuse a PRF output in the request.
- `src/auth/require-session.js`: the middleware of spec section 3, checks
  1 to 8, setting `req.anopod` (the `anopods` row) and `req.body` to
  `payload.body`. `src/auth/require-vouched.js` and
  `src/auth/require-setup.js`.
- `src/auth/auth.router.js` + `auth.handlers.js`: `POST /challenge`.
- `src/notifications/notifications.queries.js`: `notify(client, anopodId,
  kind, referenceId)` for every feature to call inside its transaction;
  `listFor(anopodId, unreadOnly, limit)`, `markRead(anopodId, numbers)`.
  `notifications.handlers.js` + `notifications.router.js`:
  `/list-notifications`, `/mark-notifications-read`.

Suggested commit: `request signing, challenges, nonces, passkey verification, notifications`.

### 4. anoPods

- `src/anopods/anopods.queries.js`: `insertAnopod(client, row)`,
  `findById`, `findByCredentialId`, `findByUsername`, `usernameTaken`,
  `replaceEphemeralKeys(client, id, keys, expiresAt)`,
  `completeSetup(client, id, fields)`, `setVouched(client, id)`,
  `countVouches(id)`, `seedStatus(id)` (`{ isSeed, isSuperSeed }`),
  `profileOf(row, status)`. `public-selfies.queries.js`: insert, find.
- `src/anopods/anopods.service.js`: `createAnopod(body)`, `unlock(body)`,
  `checkUsername`, `status(anopod)`, `profile(anopodId)`,
  `completeSetup(anopod, body)`, each with the checks of spec section 5 in
  order, returning `{ ok, status, body }` or `{ ok: false, status,
  reason }` so the handlers only log and answer.
- `anopods.handlers.js`, `anopods.router.js`: `/create-anopod`, `/unlock`,
  `/check-username` at level none; `/check-anopod-status`,
  `/get-anopod-profile` behind `requireSession`; `/complete-setup` behind
  `requireVouched`. Mount in `app.js`.

Suggested commit: `create, unlock, username check, status, profile, setup`.

### 5. Vouching

- `src/vouching/vouch-requests.queries.js`, `vouches.queries.js`,
  `seeds.queries.js` (`isSeed`, `isSuperSeed`, `insertSeed`).
- `src/vouching/vouching.service.js`: `searchUsernames`, `sendRequest`,
  `listRequests`, `approve` (the five writes of the spec in one
  transaction), `decline`.
- `vouching.handlers.js`, `vouching.router.js`: `/search-usernames`,
  `/send-vouch-request` behind `requireSession`; `/list-vouch-requests`,
  `/approve-vouch-request`, `/decline-vouch-request` behind
  `requireVouched`. Mount.

Suggested commit: `vouch requests, approvals, seeds`.

### 6. Security buckets

- `src/security/security.queries.js`: `insertImages(client, anopodId,
  type, images)`, `insertInfo(client, anopodId, type, infos)`,
  `listFor(anopodId)`.
- `security.service.js`, `security.handlers.js`, `security.router.js`:
  `/add-to-security-bucket-one`, `/add-to-security-bucket-two`,
  `/list-security-records` behind `requireVouched`. Mount.

Suggested commit: `security buckets`.

### 7. Chat

- `src/chat/chat.queries.js`: rooms, members, `chat_hpke`, invites, join
  requests, messages; `isMember`, `isCreator`, `lastPosition`.
- `src/chat/chat.service.js`: `createRoom`, `invite`, `acceptInvite`,
  `declineInvite`, `requestToJoin`, `approveJoin`, `declineJoin`, `leave`,
  `listRooms`, `listPublicRooms`, `listMessages`, `sendMessage`,
  `getChatPublicKeys`, with the spec's checks and transactions.
- `chat.handlers.js`, `chat.router.js`: the thirteen routes behind
  `requireSetup`. Mount.

Suggested commit: `chat rooms, invites, join requests, messages`.

### 8. Marketplace

- `src/marketplace/listings.queries.js`: insert, find, close, the filtered
  and sorted list (whitelisted sort columns, parameterised filters).
- `marketplace.service.js`, `marketplace.handlers.js`,
  `marketplace.router.js`: `/create-listing` (room, member, `chat_hpke` and
  listing in one transaction), `/close-listing`, `/list-listings` behind
  `requireSetup`. `/request-to-join` in the chat service checks the listing
  status for marketplace rooms. Mount.

Suggested commit: `marketplace listings`.

### 9. Genesis script, README, the spec

- `scripts/make-super-seed.js`: takes the hex id, uses `src/db/pool.js`,
  one transaction: `UPDATE anopods SET vouched = true`, `INSERT INTO
  super_seeds ... ON CONFLICT DO NOTHING`, prints what it did, exits
  non-zero on an unknown id.
- `README.md`: what the server is now; the levels table of spec section 2;
  the request envelope; the Database tables list; the Endpoints table (all
  33 routes with level and one line each); Configuration with the seven
  new variables; Genesis; the Layout tree; the deferred list.
- Anything that changed during the build goes into `docs/schemas.md`
  section 11.

Suggested commit: `genesis script; document the anoPod server`.

### 10. The web app

New repository `~/Desktop/Z/test/masterpod-test-web-app`: Angular 22,
standalone components, signals, created with `ng new` (no SSR, CSS, no
routing), laid out like `~/Desktop/Z/test/test-web-app` (read its
`crypto.service.ts`, `account-api.service.ts`, `app.ts` and `app.html`
first). Plain forms in that page's style, nothing fancy. One browser tab is
one anoPod; every key lives in memory and dies with the tab. The user
commits there too, and runs `ng serve` themselves on 4200; verify with
`ng build` only.

Dependencies: `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`
(`ml_dsa87`, `ml_kem1024`), `canonicalize`. WebCrypto for AES-GCM, HKDF and
random bytes; `navigator.credentials` for the passkey with the `prf`
extension, user verification and a resident key required.

- `crypto.service.ts`: everything in spec section 7: key generation, HKDF,
  the blobs, the backup code and its base32, the chat key pair, room key
  wrap and unwrap, message encryption, signing (P-256 r||s over SHA-256,
  ML-DSA-87 pure) and the canonical bytes.
- `passkey.service.ts`: `register(challenge, anopodId)` and
  `assert(challenge)` with the PRF salt of section 7, returning the
  `toJSON()` result with `prf.results` removed and the PRF output
  separately, plus a refusal when `prf.enabled` is not reported.
- `api.service.ts`: one method per route; a `signed(path, body)` helper
  that builds the section 3 envelope with the session keys; the unsigned
  calls for `/challenge`, `/check-username`, and the self-signed
  `/create-anopod` and `/unlock`.
- `app.ts` / `app.html`, sections shown by state:
  1. Create: first name, last name, username (with a check button), selfie
     file, Create button: challenge, passkey, keys, post, show the id.
  2. Unlock: one button: challenge, assertion, new session keys, post,
     unwrap `blob1` and the chat private key when setup is complete.
  3. Status and vouching: status, search a seed by username, send a
     request; the seed's inbox with approve and decline.
  4. Notifications: list, mark read, polled every 5 seconds.
  5. Setup: generate the encryption key and backup code, show the code,
     require it typed back, derive, build the seven fields, post.
  6. Security: bucket one (images) and bucket two (images and info texts),
     each encrypted under a fresh key shown once as hex and dropped; a
     button that lists the records.
  7. Chat: create a room, invite by anopod id, invites with accept and
     decline, public rooms with join requests, the creator's join inbox
     with approve and decline, leave, messages for the selected room
     polled every 3 seconds, send.
  8. Marketplace: create a listing, list with filters and sort, request to
     join a listing's room, close.
  Each action logs the request path and the answer the way the anos page
  does.

Suggested commit, in that repo: `anopod test app: create, unlock, vouching, setup, security, chat, marketplace`.

### 11. Verification rig

Before the report. In the scratchpad, never in the repo. The server never
opens a blob, a wrapped room key or a message, so the rig sends random
bytes of the right lengths for those; the real crypto is exercised by the
web app.

- A rig env file: `PORT=3200`, `PGDATABASE=masterpodrig`,
  `PGUSER=masterpodrig`, a random `PGPASSWORD`, defaults for the rest.
  `sh scripts/setup-db.sh <that file>`; the server started in the
  background with `node --env-file=<that file> src/server.js`.
- A scratch folder with `cbor-x` installed and `rig.mjs` using
  `node:crypto` (P-256, ML-DSA-87, SHA-256) and the project's
  `src/crypto/canonical.js`. A software authenticator: a P-256 key per pod;
  registration = `attestationObject` with `fmt: 'none'` and an `authData`
  of `sha256(rpId) || flags 0x45 || counter || aaguid || credential id ||
  COSE key`, `clientDataJSON` of type `webauthn.create` with the base64url
  challenge and `WEB_ORIGIN`, `clientExtensionResults.prf.enabled = true`;
  assertion = `authenticatorData` of `sha256(rpId) || flags 0x05 ||
  counter`, `clientDataJSON` of type `webauthn.get`, DER signature over
  `authenticatorData || sha256(clientDataJSON)`, `userHandle` the pod id.
- Flows, with the answers and the tables checked after each: check a free
  and a taken username; create pods S, B, C, D and E; promote S with the
  genesis script; a replayed nonce, an old timestamp, a wrong path and a
  bad signature all refused; unlock S with the software authenticator and
  see the old session refused; D calls a vouched route and gets 403; B and
  C each request S, S approves both: both vouched and in `seeds` with
  `vouched_by` S; D requests B and C, approved by both: vouched after the
  second, not a seed; E requests D (not a seed): `user is not seed`; E
  requests itself; a duplicate request; a decline; `/complete-setup` for S,
  B, C, D, then again: 409; bucket one and two for B, the list, and an
  `UPDATE security_images` through `psql` refused by the trigger; chat: S
  creates a private room, invites B (and D, who declines), B accepts,
  messages both ways with `afterPosition`, C is refused on
  `/list-messages`; a public room, C requests to join, S approves, D
  requests and is declined, B leaves, S cannot leave; marketplace: B
  creates a listing, `/list-listings` with each filter and sort, C requests
  to join the listing's room, B approves, B closes, D's join request
  refused; notifications for each pod listed and marked read.
- Drop the rig database and role and stop the rig server at the end.

### 12. Report

The changed and new files per step, what changed, the suggested commit
messages, the `.env.example` lines, what was verified on the rig and what
was not, and anything left open.

## Out of scope, by decision

Spec section 10: recovery and rotation, several passkeys or sessions,
purging unvouched pods, member removal and room key rotation, editing
listings and profiles, push delivery, object storage, anoSphere, the anos
interface, anti-abuse limits. The keyholders are a separate system; the
security bucket keys are shown to the user in the test app and go no
further.
