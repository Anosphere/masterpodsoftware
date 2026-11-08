# masterpodsoftware

The masterpod server for the anos system: an Express 5 server backed by
PostgreSQL, laid out like anossoftware so the two read alike. It keeps the
anoPods: a pod's public profile and selfie, its one passkey, its one live
session, the vouching that makes a pod trusted, the pod's encrypted key
material, the two security buckets, encrypted chat rooms, the marketplace
of listings, and, since 2026-10-26, the recovery cases of locked-out people:
their moderation, the keyholders' shares and the finish (`docs/schemas.md`
section 12), and the attestors' cases on assisted trades and disputed
escrows: the person's lookup id, the parties' encrypted evidence, the
sign-offs that are the validators' own follow-up objects (section 13), and,
since 2026-11-08, the break-glass cases: the moves a recovery's finish files
out of the accounts whose keys died with the lost passkey, into new accounts
of the same type, and the attestors' sign-offs on them (section 14).

Everything a pod keeps private reaches the server as ciphertext;
the server checks shapes, lengths, signatures and who may do what, and stores
bytes. The specification is `docs/schemas.md`; `docs/build-plan.md` is how it
was built.

## Requirements

- Node.js 24 or newer (ML-DSA-87 is built in)
- PostgreSQL 17 or newer, running locally

## Getting started

```bash
npm install
cp .env.example .env     # fill it in
npm run db:setup         # role, database, schema
npm start
```

Then open <http://localhost:3100>. The web app that drives it is
`~/Desktop/Z/test/masterpod-test-web-app` (`ng serve` on 4200).

## Scripts

| Command                   | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `npm start`               | Run the server (loads `.env`)                                               |
| `npm run dev`             | Same, restarting on file changes                                            |
| `npm run db:setup`        | Create the role, the database and its schema (idempotent). Pass an env file to use another one. Adds new tables to a live database without a reset. |
| `npm run db:reset`        | Drop the database and run setup again. Local data is lost; use after a change to an existing table. |
| `npm run make-super-seed -- <id>` | Genesis: make the pod with this hex id a super seed (see below).    |

## Who may call what

Every route is a `POST` with a JSON body. Four pod levels and three more:

| Level    | Meaning                                                                                  |
| -------- | ---------------------------------------------------------------------------------------- |
| none     | Plain JSON body, no signature: `/challenge`, `/check-username`, `/get-anopod-session-keys`, `/get-anos-account`, the keyholders' `/receive-recovery-share/:caseId`; `/create-anopod`, `/unlock`, `/open-recovery-case` and `/unlock-recovery-pod` are signed by the ephemeral keys inside them, `/recover-with-backup-code` by the backup code keys inside it. |

| session  | Signed by the pod's current ephemeral keys (the envelope below). Vouched or not.          |
| vouched  | session, and `anopods.vouched` is true.                                                  |
| setup    | vouched, and setup is complete (the pod has chat keys): every chat and marketplace route, the three anos account routes, the six wallet memory routes, `/rotate-backup-code` and `/store-break-glass-blob` after a recovery, the person's four attestation routes `/list-my-cases`, `/get-my-case`, `/share-lookup-id`, `/add-dispute-evidence`, and the person's two break-glass routes `/file-break-glass-moves`, `/list-my-break-glass-moves`. |
| recovery | Signed by a recovery pod's current ephemeral keys: the same envelope with `caseId` in place of `anopodId` (`src/auth/require-recovery-session.js`); `/get-recovery-pod`, `/complete-recovery-case`. |

| moderator | session, and the pod's username starts with `moderator` and a super seed vouched for it (`src/auth/require-moderator.js`; the stake is the keyholders' check); the six moderation routes. |
| attestor | session, and the pod's username starts with `attestor` and a super seed vouched for it (`src/auth/require-attestor.js`, the moderator rule with the other prefix; the stake is the validators' and the keyholders' check); the fourteen attestor routes of section 13 and the seven break-glass routes of section 14. |

Failing a level: `401` for anything wrong with the signature or the session,
`403 anopod not vouched`, `403 setup not complete`, `403 not a moderator`, `403 not an attestor`. Other errors are
`{ error: '<reason>' }` with `400` for a bad shape or value, `403` for a
caller who may not do this, `404` for a thing that does not exist, `409` for
a conflict with what is already there.

### The request envelope

A pod has one live session: the ephemeral P-256 and ML-DSA-87 key pair on its
`anopods` row, registered by `/create-anopod` or `/unlock` and replaced by the
next unlock. A session request is

```json
{
  "payload": {
    "anopodId":  "<hex 32 bytes>",
    "path":      "/send-vouch-request",
    "timestamp": "2026-10-24T18:00:00.000Z",
    "nonce":     "<hex 16 to 32 bytes>",
    "body":      { "anopodIdTo": "<hex>" }
  },
  "signatures": { "ecdsa": "<hex 64>", "mldsa": "<hex 4627>" }
}
```

Both signatures are over the RFC 8785 canonical bytes of `payload`
(`canonicalize` on both ends). `src/auth/require-session.js` checks, in
order: the shape, the pod exists, the session has not expired
(`EPHEMERAL_KEY_HOURS`), `path` is this route, `timestamp` is within
`TIMESTAMP_WINDOW_SECONDS` of the server clock, both signatures verify, and
`nonce` is new (`401 replay` otherwise). `body` is the route's own object, an
empty object where a route has none. Who is asking always comes from the
verified signature, never from the body.

Ids are 32 random bytes, hex on the wire, `BYTEA` in the database. Byte
strings are hex (base64 accepted) except images and the WebAuthn JSON, which
are base64 / base64url as the browser produces them.

## Endpoints

| Route                           | Level   | Does                                                                                     |
| ------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `/challenge`                    | none    | Issues a single-use WebAuthn challenge for `create` or `unlock`; `create` also mints the new pod's id |
| `/create-anopod`                | none    | Creates a pod: profile, selfie, passkey registration (PRF required), first session        |
| `/unlock`                       | none    | Opens a session: passkey assertion, new ephemeral keys; answers the blobs to unwrap, `identityBlob` included |
| `/check-username`               | none    | Lowercases the username, checks the rule, says whether it is free                        |
| `/check-anopod-status`          | session | The caller's vouched, vouchCount, setupComplete, isSeed, isSuperSeed, and its rows in each bucket (bucketOneImages, bucketTwoImages, bucketTwoInfos) |
| `/get-anopod-profile`           | session | A pod's public profile with its selfie                                                   |
| `/get-anopod-session-keys`      | none    | A pod's current session public keys and their expiry, for the keyholders' pod check      |
| `/search-usernames`             | session | Any pod by exact username, with selfie and seed flags; finds a seed to ask and a pod to invite |
| `/send-vouch-request`           | session | Asks a seed to vouch for the caller                                                      |
| `/list-notifications`           | session | The caller's notifications, newest first (`unreadOnly`, `limit`)                        |
| `/mark-notifications-read`      | session | Marks notifications read                                                                 |
| `/list-vouch-requests`          | vouched | The open requests addressed to the caller (a seed), oldest first, each with the requester's profile (no selfie since 2026-11-08; the wallet reads it through `/get-anopod-profile`) |
| `/approve-vouch-request`        | vouched | Records the vouch; flips `vouched` on a super seed's approval or the second vouch; a super seed's approval also makes a seed |
| `/decline-vouch-request`        | vouched | Drops the request and notifies the requester                                             |
| `/complete-setup`               | vouched | Stores the two encryption key blobs, the backup code keys, the chat keys and the identity blob (eight fields), once |
| `/add-to-security-bucket-one`   | vouched | Stores encrypted images in bucket one, under the bucket key `keyId` names                |
| `/add-to-security-bucket-two`   | vouched | Stores encrypted images and texts in bucket two, under the bucket key `keyId` names      |
| `/list-security-records`        | vouched | Everything in both buckets for the caller, each row with its `keyId`                     |
| `/create-chat-room`             | setup   | A private or public room with the creator's own wrapped room key; a private room can be about a listing (`listingId`, 2026-11-06) |
| `/invite-to-chat-room`          | setup   | The creator invites a pod, carrying the room key wrapped to it                           |
| `/accept-invite`                | setup   | Joins: the wrapped key moves into `chat_hpke`                                            |
| `/decline-invite`               | setup   | Drops the invite                                                                         |
| `/request-to-join`              | setup   | Asks to join a public or marketplace room (open listing only)                            |
| `/approve-join`                 | setup   | The creator lets the requester in with the wrapped key                                   |
| `/decline-join`                 | setup   | Drops the join request                                                                   |
| `/leave-chat-room`              | setup   | Leaves a room; the creator cannot                                                        |
| `/list-chat-rooms`              | setup   | The caller's rooms (members, invited, own wrapped key, newest message, the listing a room is about with its owner), open invites (each with its listing too), join requests on its rooms |
| `/list-public-chat-rooms`       | setup   | Public rooms by name, newest first, paged                                                |
| `/list-messages`                | setup   | A room's messages after a position, or the newest ones before a position, members only   |
| `/send-message`                 | setup   | Stores a ciphertext message, members only                                                |
| `/get-chat-public-keys`         | setup   | The chat public keys of up to 50 pods that completed setup                               |
| `/create-listing`               | setup   | A listing of anos for a fiat currency; since 2026-11-06 without a room of its own, people connect with a private room each |
| `/close-listing`                | setup   | Closes the owner's listing; an old listing's room stays, new join requests and new rooms about it are refused |
| `/list-listings`                | setup   | Listings filtered by side, currency, country and status (`any` allowed), the caller's own with `mine`, sorted and paged |
| `/get-listing`                  | setup   | One listing by id, open or closed, in the list's form                                    |
| `/create-anos-account`          | setup   | Records an anos account the pod made: type, the private halves under the pod's encryption key, the signed creation; `409` on a repeat |
| `/mark-anos-account-submitted`  | setup   | Records that a validator answered the account's creation; the caller's accounts only     |
| `/list-anos-accounts`           | setup   | The caller's anos accounts, oldest first, with the blob, the creation, `submittedAt` and `breakGlassBlob` (null until a recovery stored it) |
| `/add-noted-transaction`        | setup   | Records a note on a ledger transaction of the caller's, for their tax records: the ledger's facts in the clear, the private part as a blob under the pod's encryption key; one note per transaction, `409` on a second |
| `/update-noted-transaction`     | setup   | Replaces a note's blob; the ledger's facts never change; the caller's notes only |
| `/remove-noted-transaction`     | setup   | Deletes a note; the caller's notes only                                                  |
| `/list-noted-transactions`      | setup   | The caller's notes in a date range, newest first, the newest 1,000 with `more` when there are older ones |
| `/get-wallet-settings`          | setup   | The caller's wallet settings blob and when it was set, null before the first set         |
| `/set-wallet-settings`          | setup   | Stores the caller's wallet settings blob whole: one row per pod, replaced in place        |

| `/get-anos-account`             | none    | For the validators' binding check: the pod that made an account and whether it is vouched |
| `/open-recovery-case`           | none    | A locked-out person's recovery case and its recovery pod: the lookup id, the username, a contact email, a new passkey (PRF required) registered under the pod's id, the hybrid key the bankers encrypt shares to; `409` while a case for the lookup id is open |
| `/unlock-recovery-pod`          | none    | Opens a recovery session on a return visit: the recovery passkey's assertion, new ephemeral keys; answers the hybrid key blob to open |
| `/get-recovery-pod`             | recovery | The person's view of their case: status, the events they may see, the shares the keyholders posted, `blob2` once the case is approved |
| `/list-recovery-cases`          | moderator | The cases by status (the four in-progress ones by default), newest first, each with the pod's names and the count of approving pods |
| `/get-recovery-case`            | moderator | One case: the row, the pod's profile and selfie, every event with the acting moderator and its details complete, the shares received, the banker packet |
| `/list-case-security-records`   | moderator | The case's pod's rows of one bucket, ciphertext with their key ids; writes the viewed event |
| `/schedule-recovery-case`       | moderator | The video call: the `scheduled` event with the time and the https link; status `inReview` |
| `/sign-off-recovery-case`       | moderator | A verdict signed by pair one of an anos account in the caller's pod, verified against the stored creation; the second distinct approval approves the case |
| `/dismiss-recovery-case`        | moderator | Closes the case with a preset reason and a note; final |
| `/receive-recovery-share/:caseId` | none  | A keyholder's share for the case, stored as posted (a repeat is a no-op); the first one makes the case `delivering`; `409` before two approvals or after the end |
| `/recover-with-backup-code`     | none    | The finish: the backup code proof (both signatures by the keys the code derives); the recovery passkey becomes the pod's, `blob1` is replaced, the lost device's session ends |
| `/complete-recovery-case`       | recovery | Closes the case; final                                                                   |
| `/rotate-backup-code`           | setup   | A new backup code's `blob2` and keys, with a proof by the current code's keys; the old code is worthless from here |
| `/store-break-glass-blob`       | setup   | A recovered break-glass seed under the encryption key, on the caller's anos account; a second call replaces it |
| `/list-attestors`               | attestor | Every attestor pod with setup complete, with its chat public keys: what a dispute case's key is wrapped for |
| `/list-anos-account-profiles`   | attestor | 1 to 200 account ids turned into people: each one's type, pod and profile with selfie; nulls for an id the masterpod does not know |
| `/list-attestor-cases`          | attestor | The trade and dispute cases by status (`open` and `inReview` by default), newest first, with the parties' names, the opener and the sign-off counts |
| `/get-trade-case`               | attestor | One trade case: the row, the sender's profile and selfie, every event with the acting pod and its details complete |
| `/get-dispute-case`             | attestor | One dispute case: the row with the case key, both parties' profiles, the caller's wrapped case key, who holds one, every event, every evidence row of both sides |
| `/list-trade-case-security-records` | attestor | The sender pod's rows of one bucket, ciphertext with their key ids; writes the viewed event |
| `/open-trade-case`              | attestor | A case on an assisted trade waiting for attestations; notifies the sender's pod |
| `/open-dispute-case`            | attestor | A case on a disputed escrow with the case key's public halves and its private half wrapped to every attestor pod; notifies both parties |
| `/schedule-attestor-case`       | attestor | The video call on either kind: the `scheduled` event, status `inReview`, the parties notified |
| `/share-case-key`               | attestor | A holder of a dispute case's key wraps it for an attestor appointed after the open |
| `/sign-off-trade-case`          | attestor | An attestation, the validators' follow-up signed by two pairs of the caller's account, verified against the stored creation; the second distinct pod's decides the case and clears the lookup id |
| `/sign-off-dispute-case`        | attestor | An escrow verdict, verified the same way; the second distinct pod's of one value decides the case and removes the evidence copies and the key rows |
| `/mark-attestor-case-sent`      | attestor | Records that the stored sign-offs were posted to a validator, and the answers; a retry writes another event |
| `/dismiss-attestor-case`        | attestor | Closes either kind with a preset reason and a note, clearing as a decision does; final |
| `/list-my-cases`                | setup   | The caller's cases as a party: trades and disputes, newest first |
| `/get-my-case`                  | setup   | The person's view of one case: their subset of the events; for a dispute the case key and their own evidence with `keyForMe` |
| `/share-lookup-id`              | setup   | The person hands the attestor their lookup id on a trade case |
| `/add-dispute-evidence`         | setup   | A party's evidence files, each ciphertext with its content key wrapped twice, or files of theirs supplied again under `existing` |
| `/file-break-glass-moves`       | setup   | The finish of a recovery files its break-glass moves: the recovery case's id and, per move, the old account, the new account of the same type and the `breakGlassTransfer`'s id; a second call adds moves |
| `/list-my-break-glass-moves`    | setup   | The caller's break-glass cases with their moves and the person's subset of the events: what a lost account's card shows |
| `/list-break-glass-cases`       | attestor | The break-glass cases by status (`open` and `inReview` by default), newest first, with the person's names, the moves and the sign-off counts |
| `/get-break-glass-case`         | attestor | One case: the recovery case's lookup id, status and two moderator approvals, the person's profile and selfie, the moves, every event with the acting pod and its details complete |
| `/list-break-glass-case-security-records` | attestor | The person's rows of one bucket, ciphertext with their key ids; writes the viewed event |
| `/schedule-break-glass-case`    | attestor | The video call: the `scheduled` event, status `inReview`; no notification |
| `/sign-off-break-glass-case`    | attestor | One attestation per move of the case, each the validators' follow-up signed by two pairs of the caller's account and verified against the stored creation, posted together; the second distinct pod's decides the case |
| `/mark-break-glass-case-sent`   | attestor | Records that the stored attestations, two per move, were posted to a validator, and the answers; a retry writes another event |
| `/dismiss-break-glass-case`     | attestor | Closes the case with a preset reason and a note; final; the held moves stay on the ledger until a cancel |

The objects each route takes and answers are in `docs/schemas.md` section 5;
the notification kinds in section 6; what the phone computes (PRF-derived
key, blobs, backup code, chat key pair, room key wrapping, the identity
blob, the anos key blob) in section 7. The wallet's spec,
`~/Desktop/Z/web_app/docs/schemas.md` section 4, is where the 2026-10-25
changes (identity blob, key ids on the buckets, the status counts, anos
accounts) come from. Recovery is section 12: the fourteen routes above,
built in three builds on 2026-10-26 (the case and the recovery pod, the
moderation, the delivery and the finish). A moderator is a pod named
`moderator...` that a super seed vouched for (12.2); the moderators' app
is the wallet's moderator edition; the keyholders post the bankers'
shares to `/receive-recovery-share/:caseId`, and the person's wallet
combines them and finishes. Attestation is section 13: the eighteen routes
above, built 2026-10-26 (attestor build 2, after the validators' two
attestor reads and the keyholders' stake rule of build 1). An attestor is a
pod named `attestor...` that a super seed vouched for (13.2); the
attestors' app is the wallet's attestor edition (build 3); a sign-off is
the validators' own follow-up object, verified here against the account's
stored creation and posted to a validator by the deciding attestor's app.
Break-glass moves are section 14: the nine routes above, built 2026-11-08
(step 3 of `~/Desktop/Z-TestNet/forclaude/break-glass-plan-1.md`). When a
passkey is lost the keys of the pod's anos accounts die with it; the finish
of the recovery makes a new account of the same type for each old account
that holds anos, posts a `breakGlassTransfer` for each, signed by the
account's break-glass pair, and files the moves here; two attestors check
the person against the recovery case's two moderator approvals and sign
every move of the case in one pass, and the deciding attestor's app posts
the attestations to a validator.


## Database tables

`db/schema.sql`, applied by `npm run db:setup`. No foreign keys; the services
keep the references straight. Every table and column has a `COMMENT ON`
(`\d+ <table>` in psql).

| Table                     | Holds                                                                  |
| ------------------------- | ---------------------------------------------------------------------- |
| `anopods`                 | One row per pod: profile, passkey, live session, vouched, setup blobs and keys, the identity blob |
| `public_selfies`          | One plaintext selfie per pod                                           |
| `challenges`              | Single-use WebAuthn challenges                                         |
| `nonces`                  | The replay cache of signed requests                                    |
| `vouch_requests`          | Open vouch requests                                                    |
| `vouches`                 | Approved vouches, never changed                                        |
| `seeds`, `super_seeds`    | The pods that may vouch                                                |
| `notifications`           | What the phone polls; read, never deleted                              |
| `security_images`         | Encrypted images of both buckets, each with the id of its bucket key; append-only |
| `security_info`           | Encrypted texts of bucket two, each with the id of its bucket key; append-only |
| `chat_rooms`              | Private, public and old marketplace rooms; `listing_id` when a room is about a listing |
| `chat_room_members`       | Who is in which room                                                   |
| `chat_hpke`               | Each member's wrapped room key                                         |
| `chat_room_invites`       | Open invites, carrying the wrapped key                                 |
| `chat_room_join_requests` | Open join requests                                                     |
| `chat_room_messages`      | Ciphertext messages, numbered by `position`                            |
| `listings`                | Marketplace listings; `chat_room_id` only on the old ones that got a room |
| `anos_accounts`           | One row per anos account a pod made: type, key blob, the signed creation, when it was submitted, the break-glass blob after a recovery; never deleted |
| `noted_transactions`      | One row per ledger transaction a pod noted for its tax records: the ledger's facts in the clear, the private part as a blob under the pod's encryption key; one per pod and transaction; deleted when the person removes it |
| `wallet_settings`         | One row per pod: the small things its wallet remembers as one encrypted blob (the Protect your passkey answer first); replaced in place |
| `recovery_cases`          | One row per recovery case: lookup id, the pod being recovered, contact email, status; one open case per lookup id |
| `recovery_pods`           | One per case: the recovery passkey, the recovery session, the hybrid key and its wrapped private halves |
| `recovery_shares`         | What the keyholders posted to a case, as posted; append-only           |

| `recovery_events`         | Everything that happened to a case, append-only                        |
| `assisted_trades`         | One case per assisted trade: the trade, the sender's account and pod, the opening attestor, the lookup id the person shared (cleared at the end), the status; one open case per trade |
| `escrow_disputes`         | One case per disputed escrow: the escrow, both parties' accounts and pods, who disputed, the opening attestor, the case key's public halves, the status; one open case per escrow |
| `escrow_dispute_keys`     | A dispute case's private key wrapped to each attestor pod's chat key, as `chat_hpke`; deleted when the case ends |
| `escrow_dispute_evidence` | One row per evidence file: ciphertext, the content key under the uploader's encryption key (stays) and encrypted to the case key (nulled when the case ends) |
| `attestor_events`         | Everything that happened to a trade, dispute or break-glass case, the signed sign-offs included, append-only |
| `break_glass_cases`       | One row per recovery case whose finish filed break-glass moves: the recovery case as the attestors see it, keyed by its id; the recovered pod, the status |
| `break_glass_moves`       | One row per break-glass move: the `breakGlassTransfer`'s id, the old account, the new account of the same type, the type; append-only |

## Configuration

One env file, `.env`, holds everything the process needs. `npm start` loads
it with `node --env-file`, and `src/config/env.js` reads the variables once
at boot. Everything after `PGPASSWORD` has a default.

| Variable                   | Default                 | Description                                                      |
| -------------------------- | ----------------------- | ---------------------------------------------------------------- |
| `PORT`                     | `3100`                  | Port the server listens on                                       |
| `PGHOST`                   | `127.0.0.1`             | PostgreSQL host                                                  |
| `PGPORT`                   | `5432`                  | PostgreSQL port                                                  |
| `PGDATABASE`               | required                | Database name (`masterpod` locally)                              |
| `PGUSER`                   | required                | Application role (`masterpodsoftware` locally)                   |
| `PGPASSWORD`               | required                | Application role's password                                      |
| `WEB_ORIGIN`               | `http://localhost:4200` | The web app's origins, comma-separated: the CORS allow-list and the WebAuthn expected origins (one locally; the wallet and the moderator wallet one day) |
| `RECOVERY_POD_URL_BASE`    | `http://localhost:3100` | This server as the keyholders reach it; the banker packet's URL is built from it |
| `RP_ID`                    | `localhost`             | WebAuthn relying party id                                        |
| `EPHEMERAL_KEY_HOURS`      | `12`                    | Life of a session's ephemeral keys                               |
| `CHALLENGE_SECONDS`        | `120`                   | Life of a challenge                                              |
| `TIMESTAMP_WINDOW_SECONDS` | `120`                   | Allowed clock difference on a signed request, each way           |
| `MAX_IMAGE_BYTES`          | `10485760`              | Largest image, decoded                                           |
| `MAX_IMAGES_PER_REQUEST`   | `5`                     | Images per bucket request                                        |

The JSON body limit is computed from the last two:
`MAX_IMAGES_PER_REQUEST * MAX_IMAGE_BYTES * 1.4 + 1 MB`.

## Genesis

Nothing can be vouched until a seed exists. The first super seeds are made by
the operator: create the pod through the web app like any other, then

```bash
npm run make-super-seed -- <anopod id, hex>
```

sets `vouched = true` and inserts the `super_seeds` row with `vouched_by =
'genesis'`, in one transaction. Idempotent; there is no route for it. A pod a
super seed vouches for is vouched at once and becomes a seed; a pod two
seeds vouch for is vouched but not a seed.

## Layout

```
src/
  server.js          boots: checks the database, listens, shuts down cleanly
  app.js             builds the Express app: CORS, JSON limit, mounts the routers
  config/env.js      reads and validates the environment once
  db/pool.js         the shared pg pool, query() and closePool()
  db/transaction.js  withTransaction(fn) and the unique-violation check
  crypto/            bytes, canonical JSON, SHA-256, P-256 and ML-DSA-87 (copies of anossoftware's)
  util/              ids, images, is-object, the ok/refuse/answer result shape
  auth/              /challenge; requireSession, requireVouched, requireSetup, requireModerator, requireAttestor, requireRecoverySession; challenges, nonces, the signed envelope, WebAuthn
  anopods/           /create-anopod, /unlock, /check-username, /check-anopod-status, /get-anopod-profile, /complete-setup
  vouching/          /search-usernames, /send-vouch-request, /list-vouch-requests, /approve-vouch-request, /decline-vouch-request
  notifications/     /list-notifications, /mark-notifications-read; notify() for every feature
  security/          the three bucket routes
  chat/              the thirteen chat routes
  marketplace/       /create-listing, /close-listing, /list-listings
  anos-accounts/     /create-anos-account, /mark-anos-account-submitted, /list-anos-accounts, /get-anos-account
  wallet-memory/     the six wallet memory routes, /add-noted-transaction to /set-wallet-settings; the two tables' queries
  recovery/          /open-recovery-case, /unlock-recovery-pod, /get-recovery-pod, the six moderator routes, /receive-recovery-share/:caseId, /recover-with-backup-code, /complete-recovery-case, /rotate-backup-code, /store-break-glass-blob; the four recovery tables' queries
  attesting/         the fourteen attestor routes, /list-attestors to /dismiss-attestor-case, and the person's /list-my-cases, /get-my-case, /share-lookup-id, /add-dispute-evidence; the five attestation tables' queries; account-signatures.js, the validators' any-two-pairs rule
  break-glass/       the nine break-glass routes, the person's /file-break-glass-moves and /list-my-break-glass-moves and the attestors' /list-break-glass-cases to /dismiss-break-glass-case; the two break-glass tables' queries

  health/            GET /health: status, uptime, database round trip
  middleware/        404 and the central error handler
db/
  schema.sql         the whole schema, built from nothing
scripts/
  setup-db.sh        role, database, schema (idempotent)
  reset-db.sh        drop and set up again
  find-psql.sh       finds Homebrew's keg-only psql
  make-super-seed.js genesis
docs/
  schemas.md         the specification: tables, routes, objects, client crypto, variables
  build-plan.md      how it was built

```

Each feature folder owns its router (the paths and their levels), its
handlers (HTTP in and out only), its service (the checks in the spec's order,
returning `ok(status, body)` or `refuse(status, reason)`) and its queries
(the SQL). Every multi-row write is one transaction through
`db/transaction.js`.

## Deferred, by decision

- Inside recovery (`docs/schemas.md` section 12.9): one approval and one
  rejection on a case; revoking a moderator; the meeting link by email;
  limits on opening cases; notifications for case events (moving anos
  with the recovered break-glass seeds was built 2026-11-08, section 14).
- Inside attestation (section 13.9): revoking an attestor, an attestor's
  history of cases; a party deleting or replacing their evidence, other
  content types or larger files; a time limit on open cases, a case on a
  trade whose accounts the masterpod does not know; the meeting link by
  email; notifications for bucket views and key shares; paging on the
  lists. The attestors' app is the wallet's attestor edition (build 3).
- Inside break-glass moves (section 14.9): notifications to the attestors
  and to the person; a move filed after a cancel on the ledger; a
  dismissal with an effect on the ledger; the owner's dispute path,
  forwarding and a repeat sweep for money that lands in an old account
  after the move.

- Several passkeys or several live sessions per pod.
- Purging pods that never got vouched, and their usernames.
- Removing a member from a room and rotating the room key.
- Editing a listing, a profile or a selfie.
- Push delivery of notifications and messages; the phone polls.
- Generic encrypted object storage, anoSphere, the anos interface.
- Anti-abuse limits on `/challenge` and `/create-anopod`.
