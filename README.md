# masterpodsoftware

The masterpod server for the anos system: an Express 5 server backed by
PostgreSQL, laid out like anossoftware so the two read alike. It keeps the
anoPods: a pod's public profile and selfie, its passkeys, its one live
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
| `npm run appoint -- <id> <role>` | Appoint the pod with this hex id for a role: `moderator`, `attestor`, `validator` or `masterPod` (`docs/schemas.md` section 16; the last two only let the pod stake for that purpose, 16.7). |
| `npm run revoke -- <id>` | End the pod's appointment; the row stays on record.                   |
| `npm run small-selfies -- look` | The one-time job that makes the stored selfies small (`docs/schemas.md` section 24): `look` reads and draws every selfie and writes nothing; with `write` in its place it does the same and then writes. Its own packages are in `scripts/small-selfies/`. |
| `npm run stickers -- look <folder>` | Puts the stickers of the wallet's chat into the database (`docs/schemas.md` section 28), from a folder with `all-sets.ts`, one `.ts` file for each set and one folder of pictures for each set: `look` says what it would write, names every fault and writes nothing; with `write` in its place it does the same and then writes, all of it or nothing. |
| `npm run make-alert-push-key -- <file>` | Makes this server's key for the phones' delivery services (`docs/schemas.md` section 25): writes ONE line, `ALERT_PUSH_PRIVATE_KEY=...`, to `<file>`, which only its owner can read and which is never overwritten, and prints the public half. The line goes to the end of `.env`. |

## Who may call what

Every route is a `POST` with a JSON body, except one: `GET
/sticker-picture/<set>/<number>` (2026-11-23), which answers a picture.
Four pod levels and three more:

| Level    | Meaning                                                                                  |
| -------- | ---------------------------------------------------------------------------------------- |
| none     | Plain JSON body, no signature: `/challenge`, `/check-username`, `/get-anopod-session-keys`, `/get-anos-account`, `/check-signing-passkey`, the keyholders' `/receive-recovery-share/:caseId`, the validators' `/report-waiting-transfers`, whose message is signed by a validator's own key, `GET /sticker-picture/<set>/<number>`, which has no body; `/create-anopod`, `/unlock`, `/open-recovery-case` and `/unlock-recovery-pod` are signed by the ephemeral keys inside them, `/recover-with-backup-code` by the backup code keys inside it. |

| session  | Signed by the pod's current ephemeral keys (the envelope below). Vouched or not.          |
| vouched  | session, and `anopods.vouched` is true.                                                  |
| setup    | vouched, and setup is complete (the pod has chat keys): every chat and marketplace route, the four anos account routes, the six wallet memory routes, `/rotate-backup-code` and `/store-break-glass-blob` after a recovery, the person's four attestation routes `/list-my-cases`, `/get-my-case`, `/share-lookup-id`, `/add-dispute-evidence`, the person's two break-glass routes `/file-break-glass-moves`, `/list-my-break-glass-moves`, the two passkey routes `/add-passkey`, `/list-passkeys`, the eight routes of a pod's security alerts, `/list-alert-settings` to `/keep-alert-phone`, `/list-stickers`, and Joy's three routes `/ask-joy`, `/get-joy-memory`, `/set-joy-memory`. |
| recovery | Signed by a recovery pod's current ephemeral keys: the same envelope with `caseId` in place of `anopodId` (`src/auth/require-recovery-session.js`); `/get-recovery-pod`, `/complete-recovery-case`. |

| moderator | session, and the pod holds a live appointment for the role (`appointments`, `docs/schemas.md` section 16, written by `npm run appoint`; `src/auth/require-moderator.js`; the stake is the keyholders' check); the six moderation routes. |
| attestor | session, and the pod holds a live appointment for the role (`appointments`, section 16; `src/auth/require-attestor.js`, the moderator rule with the other role; the stake is the validators' and the keyholders' check); the fourteen attestor routes of section 13 and the seven break-glass routes of section 14. |

Failing a level: `401` for anything wrong with the signature or the session,
`403 anopod not vouched`, `403 setup not complete`, `403 not a moderator`, `403 not an attestor`. Other errors are
`{ error: '<reason>' }` with `400` for a bad shape or value, `403` for a
caller who may not do this, `404` for a thing that does not exist, `409` for
a conflict with what is already there, `410` for a thing that can no longer
be used (a code that ran out), `429` for too many in a given time, and `503`
for a part of the server that is not set up or cannot reach what it needs.

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
| `/challenge`                    | none    | Issues a single-use WebAuthn challenge for `create`, `unlock`, `openCase`, `unlockCase`, `recover` or `addPasskey`; `create` also mints the new pod's id; `openCase` takes the anoPod id the keyholders named for the lookup id and answers its username (2026-11-08); `addPasskey` (2026-11-18) takes the pod's id, and its challenge lives `ADD_PASSKEY_CHALLENGE_SECONDS`; since 2026-11-18 `openCase` may also take the lookup id, is refused `409 case already open` when a case is open for it, and answers the credential ids of the pod's passkeys (section 20) |
| `/create-anopod`                | none    | Creates a pod: profile, selfie, passkey registration (PRF required), first session        |
| `/unlock`                       | none    | Opens a session: passkey assertion, by the main passkey or an added one, new ephemeral keys; answers the blobs to unwrap, `identityBlob` included; `wrappedKeyBlobKey` for an added one |
| `/check-username`               | none    | Lowercases the username, checks the rule, says whether it is free                        |
| `/check-anopod-status`          | session | The caller's vouched, vouchCount, setupComplete, isSeed, isSuperSeed, role (`moderator`, `attestor` or null, section 16), and its rows in each bucket (bucketOneImages, bucketTwoImages, bucketTwoInfos) |
| `/get-anopod-profile`           | session | A pod's public profile with its selfie                                                   |
| `/get-anopod-session-keys`      | none    | A pod's current session public keys and their expiry, for the keyholders' pod check      |
| `/search-usernames`             | session | Any pod by exact username, with selfie and seed flags; finds a seed to ask and a pod to invite |
| `/send-vouch-request`           | session | Asks a seed to vouch for the caller                                                      |
| `/list-notifications`           | session | The caller's notifications, newest first (`unreadOnly`, `limit`); since section 34 also only the rows above a number (`since`), below one (`before`) or of some kinds (`kinds`), each row with its `seq`, and `seq`, `count` and `unread` in every answer |
| `/mark-notifications-read`      | session | Marks notifications read: the ones named by their ids, or, since section 34, every unread one up to a number (`upTo`) |
| `/list-vouch-requests`          | vouched | The open requests addressed to the caller (a seed), oldest first, each with the requester's profile (no selfie since 2026-11-08; the wallet reads it through `/get-anopod-profile`) |
| `/approve-vouch-request`        | vouched | Records the vouch; flips `vouched` on a super seed's approval or the second vouch; a super seed's approval also makes a seed |
| `/decline-vouch-request`        | vouched | Drops the request and notifies the requester                                             |
| `/complete-setup`               | vouched | Stores the two encryption key blobs, the backup code keys, the chat keys and the identity blob (eight fields), once |
| `/add-passkey`                  | setup   | Adds a passkey to the caller's pod (2026-11-18, section 19): a fresh tap of a passkey the pod has, the new passkey's registration (PRF required), and the new passkey's own locked copies of the pod's encryption key and key blob key; notifies the pod; no route removes one |
| `/list-passkeys`                | setup   | The caller's passkeys by credential id: the main one, and the added ones, oldest first    |
| `/check-signing-passkey`        | none    | For the signing servers: whether a passkey answer is from a passkey of the pod that made an account and is an answer to the given challenge; writes nothing |
| `/add-to-security-bucket-one`   | vouched | Stores encrypted images in bucket one, under the bucket key `keyId` names                |
| `/add-to-security-bucket-two`   | vouched | Stores encrypted images and texts in bucket two, under the bucket key `keyId` names      |
| `/list-security-records`        | vouched | Everything in both buckets for the caller, each row with its `keyId`                     |
| `/create-chat-room`             | setup   | A private or public room with the creator's own wrapped room key; a private room can be about a listing (`listingId`, 2026-11-06) or, when an attestor makes it, about an attestor case that is open or in review (`caseId`, 2026-11-11) |
| `/invite-to-chat-room`          | setup   | The creator invites a pod, carrying the room key wrapped to it; since 2026-11-11 a member of a listing chat who did not start it may invite an attestor, and a room about a case takes only a person on that case or an attestor |
| `/accept-invite`                | setup   | Joins: the wrapped key moves into `chat_hpke`                                            |
| `/decline-invite`               | setup   | Drops the invite                                                                         |
| `/request-to-join`              | setup   | Asks to join a public or marketplace room (open listing only)                            |
| `/approve-join`                 | setup   | The creator lets the requester in with the wrapped key                                   |
| `/decline-join`                 | setup   | Drops the join request                                                                   |
| `/leave-chat-room`              | setup   | Leaves a room; the creator cannot                                                        |
| `/list-chat-rooms`              | setup   | The caller's rooms (members, each with how far they have read, invited, own wrapped key, newest message, the listing a room is about with its owner, the case a room is about with its kind, and `pictureAt`, when the room's picture was last set), open invites (each with its listing and its case too), join requests on its rooms; every answer with `seq` and `counts`, and with `since` in the request only what changed after that number: a room whole, or its newest message alone (2026-11-24, section 29); since section 31 the newest message is given as it stands now, with `editPosition` and `deleted`: an edited one with its newest text, a deleted one without text |
| `/list-public-chat-rooms`       | setup   | Public rooms, the ones with the most members first; `search` narrows them by name (2026-11-22); each with `pictureAt`, when its picture was last set; paged |
| `/set-chat-room-picture`        | setup   | The creator of a public room gives it a picture, or another in place of the one it has (2026-11-22, section 27): at most 320 pixels wide and high and 100,000 bytes |
| `/get-chat-room-picture`        | setup   | A public room's picture, for any pod at this level: it is as public as the room's name   |
| `/list-messages`                | setup   | A room's messages after a position, or the newest ones before a position, members only; with `seenSince` in the request also the members whose seen position rose after that number (2026-11-24, section 29); since section 31 the edits and the deletes of a message are rows among them, each row has `kind` and `targetMessageId`, and a row goes out without its ciphertext once a later row names the same message |
| `/send-message`                 | setup   | Stores a ciphertext message, members only                                                |
| `/edit-message`                 | setup   | A member gives a message of their own a new text, until 15 minutes after it was sent (2026-11-24, section 31): a new row that names the message, and no row is changed; off in a room about a listing, in an old marketplace room and in a room about an attestor case |
| `/delete-message`               | setup   | A member deletes a message of their own, at any time (2026-11-24, section 31): a new row that names the message, with no ciphertext, and no row is removed; off in the same three kinds of room |
| `/mark-messages-seen`           | setup   | Records how far the caller has read in a room, members only                              |
| `/get-chat-public-keys`         | setup   | The chat public keys of up to 50 pods that completed setup                               |
| `/list-stickers`                | setup   | The stickers of the wallet's chat (2026-11-23, section 28): every set in the order of the row, each with its stickers in their order, each sticker with its two-digit number and its tags; text only, no picture |
| `GET /sticker-picture/:set/:number` | none | One sticker's picture, the bytes as `image/webp`; `404` when there is no such sticker. The one `GET` that hands out data, and the one answer that is not JSON |
| `/create-listing`               | setup   | A listing of anos for a fiat currency; since 2026-11-06 without a room of its own, people connect with a private room each; `403` at the limit of 10 open listings per pod |
| `/close-listing`                | setup   | Closes the owner's listing; an old listing's room stays, new join requests and new rooms about it are refused |
| `/list-listings`                | setup   | Listings filtered by side, currency, country and status (`any` allowed), the caller's own with `mine`, sorted and paged |
| `/get-listing`                  | setup   | One listing by id, open or closed, in the list's form                                    |
| `/create-anos-account`          | setup   | Records an anos account the pod made: type, the blob with both pairs and the first key blob, both under the pod's key blob key, the signed creation; `409` on a repeat, `403` at the limit of 20 new accounts in 30 days |
| `/mark-anos-account-submitted`  | setup   | Records that a validator answered the account's creation; the caller's accounts only     |
| `/list-anos-accounts`           | setup   | The caller's anos accounts, oldest first, each with one blob: its first key blob once it has one, the blob with both pairs until then (`firstKeyOnly` says which; section 22), with the creation, `submittedAt` and `breakGlassBlob` (null until a recovery stored it); `409 reload the wallet` for a page that cannot open a first key blob |
| `/store-first-key-blob`         | setup   | The first key blob of one of the caller's accounts, pair one alone; written once, `409` on a repeat |
| `/add-noted-transaction`        | setup   | Records a note on a ledger transaction of the caller's, for their tax records: the ledger's facts in the clear, the private part as a blob under the pod's encryption key; one note per transaction and account, `409` on a second |
| `/update-noted-transaction`     | setup   | Replaces a note's blob; the ledger's facts never change; the caller's notes only |
| `/remove-noted-transaction`     | setup   | Deletes a note; the caller's notes only                                                  |
| `/list-noted-transactions`      | setup   | The caller's notes in a date range, newest first, the newest 1,000 with `more` when there are older ones |
| `/get-wallet-settings`          | setup   | The caller's wallet settings blob and when it was set, null before the first set         |
| `/set-wallet-settings`          | setup   | Stores the caller's wallet settings blob whole: one row per pod, replaced in place        |
| `/ask-joy`                      | setup   | A message to Joy, the wallet's AI (2026-11-24, section 30): the conversation and the caller's opened memory file go to Anthropic's model, and the answer comes back as a stream of JSON lines; counted against the caller's messages of the day; nothing of it is stored; since section 32 Joy can search the web, the stream has a line when a search starts and the cited pages as `sources` in its last line, and the searches are counted for the caller's day; since section 33 (2026-11-25) Joy can have a picture made by OpenAI's image model, the stream has a line when she starts on one and one line with the picture, the description she wrote goes to OpenAI, and the pictures are counted for the caller's day |
| `/get-joy-memory`               | setup   | The caller's memory file for Joy, as the blob the wallet made, and when it was set, null before the first set |
| `/set-joy-memory`               | setup   | Stores the caller's memory file blob whole: one row per pod, replaced in place           |

| `/get-anos-account`             | none    | For the validators' binding check and their appointment check: the pod that made an account, whether it is vouched, and its role (`moderator`, `attestor` or null) |
| `/open-recovery-case`           | none    | A locked-out person's recovery case and its recovery pod: the lookup id, a contact email and a contact phone (both required since 2026-11-12; the phone since 2026-11-11), a new passkey (PRF required) registered under the pod's id (the one the keyholders named, from `/challenge` openCase), the hybrid key the bankers encrypt shares to; `409` while a case for the lookup id is open |
| `/unlock-recovery-pod`          | none    | Opens a recovery session on a return visit: the recovery passkey's assertion, new ephemeral keys; answers the hybrid key blob to open |
| `/get-recovery-pod`             | recovery | The person's view of their case: status, the contact email and phone, how many anos accounts the pod made up to the opening of the case (`anosAccounts`, 2026-11-11; only those since 2026-11-12), the events they may see, the shares the keyholders posted, `blob2` once the case is approved |
| `/list-recovery-cases`          | moderator | The cases by status (the four in-progress ones by default), newest first, each with the pod's names, the contact email and phone and the count of approving pods |
| `/get-recovery-case`            | moderator | One case: the row with the contact email and phone, the pod's profile and selfie, every event with the acting moderator and its details complete, the shares received, the banker packet |
| `/list-case-security-records`   | moderator | The case's pod's rows of one bucket, ciphertext with their key ids; writes the viewed event |
| `/schedule-recovery-case`       | moderator | The video call: the `scheduled` event with the time and the https link; status `inReview` |
| `/sign-off-recovery-case`       | moderator | A verdict signed by pair one of an anos account in the caller's pod, verified against the stored creation; the second distinct approval approves the case |
| `/dismiss-recovery-case`        | moderator | Closes the case with a preset reason and a note; final |
| `/receive-recovery-share/:caseId` | none  | A keyholder's share for the case, stored as posted (a repeat is a no-op); the first one makes the case `delivering`; `409` before two approvals or after the end |
| `/recover-with-backup-code`     | none    | The finish: the backup code proof (both signatures by the keys the code derives); the recovery passkey becomes the pod's, `blob1` is replaced, the lost device's session ends, the added passkeys are deleted |
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
| `/list-my-cases`                | setup   | The caller's cases as a party: trades and disputes, newest first; each dispute with the attestors on it (2026-11-11) |
| `/get-my-case`                  | setup   | The person's view of one case: their subset of the events; for a dispute the attestors on it, the case key and their own evidence with `keyForMe` |
| `/share-lookup-id`              | setup   | The person hands the attestor their lookup id on a trade case |
| `/add-dispute-evidence`         | setup   | A party's evidence files, each ciphertext with its content key wrapped twice, or files of theirs supplied again under `existing` |
| `/file-break-glass-moves`       | setup   | The finish of a recovery files its break-glass moves: the recovery case's id and, per move, the old account, the new account of the same type and the `breakGlassTransfer`'s id; a second call adds moves |
| `/list-my-break-glass-moves`    | setup   | The caller's break-glass cases with their moves and the person's subset of the events: what a lost account's card shows |
| `/list-break-glass-cases`       | attestor | The break-glass cases by status (`open` and `inReview` by default), newest first, with the person's names, the moves and the sign-off counts |
| `/get-break-glass-case`         | attestor | One case: the recovery case's lookup id, status and two moderator approvals, the person's profile and selfie, the moves, every event with the acting pod and its details complete |
| `/list-break-glass-case-security-records` | attestor | The person's rows of one bucket, ciphertext with their key ids; writes the viewed event |
| `/schedule-break-glass-case`    | attestor | The video call: the `scheduled` event, status `inReview`; the person is notified (`recoveryCaseScheduled`, 2026-11-11) |
| `/sign-off-break-glass-case`    | attestor | One attestation per move of the case, each the validators' follow-up signed by two pairs of the caller's account and verified against the stored creation, posted together; the second distinct pod's decides the case |
| `/mark-break-glass-case-sent`   | attestor | Records that the stored attestations, two per move, were posted to a validator, and the answers; a retry writes another event |
| `/dismiss-break-glass-case`     | attestor | Closes the case with a preset reason and a note; final; the held moves stay on the ledger until a cancel |
| `/create-dao-proposal`          | setup   | A plain-text DAO proposal, title 1 to 100 and body 1 to 5,000 characters: reads every account's DAO stake from a validator, stores the posting snapshot, counts the proposer's own weight as the first support; `503 validators unreachable` when no validator answers |
| `/support-dao-proposal`         | setup   | Supports a pending proposal with the caller's weight in the posting snapshot, once, no undo; the support that reaches `needed` opens the vote on a fresh snapshot |
| `/vote-dao-proposal`            | setup   | Votes for or against an open proposal with the caller's weight in the fresh snapshot, once, no undo |
| `/list-dao-proposals`           | setup   | The pending, open or decided proposals, newest first, paged, a date range on each, with the live sums, the caller's own part and the dials (`settings`); expired ones are never listed |
| `/get-dao-proposal`             | setup   | One proposal with its body, in the list's form; an expired one too, so an old link resolves |
| `/list-dao-votes`               | setup   | The supports or the votes of a proposal, newest first, paged: each voter's pod, username, vote, weight and time; every vote is public |
| `/list-alert-settings`          | setup   | The caller's security alerts (2026-11-21, section 25): its emails and its phones, oldest first, a phone named by the hash of its delivery address; whether email is on, and this server's public key for the phones |
| `/add-alert-email`              | setup   | An email for the caller's alerts, sent a six-digit code; a new code for one that is not confirmed yet; `403` at 3 emails, `429` at 5 codes in 24 hours or within 60 seconds of the last, `503` while email is off |
| `/confirm-alert-email`          | setup   | The code typed back: the email counts from here, and the rest of the list is told; `401` on a wrong code, `410` on one that ran out or is used up |
| `/remove-alert-email`           | setup   | "Take off": a confirmed email is set to come off a month from now and gets every alert until then; the whole list is told; one that was never confirmed goes at once |
| `/keep-alert-email`             | setup   | "Keep": an email that was set to come off stays; the whole list is told; never refused by the count of changes |
| `/add-alert-phone`              | setup   | A phone for the caller's alerts: the delivery address, the public key and the secret its browser handed over, and the kind of device; only on Apple's, Google's, Mozilla's or Microsoft's delivery service; the rest of the list is told and the phone gets a first notification; `403` at 5 phones, `503` while the phones are off |
| `/remove-alert-phone`           | setup   | "Take off": the phone is set to come off a month from now; the whole list is told |
| `/keep-alert-phone`             | setup   | "Keep": a phone that was set to come off stays; the whole list is told |
| `/report-waiting-transfers`     | none    | For the validators: the transfers that have started to wait out of a guarded, a vault or an assisted account, and a recovery's moves, in one message signed by the validator's own key; the first report of a transfer tells the pod that made the account, by email, on the phone and under the bell |

The objects each route takes and answers are in `docs/schemas.md` section 5;
the notification kinds in section 6; what the phone computes (PRF-derived
key, blobs, backup code, chat key pair, room key wrapping, the identity
blob, the anos key blob) in section 7. The wallet's spec,
`~/Desktop/Z/web_app/docs/schemas.md` section 4, is where the 2026-10-25
changes (identity blob, key ids on the buckets, the status counts, anos
accounts) come from. Recovery is section 12: the fourteen routes above,
built in three builds on 2026-10-26 (the case and the recovery pod, the
moderation, the delivery and the finish). A moderator is a pod the
operator appointed as one (`npm run appoint`, 12.2 and section 16; until
2026-11-08 a pod named `moderator...` that a super seed vouched for); the
moderators' app is the wallet's moderator edition; the keyholders post the
bankers' shares to `/receive-recovery-share/:caseId`, and the person's
wallet combines them and finishes. Attestation is section 13: the eighteen
routes above, built 2026-10-26 (attestor build 2, after the validators' two
attestor reads and the keyholders' stake rule of build 1). An attestor is a
pod the operator appointed as one (13.2 and section 16; until 2026-11-08 a
pod named `attestor...` that a super seed vouched for); the attestors' app
is the wallet's attestor edition (build 3); a sign-off is the validators'
own follow-up object, verified here against the account's stored creation
and posted to a validator by the deciding attestor's app.
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
(`\d+ <table>` in psql). Beside the tables there are two sequences.
`chat_change_seq` (2026-11-24, section 29) is the counter of the changes
of the chat lists: triggers write its values into five columns of the
chat tables. `notification_seq` (2026-11-25, section 34) is the counter
of the notifications: each new row of `notifications` takes its next
value as its `seq`. No route reads a counter itself.

| Table                     | Holds                                                                  |
| ------------------------- | ---------------------------------------------------------------------- |
| `anopods`                 | One row per pod: profile, main passkey, live session, vouched, setup blobs and keys, the identity blob |
| `added_passkeys`          | One row per passkey a pod added after its first (section 19): the passkey and its own locked copies of the pod's encryption key and key blob key; deleted, all of the pod's, by the finish of a recovery |
| `public_selfies`          | One plaintext selfie per pod                                           |
| `challenges`              | Single-use WebAuthn challenges                                         |
| `nonces`                  | The replay cache of signed requests                                    |
| `vouch_requests`          | Open vouch requests                                                    |
| `vouches`                 | Approved vouches, never changed                                        |
| `seeds`, `super_seeds`    | The pods that may vouch                                                |
| `appointments`            | The pods that are moderators or attestors, and the pods that may stake for validator or masterPod: one row per appointment, revoked rows kept |
| `notifications`           | What the phone polls; read, never deleted; twenty-one kinds, the newest the four of the security alerts (2026-11-21); `seq`, each row's running number from the counter `notification_seq` (section 34) |
| `security_images`         | Encrypted images of both buckets, each with the id of its bucket key; append-only |
| `security_info`           | Encrypted texts of bucket two, each with the id of its bucket key; append-only |
| `chat_rooms`              | Private, public and old marketplace rooms; `listing_id` when a room is about a listing, `case_id` and `case_kind` when it is about an attestor case; `message_seq` and `people_seq`, the counter's value at the room's last message, or since section 31 edit or delete of one, and at its last other change (section 29) |
| `chat_room_members`       | Who is in which room, and how far each has read; `seen_seq`, the counter's value when that last changed (section 29) |
| `chat_hpke`               | Each member's wrapped room key                                         |
| `chat_room_invites`       | Open invites, carrying the wrapped key; `change_seq`, the counter's value when the invite was written (section 29) |
| `chat_room_join_requests` | Open join requests; `change_seq`, the counter's value when the request was written (section 29) |
| `chat_room_messages`      | Ciphertext messages, numbered by `position`; since section 31 also the edits and the deletes of a message, each a row of its own with `kind` and `target_message_id`, a delete without ciphertext; no row is ever changed or removed |
| `chat_room_pictures`      | The picture of a public room (section 27): at most one per room, in the clear like the room's name, set by the room's creator |
| `sticker_sets`            | The sets of stickers of the wallet's chat (section 28), each with its place in the row of sets; written by `npm run stickers` alone |
| `stickers`                | One row per sticker: its set, its two-digit number, its place in the set and its picture, a WebP of at most 150,000 bytes; in the clear, the same for everybody |
| `sticker_tags`            | The tags of the stickers, one row per sticker and tag: the words that bring a sticker up while a person types; matched on the phone, never searched here |
| `listings`                | Marketplace listings; `chat_room_id` only on the old ones that got a room |
| `anos_accounts`           | One row per anos account a pod made: type, the blob with both pairs, the first key blob, the signed creation, when it was submitted, the break-glass blob after a recovery; never deleted |
| `noted_transactions`      | One row per ledger transaction a pod noted for its tax records: the ledger's facts in the clear, the private part as a blob under the pod's encryption key; one per pod and transaction; deleted when the person removes it |
| `wallet_settings`         | One row per pod: the small things its wallet remembers as one encrypted blob (the Protect your passkey answer first); replaced in place |
| `joy_memories`            | One row per pod: the member's memory file for Joy (section 30) as one encrypted blob, which this server cannot open; replaced in place |
| `joy_usage`               | One row per pod and day (UTC): the messages sent to Joy, the tokens Anthropic counted for them, since section 32 the web searches Anthropic made for them and, since section 33, the pictures OpenAI made for them; no text of a message and no picture; the daily limit of messages, the daily number of searches and the daily number of pictures are read from it |
| `recovery_cases`          | One row per recovery case: lookup id, the pod being recovered, contact email and phone (both on a case opened since 2026-11-12; the table's check is still at least one of the two, for a case of before), status; one open case per lookup id |
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
| `dao_proposals`           | One row per DAO proposal: the text, the proposer, the status, the current snapshot's total, the support needed, the stage times, the result; never deleted |
| `dao_votes`               | One row per pod per stage of a proposal: a support while pending, a vote for or against while open, each with the pod's weight at the time; append-only, public |
| `dao_snapshot_weights`    | A proposal's current snapshot, one row per pod with DAO votes; replaced when the proposal goes open, deleted when it finishes |
| `alert_emails`            | The emails a pod's security alerts go to (section 25), in plain text: the address, its language, the six-digit code until it is confirmed, the day it comes off once it was taken off |
| `alert_phones`            | The phones a pod's security alerts go to: one row per browser that allowed notifications, with its delivery address, public key and secret, and the kind of device |
| `alert_transfers`         | The waiting transfers the validators have reported: one row per report with its own facts, keyed by the hash of those facts; append-only |
| `alert_messages`          | One row per message to one email or one phone, written with the event it reports and sent by the alert sender; holds no address; kept after it is sent |

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
| `ADD_PASSKEY_CHALLENGE_SECONDS` | `600`              | Life of a challenge for `/add-passkey` (ten minutes)             |
| `TIMESTAMP_WINDOW_SECONDS` | `120`                   | Allowed clock difference on a signed request, each way           |
| `MAX_IMAGE_BYTES`          | `10485760`              | Largest image, decoded                                           |
| `MAX_IMAGES_PER_REQUEST`   | `5`                     | Images per bucket request                                        |
| `VALIDATOR_URLS`           | `http://localhost:3001` to `3005` | The validators asked for the DAO stake list, comma-separated, tried in order; on the servers the doormen's URLs (the wallet's list) |
| `DAO_PROPOSE_MIN_VOTES`    | `1`                     | The least DAO votes (whole staked anos) a pod needs in the snapshot to post a proposal |
| `DAO_PROPOSAL_PERCENT`     | `15`                    | The percent of all DAO votes a pending proposal needs in support to go to a vote; at most 100 |
| `DAO_PASS_PERCENT`         | `50`                    | For must be more than this percent of the votes cast; at most 99, so a tie fails |
| `DAO_PENDING_MINUTES`      | `10080`                 | How long a proposal may collect support (a week)                 |
| `DAO_VOTE_MINUTES`         | `20160`                 | How long an open proposal takes votes (two weeks)                |
| `RESEND_API_KEY`           | none: no email is sent  | The email company's key (security alerts, `docs/schemas.md` section 25); set together with `ALERT_EMAIL_FROM` or not at all |
| `ALERT_EMAIL_FROM`         | none                    | The sender of every email: `anoPod wallet <alerts@wallet.anocloud.com>` on the servers |
| `ALERT_PUSH_PRIVATE_KEY`   | none: no notification is sent | The private half of this server's key for the phones' delivery services, 43 characters, made by `npm run make-alert-push-key`; set together with `ALERT_PUSH_CONTACT` or not at all |
| `ALERT_PUSH_CONTACT`       | none                    | The contact the delivery services are given: `https://wallet.anocloud.com` on the servers |
| `ALERT_REMOVE_MINUTES`     | `43200`                 | How long an email or a phone that was taken off still gets every alert (a month) |
| `VALIDATOR_KEYS_FILE`      | `network/validators.json` | The validators' public keys, for their reports of waiting transfers; a path from the repo's root, or a full path |
| `ANTHROPIC_API_KEY`        | none: Joy is off        | Anthropic's API key (Joy, `docs/schemas.md` section 30); without it `/ask-joy` answers `503 joy is off` |
| `JOY_MODEL`                | `claude-haiku-5-5`      | The model that writes Joy's answers                              |
| `JOY_EFFORT`               | `medium`                | How hard the model thinks before it answers: `low`, `medium` or `high` |
| `JOY_MAX_TOKENS`           | `16000`                 | The most tokens one request to Anthropic may write, the model's thinking included |
| `JOY_DAILY_MESSAGES`       | `300`                   | How many messages one pod may send Joy in one day (UTC)          |
| `JOY_MAX_SEARCHES`         | `3`                     | The most web searches for one message to Joy (`docs/schemas.md` section 32); `0` switches web search off |
| `JOY_DAILY_SEARCHES`       | `100`                   | From how many web searches in one day (UTC) a pod's further messages go out without web search; `0` switches web search off |
| `OPENAI_API_KEY`           | none: Joy makes no picture | OpenAI's API key (Joy's pictures, `docs/schemas.md` section 33); without it Joy answers as before and tells a member that pictures are switched off |
| `JOY_PICTURE_MODEL`        | `gpt-image-2.6-flare`   | OpenAI's image model                                             |
| `JOY_PICTURE_QUALITY`      | `low`                   | The quality of a picture: `low`, `medium` or `high`              |
| `JOY_PICTURE_SIZE`         | `1024x1024`             | The width and the height of a picture, in pixels                 |
| `JOY_PICTURE_FORMAT`       | `jpeg`                  | The file format of a picture: `jpeg`, `png` or `webp`            |
| `JOY_DAILY_PICTURES`       | `30`                    | From how many pictures in one day (UTC) a pod's further messages go out without the picture tool; `0` switches pictures off |

The JSON body limit is computed from `MAX_IMAGES_PER_REQUEST` and
`MAX_IMAGE_BYTES`: `MAX_IMAGES_PER_REQUEST * MAX_IMAGE_BYTES * 1.4 + 1 MB`.

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

Moderators and attestors are appointed the same way (`docs/schemas.md`
section 16): create the pod through the web app, then

```bash
npm run appoint -- <anopod id, hex> <moderator|attestor|validator|masterPod>
npm run revoke -- <anopod id, hex>
```

inserts the `appointments` row with `appointed_by = 'operator'`, or ends
the pod's live appointment. `validator` and `masterPod` (2026-11-10,
section 16.7) open no route: they only let the pod stake for that purpose
at the validators. A pod holds one role at a time: revoke, then appoint
again for another. Running `appoint` again for the same role changes
nothing and says so. There is no route for either.

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
  passkeys/          /add-passkey, /list-passkeys (section 19), /check-signing-passkey (section 22); the added_passkeys table's queries
  alerts/            the security alerts (section 25): the eight routes of a pod's list, /list-alert-settings to /keep-alert-phone, and the validators' /report-waiting-transfers; the four alert tables' queries; alert-events.js, raiseAlert() for the bell's row and the messages; alert-words.js, the emails in English and Thai; email.js, the call to the email company; push.js, the scrambling of a notification for one phone; alert-sender.js, the sending and what comes off after its month, every minute; validator-keys.js, the validators' public keys
  vouching/          /search-usernames, /send-vouch-request, /list-vouch-requests, /approve-vouch-request, /decline-vouch-request
  appointments/      the appointments table's queries (section 16): who holds a live appointment as a moderator or an attestor, or as a pod that may stake for validator or masterPod; written only by scripts/appoint.js and scripts/revoke.js
  notifications/     /list-notifications, /mark-notifications-read; notify() for every feature
  security/          the three bucket routes
  chat/              the eighteen chat routes
  stickers/          /list-stickers and GET /sticker-picture/:set/:number (section 28); the three sticker tables' queries, the reads of the routes and the reads and writes of scripts/stickers.js; sticker-rules.js, the form of a set's name and of a sticker's number and the limits of a picture and of a tag
  marketplace/       /create-listing, /close-listing, /list-listings
  anos-accounts/     /create-anos-account, /mark-anos-account-submitted, /list-anos-accounts, /store-first-key-blob, /get-anos-account
  wallet-memory/     the six wallet memory routes, /add-noted-transaction to /set-wallet-settings; the two tables' queries
  joy/               Joy, the wallet's AI (section 30): /ask-joy, /get-joy-memory, /set-joy-memory; the two Joy tables' queries; joy.anthropic.js, the call to Anthropic through its own package; joy.memory.js, the memory file's text and Joy's two tools; joy.pictures.js, her third tool, make_picture, and the one request to OpenAI that makes a picture (section 33)
  recovery/          /open-recovery-case, /unlock-recovery-pod, /get-recovery-pod, the six moderator routes, /receive-recovery-share/:caseId, /recover-with-backup-code, /complete-recovery-case, /rotate-backup-code, /store-break-glass-blob; the four recovery tables' queries
  attesting/         the fourteen attestor routes, /list-attestors to /dismiss-attestor-case, and the person's /list-my-cases, /get-my-case, /share-lookup-id, /add-dispute-evidence; the five attestation tables' queries; account-signatures.js, the validators' any-two-pairs rule
  break-glass/       the nine break-glass routes, the person's /file-break-glass-moves and /list-my-break-glass-moves and the attestors' /list-break-glass-cases to /dismiss-break-glass-case; the two break-glass tables' queries
  dao/               the six DAO voting routes, /create-dao-proposal to /list-dao-votes; the three DAO tables' queries; validators.client.js, the one outbound call to the validators (the DAO stake read); snapshot.js, one weight per pod; dao-clock.js, the expiry, the flip and the close every minute

  health/            GET /health: status, uptime, database round trip
  middleware/        404 and the central error handler
db/
  schema.sql         the whole schema, built from nothing
joy/
  shared-memory.md   what every request to Anthropic begins with, the same for every member: who Joy is and how she answers (section 30)
network/
  validators.json    the id and the public key of each validator, from the validators' registry: who may report a waiting transfer (section 25)
scripts/
  setup-db.sh        role, database, schema (idempotent)
  reset-db.sh        drop and set up again
  find-psql.sh       finds Homebrew's keg-only psql
  make-super-seed.js genesis
  appoint.js         appoint a pod as a moderator or an attestor, or to stake for validator or masterPod (section 16)
  revoke.js          end a pod's appointment
  small-selfies/     the one-time job that makes the stored selfies small (section 24): small-selfies.js, with a package.json and a package-lock.json of its own for sharp
  stickers.js        puts the stickers of the wallet's chat into the database, with a look run that writes nothing and a write run (section 28)
  make-alert-push-key.js  makes this server's key for the phones' delivery services (section 25)
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
  when moves are filed, and to the person when the case is decided or
  dismissed (the one for the video call was built 2026-11-11, section 18);
  a move filed after a cancel on the ledger; a dismissal with an effect on
  the ledger; the owner's dispute path, forwarding and a repeat sweep for
  money that lands in an old account after the move.

- Several live sessions per pod.
- Purging pods that never got vouched, and their usernames.
- Removing a member from a room and rotating the room key.
- Editing a listing, a profile or a selfie.
- Push delivery of notifications and messages; the phone polls. (Since
  2026-11-21, `docs/schemas.md` section 25, the four kinds of the
  security alerts also go to the phone and by email. Every other
  notification and every chat message is still polled.)
- Generic encrypted object storage, anoSphere, the anos interface.
- Anti-abuse limits on `/challenge` and `/create-anopod`.
- Removing one passkey; a cap on a pod's passkeys; a name or a date for the
  main passkey (`docs/schemas.md` section 19).
- A route that hands out an account's blob with both pairs, for the screen
  where a person asks for their second key; signing servers that keep
  their own list of passkeys; a limit on how often `/check-signing-passkey`
  may be asked; the masterpod's own passkey check at a moderator's sign-off
  (section 22).
