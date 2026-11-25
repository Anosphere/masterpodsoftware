# Schemas: anoPods, vouching, security buckets, chat and marketplace

Design settled 2026-10-24 over four rounds of questions. This file is the
specification for the build laid out in `build-plan.md`: every table, every
route, every object a route receives and answers, and the formats the phone
produces. The README describes what is built today and is brought up to date
as part of the build; where the two disagree before then, this file wins.

`~/Desktop/masterpod_auth_flow.txt` was an earlier draft of the key handling.
Where it differs from this file, this file wins. It stays on the Desktop as
the reference for the flows that are not in this build (recovery with the
backup code, backup code rotation, several passkeys, several sessions).

## 1. Conventions

- Every authenticated request is `{ payload, signatures }`. `signatures` is
  `{ ecdsa, mldsa }`, both over the RFC 8785 canonical bytes of `payload`
  (the `canonicalize` npm package on both ends, as in anossoftware). Both
  must verify.
- Signatures are P-256 (64 bytes, r||s, over the SHA-256 of the message) and
  ML-DSA-87 (4627 bytes, pure, empty context), hex on the wire. P-256 public
  keys are 33 bytes compressed (65 uncompressed accepted), ML-DSA-87 public
  keys 2592 bytes, ML-KEM-1024 public keys 1568 bytes. The crypto helpers are
  copies of anossoftware's `src/crypto/`.
- Ids are 32 random bytes: 64 lowercase hex characters on the wire, `BYTEA`
  with a length check in the database. Hex is the wire form for every byte
  string except images and the WebAuthn JSON, which are base64 / base64url as
  the browser produces them. Base64 is accepted wherever hex is (the
  `decodeBytes` helper tells them apart by length).
- JSON field names are camelCase, database names snake_case, table names
  plural (`vouch_requests`, not `vouch_request`; `public_selfies`).
- Amounts of anos are millionths: decimal strings in JSON, `BIGINT` in the
  database, as in anossoftware. Prices in a fiat currency are decimal strings
  in JSON and `NUMERIC(24, 8)` in the database.
- Timestamps are ISO 8601 strings.
- Images travel as `{ contentType, image }`: `contentType` one of
  `image/jpeg`, `image/png`, `image/webp`; `image` base64 of the bytes as
  stored. At most `MAX_IMAGE_BYTES` (10 MB) decoded per image and
  `MAX_IMAGES_PER_REQUEST` (5) images per request. Public selfies are
  plaintext; security images are ciphertext whose content type describes the
  plaintext. Since 2026-11-12 a selfie is looked into (section 11, the
  pictures note): its bytes must begin as a picture of its content type
  does, and the width and the height its own header names must each be at
  most 4096 pixels. A security image cannot be looked into. Since
  2026-11-22 (section 27) a public room's picture is plaintext like a
  selfie and is looked into the same way, with limits of its own: at most
  320 pixels wide and high, and at most 100,000 bytes. Since 2026-11-23
  (section 28) a sticker's picture is the one picture that does not
  travel inside JSON: it is the answer of a `GET`, the bytes themselves
  with the type `image/webp`.
- Every table has `created_at`, and `updated_at` with the `set_updated_at`
  trigger unless the rows never change (then `created_at` only). (Since
  2026-11-19, section 21, one table is an exception: a `chat_room_members`
  row changes when its `seen_position` rises, and the table still has
  `created_at` only. The row says how far, not when.) Every table and
  column gets a `COMMENT ON`. No foreign keys, as in anossoftware; the
  services keep the references straight.
- Errors are `{ error: '<reason>' }` with `400` for a bad shape or value,
  `401` for anything wrong with the signature or the session, `403` for a
  caller who may not do this, `404` for a thing that does not exist, `409`
  for a conflict with what is already there. Three more are in use:
  `503` for a part of this server that is not set up or cannot reach what
  it needs (since 2026-11-08, `validators unreachable`, section 15; and
  section 25), and, since 2026-11-21 (section 25), `410` for a thing that
  can no longer be used (a code that ran out or is used up) and `429` for
  too many in a given time. Reasons are short lowercase
  phrases; the ones the phone shows to the user are quoted in section 5.
- Who is asking always comes from the verified signature, never from the
  body. Objects carry only the other party.
- Public profile data is public by design: username, first and last name,
  selfie, vouched, seed status. Everything a pod keeps private reaches the
  server as ciphertext.

## 2. Who may call what

Four levels. A route's level is given with the route in section 5.

| Level | Meaning | Routes |
| ----- | ------- | ------ |
| none | Plain JSON body, no signature. | `/challenge`, `/check-username`, `/get-anopod-session-keys`, `/get-anos-account`, `/check-signing-passkey` (section 22), `/report-waiting-transfers` (2026-11-21, section 25), whose message is signed by a validator's own key, `GET /sticker-picture/<set>/<number>` (2026-11-23, section 28), which has no body at all, and `/create-anopod`, `/unlock`, which are signed by the ephemeral keys inside them |
| session | Signed by the pod's current ephemeral keys (section 3). Vouched or not. | `/search-usernames`, `/send-vouch-request`, `/check-anopod-status`, `/list-notifications`, `/mark-notifications-read`, `/get-anopod-profile` |
| vouched | session, and `anopods.vouched` is true. | `/list-vouch-requests`, `/approve-vouch-request`, `/decline-vouch-request`, `/complete-setup`, `/add-to-security-bucket-one`, `/add-to-security-bucket-two`, `/list-security-records` |
| setup | vouched, and setup is complete (`anopod_encryption_key_blob_2` is set, so the pod has chat keys). | every chat and marketplace route; `/create-anos-account`, `/mark-anos-account-submitted`, `/list-anos-accounts`, `/store-first-key-blob` (section 22); the six wallet memory routes, `/add-noted-transaction` to `/set-wallet-settings` (2026-11-07); the person's two break-glass routes, `/file-break-glass-moves` and `/list-my-break-glass-moves` (2026-11-08, section 14); the six DAO routes, `/create-dao-proposal` to `/list-dao-votes` (2026-11-08, section 15); `/add-passkey` and `/list-passkeys` (section 19); the eight routes of a pod's security alerts, `/list-alert-settings` to `/keep-alert-phone` (2026-11-21, section 25); `/list-stickers` (2026-11-23, section 28); Joy's three routes, `/ask-joy`, `/get-joy-memory` and `/set-joy-memory` (2026-11-24, section 30) |

Three middlewares: `requireSession`, `requireVouched`, `requireSetup`.
Failing them: `401` (session), `403 anopod not vouched`, `403 setup not
complete`.

Two more levels, `moderator` and `recovery`, are in section 12.2 (2026-10-26),
and `attestor` in 13.2. Since 2026-11-08 the `moderator` and `attestor`
levels read the `appointments` table (section 16) in place of the username
prefix and the super seed's vouch.

## 3. Request signing and the session

A pod has one live session: the ephemeral key pair on its `anopods` row. A
new unlock replaces the pair, so the previous tab stops verifying. The pair
expires `EPHEMERAL_KEY_HOURS` (12) after it was registered; after that the
phone unlocks again.

A session request:

```json
{
  "payload": {
    "anopodId":  "<hex 32 bytes>",
    "path":      "/send-vouch-request",
    "timestamp": "2026-10-24T18:00:00.000Z",
    "nonce":     "<hex 16 bytes>",
    "body":      { "anopodIdTo": "<hex>" }
  },
  "signatures": { "ecdsa": "<hex 64>", "mldsa": "<hex 4627>" }
}
```

`body` is the route's object from section 5 (an empty object for routes
without one). `requireSession` checks, in this order, and stops at the first
failure:

1. Shape: `payload` an object with string `anopodId`, `path`, `timestamp`,
   `nonce` and an object `body`; `signatures` with string `ecdsa` and
   `mldsa`. Otherwise `400 bad request shape`.
2. `anopodId` decodes to 32 bytes and the row exists, else `401 unknown
   anopod`.
3. `ephemeral_expires_at` is in the future, else `401 session expired`.
4. `path` equals the request path, else `401 path mismatch`.
5. `timestamp` parses and is within `TIMESTAMP_WINDOW_SECONDS` (120) of the
   server clock either way, else `401 timestamp outside window`.
6. Both signatures verify over the canonical bytes of `payload` against the
   row's `ephemeral_auth_key` and `ephemeral_auth_key_pq`, else `401 bad
   signature`.
7. `nonce` decodes to 16 to 32 bytes and `INSERT INTO nonces` succeeds; a
   duplicate is `401 replay`. The insert also deletes every expired nonce
   (`expires_at` = now + twice the window).
8. `req.anopod` is the row. Handlers read the caller from it.

`/create-anopod` and `/unlock` carry no `path` or `nonce`: their payload holds
a `challenge` instead, single use, and is signed by the ephemeral keys inside
the payload (proof of possession). A challenge comes from `/challenge`, lives
`CHALLENGE_SECONDS` (120; one for `/add-passkey` lives
`ADD_PASSKEY_CHALLENGE_SECONDS`, 600, section 19) in the `challenges` table
and is deleted inside the transaction that uses it.

## 4. Tables

The DDL below goes into `db/schema.sql` in this order, each table with its
header comment, trigger and `COMMENT ON` lines in the style of the file's
conventions block. `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT
EXISTS` throughout, so `npm run db:setup` adds them to a live database. Long
keys get their unique index on `sha256(column)` (built into PostgreSQL) so
every value stays unique without a 2.6 KB index entry.

```sql
-- Refuses UPDATE and DELETE on append-only tables.
CREATE OR REPLACE FUNCTION refuse_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;
```

### anopods

One row per anoPod: profile, the main passkey (section 19 for the added
ones), the one live session, vouch state, and the key material that arrives
at setup. The eight setup columns (`identity_blob` added 2026-10-25 for the
wallet) are all null until `/complete-setup` and all set afterwards; the
`num_nulls` check enforces that. `vouched_by` on the seed tables is text so
it can hold either a hex anopod id or the word `genesis`.

```sql
CREATE TABLE IF NOT EXISTS anopods (
  anopod_id                    BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  first_name                   TEXT        NOT NULL CHECK (char_length(first_name) BETWEEN 1 AND 100),
  last_name                    TEXT        NOT NULL CHECK (char_length(last_name) BETWEEN 1 AND 100),
  username                     TEXT        NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_]{3,32}$'),
  pass_key_credential_id       BYTEA       NOT NULL UNIQUE CHECK (octet_length(pass_key_credential_id) BETWEEN 16 AND 1023),
  pass_key_public_key          BYTEA       NOT NULL CHECK (octet_length(pass_key_public_key) <= 1024),
  ephemeral_auth_key           BYTEA       NOT NULL UNIQUE CHECK (octet_length(ephemeral_auth_key) IN (33, 65)),
  ephemeral_auth_key_pq        BYTEA       NOT NULL CHECK (octet_length(ephemeral_auth_key_pq) = 2592),
  ephemeral_expires_at         TIMESTAMPTZ NOT NULL,
  vouched                      BOOLEAN     NOT NULL DEFAULT false,
  anopod_encryption_key_blob_1 BYTEA       CHECK (octet_length(anopod_encryption_key_blob_1) <= 1024),
  anopod_encryption_key_blob_2 BYTEA       CHECK (octet_length(anopod_encryption_key_blob_2) <= 1024),
  backup_code_public_key       BYTEA       UNIQUE CHECK (octet_length(backup_code_public_key) IN (33, 65)),
  backup_code_public_key_pq    BYTEA       CHECK (octet_length(backup_code_public_key_pq) = 2592),
  chat_public_key              BYTEA       UNIQUE CHECK (octet_length(chat_public_key) IN (33, 65)),
  chat_public_key_pq           BYTEA       CHECK (octet_length(chat_public_key_pq) = 1568),
  chat_private_key_blob        BYTEA       CHECK (octet_length(chat_private_key_blob) <= 16384),
  identity_blob                BYTEA       CHECK (octet_length(identity_blob) <= 1024),
  created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (num_nulls(anopod_encryption_key_blob_1, anopod_encryption_key_blob_2,
                   backup_code_public_key, backup_code_public_key_pq,
                   chat_public_key, chat_public_key_pq, chat_private_key_blob,
                   identity_blob) IN (0, 8))
);
CREATE UNIQUE INDEX IF NOT EXISTS anopods_pass_key_public_key_key       ON anopods (sha256(pass_key_public_key));
CREATE UNIQUE INDEX IF NOT EXISTS anopods_ephemeral_auth_key_pq_key     ON anopods (sha256(ephemeral_auth_key_pq));
CREATE UNIQUE INDEX IF NOT EXISTS anopods_backup_code_public_key_pq_key ON anopods (sha256(backup_code_public_key_pq));
CREATE UNIQUE INDEX IF NOT EXISTS anopods_chat_public_key_pq_key        ON anopods (sha256(chat_public_key_pq));
```

Columns: `pass_key_public_key` is the COSE key bytes the WebAuthn library
returns at registration. `anopod_encryption_key_blob_1` is the pod's
encryption key wrapped under the passkey's PRF-derived key, `_blob_2` the
same key wrapped under the backup-code-derived key. `chat_private_key_blob`
is the chat key pair's private half wrapped under the encryption key.
`identity_blob` is the public ledger id (32) followed by the lookup id (32)
wrapped under the encryption key, 92 bytes; the server cannot read it and
`/unlock` hands it back. Setup complete means `anopod_encryption_key_blob_2
IS NOT NULL`.

### public_selfies

```sql
CREATE TABLE IF NOT EXISTS public_selfies (
  anopod_id    BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
  image        BYTEA       NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Plaintext, written with the pod at creation. Not unique, by decision. No
route changes it in this build.

### challenges

```sql
CREATE TABLE IF NOT EXISTS challenges (
  challenge  BYTEA       PRIMARY KEY CHECK (octet_length(challenge) = 32),
  purpose    TEXT        NOT NULL CHECK (purpose IN ('create', 'unlock', 'openCase', 'unlockCase', 'recover', 'addPasskey')),
  anopod_id  BYTEA       CHECK (octet_length(anopod_id) = 32),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Single use. For `create`, `anopod_id` is the id the server minted for this
sign-up; it becomes the row's id at the write. For `openCase` it is the pod
the phone named, found through the keyholders, and for `addPasskey` the pod
the passkey is added to. For `unlock`, `unlockCase` and `recover` it is
null. Issuing a challenge also deletes the expired ones. `create` and
`unlock` are the first two purposes. The three recovery purposes came with
section 12 (12.3 and 12.4.2) and `addPasskey` on 2026-11-18 (section 19).
For a live database the ALTER pair in the recovery block of `db/schema.sql`
drops and adds `challenges_purpose_check` with the same six purposes.

### nonces

```sql
CREATE TABLE IF NOT EXISTS nonces (
  anopod_id  BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  nonce      BYTEA       NOT NULL CHECK (octet_length(nonce) BETWEEN 16 AND 32),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (anopod_id, nonce)
);
```

The replay cache of section 3, step 7.

### vouch_requests

```sql
CREATE TABLE IF NOT EXISTS vouch_requests (
  vouch_id_number BYTEA       PRIMARY KEY CHECK (octet_length(vouch_id_number) = 32),
  anopod_id_from  BYTEA       NOT NULL CHECK (octet_length(anopod_id_from) = 32),
  anopod_id_to    BYTEA       NOT NULL CHECK (octet_length(anopod_id_to) = 32),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (anopod_id_from, anopod_id_to),
  CHECK (anopod_id_from <> anopod_id_to)
);
CREATE INDEX IF NOT EXISTS vouch_requests_anopod_id_to_idx ON vouch_requests (anopod_id_to);
```

Open requests only: approve and decline delete the row. One waiting request
per requester and seed.

### vouches

```sql
CREATE TABLE IF NOT EXISTS vouches (
  vouch_id_number       BYTEA       PRIMARY KEY CHECK (octet_length(vouch_id_number) = 32),
  anopod_id_vouched_by  BYTEA       NOT NULL CHECK (octet_length(anopod_id_vouched_by) = 32),
  anopod_id_vouched_for BYTEA       NOT NULL CHECK (octet_length(anopod_id_vouched_for) = 32),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (anopod_id_vouched_by, anopod_id_vouched_for)
);
CREATE INDEX IF NOT EXISTS vouches_anopod_id_vouched_for_idx ON vouches (anopod_id_vouched_for);
```

The record of an approval; `vouch_id_number` is the request's. Never changes.

### seeds and super_seeds

```sql
CREATE TABLE IF NOT EXISTS seeds (
  anopod_id        BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  date_became_seed TIMESTAMPTZ NOT NULL DEFAULT now(),
  trust_score      INTEGER     NOT NULL DEFAULT 0,
  vouched_by       TEXT        NOT NULL CHECK (vouched_by = 'genesis' OR vouched_by ~ '^[0-9a-f]{64}$'),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS super_seeds (
  anopod_id              BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  date_became_super_seed TIMESTAMPTZ NOT NULL DEFAULT now(),
  trust_score            INTEGER     NOT NULL DEFAULT 0,
  vouched_by             TEXT        NOT NULL CHECK (vouched_by = 'genesis' OR vouched_by ~ '^[0-9a-f]{64}$'),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

A pod vouched by a super seed joins `seeds` with `vouched_by` = that super
seed's hex id. Super seeds are made only by the genesis script (section 9),
`vouched_by = 'genesis'`. `trust_score` starts at 0 and nothing reads it yet.

### appointments

```sql
CREATE TABLE IF NOT EXISTS appointments (
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  role         TEXT        NOT NULL CHECK (role IN ('moderator', 'attestor', 'validator', 'masterPod')),
  appointed_by TEXT        NOT NULL CHECK (appointed_by = 'operator' OR appointed_by ~ '^[0-9a-f]{64}$'),
  appointed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (anopod_id, appointed_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_live_per_pod
  ON appointments (anopod_id) WHERE revoked_at IS NULL;
```

The pods that are moderators or attestors (section 16, 2026-11-08) and,
since 2026-11-10 (16.7), the pods that may stake for validator or
masterPod: four roles, of which the last two open no route here. A pod
holds the role while its row has no `revoked_at`, at most one such row per
pod (the partial unique index); appointing a pod again after a revocation
adds a row, and the old one stays. `appointed_by` is `operator` for the
scripts, otherwise the hex id of the pod that appointed. Written only by
`scripts/appoint.js` and `scripts/revoke.js` (section 9); no route writes
it. On a database that already has the table, `db/schema.sql` widens the
role check by a drop-and-add of `appointments_role_check` (16.7).

### notifications

```sql
CREATE TABLE IF NOT EXISTS notifications (
  notification_number BYTEA       PRIMARY KEY CHECK (octet_length(notification_number) = 32),
  anopod_id           BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  kind                TEXT        NOT NULL CHECK (kind IN (
                        'vouchRequest', 'vouchApproved', 'vouchDeclined', 'vouched',
                        'chatInvite', 'inviteAccepted', 'inviteDeclined',
                        'joinRequest', 'joinApproved', 'joinDeclined',
                        'tradeCaseOpened', 'disputeCaseOpened', 'caseScheduled',
                        'caseDecided', 'caseDismissed', 'recoveryCaseScheduled',
                        'passkeyAdded',
                        'transferWaiting', 'recoveryMoveWaiting', 'recoveryCaseOpened',
                        'alertSettingsChanged')),
  reference_id        BYTEA       NOT NULL CHECK (octet_length(reference_id) = 32),
  read_at             TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notifications_anopod_id_created_at_idx ON notifications (anopod_id, created_at DESC);
```

`notification_number` is the row's random id. `reference_id` says which
thing (section 6). Read, never deleted. The first ten kinds are of
2026-10-24. The five kinds of an attestor case came on 2026-10-26 (13.3
and 13.7), `recoveryCaseScheduled` on 2026-11-11 (14.7 and section 18),
`passkeyAdded` on 2026-11-18 (section 19), and the four kinds of the
security alerts, `transferWaiting`, `recoveryMoveWaiting`,
`recoveryCaseOpened` and `alertSettingsChanged`, on 2026-11-21 (section
25). For a live database the ALTER pair after the attestation block of
`db/schema.sql` drops and adds `notifications_kind_check` with the same
twenty-one kinds.

### security_images and security_info

```sql
CREATE TABLE IF NOT EXISTS security_images (
  image_id     BYTEA       PRIMARY KEY CHECK (octet_length(image_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  type         SMALLINT    NOT NULL CHECK (type IN (1, 2)),
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
  image        BYTEA       NOT NULL,
  key_id       BYTEA       NOT NULL CHECK (octet_length(key_id) = 32),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_images_anopod_id_idx ON security_images (anopod_id);
CREATE OR REPLACE TRIGGER security_images_append_only
  BEFORE UPDATE OR DELETE ON security_images
  FOR EACH ROW EXECUTE FUNCTION refuse_change();

CREATE TABLE IF NOT EXISTS security_info (
  info_id    BYTEA       PRIMARY KEY CHECK (octet_length(info_id) = 32),
  anopod_id  BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  type       SMALLINT    NOT NULL CHECK (type IN (1, 2)),
  info       BYTEA       NOT NULL CHECK (octet_length(info) <= 65536),
  key_id     BYTEA       NOT NULL CHECK (octet_length(key_id) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_info_anopod_id_idx ON security_info (anopod_id);
CREATE OR REPLACE TRIGGER security_info_append_only
  BEFORE UPDATE OR DELETE ON security_info
  FOR EACH ROW EXECUTE FUNCTION refuse_change();
```

Bucket one is `security_images` with `type = 1`. Bucket two is
`security_images` with `type = 2` plus `security_info` with `type = 2`.
Both tables are ciphertext under keys the keyholders hold, not the pod;
append-only, enforced by the trigger. `info` is encrypted text. `key_id`
(added 2026-10-25 for the wallet) names the bucket key a row is under: the
same 32 bytes the pod deposited with the key's shares on the keyholders, so
a moderator holding the shares of key `key_id` knows which rows it opens.

### anos_accounts

Added 2026-10-25 for the wallet (its spec, section 4.4). One row per anos
account a pod made: the pod, the type, pair one and pair two's private
halves under the pod's key blob key, and pair one's alone in a second blob
(section 22) (which this server cannot open), the
signed creation as it went to the validator, and when a validator answered
it. No foreign keys, never deleted. The masterpod never verifies anos
signatures; the validators do.

```sql
CREATE TABLE IF NOT EXISTS anos_accounts (
  account_id   BYTEA       PRIMARY KEY CHECK (octet_length(account_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  account_type TEXT        NOT NULL CHECK (account_type IN ('spending', 'guarded', 'vault', 'assisted')),
  key_blob     BYTEA       NOT NULL CHECK (octet_length(key_blob) <= 1024),
  first_key_blob BYTEA     CHECK (octet_length(first_key_blob) BETWEEN 1 AND 1024),
  creation     JSONB       NOT NULL,
  submitted_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS anos_accounts_anopod_id_idx ON anos_accounts (anopod_id);
```

`account_id` is the SHA-256 of key1 + postQuantumKey1, as the validators
compute it. `key_blob` is 156 bytes in practice (section 7).
`first_key_blob` is 92. `submitted_at`
is null until `/mark-anos-account-submitted`. Since 2026-11-10 the account
limit counts a pod's rows by `created_at`: at most 20 in the last 30 days
(section 17).

### noted_transactions

Added 2026-11-07 for the wallet (its spec, section 4.6). One row per note a
pod made on a ledger transaction for its tax records: the ledger's own
facts in the clear (the transaction, the pod's account, the other side as
the wallet shows it, the position, the time, the amount of anos and whether
they left the account), since the masterpod already links a pod to its
accounts and every validator holds the chain; and the private part, the
kind, the money, the currency, the memo and the tag, as one blob under the
pod's encryption key, which this server cannot open. One note per pod,
transaction and account, enforced by the unique rule: a transfer between
two of the pod's own accounts is one transaction that stands in both
accounts' histories, and it can hold a note for each. Until 2026-11-20 the
rule was one note per pod and transaction (section 11, "A note for each
account of a transfer between a pod's own accounts"). The ledger facts
never change after the row is written, only the blob; the row is deleted
when the person removes the note. Stand-alone: no foreign keys.

```sql
CREATE TABLE IF NOT EXISTS noted_transactions (
  note_id          BYTEA       PRIMARY KEY CHECK (octet_length(note_id) = 32),
  anopod_id        BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  transaction_id   BYTEA       NOT NULL CHECK (octet_length(transaction_id) = 32),
  account_id       BYTEA       NOT NULL CHECK (octet_length(account_id) = 32),
  other_account_id BYTEA       CHECK (octet_length(other_account_id) = 32),
  position         BIGINT      NOT NULL CHECK (position >= 0),
  transacted_at    TIMESTAMPTZ NOT NULL,
  amount           BIGINT      NOT NULL CHECK (amount >= 0),
  sent             BOOLEAN     NOT NULL,
  note_blob        BYTEA       NOT NULL CHECK (octet_length(note_blob) <= 4096),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (anopod_id, transaction_id, account_id)
);
CREATE INDEX IF NOT EXISTS noted_transactions_anopod_id_transacted_at_idx ON noted_transactions (anopod_id, transacted_at DESC);
```

`note_blob` is at most 4096 bytes, a few hundred in practice (section 7).
`position` and `amount` are BIGINTs, as the validators keep them; the index
serves `/list-noted-transactions`, the pod's notes newest first.

### wallet_settings

Added 2026-11-07 for the wallet (its spec, section 4.7). One row per pod:
the small things its wallet remembers, as one encrypted JSON object under
the pod's encryption key, the Protect your passkey answer first; a later
thing is one more field inside the object, with no change here. Written
whole by `/set-wallet-settings`, which inserts the row or replaces its blob
in place; never deleted.

```sql
CREATE TABLE IF NOT EXISTS wallet_settings (
  anopod_id     BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  settings_blob BYTEA       NOT NULL CHECK (octet_length(settings_blob) <= 16384),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`settings_blob` is at most 16384 bytes, a few dozen in practice (section
7).

### chat_rooms

```sql
CREATE TABLE IF NOT EXISTS chat_rooms (
  chat_room_id      BYTEA       PRIMARY KEY CHECK (octet_length(chat_room_id) = 32),
  creator_anopod_id BYTEA       NOT NULL CHECK (octet_length(creator_anopod_id) = 32),
  type              TEXT        NOT NULL CHECK (type IN ('private', 'public', 'marketplace')),
  name              TEXT        CHECK (char_length(name) BETWEEN 1 AND 100),
  listing_id        BYTEA       CHECK (octet_length(listing_id) = 32),
  case_id           BYTEA       CHECK (octet_length(case_id) = 32),
  case_kind         TEXT        CHECK (case_kind IN ('trade', 'dispute', 'recovery')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  message_seq       BIGINT      NOT NULL DEFAULT 0 CHECK (message_seq >= 0),
  people_seq        BIGINT      NOT NULL DEFAULT 0 CHECK (people_seq >= 0),
  CHECK ((type = 'public') = (name IS NOT NULL)),
  CONSTRAINT chat_rooms_case_check CHECK ((case_id IS NULL) = (case_kind IS NULL)
    AND (case_id IS NULL OR (type = 'private' AND listing_id IS NULL)))
);
CREATE INDEX IF NOT EXISTS chat_rooms_type_created_at_idx ON chat_rooms (type, created_at DESC);
CREATE INDEX IF NOT EXISTS chat_rooms_listing_id_idx ON chat_rooms (listing_id) WHERE listing_id IS NOT NULL;
```

Public rooms carry a plaintext name so they can be browsed. Private rooms
have none. A marketplace room is named by its listing. `listing_id` (added
2026-11-06) is the listing a room is about: set on a private room made by
/create-chat-room with a `listingId`, one such room per person who connects
with the owner, and set on every old marketplace room by the backfill of the
marketplace block at the end of `db/schema.sql` (the column, its index, the
backfill and the `listings.chat_room_id` change below, all idempotent, after
the attestation block). No marketplace room is made since that date.

`case_id` and `case_kind` (added 2026-11-11, section 18) are the attestor
case a room is about: the case id of an `assisted_trades`, an
`escrow_disputes` or a `break_glass_cases` row, and `trade`, `dispute` or
`recovery` for the table the row is in. Both are set on a private room made
by /create-chat-room with a `caseId`, a case chat between an attestor and a
person on the case; both are null on every other room.
`chat_rooms_case_check` keeps the two together and allows them only on a
private room without a `listing_id`: a room is about a listing or about a
case, never both. For a live database the case chat block at the end of
`db/schema.sql` adds the two columns and drops and adds the check, all
idempotent; the comments of the two columns are in that block only. There
is no index on `case_id`: nothing reads a room by its case.

The index on `(type, created_at DESC)` no longer gives the order of
`/list-public-chat-rooms` since 2026-11-22: the list sorts by the number
of members (section 26).

`message_seq` and `people_seq` (added 2026-11-24, section 29) are two
values of the counter `chat_change_seq`: the first is taken when a message
is written in the room, the second when the room changes in another way (a
member joins or leaves, an invite to it is made or answered, its picture
is set, its listing is closed). Triggers set both, and both are 0 until
the room's first such change after the columns were added.
/list-chat-rooms compares them with the `since` a wallet sends. For a live
database the chat change block at the end of `db/schema.sql` adds the two
columns, with their comments; the counter, the triggers and the block are
in 29.2. The triggers' writes also move `updated_at`: since that block a
room's `updated_at` is the time of its last message or its last other
change.

### chat_room_members, chat_hpke

```sql
CREATE TABLE IF NOT EXISTS chat_room_members (
  chat_room_id BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  seen_position BIGINT NOT NULL DEFAULT 0 CHECK (seen_position >= 0),
  seen_seq BIGINT NOT NULL DEFAULT 0 CHECK (seen_seq >= 0),
  PRIMARY KEY (chat_room_id, anopod_id)
);
CREATE INDEX IF NOT EXISTS chat_room_members_anopod_id_idx ON chat_room_members (anopod_id);

CREATE TABLE IF NOT EXISTS chat_hpke (
  chat_room_id BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  hpke_key     BYTEA       NOT NULL CHECK (octet_length(hpke_key) <= 4096),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (chat_room_id, anopod_id)
);
```

`chat_hpke` holds, for each member of each room, the room key wrapped to
that member's chat public key (section 7). Stored as delivered; only that
member can open it. A member row and its `chat_hpke` row are always written
and deleted together.

`seen_position` (added 2026-11-19, section 21) is the highest message
position the member has seen in the room, 0 until the member's wallet
reports one: /mark-messages-seen raises it, and /list-chat-rooms hands it
to every member of the room.

`seen_seq` (added 2026-11-24, section 29) is the value of the counter
`chat_change_seq` taken when the row's `seen_position` last changed, 0
while `seen_position` is 0. A trigger sets it. /list-messages hands a
member's position to a wallet whose `seenSince` is below it (29.4).

### chat_room_invites, chat_room_join_requests

```sql
CREATE TABLE IF NOT EXISTS chat_room_invites (
  invite_id      BYTEA       PRIMARY KEY CHECK (octet_length(invite_id) = 32),
  chat_room_id   BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id_from BYTEA       NOT NULL CHECK (octet_length(anopod_id_from) = 32),
  anopod_id_to   BYTEA       NOT NULL CHECK (octet_length(anopod_id_to) = 32),
  hpke_key       BYTEA       NOT NULL CHECK (octet_length(hpke_key) <= 4096),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  change_seq     BIGINT      NOT NULL DEFAULT 0 CHECK (change_seq >= 0),
  UNIQUE (chat_room_id, anopod_id_to)
);
CREATE INDEX IF NOT EXISTS chat_room_invites_anopod_id_to_idx ON chat_room_invites (anopod_id_to);

CREATE TABLE IF NOT EXISTS chat_room_join_requests (
  join_request_id BYTEA       PRIMARY KEY CHECK (octet_length(join_request_id) = 32),
  chat_room_id    BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id       BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  change_seq      BIGINT      NOT NULL DEFAULT 0 CHECK (change_seq >= 0),
  UNIQUE (chat_room_id, anopod_id)
);
```

An invite carries the wrapped room key until it is answered; accept moves
it into `chat_hpke`, decline drops it. A join request carries nothing; the
creator's approval brings the wrapped key. `anopod_id_from` is the inviter:
the room's creator, or, since 2026-11-11, a member of a listing chat
bringing an attestor in (/invite-to-chat-room in section 5; section 18).

`change_seq` (added 2026-11-24, section 29), on both tables, is the value
of the counter `chat_change_seq` taken when the invite or the request was
written. A trigger sets it, and a row that was open when the column was
added got its number then. /list-chat-rooms hands the invite or the
request to a wallet whose `since` is below it (29.3).

### chat_room_messages

```sql
CREATE TABLE IF NOT EXISTS chat_room_messages (
  message_id       BYTEA       PRIMARY KEY CHECK (octet_length(message_id) = 32),
  chat_room_id     BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  sender_anopod_id BYTEA       NOT NULL CHECK (octet_length(sender_anopod_id) = 32),
  position         BIGINT      GENERATED ALWAYS AS IDENTITY,
  message          BYTEA       CHECK (octet_length(message) <= 65536),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind             TEXT        CHECK (kind IN ('edit', 'delete')),
  target_message_id BYTEA      CHECK (octet_length(target_message_id) = 32),
  CONSTRAINT chat_room_messages_edit_delete_check CHECK ((kind IS NULL) = (target_message_id IS NULL)
    AND (message IS NULL) = (kind IS NOT DISTINCT FROM 'delete'))
);
CREATE INDEX IF NOT EXISTS chat_room_messages_room_position_idx ON chat_room_messages (chat_room_id, position);
```

`message` is ciphertext under the room key. `position` orders messages and
drives pagination (`afterPosition`). The sender is the verified caller;
there is no per-message signature, by decision.

`kind` and `target_message_id` (added 2026-11-24, section 31) make a row an
edit or a delete of a message: since that day the table holds three kinds
of row. A message has neither, as every row of before. An edit has `kind`
`edit`, the `message_id` of the message it is about in `target_message_id`,
and the new text's ciphertext in `message`. A delete has `kind` `delete`,
its message in `target_message_id`, and no ciphertext: `message` is
nullable since that day, null on a delete and nowhere else.
`chat_room_messages_edit_delete_check` holds all of that. Each kind of row
takes its own `position` from the one counter, and no row is ever updated
or deleted: /edit-message and /delete-message insert. For a live database
the message edit block at the end of `db/schema.sql` adds the two columns,
drops the `NOT NULL` of `message` and drops and adds the check, all
idempotent. A second index, on `target_message_id` for the rows that have
one, and the comments of the two columns are in that block only. The block
and the reading rule are in 31.2 and 31.4.

### chat_room_pictures

```sql
CREATE TABLE IF NOT EXISTS chat_room_pictures (
  chat_room_id BYTEA       PRIMARY KEY CHECK (octet_length(chat_room_id) = 32),
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
  image        BYTEA       NOT NULL CHECK (octet_length(image) BETWEEN 1 AND 100000),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The picture of a public room (added 2026-11-22, section 27): at most one
row per room, in the clear like the room's name, set by the room's creator
with /set-chat-room-picture and handed out by /get-chat-room-picture;
`updated_at` is when the picture was last set, which the two room lists
hand out as `pictureAt`. The table is the room picture block, the last
thing in `db/schema.sql`, with its trigger and its comments.

### listings

```sql
CREATE TABLE IF NOT EXISTS listings (
  listing_id   BYTEA          PRIMARY KEY CHECK (octet_length(listing_id) = 32),
  chat_room_id BYTEA          UNIQUE CHECK (octet_length(chat_room_id) = 32),
  anopod_id    BYTEA          NOT NULL CHECK (octet_length(anopod_id) = 32),
  side         TEXT           NOT NULL CHECK (side IN ('buy', 'sell')),
  quantity     BIGINT         NOT NULL CHECK (quantity > 0),
  currency     TEXT           NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  country      TEXT           NOT NULL CHECK (country ~ '^[A-Z]{2}$'),
  price        NUMERIC(24, 8) NOT NULL CHECK (price > 0),
  status       TEXT           NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  created_at   TIMESTAMPTZ    NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ    NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS listings_status_created_at_idx ON listings (status, created_at DESC);
```

A listing is always anos for a fiat currency: `quantity` in millionths of
an anos, `price` per anos in `currency` (ISO 4217), `country` ISO 3166-1
alpha-2. Until 2026-11-06 each listing owned one marketplace room,
`chat_room_id`; since then `chat_room_id` is null on every new listing and
the people who connect each get a private room about it, linked by
`chat_rooms.listing_id`. The old rooms stay, with their listings' ids on
both rows. Since 2026-11-20 the listing limit counts a pod's rows with
`status` `open`: at most 10 at one time (section 23).

### alert_emails

Added 2026-11-21 for the security alerts (section 25). The emails a pod's
alerts go to, in plain text: this server has to read an address to send
to it. One row per pod and address, compared in lower case. A row holds
the six-digit code until the address is confirmed, and the day it comes
off once the person has taken it off. The table and its columns are in
25.2.

### alert_phones

Added 2026-11-21 (section 25). The phones a pod's alerts go to: one row
per browser that allowed notifications, with the delivery address, the
public key and the secret the browser handed the wallet. The table and
its columns are in 25.2.

### alert_transfers

Added 2026-11-21 (section 25). The waiting transfers the validators have
reported: one row per report with its own facts, keyed by the hash of
those facts. Append-only. The table and its columns are in 25.2.

### alert_messages

Added 2026-11-21 (section 25). One row per message to one email or one
phone, written inside the transaction of the event it reports and sent by
the alert sender. It holds no address, and it is kept after it is sent.
The table and its columns are in 25.2.

### sticker_sets, stickers, sticker_tags

Added 2026-11-23 (section 28). The stickers of the wallet's chat: the
sets, each with its place in the row of sets; the stickers, each with its
set, its two-digit number, its place in the set and its picture, a WebP;
and the tags of each sticker, one row per sticker and tag. In the clear
and the same for everybody. Only `scripts/stickers.js` writes them. The
tables and their columns are in 28.2.

## 5. Routes

Every route is a `POST` with a JSON body. (Since 2026-11-23, section 28,
one route is a `GET` with no body: `/sticker-picture/<set>/<number>`.)
Level `none` routes take the body
as shown; every other route takes the section 3 envelope and the body shown
is `payload.body`. Checks run in the order listed and stop at the first
failure. "The caller" is `req.anopod`. Every multi-row write is one database
transaction.

A "profile" in an answer is
`{ anopodId, username, firstName, lastName, vouched, isSeed, isSuperSeed }`;
only `/get-anopod-profile` and `/search-usernames` add the selfie.

### POST /challenge (none)

Body: `{ purpose }`, `create` or `unlock`.

Writes: a random 32-byte challenge; for `create` also a random 32-byte
anopod id; `INSERT INTO challenges` with `expires_at = now() +
CHALLENGE_SECONDS`; `DELETE FROM challenges WHERE expires_at < now()`.

Answer: `200 { challenge, anopodId, expiresAt }` (`anopodId` only for
`create`). The phone passes the challenge bytes to WebAuthn and the anopod
id as the passkey's user handle.

A sixth purpose, `addPasskey` (2026-11-18), is in 19.3, after the three
recovery purposes of 12.4.2: it takes `{ purpose, anopodId }`, the pod the
passkey is added to, is bound to that pod, lives
`ADD_PASSKEY_CHALLENGE_SECONDS` and answers `200 { challenge, anopodId,
expiresAt }`.

Since 2026-11-18 `openCase` may also take a `lookupId`, the person's lookup
id: a case already open for it is refused `409 case already open`, and no
challenge is issued. And the answer for `openCase` carries `credentialIds`,
the credential ids of the pod's passkeys. Both are in 20.2.

### POST /create-anopod (none, signed by the ephemeral keys inside)

```json
{
  "payload": {
    "anopodId":           "<hex, from /challenge>",
    "challenge":          "<hex, from /challenge>",
    "firstName":          "Bob",
    "lastName":           "Smith",
    "username":           "bob_smith",
    "selfie":             { "contentType": "image/jpeg", "image": "<base64>" },
    "passkey":            { "...": "the registration PublicKeyCredential.toJSON()" },
    "ephemeralAuthKey":   "<hex 33>",
    "ephemeralAuthKeyPq": "<hex 2592>"
  },
  "signatures": { "ecdsa": "<hex>", "mldsa": "<hex>" }
}
```

`passkey` is the browser's registration result as `toJSON()` gives it:
`{ id, rawId, type, response: { clientDataJSON, attestationObject,
transports }, clientExtensionResults }`. The phone keeps
`clientExtensionResults.prf.enabled` and removes `prf.results` if present;
the PRF output never leaves the phone.

Checks:

1. Shape, as above; `400 bad request shape`.
2. The challenge row exists with purpose `create`, is unexpired, and its
   `anopod_id` equals `payload.anopodId`; else `401 unknown or expired
   challenge`.
3. Both signatures verify over the canonical payload against the payload's
   own `ephemeralAuthKey` / `ephemeralAuthKeyPq`; else `401 bad signature`.
4. `passkey.clientExtensionResults.prf.enabled` is `true` and no
   `prf.results` is present; else `400 passkey without prf`.
5. The WebAuthn library verifies the registration with the challenge
   (base64url), `RP_ID`, `WEB_ORIGIN`, user verification required; else
   `401 passkey verification failed`. It yields the credential id and the
   COSE public key.
6. `username` matches `^[a-z0-9_]{3,32}$` (the phone lowercases before
   signing) and is free; `firstName`, `lastName` 1 to 100 characters;
   `selfie` decodes within the image rules and, since 2026-11-12, is a
   picture of its content type, at most 4096 pixels wide and high.
   `409 username taken`, else `400` with the field.
7. Since 2026-11-18 (19.3): the credential id is on no `added_passkeys`
   row and on no `recovery_pods` row; else `409 key already registered`.

Writes: `INSERT INTO anopods` (profile, credential id, COSE key, ephemeral
keys, `ephemeral_expires_at = now() + EPHEMERAL_KEY_HOURS`, `vouched =
false`), `INSERT INTO public_selfies`, `DELETE` the challenge. A unique
violation on a key column is `409 key already registered`.

Answer: `201 { anopodId, username, vouched: false, ephemeralExpiresAt,
success: true }`. The session is open: the ephemeral keys in the payload are
now the row's.

### POST /unlock (none, signed by the ephemeral keys inside)

```json
{
  "payload": {
    "challenge":          "<hex, from /challenge>",
    "assertion":          { "...": "the authentication PublicKeyCredential.toJSON()" },
    "ephemeralAuthKey":   "<hex 33>",
    "ephemeralAuthKeyPq": "<hex 2592>"
  },
  "signatures": { "ecdsa": "<hex>", "mldsa": "<hex>" }
}
```

`assertion` is `{ id, rawId, type, response: { clientDataJSON,
authenticatorData, signature, userHandle }, clientExtensionResults }` with
`clientExtensionResults.prf` removed entirely.

Checks:

1. Shape; `400 bad request shape`.
2. Challenge row with purpose `unlock`, unexpired; `401 unknown or expired
   challenge`.
3. Any `clientExtensionResults.prf.results` present: `400 prf output in
   request`.
4. The row by `pass_key_credential_id = assertion.rawId`; none is
   `401 unknown passkey`. `assertion.response.userHandle` (base64url) must
   equal the row's id; else `401 user handle mismatch`.
5. Both signatures verify against the payload's own ephemeral keys; `401
   bad signature`.
6. The library verifies the assertion against the stored COSE key with the
   challenge, `RP_ID`, `WEB_ORIGIN`, user verification required, sign
   counter ignored (synced passkeys report 0); `401 passkey verification
   failed`.

Writes: `UPDATE anopods SET ephemeral_auth_key, ephemeral_auth_key_pq,
ephemeral_expires_at = now() + EPHEMERAL_KEY_HOURS`; `DELETE` the
challenge.

Answer: `200 { anopodId, username, vouched, setupComplete, blob1,
chatPrivateKeyBlob, identityBlob, ephemeralExpiresAt }`. `blob1`,
`chatPrivateKeyBlob` and `identityBlob` are hex or null before setup. The
phone derives the PRF key, unwraps the encryption key from `blob1`, then the
chat private key and the identity blob.

Since 2026-11-18 the passkey may also be one the pod added: check 4's
second lookup, `409 reload the wallet`, check 6 and the answer's new field
`wrappedKeyBlobKey` are in 19.3.

### POST /check-username (none)

Body: `{ username }`. The server lowercases it, checks the pattern (`400
invalid username` with the rule in the message) and answers `200 {
username, available }`.

### POST /search-usernames (session)

Body: `{ username }`. Exact match on the lowercased username, any pod. The
profile's `isSeed` and `isSuperSeed` tell the client whether the match can
vouch, so a requester sees at once that a pod exists but cannot; the same
lookup finds a pod to invite to a chat room (`/invite-to-chat-room` takes
the `anopodId` it returns).

Answer: `200 { profile..., selfie }` or `404 username not found`.

### POST /send-vouch-request (session)

Body: `{ anopodIdTo }`.

Checks: caller not vouched (`409 already vouched`); `anopodIdTo` is not the
caller (`400 cannot request yourself`); the target exists (`404 anopod not
found`); the target is in `seeds` or `super_seeds` (`403 user is not
seed`); no open request from the caller to the target (`409 request already
open`).

Writes: `INSERT INTO vouch_requests` (random `vouch_id_number`), `INSERT
INTO notifications` for the target, kind `vouchRequest`, reference the
`vouch_id_number`.

Answer: `201 { vouchIdNumber }`.

### POST /check-anopod-status (session)

Body: `{}`. Read only.

Answer: `200 { anopodId, vouched, vouchCount, setupComplete, isSeed,
isSuperSeed, role, bucketOneImages, bucketTwoImages, bucketTwoInfos }`.
`vouchCount` is the number of `vouches` rows for the caller; the three
counts (added 2026-10-25) are the caller's rows in `security_images` with
`type = 1`, in `security_images` with `type = 2` and in `security_info`
with `type = 2`. The wallet's next-step rule reads them. `role` (added
2026-11-08, section 16) is the caller's live appointment, `"moderator"`,
`"attestor"`, `"validator"`, `"masterPod"` or `null` (the last two names
since 2026-11-10, 16.7); the wallet's Stake for list reads it.

### POST /list-notifications (session)

Body: `{ unreadOnly, limit }`, both optional; `unreadOnly` defaults to
false, `limit` to 100 (max 500).

Answer: `200 { notifications: [ { notificationNumber, kind, referenceId,
read, createdAt } ] }`, newest first.

### POST /mark-notifications-read (session)

Body: `{ notificationNumbers: [ ... ] }`, 1 to 500 ids.

Writes: `UPDATE notifications SET read_at = now() WHERE anopod_id = caller
AND notification_number = ANY(...) AND read_at IS NULL`.

Answer: `200 { marked }`, the number of rows changed.

### POST /get-anopod-profile (session)

Body: `{ anopodId }`.

Answer: `200 { profile..., selfie }` or `404 anopod not found`.

### POST /list-vouch-requests (vouched)

Body: `{}`. The open requests addressed to the caller, oldest first.

Answer: `200 { requests: [ { vouchIdNumber, from: profile, createdAt } ] }`.
A caller who is not a seed gets an empty list. (2026-11-08) The selfie left
this list: the wallet reads each requester's picture through
`/get-anopod-profile`, so a seed with many requests sees the list at once.

### POST /approve-vouch-request (vouched)

Body: `{ vouchIdNumber }`.

Checks: the request exists (`404 request not found`) and is addressed to
the caller (`403 not your request`); the caller is in `seeds` or
`super_seeds` (`403 user is not seed`).

Writes, one transaction:

1. `INSERT INTO vouches` (the request's `vouch_id_number`, caller,
   requester).
2. `DELETE` the request.
3. Count the requester's `vouches`. If the caller is a super seed, or the
   count is now 2 or more, and the requester is not yet vouched: `UPDATE
   anopods SET vouched = true`.
4. If the caller is a super seed and the requester is not in `seeds`:
   `INSERT INTO seeds` (requester, `vouched_by` = the caller's hex id,
   `trust_score` 0).
5. `INSERT INTO notifications` for the requester, kind `vouchApproved`,
   reference the `vouch_id_number`; and, if `vouched` flipped in this call,
   a second one, kind `vouched`, reference the requester's own id.

Answer: `200 { vouchIdNumber, vouchedFor, nowVouched, nowSeed }`.

### POST /decline-vouch-request (vouched)

Body: `{ vouchIdNumber }`. Same existence and ownership checks as approve.

Writes: `DELETE` the request; notification to the requester, kind
`vouchDeclined`, reference the `vouch_id_number`.

Answer: `200 { vouchIdNumber }`.

### POST /complete-setup (vouched)

```json
{
  "blob1":                 "<hex 60>",
  "blob2":                 "<hex 60>",
  "backupCodePublicKey":   "<hex 33>",
  "backupCodePublicKeyPq": "<hex 2592>",
  "chatPublicKey":         "<hex 33>",
  "chatPublicKeyPq":       "<hex 1568>",
  "chatPrivateKeyBlob":    "<hex 124>",
  "identityBlob":          "<hex 92>"
}
```

Checks: setup not already complete (`409 setup already complete`); every
field decodes with the lengths of section 7 (blobs at most the column
limits), in the order listed, `400 invalid <field>`; `identityBlob` (added
2026-10-25, the wallet's) is 1 to 1024 bytes, checked after
`chatPrivateKeyBlob`.

Writes: `UPDATE anopods` setting the eight columns. A unique violation is
`409 key already registered`.

Answer: `200 { anopodId, setupComplete: true }`.

### POST /add-to-security-bucket-one (vouched)

Body: `{ keyId, images: [ { contentType, image } ] }`, 1 to
`MAX_IMAGES_PER_REQUEST` images. `keyId` (added 2026-10-25) is hex, 32
bytes: the bucket key the images are under, the same value the pod
deposited with the key's shares on the keyholders. Checked right after the
body shape: `400 invalid keyId`.

Writes: one `security_images` row per image, `type = 1`, random `image_id`,
`key_id` on every row.

Answer: `201 { imageIds: [ ... ] }`.

### POST /add-to-security-bucket-two (vouched)

Body: `{ keyId, images: [ { contentType, image } ], info: [ { info } ] }`,
each array optional, at least one entry overall, images up to
`MAX_IMAGES_PER_REQUEST`, `info` base64 of at most 65536 bytes each, up to
20 per request. `keyId` as for bucket one, checked right after the shape.

Writes: `security_images` rows with `type = 2`, `security_info` rows with
`type = 2`, `key_id` on every row.

Answer: `201 { imageIds: [ ... ], infoIds: [ ... ] }`.

### POST /list-security-records (vouched)

Body: `{}`. Everything in both tables for the caller, oldest first.

Answer: `200 { images: [ { imageId, type, contentType, image, keyId,
createdAt } ], info: [ { infoId, type, info, keyId, createdAt } ] }`. Kept
for a later use; the pod cannot decrypt these itself. A moderator with the
shares of key `keyId` knows which rows it opens.

### POST /create-chat-room (setup)

Body: `{ type, name, hpkeKey, listingId, caseId }`: `type` is `private` or
`public`; `name` required for `public`, absent for `private`; `hpkeKey` is
the creator's own wrapped copy of the new room key (section 7); `listingId`
(optional, 2026-11-06) is the listing a `private` room is about: how a
person connects with a listing's owner. The room is made, then the owner is
invited with /invite-to-chat-room as for any private room, and accepts or
declines the invite. `caseId` (optional, hex of 32 bytes, 2026-11-11,
section 18) is the attestor case a `private` room is about: how an attestor
starts a chat with a person on a case. The room is made, then the person is
invited the same way.

Checks for `listingId`, after the existing ones: `type` is `private` (`400
public rooms have no listing`); the listing exists (`404 listing not
found`) and is open (`409 listing closed`); the caller is not its owner
(`400 your own listing`); the caller has no room about it yet, a room it
created with this `listing_id` (`409 room already open`).

Checks for `caseId`, after those of `listingId`: it is a string (`400 bad
request shape`); `type` is `private` (`400 public rooms have no case`); the
body has no `listingId` (`400 a room is about a listing or a case`); the
caller holds a live appointment as attestor (`403 not an attestor`); the id
decodes and names a row in `assisted_trades`, `escrow_disputes` or
`break_glass_cases`, tried in that order (`404 unknown case`); the case's
status is `open` or `inReview` (`409 case closed`).

Writes: `chat_rooms` (with `listing_id` when given; with `case_id` and
`case_kind` when a `caseId` is given, the kind `trade`, `dispute` or
`recovery` by the table the id was found in), `chat_room_members`
(creator), `chat_hpke` (creator).

Answer: `201 { chatRoomId }`.

### POST /invite-to-chat-room (setup)

Body: `{ chatRoomId, anopodIdTo, hpkeKey }`.

Checks: the room exists and the caller may invite (`403 only the creator
invites`); the room is `private` or `public` (`400 marketplace rooms take
join requests`); `anopodIdTo` decodes (`400 invalid anopodIdTo`); on a room
with a `case_id`, the target is a party to the room's case or holds a live
appointment as attestor (`403 not a party to the case`); the target exists
and has completed setup (`409 invitee has no chat key`); the target is not
a member (`409 already a member`); no open invite to the target for this
room (`409 invite already open`).

Who may invite (2026-11-11, section 18; until then the creator alone). The
room's creator, as before. And a member who is not the creator, when the
room is `private`, is about a listing (`listing_id` set) and the target
holds a live appointment as attestor: either trader of a marketplace chat
may bring an attestor in, and nobody else. Everyone else still gets `403
only the creator invites`: a room that does not exist, a caller who is no
member, a target id that does not decode, a target who is no attestor.

A case chat (2026-11-11): a room with a `case_id` takes only a person on
its case or an appointed attestor. The parties are the sender's pod of a
trade case, the seller's and the buyer's pods of a dispute case, and the
recovered pod of a break-glass case. A closed case does not stop an invite.

Writes: `chat_room_invites` with the wrapped key; notification to the
target, kind `chatInvite`, reference the `invite_id`.

Answer: `201 { inviteId }`.

### POST /accept-invite (setup)

Body: `{ inviteId }`.

Checks: the invite exists and is addressed to the caller (`404 invite not
found`).

Writes: `chat_room_members` (caller), `chat_hpke` (the invite's
`hpke_key`), `DELETE` the invite; notification to the inviter, kind
`inviteAccepted`, reference the `chat_room_id`.

Answer: `200 { chatRoomId }`.

### POST /decline-invite (setup)

Body: `{ inviteId }`. Same check.

Writes: `DELETE` the invite; notification to the inviter, kind
`inviteDeclined`, reference the `chat_room_id`.

Answer: `200 { chatRoomId }`.

### POST /request-to-join (setup)

Body: `{ chatRoomId }`.

Checks: the room exists (`404 room not found`) and is `public` or
`marketplace` (`403 room is private`); for `marketplace`, the listing is
`open` (`409 listing closed`); the caller is not a member (`409 already a
member`); no open request (`409 request already open`).

Writes: `chat_room_join_requests`; notification to the creator, kind
`joinRequest`, reference the `join_request_id`.

Answer: `201 { joinRequestId }`.

### POST /approve-join (setup)

Body: `{ joinRequestId, hpkeKey }`, the room key wrapped to the requester's
chat public key.

Checks: the request exists (`404 join request not found`) and the caller is
the room's creator (`403 only the creator approves`).

Writes: `chat_room_members` (requester), `chat_hpke`, `DELETE` the request;
notification to the requester, kind `joinApproved`, reference the
`chat_room_id`.

Answer: `200 { chatRoomId, anopodId }`.

### POST /decline-join (setup)

Body: `{ joinRequestId }`. Same checks as approve.

Writes: `DELETE` the request; notification to the requester, kind
`joinDeclined`, reference the `chat_room_id`.

Answer: `200 { chatRoomId, anopodId }`.

### POST /leave-chat-room (setup)

Body: `{ chatRoomId }`.

Checks: the caller is a member (`404 not a member`) and not the creator
(`409 the creator cannot leave`).

Writes: `DELETE` the member row and the caller's `chat_hpke` row.

Answer: `200 { chatRoomId }`.

### POST /list-chat-rooms (setup)

Body: `{ since }`, optional (2026-11-24, section 29); `{}` asks for
everything.

Answer:

```json
{
  "seq", "counts": { "rooms", "invites", "joinRequests" },
  "rooms": [ { "chatRoomId", "type", "name", "pictureAt", "listingId", "listing", "caseId", "caseKind", "creatorAnopodId", "hpkeKey",
               "members": [ { "anopodId", "username", "seenPosition" } ], "invited": [ { "anopodId", "username" } ],
               "lastMessage", "lastPosition", "createdAt" } ],
  "invites": [ { "inviteId", "chatRoomId", "type", "name", "listingId", "listing", "caseId", "caseKind", "from": profile, "createdAt" } ],
  "joinRequests": [ { "joinRequestId", "chatRoomId", "from": profile, "createdAt" } ]
}
```

`rooms` are the caller's memberships with the caller's own wrapped key, the
members, the people invited who have not answered yet (`invited`, oldest
first, `[]` when there are none), the room's newest message (`lastMessage`,
in the form /list-messages uses, null when the room has none) and its
position as `lastPosition` (0 when none); `invites` the open invites to the
caller; `joinRequests` the open requests on rooms the caller created.
A room about a listing (`chat_rooms.listing_id`: a private room made with a
`listingId`, or an old marketplace room) appears with its `listingId` and
`listing`, `{ listingId, side, quantity, currency, country, price, status,
owner: { anopodId, username } }` with `quantity` a decimal string of
millionths and `price` a decimal string without trailing zeros, as
/list-listings gives them; for other rooms `listingId` and `listing` are
null. Each invite carries the same `listingId` and `listing`, null for a
room without a listing, so the owner's request can say which listing it is
about. `invited`, `lastMessage` and `listing` were added for the wallet's
chat screens (2026-11-05); `listing` grew to this form and reached the
invites for the marketplace rework (2026-11-06).
A room about an attestor case (`chat_rooms.case_id`, 2026-11-11, section
18) appears with its `caseId` (hex) and its `caseKind` (`trade`, `dispute`
or `recovery`), straight from the room's two columns; for other rooms both
are null. Each invite carries the same two, so the person's request can say
which kind of case it is about.
Each entry of `members` carries `seenPosition` (2026-11-19, section 21),
the highest message position that member has seen in the room, as a
number, 0 until that member's wallet reports one; an entry of `invited`
carries none.
Each room carries `pictureAt` (2026-11-22, section 27): when the room's
picture was last set, an ISO 8601 string, null for a room without one.
Only a public room has a picture, and the picture itself is not in this
answer: /get-chat-room-picture hands it out.
Every answer carries `seq` and `counts` (2026-11-24, section 29). `seq` is
the highest change number among the caller's rooms, open invites and join
requests, 0 when none of them has one; `counts` is how many of each the
caller has. With `since` in the body, a number a wallet got as `seq`
before, the three lists hold only what changed after that number: a room
whose people or facts changed whole, a room with only a new message as
`{ chatRoomId, lastMessage, lastPosition }`, and the invites and the join
requests written since. `since` is a whole number from 0 (`400 invalid
since` for another value); without it the three lists hold everything, as
before. The numbered steps are in 29.3.
Since 2026-11-24, later the same day (section 31), `lastMessage` is the
room's newest message as it stands now, and never an edit or a delete of
one: `{ messageId, position, senderAnopodId, message, createdAt,
editPosition, deleted }`. The first three and `createdAt` are the
message's own. `message` is the ciphertext of the newest edit when the
message was edited, its own when it was not, and null when it was deleted.
`editPosition` is the position of the newest edit, null for a message that
was never edited, and `deleted` is true or false. `lastPosition` is the
highest position of any row of the room, so it is above
`lastMessage.position` when an edit or a delete is the room's newest row.
(Until then `lastMessage` was the room's newest row in the form
/list-messages uses, and `lastPosition` its position.) The three fields of
a room in an answer with `since` have the same form. 31.5 has the rest.

### POST /list-public-chat-rooms (setup)

Body: `{ limit, offset, search }`, all optional; `limit` defaults to 50
(max 200) and `offset` to 0. `search` (2026-11-22, section 26) is a word
of at most 100 characters (`400 invalid search` for a longer one or for a
value that is not a string): the answer then holds only the rooms whose
name holds the word anywhere, capital and small letters alike. The spaces
around the word are taken off, and an empty word means no search.

Answer: `200 { rooms: [ { chatRoomId, name, pictureAt, creator: profile,
memberCount, createdAt } ] }`, type `public` only. Since 2026-11-22
(section 26) the rooms with the most members come first, then the newest;
until then the list was newest first. Since 2026-11-22 (section 27) each
room carries `pictureAt`: when its picture was last set, an ISO 8601
string, null for a room without one.

### POST /set-chat-room-picture (setup)

Body: `{ chatRoomId, picture: { contentType, image } }` (2026-11-22,
section 27): the room, and its picture in the form of section 1.

Checks: `400 bad request shape`; the room exists and the caller is its
creator (`403 only the creator sets the picture`, also for a room that
does not exist); the room is `public` (`400 only a public room has a
picture`); the picture is one of the three types, at most 100,000 bytes,
begins as a picture of its type does and is at most 320 pixels wide and
high (`400 invalid picture: <why>`).

Writes: `chat_room_pictures`, the room's one row: its first picture, or
another in place of the one it has.

Answer: `200 { chatRoomId, pictureAt }`, `pictureAt` when the picture was
last set, as the two room lists then give it.

### POST /get-chat-room-picture (setup)

Body: `{ chatRoomId }` (2026-11-22, section 27).

Checks: `400 bad request shape`; the room exists and is `public` (`404
room not found`); it has a picture (`404 no picture`). The caller need not
be a member: the picture is as public as the room's name.

Answer: `200 { chatRoomId, picture: { contentType, image }, pictureAt }`.

### POST /list-messages (setup)

Body: `{ chatRoomId, afterPosition, beforePosition, limit, seenSince }`;
`afterPosition` defaults to 0, `limit` to 100 (max 200). `beforePosition`
is optional, 1 or more: when it is given, the answer is the newest `limit`
messages whose position is below it, and `afterPosition` is ignored (`400
invalid beforePosition` for a bad value); this is how a room opens at its
newest messages and loads older ones (2026-11-05).

Checks: the caller is a member (`403 not a member`).

Answer: `200 { messages: [ { messageId, position, senderAnopodId, message,
createdAt, kind, targetMessageId } ] }`, ascending by position, `position`
as a number.

With `seenSince` in the body (2026-11-24, section 29), a whole number from
0 (`400 invalid seenSince` for another value, checked before the member
check), the answer is `200 { messages, seen, seenSeq }`. `seen` is the
members of the room whose seen position changed after that number, each as
`{ anopodId, seenPosition }`; with `seenSince` 0 it is every member who
has seen anything. `seenSeq` is the number to send as the next
`seenSince`. Without `seenSince` the answer is `{ messages }`, as before.
The steps are in 29.4.

Since 2026-11-24, later the same day (section 31), `messages` holds every
row of the room in the order of `position`: the messages, and the rows
that /edit-message and /delete-message write. `afterPosition`,
`beforePosition` and `limit` count every row. Each entry has two fields
more: `kind`, null on a message and `edit` or `delete` on a row about one,
and `targetMessageId`, the message such a row is about, null on a message.
And `message` can be null: a row goes out without its ciphertext once a
later row of the room names the same message, and a delete never has one.
(Until then an entry had the first five fields, and `message` was always a
ciphertext.) The rule and two examples are in 31.4.

### POST /send-message (setup)

Body: `{ chatRoomId, message }`, `message` base64 of at most 65536 bytes.

Checks: member (`403 not a member`).

Writes: `chat_room_messages`.

Answer: `201 { messageId, position }`.

### POST /mark-messages-seen (setup)

Body: `{ chatRoomId, position }`, `position` a whole number, 1 or more: the
highest message position the caller's wallet has shown (2026-11-19, section
21).

Checks: `400 bad request shape`, `400 invalid chatRoomId`, `400 invalid
position`, then member (`403 not a member`).

Writes: `chat_room_members`, the caller's `seen_position`: it rises to
`position`, never above the room's newest message; a lower position changes
nothing.

Answer: `200 { chatRoomId, seenPosition }`, `seenPosition` what the row
holds afterwards, as a number.

### POST /get-chat-public-keys (setup)

Body: `{ anopodIds: [ ... ] }`, 1 to 50.

Answer: `200 { keys: [ { anopodId, chatPublicKey, chatPublicKeyPq } ] }`,
only for pods whose setup is complete; the others are left out.

### POST /list-stickers (setup)

Body: `{}` (2026-11-23, section 28).

Answer: `200 { sets: [ { name, stickers: [ { number, tags: [ ... ] } ] } ] }`:
every set of stickers in the order of the row, each with its stickers in
their order, each sticker with its two-digit number and its tags. Text
only; no picture. A set with no sticker is left out. The route writes
nothing.

### GET /sticker-picture/:set/:number (none)

No body (2026-11-23, section 28). `:set` is a set's name and `:number` a
sticker's two-digit number, as `/list-stickers` gives them.

Checks: there is such a sticker (`404 no sticker`, also for a name or a
number that cannot be one).

Answer: `200` with the picture's bytes as they are stored and
`Content-Type: image/webp`. This is the one answer of this server that is
not JSON. The route writes nothing.

### POST /create-listing (setup)

Body: `{ side, quantity, currency, country, price }`: `side` `buy` or
`sell`; `quantity` a decimal string of millionths of an anos, above zero;
`currency` three uppercase letters; `country` two uppercase letters; `price`
a decimal string, above zero, at most 8 decimals. `hpkeKey`, the owner's
wrapped copy of a room key, is optional since 2026-11-06 and ignored when
present (a string, else `400 bad request shape`), so an older client still
gets its listing.

Checks: the fields above first, each with its `400`, so a bad price is
still told as a bad price; last, the listing limit: the caller has fewer
than 10 rows in `listings` with `status` `open` (`403 listing limit
reached`). The limit was added 2026-11-20 (section 23): the count and the
insert are one transaction with the caller's row in `anopods` locked, so
requests sent at the same moment cannot all pass on the same count.

Writes: `listings` only, with `chat_room_id` null. Until 2026-11-06 a
listing got a marketplace room with it (`chat_rooms` type `marketplace`,
the owner's `chat_room_members` and `chat_hpke` rows); now the people who
connect each open a private room about it with /create-chat-room.

Answer: `201 { listingId, chatRoomId: null }`.

### POST /close-listing (setup)

Body: `{ listingId }`.

Checks: the listing exists (`404 listing not found`) and the caller owns it
(`403 not your listing`); it is open (`409 already closed`).

Writes: `UPDATE listings SET status = 'closed'`. An old listing's room and
its members stay; new join requests are refused, as are new rooms about the
listing (/create-chat-room, `409 listing closed`).

Answer: `200 { listingId, status: 'closed' }`.

### POST /list-listings (setup)

Body, all optional: `{ side, currency, country, status, mine, sortBy,
sortDirection, limit, offset }`. `status` is `open` (default), `closed` or,
since 2026-11-06, `any`; `mine` (2026-11-06) is a boolean, true for the
caller's own listings only (`400 invalid mine` otherwise), for the wallet's
Your listings page and its counts; `sortBy` is `createdAt` (default),
`price` or `quantity`; `sortDirection` `desc` (default) or `asc`; `limit`
50 (max 200); `offset` 0.

Answer: `200 { listings: [ { listingId, chatRoomId, owner: profile, side,
quantity, currency, country, price, status, createdAt } ] }`, `quantity`
and `price` as decimal strings; `chatRoomId` is the old marketplace room of
a listing made before 2026-11-06 and null since.

### POST /get-listing (setup)

Body: `{ listingId }` (`400 bad request shape` for anything else).

Checks: the listing exists (`404 listing not found`). Open or closed, any
pod with setup may read it.

Answer: `200 { listing }`, one item in the form of /list-listings. For the
wallet's listing page, which has its own address and reads one listing
(2026-11-06).

### POST /create-anos-account (setup)

Added 2026-10-25 (the wallet's spec, 4.4). Level setup implies vouched and
setup complete, which is "they are vouched" of the flow, and the encryption
key the `keyBlob` is under exists. (Since 2026-11-08 the `keyBlob` is under
the pod's key blob key, which comes from the passkey's PRF output, and no
longer under the encryption key: the wallet's spec, section 7.)

```json
{
  "accountId":   "<hex 32>",
  "accountType": "spending | guarded | vault | assisted",
  "keyBlob":     "<hex, 1 to 1024 bytes; 156 in practice>",
  "creation":    { "payload": { "...": "the signed creation" }, "signatures": { "...": "the eight signatures" } }
}
```

Checks, in order: the shape (`400 bad request shape`); `accountId` 32 bytes
(`400 invalid accountId`); `accountType` one of the four (`400 invalid
accountType`); `keyBlob` 1 to 1024 bytes (`400 invalid keyBlob`);
`creation.payload.accountId` decodes to the same 32 bytes,
`creation.payload.accountType` equals `accountType`,
`creation.payload.transactionType` is `accountCreation`, and
`creation.signatures` has the eight string fields `key1`, `postQuantumKey1`,
`key2`, `postQuantumKey2`, `breakGlassKey`, `breakGlassPostQuantumKey`,
`walletKey`, `walletPostQuantumKey` (`400 invalid creation`); no row with
this `accountId` (`409 account already registered`); last, the account
limit: the pod has fewer than 20 rows in `anos_accounts` with a
`created_at` in the last 30 days (`403 account limit reached`). The limit
was added 2026-11-10 (section 17): the count and the insert are one
transaction with the pod's row in `anopods` locked, so requests sent at
the same moment cannot all pass on the same count.

Writes: `INSERT anos_accounts`, `submitted_at` null.

Answer: `201 { accountId }`.

Since 2026-11-20 the body may also carry `firstKeyBlob`, pair one's
private halves alone (`400 invalid firstKeyBlob`): it is in 22.3.

### POST /mark-anos-account-submitted (setup)

Body: `{ accountId }`.

Checks: the shape (`400 bad request shape`), the id (`400 invalid
accountId`); a row with this `accountId` and this pod (`404 account not
found`).

Writes: `UPDATE submitted_at = COALESCE(submitted_at, now())`: the first
time is kept.

Answer: `200 { accountId, submittedAt }`, ISO 8601.

### POST /list-anos-accounts (setup)

Body: `{}`.

Answer: `200 { accounts: [ { accountId, accountType, keyBlob, creation,
submittedAt, createdAt } ] }`, the caller's rows, oldest first; `keyBlob`
hex, `submittedAt` ISO 8601 or null.

Since 2026-11-20 the body may carry `firstKeyBlobs`, every account comes
with `firstKeyOnly`, and a page that cannot open a first key blob is
refused `409 reload the wallet`: all three are in 22.3.

### POST /get-anos-account (none)

Body: `{ accountId }`. Unsigned, like `/get-anopod-session-keys`: for the
validators, which ask before accepting an account's creation and (since
2026-11-08) before accepting a stake for moderator or attestor.

Checks: the shape and the id (`400 bad request shape`); the row (`404
unknown account`).

Answer: `200 { accountId, anopodId, vouched, role }`, `vouched` read from
the pod's row; `role` (added 2026-11-08, section 16) the pod's live
appointment, `"moderator"`, `"attestor"`, `"validator"`, `"masterPod"` or
`null` (the last two names since 2026-11-10, 16.7).

### POST /add-noted-transaction (setup)

Added 2026-11-07 (the wallet's spec, 4.6), with the five routes below. A
note on a ledger transaction of the caller's, for the person's tax records:
the ledger's facts in the clear and the private part (the kind, the money,
the currency, the memo, the tag) as one blob under the pod's encryption key,
which this server cannot open.

```json
{
  "transactionId":  "<hex 32>",
  "accountId":      "<hex 32, an anos account of the caller's>",
  "otherAccountId": "<hex 32, or null>",
  "position":       12,
  "transactedAt":   "2026-11-07T10:00:00.000Z",
  "amount":         "<millionths of an anos, a decimal string>",
  "sent":           true,
  "noteBlob":       "<hex, 1 to 4096 bytes>"
}
```

Checks, in order: the shape (`400 bad request shape`: the five strings,
`otherAccountId` a string or null, `position` a number, `sent` a boolean);
`transactionId` 32 bytes (`400 invalid transactionId`); `accountId` 32
bytes (`400 invalid accountId`); `otherAccountId` 32 bytes when not null
(`400 invalid otherAccountId`); `position` an integer of 0 or more (`400
invalid position`); `transactedAt` parses (`400 invalid transactedAt`);
`amount` digits only that fit a BIGINT (`400 invalid amount`); `noteBlob` 1
to 4096 bytes (`400 invalid noteBlob`); an `anos_accounts` row with this
`accountId` and this pod (`403 not your account`); no note of this pod for
this transaction and this account (`409 already noted`; until 2026-11-20
any note of the pod for the transaction refused it, section 11), the unique
rule as the backstop (a unique violation on the insert answers the same
`409`).

Writes: `INSERT noted_transactions` with a fresh `note_id`.

Answer: `201 { noteId }`.

### POST /update-noted-transaction (setup)

Body: `{ noteId, noteBlob }`.

Checks: the shape (`400 bad request shape`); `noteId` 32 bytes (`400
invalid noteId`); `noteBlob` 1 to 4096 bytes (`400 invalid noteBlob`); the
row exists and is this pod's (`404 note not found`).

Writes: `UPDATE note_blob`; the ledger facts never change.

Answer: `200 { noteId, updatedAt }`, ISO 8601.

### POST /remove-noted-transaction (setup)

Body: `{ noteId }`.

Checks: the shape (`400 bad request shape`); `noteId` 32 bytes (`400
invalid noteId`); the row is this pod's (`404 note not found`).

Writes: `DELETE` the row.

Answer: `200 { noteId, removed: true }`.

### POST /list-noted-transactions (setup)

Body: `{ from, to }`, both optional, ISO 8601; null counts as absent.

Checks: the shape (`400 bad request shape`); `from` parses when given
(`400 invalid from`); `to` parses when given (`400 invalid to`).

Reads: the pod's rows with `transacted_at` at or after `from` and before
`to`, newest `transacted_at` first, then the highest `position`, then, of
the two notes a transfer between two of the pod's own accounts can hold,
the sent one (since 2026-11-20, section 11), 1001 rows at most.

Answer: `200 { notes: [ { noteId, transactionId, accountId,
otherAccountId, position, transactedAt, amount, sent, noteBlob, createdAt,
updatedAt } ], more }`: the first 1000, and `more` true when a 1001st row
exists. Ids and the blob hex, `otherAccountId` null when there is none,
`position` a number, the three times ISO 8601, `amount` a decimal string.

### POST /get-wallet-settings (setup)

Body: `{}`.

Answer: `200 { settingsBlob, updatedAt }`, hex and ISO 8601, both null
before the first set.

### POST /set-wallet-settings (setup)

Body: `{ settingsBlob }`.

Checks: the shape (`400 bad request shape`); `settingsBlob` 1 to 16384
bytes (`400 invalid settingsBlob`).

Writes: `INSERT` or `UPDATE` the pod's one row, whole.

Answer: `200 { updatedAt }`, ISO 8601.

### POST /list-alert-settings (setup)

Added 2026-11-21 with the eight routes below. The caller's security
alerts: its emails and its phones (25.3).

### POST /add-alert-email (setup)

An email for the caller's alerts, sent a six-digit code (25.3).

### POST /confirm-alert-email (setup)

The code typed back; the email counts from here (25.3).

### POST /remove-alert-email (setup)

"Take off": the email comes off a month from now (25.3).

### POST /keep-alert-email (setup)

"Keep": an email that was set to come off stays (25.3).

### POST /add-alert-phone (setup)

A phone for the caller's alerts, as its browser handed it over (25.3).

### POST /remove-alert-phone (setup)

"Take off": the phone comes off a month from now (25.3).

### POST /keep-alert-phone (setup)

"Keep": a phone that was set to come off stays (25.3).

### POST /report-waiting-transfers (none)

For the validators: the transfers that have started to wait, in one
message signed by the validator's own key (25.4).

## 6. Notifications

| kind | to | reference_id |
| ---- | -- | ------------ |
| `vouchRequest` | the seed | `vouch_id_number` |
| `vouchApproved` | the requester | `vouch_id_number` |
| `vouchDeclined` | the requester | `vouch_id_number` |
| `vouched` | the pod that just became vouched | its own `anopod_id` |
| `chatInvite` | the invitee | `invite_id` |
| `inviteAccepted` | the inviter | `chat_room_id` |
| `inviteDeclined` | the inviter | `chat_room_id` |
| `joinRequest` | the room's creator | `join_request_id` |
| `joinApproved` | the requester | `chat_room_id` |
| `joinDeclined` | the requester | `chat_room_id` |
| `tradeCaseOpened` | the sender's pod of a trade case | the case id (13.7, 2026-10-26) |
| `disputeCaseOpened` | the seller's and the buyer's pods of a dispute case | the case id (13.7) |
| `caseScheduled` | the parties of a trade or dispute case | the case id (13.7) |
| `caseDecided` | the parties of a trade or dispute case | the case id (13.7) |
| `caseDismissed` | the parties of a trade or dispute case | the case id (13.7) |
| `recoveryCaseScheduled` | the recovered pod of a break-glass case | the case id (14.7, 2026-11-11) |
| `passkeyAdded` | the pod a passkey was added to | the `passkey_id` (section 19) |
| `transferWaiting` | the pod that made the account a transfer is waiting to leave | the `account_id` (section 25, 2026-11-21) |
| `recoveryMoveWaiting` | the pod that made the account a recovery's break-glass move is waiting to leave | the `account_id` (section 25) |
| `recoveryCaseOpened` | the pod a recovery case was opened for | the recovery case's id (section 25) |
| `alertSettingsChanged` | the pod whose list of security alerts changed | its own `anopod_id` (section 25) |

Every notification is written inside the transaction of the event it
reports. The phone polls `/list-notifications` and marks what it has shown.
Since 2026-11-21 the last four also go out by email and to the phone, to
every confirmed email and every phone on the pod's list of security alerts
(section 25).

## 7. Client crypto

What the phone produces. The server stores all of it as opaque bytes and
checks lengths only. AES-256-GCM everywhere, 12-byte random IV, 16-byte tag,
stored as `iv || ciphertext || tag`. HKDF is HKDF-SHA-256 with an empty salt
and the info strings below; a new version of any derivation gets a new info
string.

| Thing | How |
| ----- | --- |
| PRF input | `SHA-256('masterpod/prf-salt/v1')`, the 32-byte `first` value at create and at every get |
| `KEK_prf` | `HKDF(prf output, 'masterpod/kek-prf/v1', 32)` |
| encryption key | 32 random bytes, born at setup |
| `blob1` | encryption key under `KEK_prf`: 60 bytes |
| backup code | 32 random bytes, born at setup; shown once as RFC 4648 base32 without padding (52 characters) in groups of 4; the user types it back and setup continues only on a match |
| `KEK_backup` | `HKDF(backup code, 'masterpod/kek-backup/v1', 32)` |
| `blob2` | encryption key under `KEK_backup`: 60 bytes |
| backup code P-256 key | scalar = `HKDF(backup code, 'masterpod/backup-p256/v1', 48)` as a big-endian integer, reduced modulo n minus 1, plus 1; public key compressed, 33 bytes |
| backup code ML-DSA-87 key | seed = `HKDF(backup code, 'masterpod/backup-mldsa/v1', 32)`, `ml_dsa87.keygen(seed)`; public key 2592 bytes |
| ephemeral keys | fresh random P-256 and ML-DSA-87 pairs at every create and unlock; signatures as in section 1 |
| chat key pair | random P-256 scalar (public key compressed, 33 bytes) and ML-KEM-1024 from a random 64-byte seed (public key 1568 bytes) |
| `chatPrivateKeyBlob` | `p256 scalar (32) || ml-kem seed (64)` under the encryption key: 124 bytes |
| room key | 32 random bytes, made by the room's creator |
| `hpkeKey` for member M | ephemeral P-256 pair `e`; `ss1` = x-coordinate of ECDH(`e`, M's chat P-256 key), 32 bytes; `(ct, ss2)` = `ml_kem1024.encapsulate(M's chat ML-KEM key)`; `KEK_room = HKDF(ss1 || ss2, 'masterpod/room-key-wrap/v1', 32)`; `hpkeKey = e.public (33) || ct (1568) || room key under KEK_room (60)` = 1661 bytes. M reverses it with the chat private key |
| message | UTF-8 text under the room key, base64 on the wire |
| security bucket key | 32 random bytes per add, deposited with the keyholders as Shamir shares and not kept; images and info are encrypted under it the same way, content type in the clear; `keyId`, 32 random bytes per key, travels with the shares and with the add |
| `identityBlob` (2026-10-25) | public ledger id (32) `\|\|` lookup id (32) under the encryption key: 92 bytes; the ids as `~/Desktop/Z/web_app/docs/public-ledger-id.md` makes them |
| anos `keyBlob` (2026-10-25) | key1 scalar (32) `\|\|` postQuantumKey1 seed (32) `\|\|` key2 scalar (32) `\|\|` postQuantumKey2 seed (32) under the key blob key (wallet spec 7): 156 bytes; opened only to sign |
| anos `firstKeyBlob` (2026-11-20) | key1 scalar (32) `\|\|` postQuantumKey1 seed (32) under the key blob key: 92 bytes |
| `noteBlob` (2026-11-07) | a JSON object `{ v: 1, kind, money, currency, memo, tag }` as UTF-8 under the encryption key; a few hundred bytes; the wallet's `wrapJson` |
| `settingsBlob` (2026-11-07) | a JSON object `{ v: 1, protect }` under the encryption key; the wallet's `wrapJson` |
| `wrappedKeyBlobKey` (2026-11-18) | the pod's key blob key under HKDF(the added passkey's PRF output, `masterpod/kek-keys-wrap/v1`, 32), AES-256-GCM, 60 bytes |

Keys live in RAM and die with the tab. Nothing secret is stored on the phone.

## 8. Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `WEB_ORIGIN` | `http://localhost:4200` | The web app's origin: CORS allow-list and the WebAuthn expected origin |
| `RP_ID` | `localhost` | WebAuthn relying party id |
| `EPHEMERAL_KEY_HOURS` | `12` | Life of a session's ephemeral keys |
| `CHALLENGE_SECONDS` | `120` | Life of a challenge |
| `ADD_PASSKEY_CHALLENGE_SECONDS` | `600` | Life of a challenge for `/add-passkey` (ten minutes; section 19) |
| `TIMESTAMP_WINDOW_SECONDS` | `120` | Allowed clock difference on a signed request, each way |
| `MAX_IMAGE_BYTES` | `10485760` | Largest image, decoded |
| `MAX_IMAGES_PER_REQUEST` | `5` | Images per bucket request |
| `VALIDATOR_URLS` | `http://localhost:3001` to `3005` | The validators asked for the DAO stake list, comma-separated, tried in order; on the servers the doormen's URLs (section 15.7) |
| `DAO_PROPOSE_MIN_VOTES` | `1` | The least DAO votes (whole staked anos) a pod needs in the snapshot to post a proposal |
| `DAO_PROPOSAL_PERCENT` | `15` | The percent of all DAO votes a pending proposal needs in support to go to a vote; at most 100 |
| `DAO_PASS_PERCENT` | `50` | For must be more than this percent of the votes cast; at most 99, so a tie fails |
| `DAO_PENDING_MINUTES` | `10080` | How long a proposal may collect support (a week) |
| `DAO_VOTE_MINUTES` | `20160` | How long an open proposal takes votes (two weeks) |
| `RESEND_API_KEY` | none: no email is sent | The email company's key (section 25, 2026-11-21) |
| `ALERT_EMAIL_FROM` | none | The sender of every email: `anoPod wallet <alerts@wallet.anocloud.com>` on the servers |
| `ALERT_PUSH_PRIVATE_KEY` | none: no notification is sent | The private half of this server's key for the phones' delivery services, 43 characters, made by `scripts/make-alert-push-key.js` |
| `ALERT_PUSH_CONTACT` | none | The contact the delivery services are given: `https://wallet.anocloud.com` on the servers |
| `ALERT_REMOVE_MINUTES` | `43200` | How long an email or a phone that was taken off still gets every alert (a month) |
| `VALIDATOR_KEYS_FILE` | `network/validators.json` | The validators' public keys; a path from the repo's root, or a full path |
| `ANTHROPIC_API_KEY` | none: Joy is off | Anthropic's API key (section 30, 2026-11-24) |
| `JOY_MODEL` | `claude-haiku-5-5` | The model that writes Joy's answers |
| `JOY_EFFORT` | `medium` | How hard the model thinks before it answers: `low`, `medium` or `high` |
| `JOY_MAX_TOKENS` | `16000` | The most tokens one request to Anthropic may write, the model's thinking included |
| `JOY_DAILY_MESSAGES` | `300` | How many messages one pod may send Joy in one day (UTC) |

All have defaults, so the existing `.env` keeps working. The JSON body
limit is computed from the last two: `MAX_IMAGES_PER_REQUEST *
MAX_IMAGE_BYTES * 1.4 + 1 MB`.

`WEB_ORIGIN` became a list and `RECOVERY_POD_URL_BASE` was added in section
12.7 (2026-10-26).

The last six are the security alerts' (section 25, 2026-11-21). The first
four of them have no default. With both email lines set the emails are
on, and with both phone lines set the notifications on the phone are on.
With neither line of a pair that part is off, and one line of a pair
without the other stops the boot (25.8).

The five after them are Joy's (section 30, 2026-11-24). The first has no
default: without it Joy is off and this server runs as before (30.8).

## 9. Genesis

Nothing can be vouched until a seed exists. The first super seeds are made
by the operator: the pod is created through the web app like any other,
then

```bash
npm run make-super-seed -- <anopod id, hex>
```

sets `vouched = true` and inserts the `super_seeds` row with `vouched_by =
'genesis'`. Idempotent. There is no route for it.

Moderators and attestors are appointed the same way (section 16,
2026-11-08): the pod is created through the web app, then

```bash
npm run appoint -- <anopod id, hex> <moderator|attestor|validator|masterPod>
npm run revoke -- <anopod id, hex>
```

inserts the `appointments` row with `appointed_by = 'operator'`, or ends
the pod's live appointment. Running `appoint` again for the same role
changes nothing and says so. There is no route for either.

## 10. Deferred, by decision

- Recovery with the backup code and backup code rotation: specified in
  section 12 on 2026-10-26, built by the three recovery builds.
- Several live sessions per pod.
- Purging pods that never got vouched, and their usernames.
- Removing a member from a room and rotating the room key.
- Editing a listing, a profile or a selfie.
- Push delivery of notifications and messages; the phone polls. (Since
  2026-11-21, section 25, the four kinds of the security alerts also go
  to the phone and by email. Every other notification and every chat
  message is still polled.)
- Generic encrypted object storage, anoSphere, the anos interface.
- Anti-abuse limits on `/challenge` and `/create-anopod`.
- Removing one passkey; a cap on a pod's passkeys; a name or a date for the
  main passkey (section 19).
- A route that hands out an account's blob with both pairs, for the screen
  where a person asks for their second key; signing servers that keep
  their own list of passkeys; a limit on how often `/check-signing-passkey`
  may be asked; the masterpod's own passkey check at a moderator's sign-off
  (section 22).

## 11. Notes from the build

Built 2026-10-24, straight through, and verified on the throwaway rig
(build plan step 11: five pods, every route, every refusal, the tables
checked after each flow). Where this file left a detail open, the simplest
thing was chosen and is recorded here; nothing above was changed.

- Challenges. The checks of `/create-anopod` and `/unlock` read the challenge
  row (`find`); the write transaction then consumes it with `DELETE ...
  RETURNING` (`take`, the select-for-update and the delete in one statement).
  A failed check never uses a challenge up. A challenge that vanished between
  the read and the write answers `401 unknown or expired challenge`.
- `nowVouched` and `nowSeed` in the `/approve-vouch-request` answer are the
  requester's state after the call, not whether this call changed it.
- A seed approving a second request from a pod it already vouched for (the
  pod sent another request after the first approval, before its second
  vouch): `409 vouch already recorded`, since `vouches (by, for)` is unique.
  The request stays and can be declined.
- `/list-listings` answers prices without trailing zeros (`1.5`, not
  `1.50000000`) and quantities as the BIGINT's decimal string.
- Reasons for bad values: a nonce that does not decode to 16 to 32 bytes is
  `400 invalid nonce`; a field that does not decode is `400 invalid <field>`;
  a bad selfie is `400 invalid selfie: <reason>`; the username rule is
  `400 invalid username: 3 to 32 characters, a-z, 0-9 and _` on both
  `/check-username` and `/create-anopod`; `/create-chat-room` with a name on a
  private room is `400 private rooms have no name`; `/send-vouch-request` with
  an `anopodIdTo` that does not decode is `400 invalid anopodIdTo`.
- `/invite-to-chat-room` answers `409 invitee has no chat key` for a missing
  target too, as section 5 words it.
- Lengths the server checks, section 7 being the phone's business: `hpkeKey`
  1 to 4096 bytes (the column), `blob1` and `blob2` 1 to 1024,
  `chatPrivateKeyBlob` 1 to 16384, `message` and `info` 1 to 65536 bytes.
- `requireSession` compares `payload.path` with `req.baseUrl + req.path`.
  Nonces live `2 * TIMESTAMP_WINDOW_SECONDS`.
- The sign counter is ignored by handing the WebAuthn library a stored
  counter of 0; it only compares counters when one of them is above 0.
- Orders: `/list-chat-rooms` rooms newest first, members by join time with
  the caller included; `/list-notifications` newest first, ties by
  notification number; `/get-chat-public-keys` in id order;
  `/list-security-records` and `/list-vouch-requests` oldest first.
- The JSON body limit is `ceil(MAX_IMAGES_PER_REQUEST * MAX_IMAGE_BYTES *
  1.4) + 1 MiB` bytes.
- The genesis script exits 2 on a malformed id and 1 on an unknown one;
  running it again on a super seed changes nothing and says so.
- Code layout: every service returns `ok(status, body)` or `refuse(status,
  reason)` (`src/util/result.js`) and every handler calls `answer(res,
  result)`. `src/anopods/anopods.queries.js` is born in build step 3, since
  `requireSession` needs `findById` and the row mapper, and grows in step 4.
  `src/chat/chat.queries.js` writes a member row and its `chat_hpke` row in
  one `insertMember` and deletes both in one `deleteMember`.
- The web app evaluates the PRF at creation as well as at every unlock; when
  the authenticator returns it at creation, setup can follow without an
  unlock, otherwise the setup section asks for an unlock first. The backup
  code is typed back with case and separators ignored. The security bucket
  keys are shown once as hex and not kept. The app talks to
  `http://localhost:3100` with `location.hostname` as the RP id.
- `/get-anopod-session-keys` (level none, `src/anopods/`), added 2026-10-24
  for the keyholders: body `{ anopodId }`, answer `200 { anopodId,
  ephemeralAuthKey, ephemeralAuthKeyPq, ephemeralExpiresAt }` (hex, hex,
  ISO) or `404 unknown anopod`; a malformed body is `400 bad request shape`.
  A keyholder fetches a pod's current session public keys with it, on every
  `/receive-share`, to verify the pod's signature (keyholdersoftware spec 3.1
  and 5.10). Public keys are public, so the route is unsigned.
- `/list-vouch-requests` answers each requester's profile without the selfie
  since 2026-11-08 (step 1 of
  `~/Desktop/Z-TestNet/forclaude/wallet-vouch-requests-plan-1.md`): the
  wallet reads each requester's picture through `/get-anopod-profile`, so a
  seed with many requests sees the list at once instead of waiting for every
  picture. `listOpenFor` lost its join on `public_selfies`; the order, the
  body and the other two selfie routes are unchanged, and no schema or
  environment change came with it.

### The wallet build (2026-10-25)

Step 3 of `~/Desktop/Z/web_app/docs/build-plan.md`, built as its spec says
(section 4 there). What it settled:

- The schema change is a rebuild: `anopods` gained `identity_blob` and the
  all-or-nothing check became eight-way, `security_images` and
  `security_info` gained `key_id NOT NULL`, and `anos_accounts` is new.
  Existing rows cannot satisfy the new checks, so the live `masterpod`
  database is dropped and built again (`npm run db:reset`) and the first
  pod and the genesis super seed are made again. A masterpod on the old
  code against the new schema fails every setup and bucket write, so it is
  restarted first.
- `/get-anos-account` reads `vouched` through a `LEFT JOIN` on `anopods`; a
  pod row that is gone reads as `vouched false`.
- `/mark-anos-account-submitted` on a bad id is `400 invalid accountId`;
  `/get-anos-account` on one is `400 bad request shape`, as the wallet spec
  words each.
- Checked by `test/rig.mjs` (42 checks): a throwaway database from
  `db/schema.sql`, a masterpod booted on it on port 3199, pods written
  straight into the database with session keys the rig made and a passkey
  the rig holds; `/complete-setup` with seven, eight and an oversized
  eighth field; a forged WebAuthn assertion (`clientDataJSON`,
  `authenticatorData` with UP and UV, a DER signature over
  `authenticatorData || SHA-256(clientDataJSON)` by the stored COSE key)
  unlocking and answering `identityBlob`, null before setup; both adds
  without and with `keyId`, the list showing it, the status counts; the
  four anos account routes in order with every refusal, `409` on a second
  create by the same and by another pod, `404` on marking someone else's,
  the unsigned lookup answering `vouched` true and, for a row written for
  an unvouched pod, false. The database is dropped at the end.

### The marketplace rework (2026-11-06)

Step 1 of `~/Desktop/Z-TestNet/forclaude/wallet-marketplace-plan-1.md`
(its section 1), the masterpod's part of the wallet's phone-first
marketplace: a private chat per person who connects with a listing's owner
instead of one group room per listing, the listing linked to the room by
`chat_rooms.listing_id`. Built as the plan says; what it settled:

- The schema change is additive and idempotent: `chat_rooms.listing_id`
  (nullable, a partial index) and `listings.chat_room_id` made nullable,
  inline in the two `CREATE TABLE`s for a fresh database and in the
  marketplace block at the end of `db/schema.sql` for a live one, where the
  block also sets `listing_id` on every old marketplace room from its
  listing. The index and the column comment sit in the block only: at the
  table they would run before the column exists on a live database. A second
  run changes nothing. Deployed as the deploy plan's schema paste (its
  section 6) with this Mac's new line count and hash; the backfill moves
  `updated_at` on the old rooms.
- `/create-chat-room`: a `listingId` that is not a string is `400 bad
  request shape`; one that does not decode is `404 listing not found`, as
  `/close-listing` and `/get-listing` treat theirs; `listingId: null` counts
  as absent, like every optional field. The listing checks run after the
  existing ones, in the plan's order. `roomAboutListingBy` answers the room
  in `findRoom`'s form, the oldest when there are several.
- `/list-chat-rooms` joins `listings` on `chat_rooms.listing_id` (no longer
  on `listings.chat_room_id`), so an old marketplace room keeps its listing
  through the backfill and a new private room gets its own; the owner's
  username is a second join on `anopods`. The 2026-11-05 fields of
  `listing` are unchanged; the new ones sit beside them.
- `/create-listing` keeps its field order and refusals; `hpkeKey: null`
  counts as absent. The service no longer imports from `src/chat/`.
  `/close-listing` is unchanged in code.
- `/list-listings`: `mine` is a boolean (`400 invalid mine` otherwise),
  read on the service with the caller; `status: 'any'` reaches the SQL as
  null, and the owner filter is one more parameter on the same statement.
  `/get-listing` has its own select, `findListingItem`, a copy of the
  /list-listings select for one id; `findListing` (ids as Buffers, no
  profile) stays for the services' own checks.
- `/request-to-join` still serves old marketplace rooms and public rooms.
  Between the masterpod deploy and the wallet deploy a listing made on the
  old wallet has no room, so its Request to join fails; the gap is kept
  short (plan 1.8).
- Checked with `node --check` on every changed file and the schema run
  twice against the local `masterpod` database inside one rolled-back
  transaction, first with an old-style listing and its marketplace room in
  place (the backfill set its `listing_id`), then the changed query
  functions and the two read services on the same transaction.

### The wallet memory (2026-11-07)

Step 1 of `~/Desktop/Z-TestNet/forclaude/wallet-notes-plan-1.md` (its
section 1), the masterpod's part of the wallet's memory: two tables under
the person's pod, `noted_transactions` (one note per ledger transaction,
since 2026-11-20 one per transaction and account, see the note of that day
below, for the person's tax records: the ledger's facts in the clear, the
private part as a blob this server cannot open) and `wallet_settings` (one
encrypted object per pod, the Protect your passkey answer first), and six
routes at level setup in a new feature folder, `src/wallet-memory/`, in the
shape of `src/anos-accounts/`. Why: the ledger knows the anos, the time and
the other account of a transaction, not the money the person paid or
received, and until now the wallet kept nothing of its own. Built as the
plan says; what it settled:

- The schema change is additive and idempotent: one block at the end of
  `db/schema.sql`, after the marketplace block, with `IF NOT EXISTS` and
  `OR REPLACE`, so `npm run db:setup` and the deploy plan's schema paste add
  the two tables to a live database and a second run changes nothing. Each
  table's `COMMENT ON` lines sit after its trigger, before the next table,
  as the seeds pair does; the file's header comment is unchanged, since the
  block alters nothing that exists.
- A time (`transactedAt`, `from`, `to`) is checked with `Date.parse`, as
  the session's timestamp is, and handed to the SQL in its ISO 8601 form,
  so pg sees one shape whatever the client wrote.
- The account check of `/add-noted-transaction` reads the `anos_accounts`
  row through the anos accounts feature's `findAccount`; no row and a row of
  another pod's both answer `403 not your account`.
- `/update-noted-transaction` and `/remove-noted-transaction` take their
  `404 note not found` from the write itself (`UPDATE ... RETURNING` with
  no row, `DELETE` with no row), as `/mark-anos-account-submitted` does;
  `findNote` is written as the plan lists it and no route of this step
  needs it.
- `position` and `amount` come back from pg as decimal strings (BIGINT);
  the service answers `amount` as the string and `position` as a number.
  `/list-noted-transactions` asks for 1001 rows and answers the first 1000
  with `more` true when the 1001st exists; `from: null` and `to: null`
  count as absent, like every optional field.
- Checked with `node --check` on every changed file and, by psql on the
  local `masterpod` database inside one rolled-back transaction as the
  marketplace rework was checked (`SET ROLE masterpodsoftware`), the two
  tables with their index and triggers, then each query of the two query
  files as `PREPARE` with its exact text and `EXECUTE` on a throwaway pod
  id and transaction id: the insert twice, a second note on the same
  transaction refused by the unique rule, the find by transaction, the
  find by id (none for another pod), the list without a range, with one and
  past both, the update (none for another pod), the delete (none for
  another pod), the settings upsert twice and its find; then the DDL a
  second time, which changed nothing. No server, no browser.

### Pictures: no PDFs as evidence, and the selfie check (2026-11-12)

No plan file: asked for and decided in chat on 2026-11-12, after a look at
how a file that only pretends to be a picture could reach a server or a
phone. Two changes here; the wallet's three of the same day are in the
wallet spec, section 11.

- Evidence is pictures only. `EVIDENCE_CONTENT_TYPES` in
  `src/attesting/attesting.service.js` and the check on
  `escrow_dispute_evidence.content_type` in `db/schema.sql` name
  `image/jpeg`, `image/png` and `image/webp`; `application/pdf` left both,
  and a PDF is `400 invalid contentType`. Why: a PDF is not a picture, the
  server cannot look into it (it is ciphertext), and the one who opens it
  is an attestor. The column's `COMMENT ON` line names the three.
- The check is changed inline in the `CREATE TABLE` only, with no
  drop-and-add at the end of the file: narrowing a check fails on a
  database that still holds a PDF row. A database built fresh, as a launch
  builds it, has the three. A database kept from before keeps its check of
  four, and the server refuses a PDF there all the same. Rows of before
  stay as they are; the wallet shows no file whose type is not one of its
  own three. The file's header comment is unchanged, since nothing that
  exists is altered.
- A selfie is looked into. `pictureProblem({ contentType, bytes }, maxSide)`
  in `src/util/images.js` takes what `decodeImage` returns and answers a
  reason or null; `createAnopod` calls it right after `decodeImage`, with
  `SELFIE_MAX_SIDE`, 4096. Two new reasons under `400 invalid selfie:`:
  `image must be a picture of its contentType` (the bytes do not begin as
  a picture of the named type does, the header ends early, or it names a
  width or a height of 0) and
  `image must be at most 4096 pixels wide and high`. Why: the selfie is
  the one picture stored in the clear and shown to everyone, and a small
  file can name a huge picture that every phone then has to unpack.
  (Since 2026-11-22, section 27, a public room's picture is a second
  one. It is checked the same way, with 320 pixels where the selfie has
  4096.)
- `imageSize(contentType, bytes)` reads the header only: nothing is
  decoded, no package is added, and no read goes past the end of the
  bytes. JPEG: `FF D8`, then the segments up to the first frame header
  (the markers `C0` to `CF` without `C4`, `C8` and `CC`), which carries
  the height and the width; fill bytes and the markers that stand alone
  are stepped over; a scan or the end before a frame header is not a
  picture. PNG: the eight signature bytes, then the `IHDR` chunk first.
  WebP: `RIFF`, `WEBP`, then a `VP8 ` chunk (a key frame with its start
  code), a `VP8L` chunk or a `VP8X` chunk, each with the size in its own
  place.
- The label has to be the true one: a PNG sent as `image/jpeg` is refused.
  The wallet sends a JPEG it has drawn itself, named `image/jpeg`, since
  2026-11-21 the middle of the picture as a square of at most 320 pixels,
  and before that about 1280 pixels on its longer side.
- Security images are not looked into: they are ciphertext. The 4096 is a
  constant, not a setting.
- Not stopped by this: a true picture built to break the program that
  shows it, and many pictures at the limit on one page. Redrawing every
  selfie on the server is on the list for after production.
- No schema change for the selfie check, no new setting, no package.
- Comments brought in line on the user's word ("Yes, update them"): the
  comment of `EVIDENCE_CONTENT_TYPES`, and the `COMMENT ON` line of
  `escrow_dispute_evidence.content_type` in `db/schema.sql`, which changed
  the file's sha256 a second time. With both lines the file has 1332
  lines, as before; its sha256 is in the deploy notes, section 11.
- Checked: `node --check` on the changed files, and the service module
  loaded. The schema file built from nothing into a scratch schema inside
  one rolled-back transaction on the local `masterpod` database: a PDF row
  was refused, a row of each of the three types went in, and a second run
  of the file changed nothing. In a second scratch schema the file of
  before was built, a PDF row put in, and the new file run on top: no
  error, the check of four still there, the comment the new one, the row
  kept. `imageSize` against 20 pictures made by
  macOS (`sips`) and by a browser, JPEG, PNG and WebP in its three forms,
  each size compared with the one `sips` reads; 4096 let in, 4097 refused;
  wrong and cut files refused; about 530,000 damaged files, none of which
  made the check throw. The script was a throwaway outside the repo.
  `/create-anopod` itself was not called, since it needs a passkey: the
  user's run-through.

### A note for each account of a transfer between a pod's own accounts (2026-11-20)

No plan file: found and decided in chat on 2026-11-20. The user had sent
anos from one of their accounts to another and noted the transfer twice,
in the first account's history as "Transferred to own account" and in the
second's as "Transferred from own account". The wallet's Noted
transactions page showed one row. Why: such a transfer is one transaction
on the ledger, standing in both accounts' histories, and the rule here was
one note per pod and transaction (decision 10 of
`~/Desktop/Z-TestNet/forclaude/wallet-notes-plan-1.md`). So the second
account could hold no note of its own; the wallet showed the first
account's note there, and saving it rewrote that one note. Decision 3 of
the same plan gives the two sides a kind each, which needs a note on each.
The wallet's change of the same day is in the wallet spec, section 11.

- The rule is one note per pod, transaction and account:
  `UNIQUE (anopod_id, transaction_id, account_id)` on `noted_transactions`.
- `db/schema.sql`: the rule is inline in the `CREATE TABLE`, for a fresh
  database. For a database that already has the table, three lines stand
  after the table's `COMMENT ON` lines: the old rule dropped under its name
  `IF EXISTS` (`noted_transactions_anopod_id_transaction_id_key`, the name
  PostgreSQL gave it), then a drop-and-add of the new rule under its one
  name (`noted_transactions_anopod_id_transaction_id_account_id_key`, the
  name PostgreSQL gives the inline rule), as the appointments check. Every
  row written under the old rule fits the new one, so no row changes. The
  file's header comment now names the wallet memory block among the blocks
  with an idempotent ALTER, and the table's `COMMENT ON` line says the new
  rule.
- `/add-noted-transaction`: `findNoteByTransaction` takes the account as
  its third argument and asks by pod, transaction and account, so
  `409 already noted` now means a note of this pod for this transaction and
  this account. The rest of the route is as it was: the account has to be
  the pod's (`403 not your account`), and the unique rule is the backstop.
- `/list-noted-transactions`: a third sort key, `sent DESC`. The two notes
  of such a transfer share `transacted_at` and `position`. Without a third
  key their order could change from one read to the next, since an edit
  moves a row inside the table; with it the sent one comes first.
- No new route, reason, setting or package. `/update-noted-transaction`
  and `/remove-noted-transaction` are unchanged: they go by note id.
- A note made before this day stays as it is, on the account it was made
  on. A person who noted such a transfer from both sides has one note, with
  the words saved last. With the wallet of this day they edit it in the
  first account's history and add the second in the other's.
- The order of a deploy: this server first (the schema line, then the
  code), the wallet after it. Each half-way state of this server behaves as
  before this day: the new code on the old rule answers
  `409 already noted` for the second account through the backstop, and the
  code of before on the new rule refuses it by its own check. A wallet of
  this day on a server of before shows "Add a note" in the second account's
  history and reads `409 already noted` there.
- Comments brought in line in the same change, said to the user before the
  first edit: the comments of `findNoteByTransaction`, `insertNote` and
  `listNotes` in `src/wallet-memory/noted-transactions.queries.js`; the
  header comment and the comment of `addNotedTransaction` in
  `src/wallet-memory/wallet-memory.service.js`; the
  `/add-noted-transaction` row of the README. In this spec: the
  `noted_transactions` section, the sections of the two routes, and a dated
  clause in the note of 2026-11-07 above, whose other words stay as the
  record of their day.
- Checked: `node --check` on the two code files. Then a throwaway outside
  the repo, on the local `masterpod` database inside one rolled-back
  transaction, with a stand-in in the place of `src/db/pool.js` (one
  client, as in the checks of sections 21 and 22).
  The committed `db/schema.sql` was built into a scratch schema with 5001
  notes, and a second account's note was refused there by the old rule.
  The new file was run on top twice: only the new rule was left, every row
  was kept, the tables stayed 37, a run took 18 milliseconds, and the
  second run changed nothing (one md5 over every constraint, column, index,
  comment and trigger). The service functions were then called as the
  routes call them: a second note on the same account refused, the note on
  the other own account stored, a second one there refused, an account of
  another pod refused, another pod's note on the same transaction stored,
  the database refusing a double by itself, the list with the sent note
  first and in the same order after every note was edited three times, a
  date range, a removed note and the same note made again. The new file
  built from nothing into a second scratch schema gave the same md5 as the
  upgraded one. The two half-way states were run the same way, the code of
  before from `git archive HEAD`. No server was started and no route was
  called over HTTP: the passkey, the session and the proxy are the user's
  run-through.


## 12. Recovery and moderation

Design settled 2026-10-26 (the chat is recorded in
`~/Desktop/Z/forclaude/recovery-and-moderator.md`). This section is the
masterpod's part of the specification for the three recovery builds; the
wallet's part is `~/Desktop/Z/web_app/docs/schemas.md` section 12, and the
build plans are `~/Desktop/Z/forclaude/build-1-case-and-recovery-pod.md`,
`build-2-moderation.md` and `build-3-delivery-and-finish.md`. Nothing above
this section changes except the additive items listed in 12.8. The old
draft's flows 4.6 and 4.7 are superseded by 12.4.5 and 12.4.7.

### 12.1 The flow

1. A locked-out person opens the wallet on any device: Recover account,
   I'm locked out. They type the nine birth-record fields (the lookup id is
   recomputed on the device as `docs/public-ledger-id.md` says; the public
   ledger id is dropped). The wallet asks every keyholder who owns the
   lookup id (keyholder spec section 15, `/get-owner`) and the masterpod
   names the account (`/challenge` openCase, 12.4.2), so the person reads
   the username of the pod found and types none (since 2026-11-08; before
   that they typed it). Since 2026-11-18 that request carries the lookup
   id, and a case already open for it stops the person there (section
   20). Then a contact email and a contact phone, both
   (both required since 2026-11-12, 18.4; the phone came on 2026-11-11,
   section 18, and one of the two was enough then; before that the email
   alone), and they register a passkey. The masterpod opens a
   recovery case and a recovery pod for it (12.4.2). Of the birth record
   only the lookup id reaches the server (since 2026-11-18 already at the
   `/challenge` request, for that one question, not stored); the contact
   email and phone are the plaintext facts about the person the masterpod
   keeps.
2. A moderator (12.2) sees the case, schedules a video call (the meeting
   link shows to the person in the app; the phone is for the moderator to
   text or call first, and the email is there when a text is not
   possible, both by hand, nothing is sent), pulls the
   bucket one key from three keyholders (their moderator routes answer
   synchronously; nothing changes there), reads the case pod's bucket one
   rows (12.4.4) and compares the selfie with the person on the call. A
   mismatch is a dismissal with a preset reason. Then bucket two the same
   way.
3. Two moderators sign off (12.4.4): a verdict signed by pair one of an anos
   account living in the moderator's pod, verified against the account's
   stored creation. Two approvals from two different pods approve the case,
   which then shows the banker packet: lookup id, recovery pod URL, hybrid
   key.
4. Three bankers deliver the backup code shares and the break-glass shares
   to the recovery pod through the keyholders' decrypt routes (keyholder
   spec 5.8 and 5.9); the masterpod stores what arrives (12.4.2,
   `/receive-recovery-share`).
5. The person comes back, unlocks the recovery pod with the passkey, combines
   the shares on the device, proves the backup code to the masterpod, which
   makes the recovery passkey the pod's passkey (12.4.5); unlocks the pod as
   usual; posts a break-glass move out of each old account that holds
   anos, signed with its recovered break-glass seed, and files it here for
   two attestors to sign (section 14, since 2026-11-08; until then it
   stored each seed on its account row); deposits a new backup code with
   the keyholders and then rotates the backup code on the masterpod
   (12.4.5; the deposit first since 2026-11-10,
   `~/Desktop/Z-TestNet/forclaude/recovery-finish-order-plan-1.md`);
   completes the case.

### 12.2 Who is a moderator, and two new levels

A moderator is a pod that holds a live appointment as one: an
`appointments` row with `role = 'moderator'` and no `revoked_at` (section
16). The operator appoints by `npm run appoint` and revokes by `npm run
revoke` (16.3); no route writes the table. The masterpod does not check
the stake; the keyholders do, where the secrets are, on every bucket key
request. Rewritten 2026-11-08 to the appointment rule of section 16; until
then a moderator was a pod whose `username` started with `moderator` and
that a super seed had vouched for, with no table and no script.

| Level | Meaning | Routes |
| ----- | ------- | ------ |
| moderator | session, and the pod holds a live appointment for the role (`appointments`, section 16; the stake is the keyholders' check). `requireModerator` runs `requireSession`, then the query; failing them `403 not a moderator`. | `/list-recovery-cases`, `/get-recovery-case`, `/list-case-security-records`, `/schedule-recovery-case`, `/sign-off-recovery-case`, `/dismiss-recovery-case` |
| recovery | signed by a recovery pod's ephemeral keys (12.4.1). `requireRecoverySession`. | `/get-recovery-pod`, `/complete-recovery-case` |

The other new routes are level none (`/open-recovery-case`,
`/unlock-recovery-pod`, `/recover-with-backup-code`, each signed by the keys
inside it; `/receive-recovery-share/:caseId`, unsigned, from a keyholder) or
setup (`/rotate-backup-code`, `/store-break-glass-blob`).

### 12.3 Tables

Four new tables, one new column, one widened check. DDL into
`db/schema.sql` after `anos_accounts`, in the file's style (header comment,
`COMMENT ON` for every table and column, `set_updated_at` where rows
change, `refuse_change` where they do not). `npm run db:setup` applies all
of it to the live database.

```sql
CREATE TABLE IF NOT EXISTS recovery_cases (
  case_id       BYTEA       PRIMARY KEY CHECK (octet_length(case_id) = 32),
  lookup_id     BYTEA       NOT NULL CHECK (octet_length(lookup_id) = 32),
  anopod_id     BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  contact_email TEXT        CHECK (char_length(contact_email) BETWEEN 3 AND 254 AND position('@' IN contact_email) > 1),
  contact_phone TEXT        CHECK (char_length(contact_phone) BETWEEN 6 AND 32
                              AND contact_phone ~ '^[0-9 +()-]+$'
                              AND char_length(regexp_replace(contact_phone, '[^0-9]', '', 'g')) >= 6),
  status        TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'inReview', 'approved', 'delivering', 'completed', 'dismissed')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT recovery_cases_contact_check CHECK (contact_email IS NOT NULL OR contact_phone IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS recovery_cases_one_open_per_lookup_id ON recovery_cases (lookup_id) WHERE status NOT IN ('completed', 'dismissed');
CREATE INDEX IF NOT EXISTS recovery_cases_anopod_id_idx ON recovery_cases (anopod_id);
CREATE INDEX IF NOT EXISTS recovery_cases_status_created_at_idx ON recovery_cases (status, created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_pods (
  case_id                BYTEA       PRIMARY KEY CHECK (octet_length(case_id) = 32),
  anopod_id              BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  pass_key_credential_id BYTEA       NOT NULL UNIQUE CHECK (octet_length(pass_key_credential_id) BETWEEN 16 AND 1023),
  pass_key_public_key    BYTEA       NOT NULL CHECK (octet_length(pass_key_public_key) <= 1024),
  ephemeral_auth_key     BYTEA       NOT NULL UNIQUE CHECK (octet_length(ephemeral_auth_key) IN (33, 65)),
  ephemeral_auth_key_pq  BYTEA       NOT NULL CHECK (octet_length(ephemeral_auth_key_pq) = 2592),
  ephemeral_expires_at   TIMESTAMPTZ NOT NULL,
  hybrid_key_x25519      BYTEA       NOT NULL CHECK (octet_length(hybrid_key_x25519) = 32),
  hybrid_key_mlkem       BYTEA       NOT NULL CHECK (octet_length(hybrid_key_mlkem) = 1568),
  hybrid_key_blob        BYTEA       NOT NULL CHECK (octet_length(hybrid_key_blob) <= 1024),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS recovery_pods_ephemeral_auth_key_pq_key ON recovery_pods (sha256(ephemeral_auth_key_pq));
CREATE UNIQUE INDEX IF NOT EXISTS recovery_pods_hybrid_key_mlkem_key      ON recovery_pods (sha256(hybrid_key_mlkem));

CREATE TABLE IF NOT EXISTS recovery_shares (
  share_id     BYTEA       PRIMARY KEY CHECK (octet_length(share_id) = 32),
  case_id      BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  keyholder_id SMALLINT    NOT NULL CHECK (keyholder_id BETWEEN 1 AND 99),
  lookup_id    BYTEA       NOT NULL CHECK (octet_length(lookup_id) = 32),
  share_type   TEXT        NOT NULL CHECK (share_type IN ('backupcode', 'breakglasskey')),
  key_id       BYTEA       NOT NULL CHECK (octet_length(key_id) = 32),
  share        BYTEA       NOT NULL CHECK (octet_length(share) = 1661),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (case_id, share_type, key_id, keyholder_id)
);
CREATE INDEX IF NOT EXISTS recovery_shares_case_id_idx ON recovery_shares (case_id);
CREATE OR REPLACE TRIGGER recovery_shares_append_only
  BEFORE UPDATE OR DELETE ON recovery_shares
  FOR EACH ROW EXECUTE FUNCTION refuse_change();

CREATE TABLE IF NOT EXISTS recovery_events (
  event_id   BYTEA       PRIMARY KEY CHECK (octet_length(event_id) = 32),
  case_id    BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  kind       TEXT        NOT NULL CHECK (kind IN (
               'opened', 'scheduled', 'bucketOneViewed', 'bucketTwoViewed',
               'approvalSigned', 'rejectionSigned', 'approved', 'dismissed',
               'shareReceived', 'recovered', 'completed')),
  anopod_id  BYTEA       CHECK (octet_length(anopod_id) = 32),
  details    JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS recovery_events_case_id_created_at_idx ON recovery_events (case_id, created_at);
CREATE OR REPLACE TRIGGER recovery_events_append_only
  BEFORE UPDATE OR DELETE ON recovery_events
  FOR EACH ROW EXECUTE FUNCTION refuse_change();

ALTER TABLE anos_accounts ADD COLUMN IF NOT EXISTS break_glass_blob BYTEA CHECK (octet_length(break_glass_blob) <= 1024);

ALTER TABLE challenges DROP CONSTRAINT IF EXISTS challenges_purpose_check;
ALTER TABLE challenges ADD CONSTRAINT challenges_purpose_check
  CHECK (purpose IN ('create', 'unlock', 'openCase', 'unlockCase', 'recover'));
```

`recovery_cases`: one row per case. `lookup_id` is what the person
recomputed; the public ledger id is never stored. `anopod_id` is the pod the
keyholders named for the lookup id (since 2026-11-08; before, the pod the
typed username named). `status` moves as 12.5 says; the partial unique index
is the one-open-case-per-lookup-id rule. Nothing else about a case is a
column: everything that happens is a `recovery_events` row.
`contact_email` and `contact_phone` are where a moderator can reach the
person, the contact email and the contact phone: an email of 3 to 254
characters with an `@` that is not first, a phone of 6 to 32 characters,
each a digit, a space, `+`, `-` or a round bracket, with at least 6
digits, kept as typed. Both are plain text. Since 2026-11-12 a case is
opened only with both (`/open-recovery-case`, 12.4.2; 18.4). The table
did not change for that: each column still takes a null, and its check is
still at least one of the two (`recovery_cases_contact_check`), because a
database may hold cases of before with one contact. The phone came on
2026-11-11 (section 18); until then
`contact_email` was `NOT NULL` and the only contact. For a live database
the case chat block at the end of `db/schema.sql` adds `contact_phone`,
drops the `NOT NULL` of `contact_email` and drops and adds the check, all
idempotent.

`recovery_pods`: one per case, same key as the case. The recovery passkey
(registered with user handle = `anopod_id`, so it can become the pod's
passkey at the end), the recovery session (ephemeral keys, replaced at
every `/unlock-recovery-pod`), the pod's hybrid public key (what the bankers
encrypt shares to) and `hybrid_key_blob`, the private halves under the
recovery passkey's `KEK_prf` (12.6), which the server cannot open. The same
credential id appears on `anopods` after the finish; the two uniques are
per table.

`recovery_shares`: what the keyholders posted, as posted, 1661 bytes each
(a 33-byte share under the keyholder's hybrid scheme). `share_id` is minted
here; the unique key makes a banker's second send of the same share a
no-op. `recovery_events`: the audit trail; `anopod_id` is the moderator who
acted, null for the person's and the keyholders' events; `details` per
kind in 12.5. `nonces.anopod_id` also holds case ids: a recovery session's
nonces are stored under its case id (update the column comment).

### 12.4 Routes

Conventions of section 5 throughout: every route a `POST`, checks in order,
first failure answers, every multi-row write one transaction. "The case"
is the `recovery_cases` row a route resolved; "the case's pod" is the
`anopods` row `case.anopod_id` names. Case ids and lookup ids are 32-byte
ids on the wire like every id.

#### 12.4.1 The recovery envelope

A recovery request is the section 3 envelope with `caseId` in place of
`anopodId`:

```json
{
  "payload": {
    "caseId":    "<hex 32 bytes>",
    "path":      "/get-recovery-pod",
    "timestamp": "2026-10-26T18:00:00.000Z",
    "nonce":     "<hex 16 bytes>",
    "body":      {}
  },
  "signatures": { "ecdsa": "<hex 64>", "mldsa": "<hex 4627>" }
}
```

`requireRecoverySession` runs the eight checks of section 3 against the
`recovery_pods` row (`401 unknown case` when it is missing), its
`ephemeral_expires_at`, its ephemeral keys, and inserts the nonce under the
case id. On success `req.recoveryPod` is the row, `req.recoveryCase` the
case, `req.body` is `payload.body`.

#### 12.4.2 Level none

**POST /challenge**, three more purposes. `openCase` takes `{ purpose,
anopodId }`, the anoPod id the keyholders named for the person's lookup id
(keyholder spec section 15; until 2026-11-08 it took the username): a
string, else `400 bad request shape`; 32 bytes, else `400 invalid
anopodId`; a pod's id, else `404 unknown anopod`. The challenge row is
bound to that pod and the answer is `200 { challenge, anopodId, username,
expiresAt }`, the id being the user handle the phone registers the
recovery passkey with and `username` the pod row's, so the wallet shows
the account found before any case opens. Since 2026-11-18 (20.2)
`openCase` may take `lookupId` too, the person's lookup id. When the body
has one, each of its three checks stands right after one of `anopodId`'s:
a string, else `400 bad request shape`, after the same check of
`anopodId`; 32 bytes, else `400 invalid lookupId`, after `400 invalid
anopodId`; no case open for it, else `409 case already open`, after `404
unknown anopod`, and then no challenge is issued. The answer also carries
`credentialIds`, the credential ids of the pod's passkeys, the main one
first. `unlockCase` and `recover` take
`{ purpose }` alone and answer without `anopodId`, like `unlock`. The two
existing purposes are untouched.

**POST /open-recovery-case** (signed by the ephemeral keys inside, like
`/create-anopod`):

```json
{
  "payload": {
    "anopodId":           "<hex, from /challenge openCase>",
    "challenge":          "<hex, from /challenge openCase>",
    "lookupId":           "<hex 32>",
    "contactEmail":       "alice@example.com",
    "contactPhone":       "+66 81 234 5678",
    "passkey":            { "...": "the registration PublicKeyCredential.toJSON(), prf.results removed" },
    "hybridKey":          { "x25519": "<hex 32>", "mlkem": "<hex 1568>" },
    "hybridKeyBlob":      "<hex, 124 bytes>",
    "ephemeralAuthKey":   "<hex 33>",
    "ephemeralAuthKeyPq": "<hex 2592>"
  },
  "signatures": { "ecdsa": "<hex>", "mldsa": "<hex>" }
}
```

`contactEmail` and `contactPhone` are both required (2026-11-12, 18.4).
From 2026-11-11 (section 18) until then each was optional and at least
one of the two was given; before that `contactEmail` was required and
there was no `contactPhone`.

Checks:

1. Shape; `400 bad request shape`. `contactEmail` and `contactPhone` are
   each absent, null or a string.
2. The challenge row exists with purpose `openCase`, unexpired, its
   `anopod_id` equals `payload.anopodId`, and a pod with that id exists:
   the pod the keyholders named for the lookup id; else `401 unknown or
   expired challenge`.
3. Both signatures verify against the payload's own ephemeral keys; `401
   bad signature`.
4. `passkey.clientExtensionResults.prf.enabled` true and no `prf.results`;
   `400 passkey without prf`.
5. The registration verifies with the challenge, `RP_ID`, the origins and
   user verification; `401 passkey verification failed`.
6. `lookupId` 32 bytes; then the contact: `contactEmail` or
   `contactPhone` absent or null is
   `400 contactEmail and contactPhone required` (2026-11-12, 18.4; until
   then only both absent or null was refused, with
   `400 contactEmail or contactPhone required`); `contactEmail` 3 to 254
   characters with an `@` not first; `contactPhone` 6 to 32 characters,
   each a digit, a space, `+`, `-` or a round bracket, with at least 6
   digits; then `hybridKey` 32 and 1568 bytes, `hybridKeyBlob` 1 to 1024
   bytes; `400 invalid <field>`.
7. No case for this lookup id is open (status not completed or dismissed);
   `409 case already open`. Asked at `/challenge` already since 2026-11-18
   (20.2); this check stays the rule.
8. Since 2026-11-18 (19.3): the credential id is on no `added_passkeys`
   row; else `409 key already registered`.

Writes: `INSERT INTO recovery_cases` (status `open`; the contact email and
the contact phone, both of them), `INSERT INTO
recovery_pods` (credential id, COSE key, ephemeral keys with
`ephemeral_expires_at = now() + EPHEMERAL_KEY_HOURS`, the hybrid key, the
blob), the `opened` event, the challenge consumed. Since 2026-11-21
(section 25) also the alert to the pod the case is opened for, in the
same transaction: `raiseAlert` with `recoveryCaseOpened`, which writes
the row under the pod's bell and a message for each of its emails and
phones, at most once in 24 hours for one pod (25.5). A unique violation on
the partial index is `409 case already open`; on a key column `409 key
already registered`.

Answer: `201 { caseId, status: "open", ephemeralExpiresAt }`. The recovery
session is open.

**POST /unlock-recovery-pod** (signed by the ephemeral keys inside, like
`/unlock`): payload `{ challenge (purpose unlockCase), assertion,
ephemeralAuthKey, ephemeralAuthKeyPq }`. Checks as `/unlock`, against
`recovery_pods` by `assertion.rawId` (`401 unknown passkey`);
`assertion.response.userHandle` must equal the recovery pod's `anopod_id`
(`401 user handle mismatch`). Writes the new ephemeral keys and consumes
the challenge.

Answer: `200 { caseId, status, hybridKey, hybridKeyBlob, ephemeralExpiresAt
}`. The phone derives `KEK_prf` from the assertion's PRF output and opens
the blob.

**POST /receive-recovery-share/:caseId** (unsigned; the keyholders' decrypt
routes post here, keyholder spec 5.8 and 5.9). Body, as the keyholder
sends it:

```json
{ "keyholderId": 1, "lookupId": "<hex>", "shareType": "backupcode", "keyId": "<hex>", "share": "<hex 1661 bytes>" }
```

Checks: `caseId` decodes and the case exists (`404 unknown case`); status
`approved` or `delivering` (`409 case not accepting shares`); shape,
`keyholderId` an integer 1 to 99, `shareType` one of the two, `keyId` 32
bytes, `share` exactly 1661 bytes (`400 bad request shape`); `lookupId`
equals the case's (`400 lookup id mismatch`).

Writes: `INSERT INTO recovery_shares` (`ON CONFLICT DO NOTHING` on the
unique key), the `shareReceived` event with `{ keyholderId, shareType,
keyId }`, and `status = 'delivering'` when it was `approved`.

Answer: `200 { caseId, keyholderId, shareType, keyId, received: true }`
(`received: false` for a duplicate). This is the `recoveryPod: { status,
body }` the bankers' GUI shows. The masterpod's host must be in every
keyholder's `RECOVERY_POD_HOSTS`.

**POST /recover-with-backup-code** (signed by the backup code keys inside
the payload's proof, level none): the finish. The person has combined the
backup code (12.6).

```json
{
  "payload": {
    "challenge": "<hex, from /challenge recover>",
    "caseId":    "<hex>",
    "newBlob1":  "<hex, 60 bytes>"
  },
  "signatures": { "ecdsa": "<hex>", "mldsa": "<hex>" }
}
```

Checks:

1. Shape; `400 bad request shape`.
2. The challenge row, purpose `recover`, unexpired; `401 unknown or expired
   challenge`.
3. The case exists and its status is `approved` or `delivering`; `404
   unknown case`, `409 case not ready`. The case's pod has setup complete
   (`anopod_encryption_key_blob_2` set); `409 setup not complete`.
4. Both signatures verify over the canonical payload against the case's
   pod's `backup_code_public_key` and `backup_code_public_key_pq`; `401 bad
   signature`. This is the proof of the backup code.
5. `newBlob1` 1 to 1024 bytes; `400 invalid newBlob1`.

Writes, one transaction: the challenge consumed; `UPDATE anopods SET
pass_key_credential_id = <the recovery pod's>, pass_key_public_key = <the
recovery pod's>, anopod_encryption_key_blob_1 = newBlob1,
ephemeral_expires_at = now()` for the case's pod (the lost device's session
dies now; the recovery passkey is the pod's passkey from here); since
2026-11-18 the pod's rows in `added_passkeys` deleted (section 19); the
`recovered` event. A unique violation is `409 key already registered`.

Answer: `200 { anopodId, username, recovered: true }`. The phone then
unlocks the pod through `/challenge` (unlock) and `/unlock` with the same
passkey: `blob1` opens under the same `KEK_prf`.

#### 12.4.3 Level recovery

**POST /get-recovery-pod**. Body `{}`. The person's view of their case.

Answer: `200 { caseId, status, username, contactEmail, contactPhone,
lookupId, anosAccounts, hybridKey, hybridKeyBlob, blob2, events: [ { kind,
details, createdAt } ], shares: [ { shareId, keyholderId, shareType, keyId,
share, receivedAt } ] }`. `contactEmail` and `contactPhone` are each a
string or null (the phone since 2026-11-11, section 18). `anosAccounts`
(2026-11-11, section 18) is a number: how many `anos_accounts` rows the
case's pod made up to the opening of the case. A row counts when its
`created_at` is not after the `created_at` of the case's `recovery_cases`
row (2026-11-12, 18.4; until then every row of the pod's counted). It is
sent in every status, so the wallet's wait page knows how many account
keys to wait for. The accounts that the finish's Move your money makes
are newer than the case and do not count: the bankers' shares in the
case are for the old accounts only. `blob2` is
the case's pod's `anopod_encryption_key_blob_2` (hex) once the status is
`approved` or `delivering`, null before: ciphertext under `KEK_backup`,
worth nothing without the code the bankers are sending here, and what the
finish opens first (12.4.2, `/recover-with-backup-code`). `events`
carries the person's subset only: `scheduled` (`at`, `meetLink`),
`approved`, `dismissed` (`reason` only, no note), `recovered`,
`completed`; never a moderator's id, note or signature. `shares` oldest
first, `share` hex.

**POST /complete-recovery-case**. Body `{}`. Status `approved` or
`delivering`, else `409 case not ready`. Writes `status = 'completed'` and
the `completed` event. Answer: `200 { caseId, status: "completed" }`.

#### 12.4.4 Level moderator

**POST /list-recovery-cases**. Body `{ statuses? }`, a list of statuses;
default `open`, `inReview`, `approved`, `delivering`. Newest first.

Answer: `200 { cases: [ { caseId, status, lookupId, username, firstName,
lastName, contactEmail, contactPhone, approvals, createdAt, updatedAt } ]
}`, `approvals` the count of distinct pods with an `approvalSigned` event;
`contactEmail` and `contactPhone` each a string or null (the phone since
2026-11-11, section 18).

**POST /get-recovery-case**. Body `{ caseId }`; `404 unknown case`.

Answer: `200 { case: { caseId, status, lookupId, contactEmail,
contactPhone, createdAt, updatedAt }, profile, events: [ { eventId, kind,
anopodId, username, details, createdAt } ], shares: [ { keyholderId,
shareType, keyId, receivedAt } ], bankerPacket: { lookupId, url, hybridKey
} }`. `contactEmail` and `contactPhone` are each a string or null, as in
the list. `profile` is
the case's pod's profile with the public selfie (as `/get-anopod-profile`);
`username` on an event is the acting moderator's, null when `anopodId` is
null; `details` complete (notes and signatures included; moderators see
each other's work); `url` is `RECOVERY_POD_URL_BASE +
"/receive-recovery-share/" + caseId`.

**POST /list-case-security-records**. Body `{ caseId, bucket }`, `bucket`
1 or 2. The case's pod's rows of that bucket, the shape of
`/list-security-records` (`images` with `type = bucket`; `info` only for
bucket 2), oldest first. Writes the `bucketOneViewed` or `bucketTwoViewed`
event with `{ keyIds }`, the distinct key ids returned. `404 unknown case`.
The moderator opens the rows with the bucket key the keyholders gave them
for `keyId`; the masterpod cannot.

**POST /schedule-recovery-case**. Body `{ caseId, at, meetLink }`: `at` an
ISO 8601 time, `meetLink` an `https` URL of at most 500 characters. Status
`open` or `inReview` (`409 case closed`). Writes the `scheduled` event with
`{ at, meetLink }` and `status = 'inReview'` when it was `open`. Answer:
`200 { caseId, status }`.

**POST /sign-off-recovery-case**. Body:

```json
{
  "caseId":     "<hex>",
  "accountId":  "<hex>",
  "verdict":    "approve",
  "note":       "Passport and selfie match; called at 14:00 UTC.",
  "signedAt":   "2026-10-26T14:30:00.000Z",
  "signatures": { "ecdsa": "<hex 64>", "mldsa": "<hex 4627>" }
}
```

The signed message is the RFC 8785 canonical JSON of `{ caseId, accountId,
verdict, note, signedAt }`, signed as the account envelope is (P-256 over
the SHA-256 of the bytes, ML-DSA-87 over the bytes). Checks:

1. Shape; `verdict` `approve` or `reject`; `note` 0 to 2000 characters;
   `signedAt` parses; `400 bad request shape`.
2. The case exists (`404 unknown case`) with status `open` or `inReview`
   (`409 case closed`).
3. The `anos_accounts` row `accountId` exists and its `anopod_id` is the
   caller's; else `403 not your account`.
4. Both signatures verify against
   `creation.payload.publicKeys.key1` (P-256) and
   `creation.payload.publicKeys.postQuantumKey1` (ML-DSA-87) of that row;
   `401 bad signature`. (The first time the masterpod verifies an account's
   signature; the validators still verify every anos transaction.)
5. No `approvalSigned` or `rejectionSigned` event on this case by the
   caller's pod; `409 already signed off`.

Writes: the `approvalSigned` or `rejectionSigned` event with `{ accountId,
note, signedAt, signatures }` and the caller as `anopod_id`; `status =
'inReview'` when it was `open`; and when the distinct pods with an
`approvalSigned` event now number two or more, `status = 'approved'` and
the `approved` event. A rejection changes nothing but the event (the
one-approve-one-reject rule is deferred, 12.9).

Answer: `200 { caseId, status, approvals }`.

**POST /dismiss-recovery-case**. Body `{ caseId, reason, note }`: `reason`
one of `selfieMismatch`, `documentsMismatch`, `unknownLookupId`, `noShow`,
`other`; `note` 0 to 2000 characters. Status not `completed` or `dismissed`
(`409 case closed`). Writes `status = 'dismissed'` and the `dismissed`
event with `{ reason, note }`. Answer: `200 { caseId, status: "dismissed"
}`. Final: the person opens a new case if they want another try.

#### 12.4.5 Level setup

**POST /rotate-backup-code** (the old draft's 4.7, adapted). Body:

```json
{
  "newBlob2":                 "<hex, 60 bytes>",
  "newBackupCodePublicKey":   "<hex 33>",
  "newBackupCodePublicKeyPq": "<hex 2592>",
  "proof":                    { "ecdsa": "<hex>", "mldsa": "<hex>" }
}
```

`proof` signs the canonical JSON of `{ anopodId, newBackupCodePublicKey,
newBackupCodePublicKeyPq, newBlob2 }` with the CURRENT backup code keys:
the caller shows it holds the code it is replacing, a session alone is not
enough. Checks: shape and lengths (`400`); the proof verifies against the
row's `backup_code_public_key` and `_pq` (`401 bad signature`). Writes the
three columns. A unique violation is `409 key already registered`. Answer:
`200 { anopodId, rotated: true }`. The phone has deposited the new code's
shares with the keyholders as `backupcode` under a new `keyId` before it
calls this route; the old code's shares stay there and open nothing. That
order is the wallet's since 2026-11-10
(`~/Desktop/Z-TestNet/forclaude/recovery-finish-order-plan-1.md`; wallet
spec 12.3): until then the phone called this route first and deposited
after the answer, and a tab closed between the two, or an answer that got
lost, left a pod whose shares rebuild a code this server no longer holds.
This server's behaviour did not change.

**POST /store-break-glass-blob**. Body `{ accountId, breakGlassBlob }`,
the blob 1 to 1024 bytes (60 in practice, 12.6). The row exists and is the
caller's (`404 unknown account`). Writes `break_glass_blob`; a second call
replaces it. Answer: `200 { accountId, stored: true }`.
`/list-anos-accounts` answers `breakGlassBlob` (hex or null) on every item
from this build on. The wallet stopped calling this route on 2026-11-08
(section 14): the finish uses the recovered seed once, to sign the moves,
and wipes it; the route and `anos_accounts.break_glass_blob` stay, unused.

### 12.5 Statuses and events

```
open        -> inReview    a moderator schedules or signs off
inReview    -> approved    the second distinct approval
approved    -> delivering  the first share arrives
delivering  -> completed   the person completes
any but completed, dismissed -> dismissed   a moderator dismisses
```

`/recover-with-backup-code`, `/receive-recovery-share` and
`/complete-recovery-case` need `approved` or `delivering`.

| kind | by | details |
| ---- | -- | ------- |
| `opened` | the person | `{}` |
| `scheduled` | a moderator | `{ at, meetLink }` |
| `bucketOneViewed`, `bucketTwoViewed` | a moderator | `{ keyIds }` |
| `approvalSigned`, `rejectionSigned` | a moderator | `{ accountId, note, signedAt, signatures }` |
| `approved` | the server | `{}` |
| `dismissed` | a moderator | `{ reason, note }` |
| `shareReceived` | a keyholder | `{ keyholderId, shareType, keyId }` |
| `recovered` | the person | `{}` |
| `completed` | the person | `{}` |

A new duty later is a new kind in the check, not a new column.

### 12.6 Client crypto, new

Section 7's rules hold (AES-256-GCM `iv || ciphertext || tag`, HKDF-SHA-256
with the info strings named). New:

| Thing | How |
| ----- | --- |
| the recovery passkey | registered at case open with the fixed PRF salt and user handle = the pod's `anopod_id`; its PRF output gives `KEK_prf` by section 7's derivation. If the registration returned no PRF output the phone runs one assertion with a random challenge, locally, to get it |
| the recovery hybrid pair | an X25519 pair and ML-KEM-1024 from a random 64-byte seed, as the chat pair; the public halves are `hybridKey` |
| `hybridKeyBlob` | x25519 secret (32) `\|\|` ml-kem seed (64) under `KEK_prf`: 124 bytes |
| a received share | the keyholder's hybrid wire (keyholder spec 7.1), 1661 bytes, opened with the recovery hybrid private key, aad `lookupId \|\| shareType \|\| keyId`; three shares of one `keyId` combine (`shamir-secret-sharing` `combine`) to the 32-byte secret |
| the banker packet | `{ lookupId, url, hybridKey }` as `/get-recovery-case` answers it; the bankers' GUI takes the three |
| a moderator's response key | a fresh hybrid pair per keyholder request; the shares in the keyholder's answer opened with it, same aad; the bucket key opens the rows whose `keyId` matches |
| the sign-off | canonical JSON of `{ caseId, accountId, verdict, note, signedAt }` signed by pair one, opened from the account's `keyBlob` for the one signature |
| the backup code proof | the `/recover-with-backup-code` payload signed by the backup code P-256 and ML-DSA-87 keys of section 7, derived from the combined code |
| the new `blob1` | the encryption key (from `blob2` under `KEK_backup`) under the recovery passkey's `KEK_prf`: 60 bytes |
| `breakGlassBlob` | a 32-byte break-glass seed under the encryption key: 60 bytes. A seed is matched to its account by deriving `breakGlassKey` and `breakGlassPostQuantumKey` (wallet spec 7) and comparing with `creation.payload.publicKeys` |
| the rotation | a new backup code, new `KEK_backup`, new `blob2` and new backup code keys by section 7's rules; first the new code split and deposited as `backupcode` under a new `keyId`, then the proof by the old keys (the deposit first since 2026-11-10, 12.4.5) |

On an authenticator that still holds the pod's passkey, registering the
recovery passkey under the same user handle replaces it (that is how
discoverable credentials behave). A device that still holds the pod's
passkey is not locked out, so this only matters when testing on one
machine: test the person's side in a browser or profile without the pod's
passkey, or accept that the original passkey is gone from that device once
a case is opened.

### 12.7 Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `WEB_ORIGIN` | `http://localhost:4200` | Now a comma-separated list: every web origin, the CORS allow-list and the WebAuthn expected origins. `https://wallet.masterpod.com,https://moderatorwallet.masterpod.com` one day |
| `RECOVERY_POD_URL_BASE` | `http://localhost:3100` | This server as the keyholders reach it; the banker packet's URL is built from it |

### 12.8 Changes to what exists (all additive)

- `db/schema.sql`: the four tables, the `anos_accounts` column, the
  `challenges` check widened, the `nonces.anopod_id` comment.
- `src/config/env.js`: `webOrigins` (a list) in place of `webOrigin`,
  `recoveryPodUrlBase`.
- `src/app.js`: `cors({ origin: env.webOrigins })`; the recovery router
  mounted.
- `src/auth/webauthn.js`: `expectedOrigin: env.webOrigins` (the library
  takes a list).
- `src/auth/auth.handlers.js`: the three purposes; `openCase` reads
  `username`.
- `src/anos-accounts`: `breakGlassBlob` in `/list-anos-accounts`.
- The records in `~/Desktop/Z/masterpod_software_architecture` get the new
  tables, routes, flows and rules; `README.md` the new routes.

Nothing else in existing code changes. The new routes live in
`src/recovery/` (router, handlers, service, the four queries files) with
`src/auth/require-moderator.js` and `src/auth/require-recovery-session.js`.

### 12.9 Deferred, by decision

- One approval and one rejection on a case; a rejection is recorded and
  the case waits for two approvals or a dismissal.
- Revoking a moderator (built 2026-11-08: `npm run revoke`, section 16; the
  stake the pod holds at the validators comes back through the guardians'
  payout); a moderator's record of past cases.
- Sending the meeting link by email; the moderator writes by hand.
- Limits on opening cases; a dispute when a lookup id's one open case is
  not the person's.
- Moving anos with the break-glass keys; this build stores the seeds
  (built 2026-11-08, section 14).
- Notifications for case events; the person opens the app.
- The attestor app.

### 12.10 Notes from the builds

Filled in by each build chat: what was checked, what the spec left open
and how it was decided, anything that differed and why.

#### Build 1, the case and the recovery pod (2026-10-26)

Built straight through from
`~/Desktop/Z/forclaude/build-1-case-and-recovery-pod.md` and checked by
`test/rig-recovery.mjs` (56 checks). What this section left open and how
it was decided:

- The schema block sits at the end of `db/schema.sql`, after
  `anos_accounts`: the DDL of 12.3 with a header comment and a `COMMENT ON`
  for every table and column. The inline check of `challenges.purpose` in
  its `CREATE TABLE` was widened as well, so a fresh database and a live
  one end the same; the `ALTER` after `anos_accounts` is what a live
  database needs. The comments on `challenges.purpose`,
  `challenges.anopod_id` and `nonces.anopod_id` were reworded in place.
  Applied to the rig (the file run twice, to prove it idempotent) and to
  the live `masterpod` database as the superuser with `SET ROLE
  masterpodsoftware`; the four pods and two accounts there were untouched.
- `WEB_ORIGIN` is split on commas, items trimmed, empty items dropped; a
  value with no item is a boot error. `cors` and both WebAuthn wrappers
  take the array. `RECOVERY_POD_URL_BASE` drops a trailing slash.
- `/challenge openCase` lowercases the username before the lookup and
  does not apply the username rule: a name that breaks the rule is simply
  `404 unknown username`. `/open-recovery-case` lowercases
  `payload.username` the same way for its check 2 and answers `401
  unknown or expired challenge` when the username names another pod than
  the challenge's.
- `/get-recovery-pod` answers the `opened` event too (the build plan's rig
  expects it; 12.4.3's list did not name it): the person's subset is
  `opened`, `scheduled` (`at`, `meetLink`), `approved`, `dismissed`
  (`reason`), `recovered`, `completed`, every other detail field dropped.
  `username` is read from the pod's row; `status` on
  `/unlock-recovery-pod` from the case's row.
- The statuses in which `blob2` is handed out, `approved` and
  `delivering`, are one constant in the service, for build 3's share
  route to share.
- `requireRecoverySession` is `requireSession`'s eight steps against
  `recovery_pods` with its own shape check (`caseId`), `401 unknown case`
  for a missing pod or case, the nonce under the case id.
  `signed-request.js` is untouched.
- Reasons for bad values, as the pattern: `400 invalid lookupId`, `invalid
  contactEmail`, `invalid hybridKey` (either half), `invalid
  hybridKeyBlob`.
- The service's private helpers (`ephemeralKeysOf`, `sessionExpiry`,
  `hasEnvelopeShape`, the credential id length) are copied from
  `anopods.service.js` rather than exported from it, to leave that file
  alone.
- The rig: a throwaway `masterpodrig` on 3200, booted with `WEB_ORIGIN`
  listing two origins; a software authenticator that forges a registration
  (`attestationObject` with `fmt: 'none'`, hand-encoded CBOR, so `cbor-x`
  is not needed) and an assertion; a pod with setup complete written
  straight into the database. Checked: the three purposes; every refusal
  of `/open-recovery-case` in order, then the 201, then 409 for the same
  lookup id; the three tables after the write and the challenge consumed;
  `/get-recovery-pod` unsigned, with a pod envelope, for an unknown case,
  a wrong path, signed, replayed; `/unlock-recovery-pod` with the wrong
  user handle, an unknown passkey, the pod's own passkey, an `unlock`
  challenge, a foreign origin, then 200 and the old recovery session
  refused; `blob2` after `UPDATE ... status = 'approved'`; `/create-anopod`
  and `/unlock` unchanged from the first origin; CORS for both origins and
  not a third. Torn down: server stopped, database dropped.
- Not touched: `src/anos-accounts` (`breakGlassBlob` in
  `/list-anos-accounts` comes with the column's writer, build 3).

#### Build 2, moderation (2026-10-26)

Built straight through from `~/Desktop/Z/forclaude/build-2-moderation.md`
and checked by `test/rig-recovery.mjs`, build 1's rig extended in place
(125 checks: build 1's 56 and 69 for this build). No schema change. What
this section left open and how it was decided:

- `requireModerator` is `[requireSession, mustBeModerator]` in
  `src/auth/require-moderator.js`, the super-seed query of 12.2 inline in
  that file (no vouching queries file touched); the username prefix is
  checked first, so a pod that is no moderator costs no query. The six
  routes live in build 1's recovery files; `src/security/`,
  `src/vouching/`, `src/anos-accounts/` and `signed-request.js` are
  untouched: the bucket rows come from `security.queries.js` `listFor`
  filtered by `type` in the recovery service, the account from
  `anos-accounts.queries.js` `findAccount`, the profile from
  `anopods.service.js` `profileWithSelfie`.
- `/list-recovery-cases`: `statuses` absent means the four in-progress
  ones; present, it must be a list of known statuses (`400 bad request
  shape` otherwise) and an empty list answers no cases. The pod's
  username and names come from a LEFT JOIN, null when the row is gone;
  `approvals` is `count(DISTINCT anopod_id)` over `approvalSigned`
  events, so a pod with two accounts cannot approve twice.
- `/get-recovery-case`: a `caseId` that is not a string is `400`, one
  that does not decode or names no case is `404 unknown case`; `profile`
  is null when the pod's row is gone, `bankerPacket.hybridKey` null when
  the recovery pod row is (never, in practice).
- `/list-case-security-records`: `bucket` must be the JSON number 1 or 2
  (the string `"1"` is `400`; the rig caught an `in` check that let it
  through); `info` is answered for both buckets, empty for bucket one;
  the viewed event is written even for an empty bucket (`keyIds: []`);
  there is no status check, so the buckets of a closed case can still be
  read.
- `/schedule-recovery-case`: `at` is any string `Date.parse` understands
  and is stored normalised (`toISOString`); `meetLink` is parsed with
  `new URL`, must be `https:` and at most 500 characters; a second
  schedule on an `inReview` case is allowed and adds a second event.
- `/sign-off-recovery-case`: the message verified is rebuilt from the
  five strings exactly as sent, so the wallet's canonical bytes are
  reproduced; an `accountId` that does not decode is `403 not your
  account` (no account of the caller's has it); the stored `signatures`
  detail holds `ecdsa` and `mldsa` only; `approvals` in the answer is
  the count after the write.
- Every moderator write runs inside `withLockedCase`: one transaction
  that locks the case row (`SELECT ... FOR UPDATE`), re-checks the status
  (and, for a sign-off, the one-sign-off-per-pod rule) under the lock and
  answers `409 case closed` when the status moved meanwhile. The checks
  still run first, outside the transaction, in the spec's order, so the
  first failure answers as 12.4.4 says. The dismissal of an `approved` or
  `delivering` case is allowed, as 12.5 says.
- `insertEvent` stamps `created_at` with `clock_timestamp()` rather than
  the column's `now()` default, so a sign-off and the `approved` event it
  completes, written in one transaction, keep their order.
- The rig: a super seed written into `super_seeds` and three moderator
  pods (`moderatorjoy`, `moderatorsam`, `moderatormax`) vouched straight
  into `vouches` (the vouching routes were exercised by the earlier rig);
  `moderatorjoe` vouched by a plain pod and `rig_alice` vouched by the
  super seed, both `403`; an `anos_accounts` row per moderator whose
  creation names pair-one keys the rig holds, the rest random bytes; a
  selfie and the bucket rows written straight into the tables; the
  server booted with `RECOVERY_POD_URL_BASE` ending in a slash to check
  the drop. Checked, after build 1's checks: the four refusals of the
  level; the list with and without a filter; the case with the profile,
  the selfie, the events and the packet; the schedule's refusals, the
  event and the status; both bucket listings and their viewed events;
  the sign-off's nine refusals in order, approve, the repeat, reject,
  the third moderator's approval making the case `approved` with the
  four events in order; the person's `/get-recovery-pod` showing only
  the person's subset and `blob2`; the dismissal, its event, the repeat,
  the lists, the person's view ending with `dismissed { reason }` and
  `blob2` withheld, and a new case for the freed lookup id. Torn down.
- The user's masterpod on 3100 runs under `npm run dev` (`--watch`) and
  restarted itself on the file changes, so it serves the six routes; no
  variable was added and no DDL was applied.

#### Build 3, delivery, combining and the finish (2026-10-26)

Built straight through from
`~/Desktop/Z/forclaude/build-3-delivery-and-finish.md` and checked by
`test/rig-recovery.mjs`, builds 1 and 2's rig extended in place (220
checks: their 125 and 95 for this build). No schema change, no new
variable. What this section left open and how it was decided:

- The five routes live in build 1's recovery files: the share route and
  the finish beside the person's routes in `recovery.service.js`, the
  shares insert in `recovery-shares.queries.js`, the two anopods writes
  (`adoptRecoveryPasskey`, `replaceBackupCode`) appended to
  `anopods.queries.js`, the break-glass write (`setBreakGlassBlob`, one
  UPDATE on the account id and the caller's pod id, so "not the caller's"
  and "no such account" are one `404`) appended to
  `anos-accounts.queries.js`, whose column list and row mapper gained
  `break_glass_blob`; `/list-anos-accounts` answers `breakGlassBlob` as
  the column in hex, null until stored. `app.js`'s one-line comment on
  the recovery router still names build 1's three paths and was left as
  it is (not on this build's list).
- `/receive-recovery-share/:caseId`: a `lookupId` that is missing or not
  a string is `400 bad request shape` (part of the shape); one that does
  not decode to 32 bytes, or differs from the case's, is `400 lookup id
  mismatch`. The writes run in build 2's `withLockedCase` with the
  approved-or-delivering list (build 1's `BLOB2_STATUSES`), so a
  dismissal racing the first share is seen (`409 case not accepting
  shares` under the lock). A duplicate (the unique key) writes nothing:
  no event, the status untouched, `received: false`. The answer's `keyId`
  is the decoded id as lowercase hex.
- `/recover-with-backup-code`: check 3 reads the pod and the recovery pod
  together; a missing recovery pod row (never, in practice) is `404
  unknown case`. The writes run under the case lock too (`409 case not
  ready` when the status moved), the challenge taken first inside it. The
  proof can be repeated while the case is delivering (another `recovered`
  event, blob1 rewritten): nothing forbids it, and the rotation that
  follows makes the old code worthless anyway. The recovery session is
  left alone, so the person still reads and completes the case with it.
- `/complete-recovery-case` locks the case too and writes the status and
  the event; it does not check that the finish ran (the person's call).
  Nothing ends the recovery session; it expires.
- `/rotate-backup-code`: a field that is not a string is `400 bad request
  shape`, one of the wrong length `400 invalid <field>`; the message is
  rebuilt from the three strings exactly as sent plus the caller's id as
  lowercase hex, so the wallet signs the same bytes. The write is one
  UPDATE in a transaction.
- `/store-break-glass-blob`: `400 invalid accountId` and `400 invalid
  breakGlassBlob` for the values, the pattern of the anos account routes.
- The rig: `makePod` now makes setup with an encryption key and a backup
  code it holds (blob2 under KEK_backup, the backup code keys by section
  7's derivations); `makeAccount` derives the two break-glass keys from a
  seed it holds; `openCase` keeps the hybrid private halves. The person's
  and the keyholders' crypto (X25519, ML-KEM-1024, P-256 and ML-DSA-87
  from `@noble`, `shamir-secret-sharing`, which takes plain `Uint8Array`s,
  not `Buffer`s) is imported from the wallet's `node_modules`
  (`../../web_app/node_modules`, or `RIG_WALLET_MODULES`), since this
  repository has no such dependency and `package.json` was not on the
  list; HKDF and AES-GCM are node:crypto's. Checked, on a new case for
  bob's pod scheduled and approved by two moderators as in build 2: the
  share route's refusals in order (unknown case, open, inReview,
  dismissed, every shape refusal, both lookup id mismatches), the first
  share and `delivering`, the duplicate, the three rows and the three
  events, six break-glass shares, the moderators' and the person's views;
  the shares opened and combined to the code and the seeds, blob2 opened;
  the proof's refusals (unsigned, no caseId, the wrong purpose, unknown
  case, the dismissed case, a wrong code, a changed blob, an empty and an
  oversize blob), then 200 and the anopods row (the recovery pod's
  credential id and COSE key, blob1, the expiry in the past), the event,
  the challenge consumed, the old session `401 session expired`, the old
  passkey `401 unknown passkey`, `/unlock` with the recovery passkey
  answering the new blob1; the break-glass refusals (levels, shape, both
  values, another pod's account, an unknown one), the store, the column,
  the listing, the replace, the second account; the rotation's refusals
  (levels, shape, the three lengths, the wrong keys, the new keys, a
  changed blob), the rotation, the three columns, the old keys refused
  for a rotation and for a proof; the completion, its event, the repeat,
  a share and a proof on the completed case, the person's five events,
  the moderators' lists, the lookup id free again. Torn down.
- The user's masterpod on 3100 runs under `npm run dev` (`--watch`) and
  restarted itself on the file changes, so it serves the five routes; no
  variable was added and no DDL was applied.

#### The lookup through the keyholders (2026-11-08)

Built 2026-11-08 from
`~/Desktop/Z-TestNet/forclaude/recovery-lookup-plan-1.md` (FINAL,
2026-11-08), step 3 of five; the keyholder's `docs/schemas.md` section 15
is the route the wallet asks. The locked-out person no longer types a
username: the wallet computes the lookup id, asks every keyholder
`/get-owner` which pod deposited for it, and brings the anoPod id here.
The masterpod is not in the lookup: it has no standing at the keyholders
and stays unable to link a birth record to a pod, as designed. (Since
2026-11-18, section 20, the wallet sends it the lookup id with the anoPod
id at `/challenge`, for the open case question alone, and it stores
nothing of it.) Where the plan was silent the simplest thing was chosen
and is recorded here.

- `/challenge openCase` takes `{ purpose, anopodId }` and answers the
  pod's `username` beside `anopodId`. In `auth.handlers.js` `findById`
  replaces `findByUsername`, `decodeId` comes from `util/ids.js`, and the
  refusals are `400 bad request shape` (not a string), `400 invalid
  anopodId` (not 32 bytes) and `404 unknown anopod`, the word
  `require-session.js` uses. The pod row is kept in a variable beside the
  id so the username is added to the body after `anopodId`; the body is
  otherwise built as before, so a JSON reader sees `challenge`,
  `expiresAt`, `anopodId`, `username`.
- `/open-recovery-case` drops `username`: the field list of check 1 loses
  it, and check 2 is the challenge row (purpose openCase, unexpired,
  `anopod_id` equal to `payload.anopodId`) and then `findAnopod(anopodId)`
  not null, both `401 unknown or expired challenge` as before.
  `findByUsername` left the import; that check was its only use. The case
  row's `anopod_id` is the challenge's pod, as before; nothing after check
  2 used the pod row.
- `db/schema.sql` changed in comments only: `challenges.anopod_id`, the
  `recovery_cases` block comment, its `COMMENT ON TABLE` and the
  `anopod_id` column, each rewritten within its line, so the file stays
  1283 lines and only its hash changes (the Test Net 2 deploy list notes
  both). `COMMENT ON` overwrites, so `npm run db:setup` applies them to a
  live database.
- 12.3's paragraph under the `recovery_cases` DDL said `anopod_id` "is
  the pod the typed username named"; the plan named the schema comments
  and not that paragraph, so it was fixed on the user's word, in the build
  chat, before the step was committed. The build-1 notes above that
  describe the username lookup stay as history, as the plan says.
- `node --check` passed on the three JavaScript files. Nothing booted, no
  database touched; the wallet's step 4 is the first caller.

## 13. Attestation: assisted trades and escrow disputes

Design settled 2026-10-26 over three rounds of questions (the chat is
recorded in `~/Desktop/Z/forclaude/attestor.md`). This section is the
masterpod's part of the specification for the three attestor builds. The
wallet's part is `~/Desktop/Z/web_app/docs/schemas.md` section 13, the
validators' part `~/Desktop/Z/anossoftware/docs/schemas.md` section 13
(two reads), the keyholders' part
`~/Desktop/Z/keyholdersoftware/docs/schemas.md` section 13 (the stake rule
on the two bucket key routes), and the build plans are
`~/Desktop/Z/forclaude/attestor-build-1-validators-and-keyholders.md`,
`attestor-build-2-masterpod.md` and `attestor-build-3-wallet.md`. Nothing
above this section changes except the additive items listed in 13.8.

### 13.1 The two jobs

An attestor is staff, like a moderator (section 12): a pod of their own, an
anos account in it staked for `attestor` on the validators, and the
attestor edition of the wallet. The validators already give attestors two
jobs (anossoftware spec 4.1, 4.2, 5.2 and 5.6); the masterpod's part is the
case work around them, the checks on the person, and the evidence.

**An assisted trade.** An assisted account spends only with two
attestations on its `assistedAnosTransfer`, which waits in the validators'
`assisted_transfers` table until two attestor-staked accounts have signed
an `attestation` for it. The flow:

1. The attestor's app lists the trades waiting for attestors from a
   validator (anossoftware 13) and shows each sender as a person: the
   masterpod maps the sender's account id to its pod (13.4.3,
   `/list-anos-account-profiles`).
2. An attestor opens a case on a trade (13.4.4, `/open-trade-case`). That
   is the request to the person: a `tradeCaseOpened` notification.
3. The person shares their lookup id (13.4.5, `/share-lookup-id`): the
   wallet opens `identity_blob` in session and posts the 32 bytes. The
   masterpod cannot read the identity blob, and nothing else about the
   person is needed: the buckets are on the masterpod and their keys on the
   keyholders.
4. The attestor pulls the bucket one key from the keyholders by that lookup
   id (keyholder spec 5.3, open to attestor stake from keyholder 13 on),
   reads the sender pod's bucket one rows (13.4.3,
   `/list-trade-case-security-records`), schedules a video call, compares
   the selfie with the person on the call, then bucket two the same way and
   compares the documents. A mismatch is a dismissal with a preset reason;
   the trade stays held on the validators until its sender cancels it.
5. The attestor signs the attestation, the validators' own follow-up
   object, with their staked account; the masterpod verifies it against
   the account's stored creation and records it (13.4.4,
   `/sign-off-trade-case`). A second attestor, from a different pod, reads
   the case and signs too. Two attestations decide the case, and the lookup
   id is cleared from the row.
6. The app of the attestor whose signature decided the case posts both
   stored attestations to a validator (`POST /attestation`, which takes a
   follow-up from any caller since it checks the signatures) and records
   the answers (13.4.4, `/mark-attestor-case-sent`). The trade joins the
   next leader round.

**An escrow dispute.** A seller's `escrowTransfer` waits in
`escrow_transfers`; once one party has signed an `escrowDispute`, only two
agreeing `escrowVerdict`s from attestors move it (anossoftware 5.6). The
flow:

1. The app lists the disputed escrows from a validator (anossoftware 13),
   both parties shown as people.
2. An attestor opens a case (13.4.4, `/open-dispute-case`). Their browser
   makes a hybrid key pair for the case: the public half goes on the case
   row, and the private half goes to every attestor pod, wrapped to each
   one's chat public key the way a room key is (13.6), one row each in
   `escrow_dispute_keys`. Any attestor can then pick the case up. Both
   parties get a `disputeCaseOpened` notification: the request for
   evidence.
3. Each party uploads evidence from their wallet (13.4.5,
   `/add-dispute-evidence`): screenshots and photos of receipts, pictures
   only (no PDFs since 2026-11-12; section 11, the pictures note). Each
   file is encrypted once under a fresh content key; the row carries the
   key twice, under the uploader's pod encryption key (their own copy,
   which stays) and encrypted to the case key (the attestors' copy). A
   party sees only their own files; the attestors see both sides.
4. The attestors open the evidence with the case key (13.4.3,
   `/get-dispute-case`), schedule calls as needed, and each signs a
   verdict, `success` or `cancel`, the validators' own follow-up object,
   verified and recorded by the masterpod (13.4.4,
   `/sign-off-dispute-case`). Two verdicts from different pods that agree
   decide the case; a third attestor may sign while the first two disagree.
5. In the transaction of the deciding signature the masterpod removes the
   case-key copies from every evidence row and deletes every
   `escrow_dispute_keys` row of the case: from then on nobody but the
   uploaders can open the files, and nobody has to remember to delete.
   Then the deciding attestor's app posts the two agreeing verdicts to a
   validator (`POST /escrow-signature`) and records the answers.
6. The person keeps their copy. Supplying a file to a later case is a new
   wrap of its content key to that case's key (13.4.5), not a new upload.

Everything that happens to a case is a row in `attestor_events`, the log of
both kinds of case, never deleted (13.5). The parties hear through
notifications (13.7). An attestor who finds nothing to attest or to decide
dismisses the case (13.4.4); a dismissed case clears its lookup id or its
evidence copies like a decided one.

### 13.2 Who is an attestor, and the new level

An attestor is a pod that holds a live appointment as one: an
`appointments` row with `role = 'attestor'` and no `revoked_at` (section
16), the moderator rule of 12.2 with the other role, the same query. The
operator appoints and revokes by script (16.3); no route writes the
table. The masterpod does not check the stake: the validators do on every
read and every follow-up, and the keyholders on every bucket key request.
A pod has one live appointment at a time (the partial unique index of
16.1), so a pod is a moderator or an attestor, never both. Rewritten
2026-11-08 to the appointment rule of section 16; until then an attestor
was a pod whose `username` started with `attestor` and that a super seed
had vouched for, with no table and no script.

| Level | Meaning | Routes |
| ----- | ------- | ------ |
| attestor | session, and the pod holds a live appointment for the role (`appointments`, section 16; the stake is the validators' and the keyholders' check). `requireAttestor` runs `requireSession`, then the query; failing them `403 not an attestor`. | the fourteen routes of 13.4.3 and 13.4.4, and the seven break-glass routes of 14.4.2 (2026-11-08) |

The person's four routes (13.4.5) are level setup: the person needs their
encryption key, their identity blob and their anos accounts.

### 13.3 Tables

Five new tables and one widened check. DDL into `db/schema.sql` after the
recovery block, in the file's style (header comment, `COMMENT ON` for every
table and column, `set_updated_at` where rows change, `refuse_change` where
they do not). `npm run db:setup` applies all of it to the live database;
the `notifications` check is widened inline in its `CREATE TABLE` as well,
so a fresh database and a live one end the same.

```sql
CREATE TABLE IF NOT EXISTS assisted_trades (
  case_id        BYTEA       PRIMARY KEY CHECK (octet_length(case_id) = 32),
  transaction_id BYTEA       NOT NULL CHECK (octet_length(transaction_id) = 32),
  account_id     BYTEA       NOT NULL CHECK (octet_length(account_id) = 32),
  anopod_id      BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  opened_by      BYTEA       NOT NULL CHECK (octet_length(opened_by) = 32),
  lookup_id      BYTEA       CHECK (octet_length(lookup_id) = 32),
  status         TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'inReview', 'decided', 'dismissed')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS assisted_trades_one_open_per_transaction ON assisted_trades (transaction_id) WHERE status IN ('open', 'inReview');
CREATE INDEX IF NOT EXISTS assisted_trades_anopod_id_idx         ON assisted_trades (anopod_id);
CREATE INDEX IF NOT EXISTS assisted_trades_status_created_at_idx ON assisted_trades (status, created_at DESC);

CREATE TABLE IF NOT EXISTS escrow_disputes (
  case_id         BYTEA       PRIMARY KEY CHECK (octet_length(case_id) = 32),
  transaction_id  BYTEA       NOT NULL CHECK (octet_length(transaction_id) = 32),
  account_id      BYTEA       NOT NULL CHECK (octet_length(account_id) = 32),
  account_id_to   BYTEA       NOT NULL CHECK (octet_length(account_id_to) = 32),
  anopod_id       BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  anopod_id_to    BYTEA       NOT NULL CHECK (octet_length(anopod_id_to) = 32),
  disputed_by     BYTEA       NOT NULL CHECK (octet_length(disputed_by) = 32),
  opened_by       BYTEA       NOT NULL CHECK (octet_length(opened_by) = 32),
  case_key_x25519 BYTEA       NOT NULL CHECK (octet_length(case_key_x25519) = 32),
  case_key_mlkem  BYTEA       NOT NULL CHECK (octet_length(case_key_mlkem) = 1568),
  status          TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'inReview', 'decided', 'dismissed')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS escrow_disputes_one_open_per_transaction ON escrow_disputes (transaction_id) WHERE status IN ('open', 'inReview');
CREATE INDEX IF NOT EXISTS escrow_disputes_anopod_id_idx         ON escrow_disputes (anopod_id);
CREATE INDEX IF NOT EXISTS escrow_disputes_anopod_id_to_idx      ON escrow_disputes (anopod_id_to);
CREATE INDEX IF NOT EXISTS escrow_disputes_status_created_at_idx ON escrow_disputes (status, created_at DESC);

CREATE TABLE IF NOT EXISTS escrow_dispute_keys (
  case_id     BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  anopod_id   BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  wrapped_key BYTEA       NOT NULL CHECK (octet_length(wrapped_key) <= 4096),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, anopod_id)
);

CREATE TABLE IF NOT EXISTS escrow_dispute_evidence (
  evidence_id  BYTEA       PRIMARY KEY CHECK (octet_length(evidence_id) = 32),
  case_id      BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
  file         BYTEA       NOT NULL,
  key_for_me   BYTEA       NOT NULL CHECK (octet_length(key_for_me) = 60),
  key_for_case BYTEA       CHECK (octet_length(key_for_case) = 1660),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS escrow_dispute_evidence_case_id_idx   ON escrow_dispute_evidence (case_id);
CREATE INDEX IF NOT EXISTS escrow_dispute_evidence_anopod_id_idx ON escrow_dispute_evidence (anopod_id);

CREATE TABLE IF NOT EXISTS attestor_events (
  event_id   BYTEA       PRIMARY KEY CHECK (octet_length(event_id) = 32),
  case_id    BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  kind       TEXT        NOT NULL CHECK (kind IN (
               'opened', 'lookupIdShared', 'evidenceAdded', 'scheduled',
               'bucketOneViewed', 'bucketTwoViewed', 'caseKeyShared',
               'attestationSigned', 'verdictSigned', 'decided',
               'lookupIdCleared', 'evidenceDeleted', 'sent', 'dismissed')),
  anopod_id  BYTEA       CHECK (octet_length(anopod_id) = 32),
  details    JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS attestor_events_case_id_created_at_idx ON attestor_events (case_id, created_at);
CREATE OR REPLACE TRIGGER attestor_events_append_only
  BEFORE UPDATE OR DELETE ON attestor_events
  FOR EACH ROW EXECUTE FUNCTION refuse_change();

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('vouchRequest', 'vouchApproved', 'vouchDeclined', 'vouched',
                  'chatInvite', 'inviteAccepted', 'inviteDeclined',
                  'joinRequest', 'joinApproved', 'joinDeclined',
                  'tradeCaseOpened', 'disputeCaseOpened', 'caseScheduled',
                  'caseDecided', 'caseDismissed'));
```

`assisted_trades`: one case per assisted trade. `transaction_id` is the
trade's id on the validators, `account_id` the sender's anos account,
`anopod_id` the pod that made it (from `anos_accounts`), `opened_by` the
attestor pod that opened the case, `lookup_id` what the person shared, null
until then and null again once the case is decided or dismissed. The
partial unique index is the one-open-case-per-trade rule; a dismissed
trade can get a new case. Nothing else about a case is a column: everything
that happens is an `attestor_events` row.

`escrow_disputes`: one case per disputed escrow. `account_id` and
`anopod_id` are the seller and their pod, `account_id_to` and
`anopod_id_to` the buyer and theirs, `disputed_by` whichever of the two
signed the dispute (as the validator reported it), `opened_by` the attestor
pod, `case_key_x25519` and `case_key_mlkem` the public halves of the case
key (13.6). The private halves are never on this row.

`escrow_dispute_keys`: the case's private key wrapped to each attestor
pod's chat public key, exactly as `chat_hpke` holds a room key for a member
(a longer plaintext, so up to 4096 bytes). Written at open for every
attestor and by `/share-case-key` afterwards; every row of a case is
deleted when the case is decided or dismissed.

`escrow_dispute_evidence`: one row per file. `anopod_id` is the uploader,
a party to the case. `file` is the ciphertext under the file's content key,
`key_for_me` that key under the uploader's pod encryption key (60 bytes,
stays for good), `key_for_case` the same key encrypted to the case key
(1660 bytes), set to null when the case is decided or dismissed. The
masterpod can open none of it.

`attestor_events`: the log of both kinds of case, append-only. `anopod_id`
is the acting pod, an attestor or a party; null for the server's own
events. `details` per kind in 13.5.

### 13.4 Routes

#### 13.4.1 Conventions

Conventions of section 5 throughout: every route a `POST`, checks in
order, first failure answers, every multi-row write one transaction.
"The case" is the row a route resolved by `caseId`; the routes that take
either kind (`/schedule-attestor-case`, `/mark-attestor-case-sent`,
`/dismiss-attestor-case`, `/get-my-case`) look in `assisted_trades` first
and then in `escrow_disputes`; a case id names one row in one table, since
ids are 32 random bytes. `404 unknown case` when neither has it. Every
write to a case runs with the row locked (`SELECT ... FOR UPDATE`, as
12.10's `withLockedCase`), re-checking the status under the lock; a status
that moved on meanwhile answers `409 case closed`.

"The parties" of a trade case is the sender's pod; of a dispute case, the
seller's and the buyer's pods. A profile is a pod's profile with its public
selfie, as `/get-anopod-profile` answers it, null when the pod's row is
gone.

Review statuses are `open` and `inReview`; a case in either is open for
work. `decided` and `dismissed` are final.

#### 13.4.2 The sign-off objects

A sign-off is the validators' own follow-up object, built and signed in the
wallet exactly as the account page builds a follow-up today (pair one in
the browser, the wallet pair added by the signing server), posted to the
masterpod first and to a validator once the case is decided:

```json
{
  "payload":    { "type": "attestation", "transactionId": "<hex>", "accountId": "<hex>", "attestorId": "<hex>", "signedAt": "2026-10-26T14:30:00.000Z" },
  "signatures": { "key1": "<hex 64>", "postQuantumKey1": "<hex 4627>", "walletKey": "<hex 64>", "walletPostQuantumKey": "<hex 4627>" }
}
```

and for a dispute `{ "type": "escrowVerdict", "transactionId",
"arbitratorId", "verdict": "success" | "cancel", "signedAt" }` with the
same `signatures`. The masterpod checks a sign-off the way the validators
will (anossoftware spec 5.1, "any two pairs"):

1. `payload` has the kind's fields, every one a string, `signedAt`
   parsing, `verdict` one of the two; `signatures` is an object of hex
   strings under the eight role names of a creation, at least two of the
   three pairs `key1`/`postQuantumKey1`, `key2`/`postQuantumKey2`,
   `walletKey`/`walletPostQuantumKey` present and both halves of every
   present pair; `400 bad request shape`.
2. `payload.transactionId` equals the case's transaction id, and for an
   attestation `payload.accountId` equals the case's `account_id`; `400
   sign-off does not match the case`.
3. The `anos_accounts` row the signer field names (`attestorId` or
   `arbitratorId`) exists and its `anopod_id` is the caller's; `403 not
   your account`. For a verdict the caller's pod is neither party's pod;
   `403 a party to the escrow`.
4. Every present pair verifies over the RFC 8785 canonical bytes of
   `payload` against the matching keys of `creation.payload.publicKeys`
   (P-256 over the SHA-256 of the bytes, ML-DSA-87 over the bytes);
   `401 bad signature`.
5. No `attestationSigned` or `verdictSigned` event on this case by the
   caller's pod; `409 already signed off`.

The masterpod does not check the signer's stake: the validator checked it
when it answered the attestor's read, and checks it again when the object
arrives. The stored object goes into the event whole, so the app can post
it later.

#### 13.4.3 Level attestor, reads

**POST /list-attestors**. Body `{}`. Every attestor pod (13.2) whose setup
is complete, username order.

Answer: `200 { attestors: [ { anopodId, username, firstName, lastName,
chatPublicKey, chatPublicKeyPq } ] }`, the chat keys hex as
`/get-chat-public-keys` answers them. What the opener's app wraps a case
key for.

**POST /list-anos-account-profiles**. Body `{ accountIds }`, 1 to 200 hex
ids (`400 bad request shape`, `400 invalid accountIds`).

Answer: `200 { profiles: [ { accountId, accountType, anopodId, profile } ]
}`, one entry per id in the order given; an id the masterpod does not know
answers `accountType` and `anopodId` null and `profile` null. The lists of
trades and disputes from a validator carry account ids; this turns them
into people.

**POST /list-attestor-cases**. Body `{ statuses? }`, a list of statuses;
default `open`, `inReview`; an empty list answers no cases. Newest first.

Answer: `200 { trades: [ { caseId, transactionId, accountId, status,
username, firstName, lastName, openedBy, signOffs, lookupIdShared,
createdAt, updatedAt } ], disputes: [ { caseId, transactionId, accountId,
accountIdTo, status, seller: { username, firstName, lastName }, buyer: {
username, firstName, lastName }, openedBy, signOffs, evidenceCount,
createdAt, updatedAt } ] }`. `openedBy` is the opening attestor's username;
`signOffs` the count of distinct pods with an `attestationSigned` or
`verdictSigned` event; names come from a LEFT JOIN on `anopods`, null when
the row is gone.

**POST /get-trade-case**. Body `{ caseId }`; `404 unknown case` (also
when the id names a dispute).

Answer: `200 { case: { caseId, transactionId, accountId, anopodId,
openedBy, lookupId, status, createdAt, updatedAt }, profile, events: [ {
eventId, kind, anopodId, username, details, createdAt } ] }`. `lookupId`
hex or null; `profile` the sender's; `username` on an event the acting
pod's, null when `anopodId` is null; `details` complete (notes, objects and
signatures included; attestors see each other's work). The stored
attestations are in the `attestationSigned` events, for the posting after
the decision.

**POST /get-dispute-case**. Body `{ caseId }`; `404 unknown case`.

Answer: `200 { case: { caseId, transactionId, accountId, accountIdTo,
anopodId, anopodIdTo, disputedBy, openedBy, caseKey: { x25519, mlkem },
status, createdAt, updatedAt }, seller, buyer, myKey, keyHolders: [
anopodId ], events: [ as above ], evidence: [ { evidenceId, anopodId,
username, side, contentType, file, keyForCase, createdAt } ] }`. `seller`
and `buyer` are profiles; `myKey` is the caller's `escrow_dispute_keys`
row's `wrappedKey` in hex, null when the caller holds none (then the page
asks a holder to share it; `keyHolders` says who holds one); `evidence` is
every row of the case, oldest first, `side` `seller` or `buyer`, `file`
base64 as stored, `keyForCase` hex or null after the decision. The stored
verdicts are in the `verdictSigned` events.

**POST /list-trade-case-security-records**. Body `{ caseId, bucket }`,
`bucket` the number 1 or 2; `404 unknown case`. The sender pod's rows of
that bucket, the shape of `/list-security-records` (`images` with `type =
bucket`; `info` only for bucket 2), oldest first. Writes the
`bucketOneViewed` or `bucketTwoViewed` event with `{ keyIds }`, the
distinct key ids returned. No status check. The attestor opens the rows
with the bucket key the keyholders gave them for `keyId`; the masterpod
cannot.

#### 13.4.4 Level attestor, writes

**POST /open-trade-case**. Body `{ transactionId, accountId }`, both hex
32 bytes (`400 invalid <field>`). Checks: the `anos_accounts` row
`accountId` exists (`404 unknown account`) and its `account_type` is
`assisted` (`409 not an assisted account`); no open case for this
transaction (`409 case already open`, also on a unique violation).

Writes: the case (`anopod_id` from the account row, `opened_by` the
caller, status `open`), the `opened` event with `{ transactionId,
accountId }`, the `tradeCaseOpened` notification to the sender's pod.

Answer: `201 { caseId, status: "open" }`.

**POST /open-dispute-case**. Body:

```json
{
  "transactionId": "<hex 32>",
  "accountId":     "<hex 32, the seller>",
  "accountIdTo":   "<hex 32, the buyer>",
  "disputedBy":    "<hex 32, one of the two>",
  "caseKey":       { "x25519": "<hex 32>", "mlkem": "<hex 1568>" },
  "keys":          [ { "anopodId": "<hex 32>", "wrappedKey": "<hex, 1725 bytes>" } ]
}
```

Checks: the ids 32 bytes and the two accounts different (`400 invalid
<field>`); both `anos_accounts` rows exist (`404 unknown seller account`,
`404 unknown buyer account`); `disputedBy` is one of the two (`400 invalid
disputedBy`); `caseKey` 32 and 1568 bytes (`400 invalid caseKey`); `keys`
1 to 200 entries, each `anopodId` an attestor pod (13.2) and each
`wrappedKey` 1 to 4096 bytes, no pod twice (`400 invalid keys`); no open
case for this transaction (`409 case already open`).

Writes: the case (`anopod_id` and `anopod_id_to` from the account rows,
`opened_by` the caller), one `escrow_dispute_keys` row per entry of
`keys`, the `opened` event with `{ transactionId, accountId, accountIdTo,
disputedBy, keyHolders }` (the count), the `disputeCaseOpened`
notification to both parties.

Answer: `201 { caseId, status: "open" }`.

**POST /schedule-attestor-case**. Body `{ caseId, at, meetLink }`, either
kind: `at` an ISO 8601 time, `meetLink` an `https` URL of at most 500
characters. Status `open` or `inReview` (`409 case closed`). Writes the
`scheduled` event with `{ at, meetLink }`, `status = 'inReview'` when it
was `open`, the `caseScheduled` notification to the parties. Answer: `200
{ caseId, status }`.

**POST /share-case-key**. Body `{ caseId, anopodId, wrappedKey }`, a
dispute case. Checks: status `open` or `inReview` (`409 case closed`); the
caller holds a key row for the case (`403 no key for this case`);
`anopodId` is an attestor pod (`400 not an attestor`); no row for that pod
yet (`409 key already shared`); `wrappedKey` 1 to 4096 bytes (`400 invalid
wrappedKey`). Writes the row and the `caseKeyShared` event with `{
anopodId }`. Answer: `200 { caseId, anopodId, shared: true }`. For an
attestor appointed after the case was opened.

**POST /sign-off-trade-case**. Body `{ caseId, attestation }`, a trade
case. The case exists (`404 unknown case`) with status `open` or
`inReview` (`409 case closed`); then the five checks of 13.4.2 on
`attestation`.

Writes, under the case lock: the `attestationSigned` event with `{
attestorId, attestation }` (the whole object) and the caller as
`anopod_id`; `status = 'inReview'` when it was `open`; and when the
distinct pods with an `attestationSigned` event now number two or more,
`status = 'decided'`, the `decided` event with `{ attestorIds }`,
`lookup_id = NULL`, the `lookupIdCleared` event, and the `caseDecided`
notification to the sender's pod.

Answer: `200 { caseId, status, signOffs }`, the count after the write.

**POST /sign-off-dispute-case**. Body `{ caseId, verdict }`, a dispute
case; `verdict` the `escrowVerdict` object. The case and its status as
above; the five checks of 13.4.2.

Writes, under the case lock: the `verdictSigned` event with `{
arbitratorId, verdict: "success" | "cancel", object }` (the whole object as
`object`) and the caller as `anopod_id`; `status = 'inReview'` when it was
`open`; and when, for either value, the distinct pods with a
`verdictSigned` event of that value now number two or more, `status =
'decided'`, the `decided` event with `{ verdict, arbitratorIds }`, `UPDATE
escrow_dispute_evidence SET key_for_case = NULL` for the case, `DELETE FROM
escrow_dispute_keys` for the case, the `evidenceDeleted` event with `{
evidence, keys }` (the counts), and the `caseDecided` notification to both
parties.

Answer: `200 { caseId, status, signOffs, decidedVerdict }`, the last null
until decided.

**POST /mark-attestor-case-sent**. Body `{ caseId, validator, results }`,
either kind: `validator` an integer 1 to 99, `results` 1 to 10 entries `{
signer, status, error? }` (`signer` hex 32 bytes, `status` an integer,
`error` a string of at most 500 characters). Status `decided` (`409 case
not decided`). Writes the `sent` event with `{ validator, results }`.
Answer: `200 { caseId, status: "decided" }`. The app calls it after
posting the stored objects to a validator; a failed post is recorded too,
and a later retry writes another event.

**POST /dismiss-attestor-case**. Body `{ caseId, reason, note }`, either
kind: `reason` one of `selfieMismatch`, `documentsMismatch`, `noShow`,
`withdrawn`, `settled`, `other`; `note` 0 to 2000 characters. Status `open`
or `inReview` (`409 case closed`). Writes `status = 'dismissed'`, the
`dismissed` event with `{ reason, note }`, the clearing of a decision
(`lookup_id = NULL` and `lookupIdCleared` for a trade; the `key_for_case`
nulls, the key rows deleted and `evidenceDeleted` for a dispute), and the
`caseDismissed` notification to the parties. Answer: `200 { caseId,
status: "dismissed" }`. Final: another attestor may open a new case on the
same transaction.

#### 13.4.5 Level setup, the person

**POST /list-my-cases**. Body `{}`. The cases where the caller's pod is a
party, newest first.

Answer: `200 { trades: [ { caseId, transactionId, accountId, status,
lookupIdShared, createdAt, updatedAt } ], disputes: [ { caseId,
transactionId, accountId, accountIdTo, side, attestors, status, createdAt,
updatedAt } ] }`, `side` `seller` or `buyer`. `attestors` (2026-11-11,
section 18) is a list of `{ anopodId, username }`, the attestors on the
case: the acting pods of the case's `attestor_events` rows, each once, in
the order they first acted, so the attestor who opened the case comes
first. A pod that is a party to the case is left out, and so is a pod that
holds no live appointment as attestor any more. Every dispute carries it;
a trade case has no such list. It is what the wallet lists under "Invite
an attestor" in the marketplace chat of the trade.

**POST /get-my-case**. Body `{ caseId }`; `404 unknown case`, also when
the caller's pod is not a party.

Answer for a trade: `200 { kind: "trade", case: { caseId, transactionId,
accountId, status, lookupIdShared, createdAt, updatedAt }, events }`. For
a dispute: `200 { kind: "dispute", case: { caseId, transactionId,
accountId, accountIdTo, side, attestors, caseKey, status, createdAt,
updatedAt }, events, evidence: [ { evidenceId, contentType, file, keyForMe,
createdAt } ] }`, the caller's own rows only; `attestors` as in
`/list-my-cases` (2026-11-11). The events still name no attestor; the
case's `attestors` does. `events` is the person's subset of 13.5:
`opened`, `lookupIdShared`, `evidenceAdded` (the caller's own), `scheduled`
(`at`, `meetLink`), `decided` (`{}` for a trade, `{ verdict }` for a
dispute), `lookupIdCleared`, `evidenceDeleted`, `sent` (`{}`), `dismissed`
(`reason` only); never an attestor's id, username, note or signature, never
the other party's events.

**POST /share-lookup-id**. Body `{ caseId, lookupId }`, a trade case of
the caller's pod. Checks: status `open` or `inReview` (`409 case closed`);
`lookup_id` null (`409 lookup id already shared`); `lookupId` 32 bytes
(`400 invalid lookupId`). Writes `lookup_id`, the `lookupIdShared` event
with the caller as `anopod_id`, `status = 'inReview'` when it was `open`.
Answer: `200 { caseId, status }`.

**POST /add-dispute-evidence**. Body `{ caseId, files?, existing? }`, a
dispute case of the caller's pod:

```json
{
  "caseId":   "<hex>",
  "files":    [ { "contentType": "image/jpeg", "file": "<base64 ciphertext>", "keyForMe": "<hex 60 bytes>", "keyForCase": "<hex 1660 bytes>" } ],
  "existing": [ { "evidenceId": "<hex>", "keyForCase": "<hex 1660 bytes>" } ]
}
```

Checks: status `open` or `inReview` (`409 case closed`: once decided the
case key is gone); at least one entry over both lists, `files` up to
`MAX_IMAGES_PER_REQUEST`, `existing` up to 20 (`400 bad request shape`);
each `contentType` one of the three picture types (`image/jpeg`,
`image/png`, `image/webp`; no PDF since 2026-11-12), each `file` base64 of
at most
`MAX_IMAGE_BYTES` decoded, `keyForMe` 60 bytes, `keyForCase` 1660 bytes
(`400 invalid <field>`); each `evidenceId` in `existing` names a row whose
`anopod_id` is the caller's, from any case (`404 unknown evidence`).

Writes, one transaction: one row per file (`anopod_id` the caller); for
each `existing` entry a new row for this case copying `content_type`,
`file` and `key_for_me` from the named row, with the new `keyForCase` (the
server copies; nothing is re-sent); the `evidenceAdded` event with `{
evidenceIds }` and the caller as `anopod_id`; `status = 'inReview'` when
it was `open`.

Answer: `201 { evidenceIds }`, in order, the copies after the files.

### 13.5 Statuses and events

```
open      -> inReview   the person shares the lookup id or adds evidence; an attestor schedules or signs
inReview  -> decided    the second attestation from a different pod; the second agreeing verdict from a different pod
open, inReview -> dismissed   an attestor dismisses
```

`decided` and `dismissed` are final. The deletion of the evidence copies,
the clearing of the lookup id and the posting to a validator are events,
not statuses.

| kind | by | case | details |
| ---- | -- | ---- | ------- |
| `opened` | an attestor | trade | `{ transactionId, accountId }` |
| `opened` | an attestor | dispute | `{ transactionId, accountId, accountIdTo, disputedBy, keyHolders }` |
| `lookupIdShared` | the person | trade | `{}` |
| `evidenceAdded` | a party | dispute | `{ evidenceIds }` |
| `scheduled` | an attestor | both | `{ at, meetLink }` |
| `bucketOneViewed`, `bucketTwoViewed` | an attestor | trade | `{ keyIds }` |
| `caseKeyShared` | an attestor | dispute | `{ anopodId }` |
| `attestationSigned` | an attestor | trade | `{ attestorId, attestation }` |
| `verdictSigned` | an attestor | dispute | `{ arbitratorId, verdict, object }` |
| `decided` | the server | trade | `{ attestorIds }` |
| `decided` | the server | dispute | `{ verdict, arbitratorIds }` |
| `lookupIdCleared` | the server | trade | `{}` |
| `evidenceDeleted` | the server | dispute | `{ evidence, keys }` |
| `sent` | an attestor | both | `{ validator, results }` |
| `dismissed` | an attestor | both | `{ reason, note }` |

Events written in one transaction with another (a sign-off and the
`decided` it completes, `decided` and the clearing) keep their order by
`clock_timestamp()`, as 12.10 says. A new duty later is a new kind in the
check, not a new column.

### 13.6 Client crypto, new

Section 7's rules hold. New:

| Thing | How |
| ----- | --- |
| the case pair | an X25519 pair and ML-KEM-1024 from a random 64-byte seed, as the recovery pair (12.6); the public halves are `caseKey` |
| a wrapped case key | the 96 secret bytes (x25519 secret, then the ml-kem seed) wrapped to an attestor pod's chat public key exactly as a room key is (section 7, `wrapRoomKey`: an ephemeral P-256 pair, ML-KEM-1024 encapsulation, HKDF, AES-GCM), 1725 bytes; opened with that pod's chat keys. The opener wraps one for every attestor pod, itself included |
| a content key | 32 random bytes per file |
| the file | the file's bytes under the content key, AES-256-GCM `iv`, ciphertext, tag, base64 on the wire |
| `keyForMe` | the content key under the uploader's pod encryption key: 60 bytes. Opened at any time by the uploader |
| `keyForCase` | the content key encrypted to the case key as a share is encrypted to a keyholder (`encryptToHybrid`, keyholder spec 7.1), aad = the case id's 32 bytes: 1660 bytes. Opened with the case private key by an attestor who holds it |
| a sign-off | the follow-up object of 13.4.2, signed as the account page signs one today |
| supplying again | the uploader opens `keyForMe`, encrypts the content key to the new case's key, posts it under `existing` |

### 13.7 Notifications

| kind | to | reference_id |
| ---- | -- | ------------ |
| `tradeCaseOpened` | the sender's pod | the case id |
| `disputeCaseOpened` | the seller's and the buyer's pods | the case id |
| `caseScheduled` | the parties | the case id |
| `caseDecided` | the parties | the case id |
| `caseDismissed` | the parties | the case id |

Written inside the event's transaction, as section 6's are. The wallet
polls as today; its notifications page opens the case.

### 13.8 Changes to what exists (all additive)

- `db/schema.sql`: the five tables; the `notifications` check widened
  inline and by `ALTER`.
- `src/app.js`: the attesting router mounted, with its comment line.
- `src/notifications/notifications.queries.js`: the five kinds, only if
  the kinds are listed there as well as in the check.
- `README.md`: the routes and the level. The records in
  `~/Desktop/Z/masterpod_software_architecture` get the tables, routes,
  flows and rules.

Nothing else in existing code changes. New: `src/auth/require-attestor.js`
(the prefix; `vouchedBySuperSeed` imported from `require-moderator.js`),
`src/attesting/` (router, handlers, service, `assisted-trades.queries.js`,
`escrow-disputes.queries.js`, `escrow-dispute-keys.queries.js`,
`escrow-dispute-evidence.queries.js`, `attestor-events.queries.js`, and
`account-signatures.js`, the any-two-pairs rule of 13.4.2 over
`verifySignatures`). The bucket rows come from `security.queries.js`
`listFor`, the accounts from `anos-accounts.queries.js` `findAccount`, the
profiles from `anopods.service.js` `profileWithSelfie`, the chat keys from
`chat.queries.js` `findChatPublicKeys`, the notifications from
`notifications.queries.js` `notify`, as the recovery feature does.

### 13.9 Deferred, by decision

- Revoking an attestor (built 2026-11-08: `npm run revoke`, section 16; the
  stake the pod holds at the validators comes back through the guardians'
  payout); an attestor's history of cases.
- A party deleting or replacing their own evidence; evidence other than
  the three content types or larger than `MAX_IMAGE_BYTES`.
- A time limit on open cases; a case on a trade whose accounts the
  masterpod does not know.
- Sending the meeting link by email; the attestor writes by hand.
- Notifications for bucket views and key shares; the person sees the
  timeline.
- Paging on the lists; the holding tables and the staff are small.

### 13.10 Notes from the builds

Filled in by the build chat: what was checked, what the spec left open and
how it was decided, anything that differed and why.

#### Build 2, the masterpod (2026-10-26)

Built straight through from `~/Desktop/Z/forclaude/attestor-build-2-masterpod.md`
and checked by `test/rig-attesting.mjs` (217 checks). The schema was
applied to the live `masterpod` database as the superuser with `SET ROLE
masterpodsoftware` (the whole file, idempotent); the six pods, five
accounts and fourteen notifications there were untouched, the five new
tables are empty. The user's masterpod on 3100 runs under `npm run dev`
(`--watch`) and restarted itself on the file changes, so it serves the
eighteen routes; no variable was added. What this section left open and
how it was decided:

- The schema block sits at the end of `db/schema.sql`, after the recovery
  block: the DDL of 13.3 with a header comment, a `COMMENT ON` for every
  table and column, `set_updated_at` on the three tables whose rows change
  and `refuse_change` on `attestor_events`; `escrow_dispute_keys` has
  neither (its rows are deleted, never changed). The `notifications` check
  was widened inline in its `CREATE TABLE` and by the `ALTER` pair, and
  the comments on `notifications.kind` and `notifications.reference_id`
  were reworded in place to name the five kinds and the case id; the
  file's header comment now says the recovery and attestation blocks hold
  the only `ALTER`s. The rig runs the file twice on its fresh database to
  prove it idempotent.
- `src/notifications/notifications.queries.js` was not changed: the check
  in the schema is the only list of kinds (its comment says "one of the
  ten kinds of spec section 6" and was left alone, that file not being on
  the list).
- `requireAttestor` is `[requireSession, mustBeAttestor]` in
  `src/auth/require-attestor.js`, `vouchedBySuperSeed` imported from
  `require-moderator.js`, the prefix checked first. The same file holds
  the two queries of the attestor rule asked about other pods:
  `isAttestorPod(anopodId)` (prefix and vouch in one `EXISTS`, used by
  `/open-dispute-case` for every `keys` entry and by `/share-case-key` for
  the target) and `listAttestorPods()` (the attestor pods with setup
  complete, username order), so no existing queries file was touched;
  `/list-attestors` adds the chat keys from `chat.queries.js`
  `findChatPublicKeys`. Neither query requires setup for the rule itself;
  `/list-attestors` filters on it because a case key can only be wrapped
  to a pod with chat keys.
- `src/attesting/account-signatures.js` is the validators'
  `verifyAccountSignatures` recast for a stored creation: `SIGNING_PAIRS`
  names the three pairs by their creation role names,
  `hasAccountSignatureShape` is check 1 of 13.4.2 (fields only under the
  eight role names, every value a string, at least two pairs, both halves
  of each), `verifyAccountSignatures` is check 4 (every present pair over
  the canonical bytes of the payload as received, against
  `creation.payload.publicKeys`; a key or signature that does not decode
  is `401 bad signature`). A `breakGlassKey` signature is accepted by the
  shape and ignored by the verification, as the validators ignore it.
- The sign-off's `payload.type` must be `attestation` or `escrowVerdict`
  for its route (part of "the kind's fields"); the signer id and the
  transaction id are compared as decoded bytes, so hex case and base64 do
  not matter. The `attestorId` / `arbitratorId` stored beside the object
  is the account id as lowercase hex; the object itself is stored exactly
  as sent.
- `withLockedCase` takes the kind's `lockById`, so one helper serves both
  tables; the routes that take either kind look in `assisted_trades`
  first, then `escrow_disputes`. The notifications are written inside the
  same transactions. A dispute whose seller and buyer are two accounts of
  one pod has one party: one notification, `side` seller.
- `/list-anos-account-profiles`: ids that are not strings, or none, or
  more than 200, are `400 bad request shape`; one that does not decode is
  `400 invalid accountIds`; a pod with several accounts is read once per
  call.
- `/open-dispute-case`: two equal accounts answer `400 invalid
  accountIdTo`; the `keys` check runs after `caseKey`, in the spec's
  order, and every entry's pod is checked with `isAttestorPod` (a pod
  named `attestor...` without the vouch is refused). The opened event's
  ids are lowercase hex of the decoded bytes.
- The sign-offs: `signOffs` in both answers is the count of distinct pods
  with a sign-off event of the case's kind, either verdict value for a
  dispute, as the lists define it; the decision for a dispute counts the
  caller's value only (the other value cannot have changed). The `decided`
  event's `attestorIds` / `arbitratorIds` are the signers' account ids
  from the stored events, in event order, the deciding value's only for a
  dispute.
- The clearing: `lookupIdCleared` is written on every trade decision and
  dismissal, even when no lookup id was ever shared, as 13.4.4 reads;
  `evidenceDeleted`'s `evidence` is the rows whose `key_for_case` was
  non-null and is now null, `keys` the key rows deleted.
- `/mark-attestor-case-sent` normalises each `signer` to lowercase hex and
  stores `error` only when sent; the write runs under the case lock like
  every other, with `decided` the only status admitted.
- `/get-my-case`: `evidenceAdded` keeps `evidenceIds` (the caller's own
  ids, filtered to the caller's own events); `decided` keeps `verdict`
  alone, so a trade's reads `{}` and a dispute's `{ verdict }`; `opened`,
  `lookupIdShared`, `lookupIdCleared`, `evidenceDeleted` and `sent` read
  `{}`; the events carry `kind`, `details`, `createdAt` only, as
  `/get-recovery-pod`'s do. A case the caller is no party to is `404
  unknown case` on every person route, `/share-lookup-id` and
  `/add-dispute-evidence` included.
- `/add-dispute-evidence`: `files` and `existing`, when present, must be
  lists (`400 bad request shape` before the case is looked up); the file
  is decoded with `decodeBase64` of `util/images.js` to at most
  `MAX_IMAGE_BYTES` (the ciphertext, so the plaintext is 28 bytes
  smaller); a copy is one `INSERT ... SELECT` on the source row, which
  must be the caller's. The field refusals are `400 invalid contentType`,
  `invalid file`, `invalid keyForMe`, `invalid keyForCase`.
- The rig: `test/rig-attesting.mjs`, `rig-recovery.mjs`'s machinery with
  pods that hold their chat keys and encryption key (noble P-256 and
  ML-KEM from the wallet's `node_modules`) and accounts whose creations
  name pair one and the wallet pair as keys the rig holds; the rig wraps
  the case pair as `wrapRoomKey` does (1725 bytes), encrypts a content key
  to the case key as `encryptToHybrid` does with the case id as aad (1660
  bytes), and signs the follow-ups with two pairs as the wallet does.
  Checked, in order: the level's refusals (unsigned, the name without the
  vouch, a moderator, a plain pod, the super seed, the level before any
  other check, the setup level for the person); `/list-attestors`;
  `/list-anos-account-profiles`; a trade case: the open refusals, the open,
  the row, the event and the notification, the repeat, both lists and
  the case, the person's list and view, the lookup id (the refusals, the
  share, the repeat), the schedule, both bucket listings and their
  events, the sign-off's fourteen refusals in the spec's order, joy's
  attestation, the repeat, sam's deciding one with the four events, the
  cleared row and the notification, max's `409 case closed`, the sent
  refusals, the posting and a retry, the attestors' and the person's
  views; a second trade dismissed (`selfieMismatch`, the clearing, the
  notification, the person's view) and reopened; a dispute: the open
  refusals, the open with three wraps (the rows, the event, both
  notifications), the lists, the case for joy with `myKey` opened to the
  case secret, a fourth attestor's view without a key, `/share-case-key`'s
  refusals and the share, evidence (the refusals, two files by sue and one
  by ben, both wraps opened to the same content key and the file, both
  parties' views), a second dispute with a file supplied again under
  `existing` (the copied row, the new wrap opened), the schedule, the
  verdict refusals (a party's own escrow among them, on a third case),
  joy success, sam cancel, max success deciding it with `evidenceDeleted
  { evidence: 3, keys: 4 }`, the late upload, verdict and share, the
  posting, the attestors' and the parties' views; the third dispute
  dismissed with `settled` and the clearing; the append-only trigger; the
  five notification kinds. Torn down: server stopped, database dropped.
- Not touched: `src/recovery/`, `src/security/`, `src/vouching/`,
  `src/anos-accounts/`, `src/chat/`, `signed-request.js`, the moderator
  routes. The validators and the keyholders are build 1's, unchanged.

## 14. Break-glass moves

Design settled 2026-11-08 in a planning chat of five rounds (the plan is
`~/Desktop/Z-TestNet/forclaude/break-glass-plan-1.md`, FINAL). Why: the
key blobs of a pod's anos accounts were wrapped under the anoPod encryption
key, which the backup code also opens, so whoever rebuilt a backup code held
the original signing keys, and the recovery of 2026-10-26 handed a
recovered person exactly those keys back while the break-glass seed
deposited for this very case went unused. From 2026-11-08 the wallet wraps
the signing keys under a key from the passkey's PRF output alone, so a lost
passkey kills the old accounts' keys for good, and the break-glass key is
what moves the money: a new ledger transaction type, `breakGlassTransfer`,
signed by the account's break-glass pair alone and attested by two
attestors like an assisted transfer, from each old account to a new account
of the same type. Four repos in order: the validator (anossoftware spec
section 22), the doorman (its section 5), this server (this section, step 3
of the plan) and the wallet (its section 11); deployed after a reset of the
testnet with a fresh genesis, the wallet last. This section is the
masterpod's part: the break-glass cases the attestors work from, a case per
recovery case with one row per move, filed by the wallet at the finish and
listed to the attestor edition beside the trades. Nothing above this
section changes except the items in 14.8.

### 14.1 The flow

1. The finish of a recovery (12.4.2 and 12.4.5: after
   `/recover-with-backup-code`, before the rotation and the completion)
   reads each old account from a validator with the recovered break-glass
   pair: a move already held for it, and its balance. It makes a new
   account of the same type for each old account that holds anos (12.4.5's
   `/store-break-glass-blob` is not called any more), posts a
   `breakGlassTransfer` per account to a validator, signed by the
   break-glass pair alone, and files each move here with a call of its own
   as soon as the move is on the validators (14.4.1,
   `/file-break-glass-moves`): the recovery case's id and the move's old
   account, new account and transaction id. A move the finish finds
   already held on a validator (an earlier run posted it and its filing
   never arrived here) is filed as it stands there, and no new account is
   made for it. The break-glass case is the recovery case seen by the
   attestors; every call adds its move to it. The seed is wiped; nothing
   of it is stored here. The order and the filing are the wallet's since
   2026-11-10
   (`~/Desktop/Z-TestNet/forclaude/recovery-finish-order-plan-1.md`;
   wallet spec 12.3): until then the moves were made after the rotation
   and filed in one call at the end of a run, so a run that stopped half
   way left moves on the validators that no attestor was shown.
2. The attestor edition lists the break-glass cases beside the trades
   (14.4.2, `/list-break-glass-cases`) and opens one
   (`/get-break-glass-case`): the person's profile with the selfie, the
   recovery case's lookup id and its two moderator approvals, the moves and
   the events. The amounts and the stage of each move come from a
   validator's `/list-assisted-transfers`, which answers `type` since
   2026-11-08 (anossoftware 13.2).
3. The attestor pulls the bucket keys from the keyholders by the lookup id,
   as for a trade, reads the buckets (`/list-break-glass-case-security-records`),
   schedules a video call (`/schedule-break-glass-case`) and checks the
   person once more. A mismatch is a dismissal with a preset reason
   (`/dismiss-break-glass-case`); the held moves stay on the ledger until a
   cancel (14.9).
4. The attestor signs one attestation per move, the validators' own
   follow-up object (13.4.2), in one tap, and posts them together
   (`/sign-off-break-glass-case`); the masterpod verifies each against the
   attestor's stored creation and records them. A second attestor, from a
   different pod, does the same; two sign-offs decide the case.
5. The app of the attestor whose sign-off decided the case posts both
   attestors' stored attestations, two per move, to a validator and records
   the answers (`/mark-break-glass-case-sent`). The validators write each
   move once both attestations are approved, no cancel is present and its
   unlock moment has passed; the sender's stakes row moves with the money
   (anossoftware 4.5).
6. The person's wallet reads the case's progress from
   `/list-my-break-glass-moves`: the lost account's card shows it. One
   notification is sent, when an attestor sets up the video call (14.7,
   since 2026-11-11; until then none).

### 14.2 Who

The person at level setup (section 2): after the finish they hold their
pod's session again (the recovery passkey is the pod's passkey from
`/recover-with-backup-code` on) and setup is complete. The attestors at
level attestor (13.2): the same pods and the same `requireAttestor`; the
masterpod does not check the stake, the validators do on every read and
every follow-up, and the keyholders on every bucket key request.

| Level | Routes |
| ----- | ------ |
| setup | `/file-break-glass-moves`, `/list-my-break-glass-moves` |
| attestor | `/list-break-glass-cases`, `/get-break-glass-case`, `/list-break-glass-case-security-records`, `/schedule-break-glass-case`, `/sign-off-break-glass-case`, `/mark-break-glass-case-sent`, `/dismiss-break-glass-case` |

### 14.3 Tables

Two new tables, no new column, no widened check. DDL into `db/schema.sql`
after the wallet memory block, in the file's style (header comment,
`COMMENT ON` for every table and column, `set_updated_at` on the cases,
`refuse_change` on the moves). The whole file, idempotent, applies it to
the live database (13.10).

```sql
CREATE TABLE IF NOT EXISTS break_glass_cases (
  case_id    BYTEA       PRIMARY KEY CHECK (octet_length(case_id) = 32),
  anopod_id  BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  status     TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'inReview', 'decided', 'dismissed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS break_glass_cases_status_created_at_idx ON break_glass_cases (status, created_at DESC);

CREATE TABLE IF NOT EXISTS break_glass_moves (
  transaction_id BYTEA       PRIMARY KEY CHECK (octet_length(transaction_id) = 32),
  case_id        BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  account_id     BYTEA       NOT NULL CHECK (octet_length(account_id) = 32),
  account_id_to  BYTEA       NOT NULL CHECK (octet_length(account_id_to) = 32),
  account_type   TEXT        NOT NULL CHECK (account_type IN ('spending', 'guarded', 'vault', 'assisted')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS break_glass_moves_case_id_idx ON break_glass_moves (case_id);
CREATE OR REPLACE TRIGGER break_glass_moves_append_only
  BEFORE UPDATE OR DELETE ON break_glass_moves
  FOR EACH ROW EXECUTE FUNCTION refuse_change();
```

`break_glass_cases`: one row per recovery case whose finish filed moves.
`case_id` is the recovery case's id (`recovery_cases.case_id`): a
break-glass case is the recovery case seen by the attestors, and the
recovery case's lookup id and approvals are read from its own tables.
`anopod_id` is the recovered pod (`recovery_cases.anopod_id`), the caller
of the filing. `status` moves as 14.5 says, the statuses of a trade case.
Nothing else about a case is a column: everything that happens is an
`attestor_events` row with that `case_id`, the kinds `scheduled`,
`bucketOneViewed`, `bucketTwoViewed`, `attestationSigned`, `decided`,
`sent` and `dismissed`, which the column's check already allows; `opened`
records the filing. As trades and disputes already share that log, a case
id names one row in one of three tables.

`break_glass_moves`: one row per move, append-only. `transaction_id` is the
`breakGlassTransfer`'s id on the validators and the key: one move per
transaction, so a second filing of the same transaction is refused.
`account_id` is the old account, `account_id_to` the new one, both
`anos_accounts` rows of the pod's, `account_type` the type both have,
checked at filing (the validators check it again). No foreign keys, as
everywhere.

### 14.4 Routes

Conventions of section 5 throughout: every route a `POST`, checks in
order, first failure answers, every multi-row write one transaction. "The
case" is the `break_glass_cases` row a route resolved by `caseId`; "the
recovery case" the `recovery_cases` row of the same id; "the case's pod"
the `anopods` row `case.anopod_id` names. Every write to a case runs with
the row locked (`SELECT ... FOR UPDATE`, as 12.10's `withLockedCase`),
re-checking the status under the lock; a status that moved on meanwhile
answers `409 case closed` (`409 case not decided` on the sent route). The
filing locks the row too, right after inserting it when it is new. Review
statuses are `open` and `inReview`; `decided` and `dismissed` are final. A
profile is a pod's profile with its public selfie, as `/get-anopod-profile`
answers it, null when the pod's row is gone.

#### 14.4.1 Level setup, the person

**POST /file-break-glass-moves**. Body:

```json
{
  "caseId": "<hex 32, the recovery case>",
  "moves":  [ { "accountId": "<hex 32, the old account>", "accountIdTo": "<hex 32, the new account>", "transactionId": "<hex 32, the breakGlassTransfer>" } ]
}
```

1 to 20 moves. Checks:

1. Shape: `caseId` a string, `moves` a list of 1 to 20 objects each with
   the three strings; `400 bad request shape`. Then every id decodes to 32
   bytes: `400 invalid caseId`, and per move `400 invalid accountId`,
   `invalid accountIdTo`, `invalid transactionId`, in that order.
2. The recovery case exists and its `anopod_id` is the caller's; `404
   unknown case`. Its status is `delivering` or `completed`; `409 case not
   ready`.
3. For each move, in order: both `anos_accounts` rows exist and belong to
   the caller's pod (`404 unknown account`); the two differ (`400 same
   account`); their `account_type` is equal (`400 account types differ`);
   no move with this `transactionId` yet (`409 move already filed`, also
   on a unique violation at the write).

Writes, one transaction with the case row locked: the `break_glass_cases`
row if none (status `open`), the moves with the shared `account_type`, the
`opened` attestor event with `{ moves }` (the count in this call) and the
caller as `anopod_id`.

Answer: `201 { caseId, status, moves }`, `status` the case's and `moves`
the count now on the case. A second call for the same case adds moves: the
wallet calls it once per move, as soon as that move is on the validators,
so each call carries one move and writes one `opened` event. That is the
wallet's since 2026-11-10
(`~/Desktop/Z-TestNet/forclaude/recovery-finish-order-plan-1.md`): until
then it called once per finish with the moves of the run, and again on
Retry for the moves that failed. The route takes 1 to 20 moves as before.
The break-glass case's own status is not checked: a later filing adds to
a case under review as to a fresh one.

**POST /list-my-break-glass-moves**. Body `{}`. The caller's break-glass
cases, newest first, each with its moves and the person's subset of the
events. What the lost account's card reads.

Answer: `200 { cases: [ { caseId, status, signOffs, moves: [ { accountId,
accountIdTo, transactionId, accountType, createdAt } ], events: [ { kind,
details, createdAt } ], createdAt, updatedAt } ] }`. `signOffs` is the
count of distinct pods that signed; `moves` are in account order; `events`
carries `scheduled` (`at`, `meetLink`), `decided` (`{}`), `sent` (`{}`) and
`dismissed` (`reason` only), never an attestor's id, note or signature,
and not the filing, the bucket views or the sign-offs themselves.

#### 14.4.2 Level attestor

**POST /list-break-glass-cases**. Body `{ statuses? }`, a list of statuses;
default `open`, `inReview`; an empty list answers no cases; a status that
is not one of the four is `400 bad request shape`. Newest first.

Answer: `200 { cases: [ { caseId, status, username, firstName, lastName,
signOffs, moves: [ { accountId, accountIdTo, transactionId, accountType }
], createdAt, updatedAt } ] }`. The names come from a LEFT JOIN on
`anopods`, null when the row is gone; `signOffs` is the count of distinct
pods with an `attestationSigned` event on the case; `moves` are in account
order.

**POST /get-break-glass-case**. Body `{ caseId }`; `404 unknown case`.

Answer: `200 { case: { caseId, status, lookupId, recoveryStatus, approvals:
[ { username, signedAt } ], createdAt, updatedAt }, profile, moves: [ {
accountId, accountIdTo, transactionId, accountType, createdAt } ], events:
[ { eventId, kind, anopodId, username, details, createdAt } ] }`.
`lookupId` and `recoveryStatus` are the recovery case's (null when its row
is gone, never in practice); `approvals` are the `approvalSigned` recovery
events in time order, each with the moderator's username (a LEFT JOIN, null
when the pod's row is gone) and `signedAt` from the event's details;
`profile` is the case's pod's with the public selfie; `events` are the
attestor events of this case with the acting pod's username and the
details complete, as `/get-trade-case` answers them: the stored attestations
are in the `attestationSigned` events, for the posting after the decision.

**POST /list-break-glass-case-security-records**. Body `{ caseId, bucket }`,
`bucket` the number 1 or 2; `404 unknown case`. The case's pod's rows of
that bucket, the shape of `/list-trade-case-security-records` (`images`
with `type = bucket`; `info` only for bucket 2), oldest first. Writes the
`bucketOneViewed` or `bucketTwoViewed` attestor event with `{ keyIds }`, the
distinct key ids returned. No status check. The attestor pulls the bucket
keys from the keyholders by the case's `lookupId`, as for a trade; the
masterpod cannot open the rows.

**POST /schedule-break-glass-case**. Body `{ caseId, at, meetLink }` as
`/schedule-attestor-case`: `at` an ISO 8601 time, `meetLink` an `https` URL
of at most 500 characters. Status `open` or `inReview` (`409 case closed`).
Writes, under the case lock: the `scheduled` event with `{ at, meetLink }`,
then one notification to the case's pod, the recovered pod, kind
`recoveryCaseScheduled`, reference the case id (2026-11-11, 14.7 and
section 18; until then no notification), and `status = 'inReview'` when it
was `open`. Answer: `200 { caseId, status }`. The person's wallet reads
the event itself from `/list-my-break-glass-moves`.

**POST /sign-off-break-glass-case**. Body:

```json
{
  "caseId":       "<hex>",
  "attestations": [ { "transactionId": "<hex 32>", "attestation": { "payload": { "type": "attestation", "transactionId": "<hex>", "accountId": "<hex>", "attestorId": "<hex>", "signedAt": "..." }, "signatures": { "...": "as 13.4.2" } } } ]
}
```

One attestation per move of the case, each the validators' attestation
follow-up as it stands (13.4.2; anossoftware 5.2): `transactionId` and
`accountId` the move's, `attestorId` the attestor's account, signed by that
account's keys under any two pairs. Checks:

1. Shape: `caseId` a string, `attestations` a list of 1 to 20 objects each
   with a string `transactionId`; `400 bad request shape`.
2. The case exists (`404 unknown case`) with status `open` or `inReview`
   (`409 case closed`).
3. The list names every move of the case exactly once and nothing else: a
   `transactionId` that does not decode, names no move of the case or is
   named twice, or a move left out, is `400 attestations do not match the
   moves`.
4. Each `attestation`, in move order, passes checks 1 to 4 of 13.4.2
   against its move: the shape (`400 bad request shape`); `payload.type`
   `attestation`; `payload.transactionId` and `payload.accountId` the
   move's transaction and old account (`400 sign-off does not match the
   case`); `attestorId` an `anos_accounts` row of the caller's pod (`403
   not your account`); the signatures against that row's creation keys
   (`401 bad signature`). The same `attestorId` on all; a second one is
   `400 attestations differ in attestorId`.
5. No `attestationSigned` event on this case by the caller's pod; `409
   already signed off`.

Writes, under the case lock: the `attestationSigned` event with `{
attestorId, attestations }` (the attestor's account id as hex; the whole
follow-up objects, in move order) and the caller as `anopod_id`; `status =
'inReview'` when it was `open`; and when the distinct pods with an
`attestationSigned` event now number two or more, `status = 'decided'` and
the `decided` event with `{ attestorIds }`, the signers' account ids from
the stored events in event order.

Answer: `200 { caseId, status, signOffs }`, the count after the write.

**POST /mark-break-glass-case-sent**. Body `{ caseId, validator, results }`
as `/mark-attestor-case-sent`: `validator` an integer 1 to 99, `results` 1
to 40 entries `{ signer, status, error? }` (two attestations per move;
`signer` hex 32 bytes, `status` an integer, `error` a string of at most 500
characters). Status `decided` (`409 case not decided`). Writes the `sent`
event with `{ validator, results }`. Answer: `200 { caseId, status:
"decided" }`. A failed post is recorded too; a later retry writes another
event.

**POST /dismiss-break-glass-case**. Body `{ caseId, reason, note }`,
`reason` one of `selfieMismatch`, `documentsMismatch`, `noShow`,
`withdrawn`, `other`; `note` 0 to 2000 characters. Status `open` or
`inReview` (`409 case closed`). Writes `status = 'dismissed'` and the
`dismissed` event with `{ reason, note }`. Answer: `200 { caseId, status:
"dismissed" }`. Final. Nothing is cleared (the lookup id is the recovery
case's) and nothing happens on the ledger: the held moves stay until a
cancel, which the plan leaves to the later dispute work (its decisions 8
and 11; 14.9).

### 14.5 Statuses and events

```
open      -> inReview   an attestor schedules or signs off
inReview  -> decided    the second sign-off from a different pod
open, inReview -> dismissed   an attestor dismisses
```

The statuses of a trade case (13.5). `decided` and `dismissed` are final;
the posting to a validator is an event, not a status. The recovery case's
own status (12.5) is not touched by anything here; a filing needs it to be
`delivering` or `completed`.

| kind | by | details |
| ---- | -- | ------- |
| `opened` | the person | `{ moves }`, the count filed in that call; a Retry writes a second `opened` |
| `scheduled` | an attestor | `{ at, meetLink }` |
| `bucketOneViewed`, `bucketTwoViewed` | an attestor | `{ keyIds }` |
| `attestationSigned` | an attestor | `{ attestorId, attestations }`, the whole follow-up objects in move order |
| `decided` | the server | `{ attestorIds }` |
| `sent` | an attestor | `{ validator, results }` |
| `dismissed` | an attestor | `{ reason, note }` |

Events written in one transaction with another (a sign-off and the
`decided` it completes) keep their order by `clock_timestamp()`, as 12.10
says. A new duty later is a new kind in the check, not a new column.

### 14.6 Client crypto, new

Nothing on the masterpod: it stores no new ciphertext and verifies an
attestation as 13.4.2 verifies a trade's, against the stored creation. The
wallet's side, the key the account key blobs are wrapped under
(`masterpod/kek-keys/v1`, from the passkey's PRF output), the break-glass
pair's signature on a `breakGlassTransfer` and the `/get-account` read
signed with it, is the wallet's spec, section 7 (2026-11-08).

### 14.7 Notifications

One kind, since 2026-11-11 (section 18):

| kind | to | reference_id |
| ---- | -- | ------------ |
| `recoveryCaseScheduled` | the case's pod, the recovered pod | the case id |

Written by `/schedule-break-glass-case` inside the event's transaction, as
section 6's are. It is a kind of its own, not `caseScheduled`, so the
wallet's notifications page opens the recovery case page. Only the video
call notifies: a decision and a dismissal show on the person's case page,
which the wallet reads from `/list-my-break-glass-moves`, and the attestors
list the cases. Until 2026-11-11 this section read "None": the break-glass
plan's decision 14 added no notification kind.

### 14.8 Changes to what exists (all additive)

- `db/schema.sql`: the two tables; the comments on `attestor_events` (the
  table, `case_id`, `details`) and the paragraph above its `CREATE TABLE`
  name the third kind of case and its two detail shapes.
- `src/app.js`: the break-glass router mounted, with its comment line.
- `src/auth/require-attestor.js`: the comment counting the routes the level
  serves names the seven of this section.
- `/store-break-glass-blob` (12.4.5) and `anos_accounts.break_glass_blob`
  are unused since 2026-11-08: the finish uses the recovered seed once, to
  sign the moves, and wipes it. The route and the column stay.
- 12.9's "Moving anos with the break-glass keys" is built here; section 2's
  and 13.2's level tables name the new routes.
- `README.md`: the routes, the folder, the tables.

Nothing else in existing code changes. New: `src/break-glass/` (router,
handlers, service, `break-glass.queries.js`). The sign-off checks reuse
`src/attesting/account-signatures.js` (`hasAccountSignatureShape`,
`verifyAccountSignatures`) and `anos-accounts.queries.js` `findAccount`;
the events go through `src/attesting/attestor-events.queries.js`
(`insertEvent`, `listForCase`, `listForCaseWithUsernames`, `countSignOffs`,
`signedOffBy`, `listDetails`); the statuses are
`assisted-trades.queries.js`'s; the recovery case and its events come from
`src/recovery/recovery-cases.queries.js` and `recovery-events.queries.js`;
the bucket rows from `security.queries.js` `listFor`; the profile from
`anopods.service.js` `profileWithSelfie`.

### 14.9 Deferred, by decision

- Notifications to the attestors when moves are filed and to the person
  when the case is decided or dismissed; the attestor edition and the
  person's wallet read the case. (The person's notification when the
  video call is set up was built 2026-11-11, 14.7 and section 18.)
- A move filed after a cancel on the ledger (a `breakGlassCancel` or the
  owner's `assistedTransferCancel`): the masterpod does not read the
  ledger; the case stays as filed, and the attestor edition shows the move
  as not listed on the validator.
- Dismissing with an effect on the ledger: a dismissal records the
  attestors' refusal; the held moves stay until a cancel (the plan's
  decisions 8 and 11).
- The owner's dispute path, forwarding and a repeat sweep for money that
  lands in an old account after the move (the plan's section 9).

### 14.10 Notes from the builds

#### Build 1, the masterpod (2026-11-08)

Built from `~/Desktop/Z-TestNet/forclaude/break-glass-plan-1.md` section
3, on main at aa102ec (the wallet memory merge). No new npm package, no new
variable, no test script and no rig (none was asked for). The schema was
not applied to any database for keeps: the user applies the whole file by
psql as the superuser with `SET ROLE masterpodsoftware`, as 13.10 records.
What the plan left open and how it was decided:

- The schema block sits at the end of `db/schema.sql`, after the wallet
  memory block: the plan's DDL, aligned in the file's column style, with a
  header comment and a `COMMENT ON` for every table and column. The
  `attestor_events` comments (the table, `case_id`, `details`) and the
  paragraph above its `CREATE TABLE` were reworded in place, since the
  third kind of case had made them false.
- `findMove(transactionId)` joins the plan's eight query functions: the
  filing's "no move with this transactionId yet" needs a lookup by
  transaction id before the write, so the refusals come in the plan's
  order; the unique violation on the primary key is the backstop, and it
  is also where the same transaction id twice in one request lands.
- The two lists aggregate a case's moves as JSON in the database
  (`json_agg ... ORDER BY account_id, transaction_id`), so those moves'
  ids leave the queries file as lowercase hex (`encode(..., 'hex')`, the
  wire form) rather than Buffers, and their `createdAt` as the database's
  text, which the service normalises with `toISOString()`.
  `/list-break-glass-cases` drops `createdAt` from the moves, as the plan's
  answer reads; the person's list and `/get-break-glass-case` keep it.
  `listMoves` and `findMove` return Buffers as every queries file does.
- The filing: the shape first, then every id of every move decoded, then
  the recovery case, then the per-move checks move by move in the plan's
  order. The writes run in one transaction with the case row locked right
  after the `ON CONFLICT DO NOTHING` insert, as every other write to a case
  locks its row, so a filing and a sign-off racing see each other. `moves`
  in the answer counts the case's rows after the write; `status` is the
  locked row's. Nothing checks the break-glass case's own status on a
  filing, as the plan reads; a duplicate within one request lands as `409
  move already filed` at the write.
- The statuses are imported from `assisted-trades.queries.js`
  (`CASE_STATUSES`, `REVIEW_STATUSES`, `DEFAULT_LIST_STATUSES`) rather
  than copied, since the plan makes the break-glass statuses a trade
  case's; the private helpers of the attesting service (`isNote`,
  `isMeetLink`, `isTime`, `pick`, `withLockedCase`, `profileOf`,
  `attestorEvents`) are copied, as the attesting build copied the
  recovery's, to leave `attesting.service.js` alone.
- `/list-my-break-glass-moves` ignores the body, as `/list-my-cases` does;
  the person's events are the four kinds the plan names (`scheduled`,
  `decided`, `sent`, `dismissed`), so the `opened`, the bucket views and the
  sign-offs are not answered. The events come from `listForCase` of the
  attestor events module, the one read without usernames.
- `/get-break-glass-case`: `lookupId` and `recoveryStatus` are null when
  the recovery case row is gone (never, in practice); `approvals` are the
  `approvalSigned` recovery events in time order with the moderator's
  username from the LEFT JOIN and `signedAt` from the details (null when
  a detail lacks it); `moves` carry `createdAt`.
- `/sign-off-break-glass-case`: `attestations` must be a list of 1 to 20
  objects each with a string `transactionId`, the filing's ceiling (`400
  bad request shape`); the matching with the moves is one pass over the
  list (a decode failure, an unknown or repeated id) and a count; checks 1
  to 4 of 13.4.2 then run per attestation in move order with 13.4.2's
  reason strings (`sign-off does not match the case` for a wrong
  transaction or account); a second `attestorId` among them is `400
  attestations differ in attestorId`, a reason the plan did not name;
  check 5 (`409 already signed off`) runs once after them, and again under
  the lock. The stored `attestations` are the follow-up objects exactly as
  sent, in move order; `attestorId` beside them the account id as lowercase
  hex, as a trade's event has it; `decided`'s `attestorIds` come from the
  stored events through `listDetails`.
- `/mark-break-glass-case-sent` is `/mark-attestor-case-sent` with 40
  entries, each `{ signer, status, error? }` as 13.4.4 has them; nothing
  names the move, since the plan keeps the shape.
- `/dismiss-break-glass-case` clears nothing: a break-glass case holds no
  lookup id and no evidence.
- Checks: `node --check` on the five source files (`app.js` and the four
  new ones). Beyond the plan, the whole app was imported once with dummy
  environment values, to catch a wrong import name or an import cycle: it
  imported, with the nine paths registered (the server was not started).
  The SQL ran against the local `masterpod` database (no `masterpodrig`
  exists on this machine) as the superuser inside one transaction, rolled
  back: the block applied twice (`IF NOT EXISTS`, `OR REPLACE`, the
  comments overwritten), a throwaway pod, two cases, three moves filed in
  a shuffled order and the events; the real query functions on the
  transaction's client (28 checks: `findCase`, `insertCase` inserting once
  and doing nothing the second time, `lockCase`, `updateStatus` with the
  trigger, `listMoves` in account order, `findMove`, `insertMove`'s unique
  violation, `listCasesByStatus` with the pod's names, the moves as hex in
  account order, `signOffs` counting two distinct pods once each, `[]` and
  `0` for a case without moves, an empty status list, `listCasesForPod`;
  the aggregated `createdAt` parsing back to the row's time; the
  append-only trigger refusing an `UPDATE` and a `DELETE`; all seven kinds
  and `opened` accepted by `attestor_events`), and the same by psql with
  the list select's text; the tables and the throwaway pod gone after the
  rollback. The whole file was also applied twice, with `SET ROLE
  masterpodsoftware`, to a throwaway database made for it and dropped
  after: the two tables owned by the app role, thirteen comments, the two
  triggers.
- Not touched: `src/attesting/` (its files are imported, their comments
  still count two kinds of case), `src/recovery/` (`/store-break-glass-blob`
  and `setBreakGlassBlob` stay as they are), `src/anos-accounts/`,
  `src/security/`, `signed-request.js`, `package.json`, the scripts.

## 15. DAO voting

Design settled 2026-11-08 in a planning chat of five rounds (the plan is
`~/Desktop/Z-TestNet/forclaude/dao-voting-plan-1.md`, FINAL). Why:
`daoVote` has been one of the six stake purposes since 2026-10-23
(anossoftware spec section 2), recorded only: a transferToFund for daoVote
adds to `stakes.dao_vote_stake` and nothing read it. A DAO voting ledger,
simple and quick, to be made more sophisticated after the production
launch: plain-text proposals; a pending stage in which a proposal collects
support like a petition collects signatures, so junk never reaches a vote;
two weeks of for and against; one staked anos one vote; votes by anoPod
id. Four repos in order: the validator (anossoftware spec section 23, one
public read of every account's DAO stake), the doorman (its section 6, the
line that lets the read through), this server (this section, step 3 of
the plan: the tables, the six routes and the clock) and the wallet (its
section 11, steps 4 and 5). No reset: everything is additive, deployed
validators and doormen first, then this server, then the wallet. The
guardians' fund proposals (anossoftware sections 3 to 6) are a different
system and are not touched. Nothing above this section changes except the
items in 15.8.

### 15.1 The flow

1. A pod posts a proposal (`/create-dao-proposal`, 15.4): a title and a
   body, plain text. This server reads every account's DAO stake from a
   validator once and boils it down to one weight per pod (15.6), the
   posting snapshot, stored with the proposal. The proposer needs at least
   `DAO_PROPOSE_MIN_VOTES` votes in it and no pending proposal of their
   own. The proposal is `pending`, with `needed`, the support that takes it
   to a vote (`DAO_PROPOSAL_PERCENT` of the snapshot's total), and
   `pending_until`, `DAO_PENDING_MINUTES` ahead. The proposer's own weight
   is the first support.
2. Other pods support it (`/support-dao-proposal`), each with its weight in
   the posting snapshot, once, no undo: a petition. A pod with no DAO votes
   in the snapshot cannot.
3. The flip (15.5): when the support reaches `needed`, right after the
   support that reached it or on the clock's next tick, a fresh snapshot
   replaces the posting one and fixes the voting power, and the proposal is
   `open` with `vote_closes_at` `DAO_VOTE_MINUTES` ahead. A proposal that
   reaches its support while no validator can be reached stays pending
   with the support recorded; the clock retries every minute. A proposal
   still pending at `pending_until` expires and leaves the lists.
4. Pods vote for or against (`/vote-dao-proposal`), each with its weight in
   the fresh snapshot, once, no undo. A support in the pending stage is not
   a vote for in the official stage; everyone votes fresh. Every support
   and every vote is public (`/list-dao-votes`): the voter's username,
   weight and time.
5. The close (15.5): at `vote_closes_at` the clock sums the votes;
   `accepted` when for is more than `DAO_PASS_PERCENT` percent of the votes
   cast, else `rejected` (a tie fails; no vote at all fails; there is no
   quorum, the pending stage is the quorum). The results go on the row,
   the snapshot rows are deleted, the proposal is in the Decided list.
   Accepted means recorded: nothing moves money or changes a setting;
   people act on it.

### 15.2 Who

Level setup (section 2) on every route: a vouched pod with setup complete,
signed by its session keys like every other request. A vote is recorded by
anoPod id, so it is exactly as trustworthy as this server (the plan's
decision 3, accepted for now; signing with pair one of a staked account,
verifiable against the chain, is the upgrade for later and changes no
table). The weight comes from the proposal's snapshot (15.6), never from a
live read: a pod's DAO votes are the whole anos of `dao_vote_stake` summed
over its anos accounts (`anos_accounts` maps each account to its pod),
millionths floored. `STAKE_MIN_DAO_VOTE_ANOS` on the validators stays the
smallest single stake; the only other minimum is `DAO_PROPOSE_MIN_VOTES` to
post. A pod with no votes in a proposal's snapshot may read it but neither
support nor vote on it.

### 15.3 Tables

Three new tables, no new column, no widened check. DDL into
`db/schema.sql` after the break-glass block, in the file's style (header
comment, `COMMENT ON` for every table and column, `set_updated_at` on
`dao_proposals`, `refuse_change` on `dao_votes`, neither on
`dao_snapshot_weights`, whose rows the service replaces and deletes). The
whole file, idempotent, applies it to the live database (13.10).

```sql
CREATE TABLE IF NOT EXISTS dao_proposals (
  proposal_id    BYTEA       PRIMARY KEY CHECK (octet_length(proposal_id) = 32),
  anopod_id      BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  title          TEXT        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 100),
  body           TEXT        NOT NULL CHECK (char_length(body) BETWEEN 1 AND 5000),
  status         TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'open', 'accepted', 'rejected', 'expired')),
  snapshot_total BIGINT      NOT NULL CHECK (snapshot_total >= 0),
  snapshot_at    TIMESTAMPTZ NOT NULL,
  needed         BIGINT      NOT NULL CHECK (needed >= 1),
  pending_until  TIMESTAMPTZ NOT NULL,
  opened_at      TIMESTAMPTZ,
  vote_closes_at TIMESTAMPTZ,
  decided_at     TIMESTAMPTZ,
  result_for     BIGINT,
  result_against BIGINT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dao_proposals_status_created_at_idx ON dao_proposals (status, created_at DESC);
CREATE INDEX IF NOT EXISTS dao_proposals_status_decided_at_idx ON dao_proposals (status, decided_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS dao_proposals_one_pending_per_pod_idx ON dao_proposals (anopod_id) WHERE status = 'pending';
CREATE OR REPLACE TRIGGER dao_proposals_set_updated_at
  BEFORE UPDATE ON dao_proposals
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS dao_votes (
  proposal_id BYTEA       NOT NULL CHECK (octet_length(proposal_id) = 32),
  anopod_id   BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  stage       TEXT        NOT NULL CHECK (stage IN ('pending', 'official')),
  vote        TEXT        NOT NULL CHECK (vote IN ('for', 'against')),
  weight      BIGINT      NOT NULL CHECK (weight >= 1),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (proposal_id, anopod_id, stage),
  CHECK (stage = 'official' OR vote = 'for')
);
CREATE INDEX IF NOT EXISTS dao_votes_anopod_id_created_at_idx ON dao_votes (anopod_id, created_at DESC);
CREATE OR REPLACE TRIGGER dao_votes_append_only
  BEFORE UPDATE OR DELETE ON dao_votes
  FOR EACH ROW EXECUTE FUNCTION refuse_change();

CREATE TABLE IF NOT EXISTS dao_snapshot_weights (
  proposal_id BYTEA  NOT NULL CHECK (octet_length(proposal_id) = 32),
  anopod_id   BYTEA  NOT NULL CHECK (octet_length(anopod_id) = 32),
  weight      BIGINT NOT NULL CHECK (weight >= 1),
  PRIMARY KEY (proposal_id, anopod_id)
);
```

`dao_proposals`: one row per proposal, never deleted. `snapshot_total`,
`needed`, `result_for` and `result_against` are votes, whole anos, never
millionths. `snapshot_total` and `snapshot_at` (the validator's `asOf`) are
the current snapshot's, replaced when the proposal goes open; `needed` is
the posting snapshot's number, `max(1, ceil(total * DAO_PROPOSAL_PERCENT /
100))`, and never changes. `result_for` and `result_against` are written
at the close and null before it (and on an expired proposal); `decided_at`
is set at the close and at the expiry. The partial unique index is the
"one pending proposal per pod" rule.

`dao_votes`: one row per pod per stage, append-only; a vote never changes.
`stage` `pending` is a support (always `for`, the check), `official` a
vote. `weight` is the pod's votes in the proposal's snapshot at the time,
the posting snapshot in the pending stage and the fresh one in the
official stage, so the archive stands on its own once the snapshot rows
are gone.

`dao_snapshot_weights`: the proposal's current snapshot, one row per pod
with votes (pods at 0 have no row), replaced at the flip and deleted at
the end. Stake on an account the masterpod does not know counts in
`snapshot_total` and in nobody's weight. No foreign keys, as everywhere.

### 15.4 Routes

Conventions of section 5 throughout: every route a `POST` at level setup,
checks in order, first failure answers, every multi-row write one
transaction. The caller is `req.anopod`. Ids on the wire are hex; weights,
totals and sums are votes (whole anos) as JSON numbers, the BIGINT strings
converted (they stay far below 2^53); times ISO 8601. Every write to a
proposal runs with the row locked (`SELECT ... FOR UPDATE`) and the status
checked under the lock, so a support racing the flip, or two flips on two
boxes, see each other.

**POST /create-dao-proposal**. Body `{ title, body }`. Checks, in order:

1. Shape: both strings; `400 bad request shape`.
2. `title` trimmed at both ends, 1 to 100 characters; `400 invalid title`.
   `body` trimmed at both ends, 1 to 5,000 characters; `400 invalid body`.
3. The snapshot (15.6); `503 validators unreachable` when no validator
   answered.
4. The caller's weight in it at least `DAO_PROPOSE_MIN_VOTES`; `403 not
   enough DAO votes`.
5. No pending proposal of the caller's; `409 a pending proposal is already
   open`, also on the unique violation at the write.

Writes, one transaction: the proposal (status `pending`, `snapshot_total`
and `snapshot_at` from the snapshot, `needed` as 15.3 says, `pending_until
= now() + DAO_PENDING_MINUTES`), the snapshot rows, the proposer's
pending-stage `for` row with their weight. Then the flip (15.5), outside
the transaction.

Answer: `201 { proposalId, status }`, `status` after the flip attempt:
`open` when the proposer alone reaches `needed`, else `pending`.

**POST /support-dao-proposal**. Body `{ proposalId }`; `400 bad request
shape`, `400 invalid proposalId`. One transaction with the row locked: the
row exists (`404 unknown proposal`); status `pending` (`409 proposal not
pending`); `pending_until` ahead (`409 proposal expired`); the caller's
weight in the snapshot at least 1 (`403 no DAO votes in this proposal`);
no pending-stage row of the caller's (`409 already supported`, also on the
unique violation); the row inserted with the caller's weight. Then the
flip.

Answer: `200 { proposalId, status, support, needed }`: `support` the
pending-stage sum after the write, `status` after the flip attempt.

**POST /vote-dao-proposal**. Body `{ proposalId, vote }`; `400 bad request
shape`, `400 invalid proposalId`; `vote` `for` or `against` (`400 invalid
vote`). One transaction with the row locked: the row exists (`404 unknown
proposal`); status `open` (`409 proposal not open`); `vote_closes_at`
ahead (`409 voting closed`); the caller's weight in the (fresh) snapshot at
least 1 (`403 no DAO votes in this proposal`); no official-stage row of the
caller's (`409 already voted`, also on the unique violation); the row
inserted.

Answer: `200 { proposalId, for, against, yourVote }`, the official sums
after the write.

**POST /list-dao-proposals**. Body `{ status, from?, to?, limit?, offset?
}`: `status` `pending`, `open` or `decided` (accepted and rejected
together; `400 invalid status`); `from` and `to` ISO 8601 or absent (`400
invalid from`, `400 invalid to`), `from` at or after and `to` before, on
`created_at` for pending and open and on `decided_at` for decided; `limit`
1 to 100, default 20 (`400 invalid limit`); `offset` 0 or more, default 0
(`400 invalid offset`). Newest first by the same column. Expired proposals
are never listed.

Answer: `200 { proposals: [ item ], settings }`.

```json
{
  "proposalId":    "<hex>",
  "title":         "...",
  "status":        "pending",
  "proposer":      { "anopodId": "<hex>", "username": "..." },
  "createdAt":     "2026-11-08T12:00:00.000Z",
  "pendingUntil":  "2026-11-15T12:00:00.000Z",
  "openedAt":      null,
  "voteClosesAt":  null,
  "decidedAt":     null,
  "snapshotTotal": 1200,
  "needed":        180,
  "support":       25,
  "for":           0,
  "against":       0,
  "yourWeight":    12,
  "yourSupport":   true,
  "yourVote":      null
}
```

`for` and `against` are the stored results once decided and the live sums
before; `yourWeight` is the caller's votes in the proposal's current
snapshot (0 when none), `yourSupport` whether the caller supported it,
`yourVote` the caller's vote or null. `username` is null when the pod's row
is gone. `settings` is `{ proposeMinVotes, proposalPercent, passPercent,
pendingMinutes, voteMinutes }`, the dials of 15.7, so the wallet's words
carry the numbers.

**POST /get-dao-proposal**. Body `{ proposalId }`; `400 bad request shape`,
`400 invalid proposalId`, `404 unknown proposal`. Answer: `200 { proposal
}`, the item of the list with `body` added. An expired proposal is answered
too (status `expired`, its results null), so an old link resolves.

**POST /list-dao-votes**. Body `{ proposalId, stage, limit?, offset? }`;
`400 bad request shape`, `400 invalid proposalId`; `stage` `pending` (the
supports) or `official` (the votes; `400 invalid stage`); `limit` 1 to 200,
default 50 (`400 invalid limit`); `offset` 0 or more (`400 invalid
offset`); `404 unknown proposal`. Answer: `200 { votes: [ { anopodId,
username, vote, weight, createdAt } ] }`, newest first; `username` null
when the pod's row is gone. The wallet marks the caller's own row by
`anopodId`.

### 15.5 Statuses and the clock

```
pending -> open      the flip: the support reached needed; a fresh snapshot fixes the voting power
pending -> expired   the clock: pending_until passed with the support under needed
open    -> accepted  the clock: vote_closes_at passed and for * 100 > DAO_PASS_PERCENT * (for + against)
open    -> rejected  the clock: vote_closes_at passed, otherwise (a tie, or no vote at all)
```

`accepted`, `rejected` and `expired` are final. Expired proposals are kept
with their rows and hidden from the lists, not deleted.

The flip, `flipIfReached(proposalId)` in `src/dao/dao.service.js`, runs
after a posting and after a support, and from the clock: a fresh snapshot
(15.6); when no validator answers it logs `dao: the flip of <id> waits,
validators unreachable` and answers `pending`. Then one transaction: the
row locked; a status other than `pending` answers that status; a
pending-stage sum under `needed` answers `pending`; else the fresh weights
replace the snapshot rows, the row gets `status = 'open'`, the fresh total
and `asOf`, `opened_at = now()` and `vote_closes_at = now() +
DAO_VOTE_MINUTES`; `open`. `needed` is not recomputed: it is the posting
snapshot's number, and the support rows carry that snapshot's weights.

The clock, `src/dao/dao-clock.js`, in the shape of anossoftware's
`src/held-transactions/unapproved-sweep.js`: `startDaoClock()` after
`listen` in `src/server.js`, `stopDaoClock()` in its `shutdown`; one tick
at boot, then every 60 seconds, `unref`'d. A tick:

1. The expiry: one statement moves every pending proposal whose
   `pending_until` has passed to `expired` with `decided_at = now()`; each
   one's snapshot rows are deleted; one log line per proposal.
2. The flip: every pending proposal whose pending-stage sum is at or above
   `needed` goes through `flipIfReached`, the retry for a flip that found
   the validators unreachable when the support arrived.
3. The close, one transaction: the open proposals whose `vote_closes_at`
   has passed, locked with `SKIP LOCKED`; for each, the official sums,
   `accepted` when `for * 100 > DAO_PASS_PERCENT * (for + against)` else
   `rejected`, the results and `decided_at` written, the snapshot rows
   deleted; one log line per proposal.

Three masterpods run the clock at once on prod1, prod2 and prod3: the
expiry is one idempotent statement, the flip locks the row and re-checks
the status, the close skips the rows another box holds. A tick that throws
logs the error and the next tick runs.

### 15.6 The validator read and the snapshot

The one outbound call this server makes, `src/dao/validators.client.js`
`fetchDaoStakes()`: for each URL of `VALIDATOR_URLS`, in order, `POST
<url>/list-dao-stakes` with the header `Content-Type: application/json`,
the body `{}` and a five-second timeout, the shape of anossoftware's
`src/masterpod/masterpod.client.js`. The validator's answer (anossoftware
spec 23) is `200 { asOf, total, stakes: [ { accountId, daoVoteStake } ]
}`: `asOf` ISO 8601, `total` a decimal string of millionths, `stakes` every
account with DAO stake above zero, `accountId` 64 lowercase hex,
`daoVoteStake` a decimal string of millionths. The first `200` of that
shape is the answer; anything else moves to the next URL with one log line:
a doorman or a validator that has not pulled the route (`404`), a joiner
(`503 not counted yet`), the doorman's own refusals (doormansoftware spec
6: `400`, `413`, `429 too many requests`, `502`, `504`), a redirect
(2026-11-19, 15.10), a timeout, a body of the wrong shape. A redirect is
not followed (`redirect: 'manual'` in the fetch): a doorman is a machine
we do not own, and a redirect that is followed lets it pick another
address for the call, which this server would then make from inside its
own network. When every URL failed, null. The read is public and
unsigned: everything in it is on the public chain, and this server has no
anos account or validator key to sign with. The doormen's certificates are
Let's Encrypt, so the fetch verifies them as any other. (Since 2026-11-21,
section 25, it is the one outbound call to the validators and no longer
the only one this server makes: the alert sender calls the email company
and the phones' delivery services, 25.6.)

The snapshot, `src/dao/snapshot.js` `takeSnapshot()`: the stakes (null
passed through); `findPodsForAccounts` (15.8) maps the accounts to pods;
per pod the millionths are summed as BigInt and floored to whole anos
(`weight = sum / 1,000,000`), pods at 0 dropped; `total` the answer's
`total` floored the same way. Returns `{ asOf, total, weights: [ {
anopodId, weight } ] }`. Taken when a proposal is posted (the posting
snapshot: the support stage counts against it) and again at the flip (the
fresh snapshot: the voting power for the two weeks). Stake added after a
snapshot counts from the next one. Stake on an account the masterpod does
not know (none today: every account is made through
`/create-anos-account`) counts in `total` and in nobody's weight.

### 15.7 Environment variables

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `VALIDATOR_URLS` | `http://localhost:3001` to `3005`, the five local validators | the validators asked for the DAO stake list, comma-separated, tried in order; on the servers the doormen's URLs, the list of the wallet's `network/wallet.env`; a trailing slash is dropped |
| `DAO_PROPOSE_MIN_VOTES` | `1` | the least DAO votes (whole staked anos) in the snapshot a pod needs to post |
| `DAO_PROPOSAL_PERCENT` | `15` | the percent of all DAO votes a pending proposal needs in support; at most 100 |
| `DAO_PASS_PERCENT` | `50` | for must be more than this percent of the votes cast; at most 99, so a tie fails |
| `DAO_PENDING_MINUTES` | `10080` | how long a proposal may collect support (a week) |
| `DAO_VOTE_MINUTES` | `20160` | how long an open proposal takes votes (two weeks) |

`env.validatorUrls` and `env.dao` (`proposeMinVotes`, `proposalPercent`,
`passPercent`, `pendingMinutes`, `voteMinutes`) in `src/config/env.js`;
every integer a positive integer, the two percents also capped. All have
defaults, so the existing `.env` keeps working; on the servers the user
adds `VALIDATOR_URLS` (a masterpod with no validator to ask answers `503`
to every posting). Locally the minutes may be set small to try the clock.

### 15.8 Changes to what exists (all additive)

- `db/schema.sql`: the three tables, as a block after the break-glass
  block.
- `src/anos-accounts/anos-accounts.queries.js`:
  `findPodsForAccounts(accountIds, db)`, `SELECT account_id, anopod_id
  FROM anos_accounts WHERE account_id = ANY($1)`, a Map from the account
  id in hex to the pod's id as a Buffer; the snapshot's one lookup.
- `src/config/env.js` and `.example.env`: the six variables of 15.7.
- `src/app.js`: the DAO router mounted, with its comment line.
- `src/server.js`: the clock started in the `listen` callback and stopped
  first thing in `shutdown`; the one thing this server runs on its own
  besides the listener.
- Section 2's level table names the six routes; section 8's table the six
  variables.
- `README.md`: the routes, the tables, the folder, the variables.

Nothing else in existing code changes. New: `src/dao/` (`dao.router.js`,
`dao.handlers.js`, `dao.service.js`, `dao.queries.js`,
`validators.client.js`, `snapshot.js`, `dao-clock.js`). No new npm package.

### 15.9 Deferred, by decision

- A moderator hide for a proposal's text (on the user's own after-launch
  list).
- Votes signed by pair one of a staked account, verifiable against the
  chain; changes no table.
- Notifications; the wallet reads the lists, and Home's "Things to do" line
  counts the open proposals the pod has not voted on.
- Editing or withdrawing a proposal.
- A cursor on the lists (`offset` paging today).
- A vote list export.
- A logged-out public view of the proposals.
- Also out (the plan's section 8): comments on a proposal (the chat is
  there); a quorum (the pending stage is the quorum); any weighting but one
  anos one vote; the stake withdrawal lock, which the guardians work by
  hand from the vote rows' times.

### 15.10 Notes from the build

#### Build 1, the masterpod (2026-11-08)

Built from `~/Desktop/Z-TestNet/forclaude/dao-voting-plan-1.md` section 3,
on main at 846111b (the vouching selfie change). No new npm package, no
test script and no rig (none was asked for). The schema was not applied to
any database for keeps: the user applies the whole file by psql as the
superuser with `SET ROLE masterpodsoftware`, as 13.10 records, and
locally with `npm run db:setup`. What the plan left open and how it was
decided:

- The schema block sits at the end of `db/schema.sql`, after the
  break-glass block: the plan's DDL, aligned in the file's column style,
  with a header comment and a `COMMENT ON` for every table and column.
  `dao_snapshot_weights` has no `created_at` and no trigger, as the plan's
  DDL has it; the file's header comment, which names the blocks that hold
  the ALTERs, is unchanged, since this block has none.
- The validator client's shape check requires `asOf` too (a string
  `Date.parse` understands), beside the plan's `total` and `stakes`: it
  lands in `snapshot_at`, which is NOT NULL, so an answer without it is a
  body of the wrong shape and moves to the next URL. `accountId` must be
  lowercase hex, as the validator's spec answers it; `total` and
  `daoVoteStake` digits with no leading zero. The log line names the URL
  and the reason: the HTTP status with the answer's `error` when there is
  one, the fetch error's message (a timeout included), or `bad shape`.
- Two queries join the plan's list: `hasPendingProposal(anopodId)`, the
  posting's "no pending proposal of the caller" before the write (the
  partial unique index is the backstop, as the plan says), and
  `findVote(client, proposalId, anopodId, stage)`, the "no row of the
  caller in this stage" check under the lock on a support and on a vote
  (the primary key the backstop). `PROPOSAL_STATUSES`, `DECIDED_STATUSES`
  and `STAGES` are exported from the queries file for the service.
- The times: `pending_until`, `opened_at` and `vote_closes_at` are
  computed in the service from the server's clock and passed to the
  queries, as the plan's signatures read; `decided_at` is the database's
  `now()` at the expiry and at the close. `snapshot_at` is the validator's
  `asOf`, parsed and passed as a Date. The support route's "pending_until
  ahead" and the vote route's "vote_closes_at ahead" compare the locked
  row's time with the server's clock.
- The flip takes the snapshot before looking at the support, as 3.5
  orders it, so a support that leaves the proposal far from `needed` costs
  one validator read too (and, while no validator answers, the "waits"
  log line and up to five seconds per URL before the `200`). A check of
  the sum before the read is a one-line change for later. The flip logs
  one line when it opens a proposal (the support reached, the closing
  time), beside the plan's line for the unreachable validators.
- The lists: `from` is at or after and `to` before, as `listNotes` reads
  its bounds; a bad `limit` or `offset` is `400 invalid limit` or `400
  invalid offset`, the marketplace's and the chat's reasons. A `vote`,
  `stage` or `status` that is not one of its words is `400 invalid vote`,
  `invalid stage` or `invalid status` whatever its type, after the shape
  check of the strings the route needs. The item's `for` and `against`
  read the stored result when it is set and the live sum otherwise, so an
  expired proposal (results null) reads 0 and 0. `settings` is `env.dao`
  itself, a frozen object of the five dials.
- `/list-dao-votes` checks that the proposal exists through
  `findProposal`, the one read of a proposal by id; `/get-dao-proposal`
  answers the same row with the body.
- `findPendingReached` does not look at `pending_until`: the expiry runs
  before the flip in every tick, so a proposal past its time is expired
  before the flip pass looks. The tick is one try/catch over the three
  steps, as the sweep's, with no guard against a tick that outlives the
  minute: the flip is safe to repeat (the lock and the status check), so
  an overlap costs a validator read at most. The expiry's `deleteSnapshot`
  runs on the pool, one proposal at a time; the close's on the close's
  client. `replaceSnapshot` is `deleteSnapshot` and then the one `INSERT
  ... SELECT` over `unnest`; an empty snapshot inserts nothing.
- `VALIDATOR_URLS`' default is built as `http://localhost:300<n>` for 1 to
  5; `optionalPercent` is `optionalInteger` with a ceiling, for the two
  percents (100 and 99).
- Checks (3.8): `node --check` on the eleven changed source files (the
  seven of `src/dao/`, `anos-accounts.queries.js`, `env.js`, `app.js`,
  `server.js`), clean; every name imported by the new files is exported
  where it is imported from. The SQL by psql against the local `masterpod`
  database (as the superuser `codex`; the app's role `masterpodsoftware`
  is not one) inside one transaction, rolled back: the DAO block applied
  twice (`IF NOT EXISTS`, `OR REPLACE`, the comments overwritten; the
  three tables with 16, 6 and 3 columns, a comment on each table and
  column, the two triggers, the seven indexes); every query of
  `dao.queries.js` and `findPodsForAccounts` prepared with its exact text
  (twenty statements, the text taken from the functions by a throwaway
  client that recorded what they sent, outside the repo) and executed on
  throwaway rows (one pod with an `anopods` row, one without, three
  proposals): the partial unique index refusing a second pending proposal
  of the pod, `set_updated_at` overriding a backdated `updated_at`, the
  replace (the delete and the `unnest` insert, a pod dropped on the
  second replace, an empty replace), the append-only trigger refusing an
  `UPDATE` and a `DELETE`, the primary key refusing a second row of the
  pod in the stage, the check refusing a pending `against`,
  `findProposal` with the username, the three sums and the caller's part
  for two callers, the list for pending and for open with a `from` bound,
  a `to` bound, `limit` and `offset`, the lock, the sums, the votes list
  with the username and a null for the pod without a row, `findWeight`,
  `findVote`, `hasPendingProposal`, the clock's three steps (the expiry of
  the proposal past `pending_until`, the reached one found and opened by
  `setOpen`, the closable one locked and decided accepted 7 to 3 with its
  snapshot rows gone), the decided list with the stored and the live sums
  equal, the expired proposal in no list but still found by id. After the
  rollback the three tables and the throwaway pod were gone.
  `findPodsForAccounts` ran once more, read-only, on two live account ids
  and one unknown id: the two mapped to their pods, the unknown absent,
  an empty list answering no rows.
- Not touched: `src/attesting/`, `src/break-glass/`, `src/recovery/`,
  `src/wallet-memory/`, `src/marketplace/`, `src/chat/`, the auth
  middlewares, `package.json`, the scripts; in the README the level table
  and the paragraph after the routes table (the plan names the routes
  list, the tables list, the folder list and the variables table).

#### The validator read does not follow a redirect (2026-11-19)

Built from `~/Desktop/Z-TestNet/forclaude/validator-redirects-plan-1.md`
(FINAL, 2026-11-19), its step 1 of two, its section 1, one commit, on
main at e308d3e. One line of code: in `askOne` of
`src/dao/validators.client.js` the options of the `fetch` gain `redirect:
'manual'`, after the `body` line. The comment at the top of that file and
the sentence of 15.6 that lists what moves the read to the next URL each
gain the redirect. No route, no table, no variable, no npm package.

- Why. A redirect is an answer that says "ask this other address
  instead". Node's `fetch` follows one by itself, up to 20 in a row. The
  read goes to a validator's doorman, a machine we do not own. Whoever
  runs that doorman, or breaks into it, could so pick another address for
  the call, and this server would make that call from inside its own
  network, where addresses answer that the outside cannot reach. The same
  word already stands in the doorman's relay to its worker
  (`doormansoftware/src/door/forward.js`) and in the monitor's sweep
  (`monitorsoftware/server/sweep/ask.js`).
- What a redirect is now: an answer with its own status, and nothing
  more. `askOne` gives the text `status 302` (or 301, 303, 307, 308, with
  the body's `error` after it when the body is JSON and has one),
  `fetchDaoStakes` writes its one log line, `dao: <url>/list-dao-stakes
  failed: status 302`, and asks the next URL. Nothing is sent to the
  address the redirect names. No new handling was needed: a status that is
  not 200 already moved the read on.
- What a person sees: nothing. Honest validators send no redirect.
- The validator's own two calls to the other validators get the same word
  in step 2 of that plan, in anossoftware (its spec, 19.1 and 19.5). The
  validator's call to this server and the keyholder's calls are left as
  they are, on purpose (the plan's decision 5).
- Checked. `git status --short` showed a clean tree at e308d3e at the
  start, and this step's two files and no others at the end:
  `src/dao/validators.client.js` and this file. `node --check
  src/dao/validators.client.js` passes. The built file equals the planning
  chat's own trial file but for the three comment lines. No server was
  started and no database was opened. Beyond the plan's two checks, one
  throwaway run on loopback, on the user's Mac, Node v24.22.0: the real
  `fetchDaoStakes` of the working tree, loaded with made-up database
  names, in front of three made-up validators and one more made-up server,
  "the other address", which stands in for an address inside the
  masterpod's own network and answers a stake list of its own. The script
  is in the build chat's scratchpad and nothing of it is in the repo. 31
  checks, all as expected. A first validator that answers 301, 302, 303,
  307 or 308 with the other address as its target: the other address gets
  no call, the log line says `status` and the number, and the answer taken
  is the second validator's. A redirect with a JSON body, and one to a
  path on the validator's own address: the same. Three validators that all
  redirect: null, one log line for each, no call to the other address. As
  before: a good first answer wins and nobody else is asked; a 404, a 503
  `not counted yet`, a 429, an HTML 502, a body of the wrong shape and the
  five-second timeout each move to the next URL with the log line they
  had; the call is still `POST /list-dao-stakes` with the body `{}`. The
  file of e308d3e went through the same script: 6 of the 31 checks were as
  expected, and the 25 others are what this step changes. There the other
  address got the call, a GET after a 301, 302 or 303 and the POST again
  after a 307 or 308; its made-up stake list was taken as the validator's
  answer, with no log line; and a redirect to the validator's own address
  was followed twenty times before the read moved on. Not run: a doorman,
  TLS, a real validator, the masterpod itself, a database.
- The deploy is the user's, with their own lines for the masterpod: the
  pull and the restart on each of prod1, prod2 and prod3, the leader last,
  then the check line. No database line, no `npm ci`, no variable. The
  commit has to be on GitHub's `main` first. The pull brings whatever
  `main` holds: if prod1, prod2 and prod3 are not on e308d3e yet, "Seen in
  chat" (section 21) comes along, and its database line runs on the leader
  before any restart.

## 16. Appointments (2026-11-08)

Design settled 2026-11-08 in a planning chat of one round (the plan is
`~/Desktop/Z-TestNet/forclaude/appointments-plan-1.md`, FINAL). Why: until
this section a moderator was a pod whose `username` started with
`moderator` and that any super seed had vouched for, and an attestor the
same with `attestor` (12.2 and 13.2 as they were). Nothing reserved the
usernames, so the rule was really "any super seed vouched for you", and at
the production launch about a thousand pods will be super seeds. The
validators and the keyholders check only that the signing account holds
the stake, and anyone with a spending account and the minimum may stake.
Moderator and attestor are positions of trust, so one list decides: the
`appointments` table on this server, written by the operator's scripts,
read by the two gates and by the two answers that carry a pod's role.
Three repos in order: this server (this section, step 1 of the plan: the
table, the two scripts, the gates, the two answers), the validator
(anossoftware spec section 24, step 2: the receiving validator asks
`/get-anos-account` for the pod's role before it accepts a stake for
moderator or attestor, the way it asks at create-account whether a vouched
pod made the account) and the wallet (its section 11, step 3: the Stake
for list offers moderator and attestor only to a pod appointed for it),
then the two record folders. Nothing is reset: the table is new, and the
Test Net 2 relaunch starts this server's database fresh anyway. The
keyholders, the doorman and the signing server are not touched. Nothing
above this section changes except the items in 16.5.

### 16.1 The table

```sql
CREATE TABLE IF NOT EXISTS appointments (
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  role         TEXT        NOT NULL CHECK (role IN ('moderator', 'attestor', 'validator', 'masterPod')),
  appointed_by TEXT        NOT NULL CHECK (appointed_by = 'operator' OR appointed_by ~ '^[0-9a-f]{64}$'),
  appointed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (anopod_id, appointed_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_live_per_pod
  ON appointments (anopod_id) WHERE revoked_at IS NULL;
```

(2026-11-10: the role check gained `'validator'` and `'masterPod'`, 16.7;
until then it read `role IN ('moderator', 'attestor')`. The paragraph
below is as written on 2026-11-08, for the two roles of that day.)

One row per appointment of a pod as a moderator or an attestor. A pod
holds the role while its row has no `revoked_at`; the partial unique index
`appointments_one_live_per_pod` keeps that to one row per pod, so a pod is
a moderator or an attestor, never both: revoke, then appoint again for the
other role. Revoking sets `revoked_at`; the row stays, so who held what
when is on record, and appointing the pod again adds a row (the primary
key is the pod and `appointed_at`). `appointed_by` is `operator` for the
scripts; a pod's hex id is for a DAO proposal kind that appoints, later.
The `set_updated_at` trigger and a `COMMENT ON` for the table and every
column, as every other table has them; the block sits after the
`super_seeds` block in `db/schema.sql`. No foreign keys, as everywhere.

### 16.2 The rule

A moderator is a pod with a live `appointments` row with `role =
'moderator'`; an attestor, one with `role = 'attestor'`:

```sql
SELECT EXISTS (SELECT 1 FROM appointments
               WHERE anopod_id = $1 AND role = $2 AND revoked_at IS NULL)
```

`src/appointments/appointments.queries.js` holds it (`isAppointed`), with
`findLiveRole` (the pod's live role, `'moderator'`, `'attestor'` or
`null`), `listAppointedPods` (the pods with a live row for a role whose
setup is complete, username order, as `listAttestorPods` filtered before)
and the two writes of the scripts, `insertAppointment` and
`revokeAppointment`. The gates: `mustBeModerator`
(`src/auth/require-moderator.js`) is `isAppointed(anopodId, 'moderator')`,
else `403 not a moderator`; `mustBeAttestor`
(`src/auth/require-attestor.js`) the same with `'attestor'`, else `403 not
an attestor`. `isAttestorPod` and `listAttestorPods` in that file, which
`attesting.service.js` uses for `/list-attestors` and for the pods a case
key is wrapped to in `/open-dispute-case` and `/share-case-key`, are the
two queries with `'attestor'`; their callers (`attesting.service.js`,
`recovery.router.js`, `attesting.router.js`, `break-glass.router.js`) do
not change, and the levels of 12.2 and 13.2 keep their routes. The
username prefix rule is gone: `MODERATOR_PREFIX`, `ATTESTOR_PREFIX` and
`vouchedBySuperSeed` are removed, usernames are free, and a super seed's
vouch appoints nobody (the build notes of 12.10 and 13.10 describe the
prefix rule as it was). The masterpod still does not check the stake: the
keyholders do on every bucket key request, the validators on every
attestor read and follow-up; and from step 2 the validators accept a
moderator or attestor stake only from an account whose pod is appointed
for it, so the stake checks there stand unchanged.

### 16.3 The scripts

No route writes the table. On a prod box, as the masterpod user in the
checkout, after the pod is made at the wallet like any other:

```bash
npm run appoint -- <anopod id, 64 hex> <moderator|attestor|validator|masterPod>
npm run revoke -- <anopod id, 64 hex>
```

(2026-11-10: `appoint` takes `validator` and `masterPod` as well, 16.7;
until then the usage line ended `<moderator|attestor>`.)

`scripts/appoint.js`, the shape of `scripts/make-super-seed.js`: the id
and the role parsed (exit 2 with the usage line on a malformed one); one
transaction: the pod's row read by id (exit 1, `<id>: no anopod with this
id`); a live row with the same role, `<username> (<id>): already appointed
as attestor`, exit 0; a live row with the other role, `<username> (<id>):
is a moderator; revoke first`, exit 1; otherwise the row inserted with
`appointed_by 'operator'` and `<username> (<id>): appointed as attestor`.
It requires the pod to exist and nothing else, not `vouched`, not setup:
the operator appoints whom they choose, and the stake needs a vouched pod
anyway. `scripts/revoke.js`: `<username> (<id>): revoked as attestor`, or
`<username> (<id>): holds no appointment`, exit 0 both; exit 1 on an
unknown id, 2 on a malformed one. Revoking takes effect here at once; the
stake the pod holds at the validators comes back through the guardians'
fund proposal payout with `stakeFor`, which already drops the role at the
validators and the keyholders, and until that payout is written the stake
still counts there (the plan's decision 6, accepted for the production
launch and listed as a follow-up). `package.json`: `appoint` and `revoke`,
each `node --env-file=.env scripts/<name>.js`.

### 16.4 The two answers

- `/get-anos-account` (none): `200 { accountId, anopodId, vouched, role }`,
  `role` the pod's live role, `"moderator"`, `"attestor"` or `null`, read
  by `findLiveRole`. For the validators' appointment check at stake time
  (step 2), beside the binding check they already run at create-account.
  Nothing new is given away: the chain already shows which accounts staked
  for which purpose, and the route already maps any account to its pod.
- `/check-anopod-status` (session): the answer gains `role` the same way,
  after `isSuperSeed`. The wallet's Stake for list reads it (step 3). An
  older wallet ignores the field.

### 16.5 Files

- `db/schema.sql`: the `appointments` block after the `super_seeds` block.
- `src/appointments/appointments.queries.js`, new.
- `src/auth/require-moderator.js`, `src/auth/require-attestor.js`: the
  gates on the table; the prefixes, `vouchedBySuperSeed` and the import
  between the two files gone.
- `src/anos-accounts/anos-accounts.service.js` (`getAnosAccount`) and
  `src/anopods/anopods.service.js` (`status`): `role`.
- `scripts/appoint.js` and `scripts/revoke.js`, new; `package.json`, the
  two script lines.
- Here: section 2 (a dated pointer), section 4 (`### appointments`),
  section 5 (the two answers), section 9 (the scripts), 12.2 and 13.2
  (rewritten in place), 12.9 and 13.9 (the revoking items). `README.md`:
  the scripts table, the levels table, the tables list, the two route
  rows, and, on the user's word after the build, the paragraph after the
  routes table, the Genesis section and the folder lists.

Nothing else in existing code changes. No env variable, no npm package,
no new route.

### 16.6 Notes from the build

#### Build 1, the masterpod (2026-11-08)

Built from `~/Desktop/Z-TestNet/forclaude/appointments-plan-1.md` section
1, on main at 68b8ba2 (DAO voting). No new npm package, no test script
and no rig (none was asked for). The schema was not applied to any
database for keeps: the user applies the whole file by psql as the
superuser with `SET ROLE masterpodsoftware`, as 13.10 records, and
locally with `npm run db:setup`. A masterpod that keeps its database
needs `npm run appoint` for every moderator and attestor pod it already
has, or the two editions refuse them (the plan's section 5). What the
plan left open and how it was decided:

- Section 2's level table has no `moderator` or `attestor` row (the two
  levels have their tables in 12.2 and 13.2), so the plan's wording for
  those rows went on the rows of 12.2 and 13.2, and section 2's closing
  sentence gained the dated pointer to section 16.
- The plan gave the comments of the table, `appointed_by` and
  `revoked_at`; the other columns got one each in the file's words, the
  `appointed_at` comment saying why it is in the primary key.
- The scripts read the pod's row inline (`SELECT username ... WHERE
  anopod_id = $1`), as `make-super-seed.js` runs its own `UPDATE`; the
  exits that write nothing roll back. `appoint.js` parses the role
  against the two words and spells the refusal "is a moderator" or "is an
  attestor". `decodeId` takes base64 as well as hex, as everywhere.
- `isAttestorPod(anopodId, db)` and `listAttestorPods(db)` pass `db`
  through to the two queries; left out, it falls to the queries' pool
  default, so the callers in `attesting.service.js` did not change.
- `status` runs `findLiveRole` in the same `Promise.all` as its three
  other reads; `getAnosAccount` runs it after the account is found.
- Checks (1.7): `node --check` on the seven changed source files
  (`appointments.queries.js`, the two gates, the two services, the two
  scripts), clean; every name imported by them is exported where it is
  imported from; `grep -rn "PREFIX\|startsWith" src` finds only the SPKI
  key prefixes of `crypto/signatures.js`. The SQL by psql against the
  local `masterpod` database as the superuser `codex` with `SET LOCAL ROLE
  masterpodsoftware`, three transactions, each rolled back: the block
  applied (owner `masterpodsoftware`, seven columns, the primary key and
  the partial unique index, the trigger, a comment on the table and every
  column) and gone after the rollback; the block applied twice (the
  `IF NOT EXISTS` notices, the comments overwritten), a throwaway pod
  appointed as attestor, the same pod inserted again with another
  `appointed_at` (inside one transaction `now()` is one value, so a
  second insert at the default would hit the primary key first) and
  refused by `appointments_one_live_per_pod`, a role of `guardian` refused
  by the role check, the three reads of 1.2 run by hand (`findLiveRole`
  `attestor`, and no row for a pod without one; `isAppointed` true for
  `attestor` and false for `moderator`; `listAppointedPods('attestor')`
  empty while the throwaway pod has no `anopods` row, then two real local
  pods appointed and the one with setup complete listed alone), the
  revoke (`UPDATE 1`, `updated_at` moved to `now()` by the trigger,
  `created_at` untouched, then no live role, a second revoke `UPDATE 0`),
  the pod appointed again as moderator with the revoked row kept (two
  rows, one live); and `appointed_by = 'genesis'` refused by its check
  while a 64-hex `appointed_by` is accepted. After each rollback the table
  was gone and the real pods untouched. No server was booted.
- Not touched: `src/attesting/`, `src/recovery/`, `src/break-glass/`,
  `src/vouching/`, `src/dao/`, `app.js`, `env.js`, `.example.env`, the
  three shell scripts. Three README places the plan did not name still
  described the username rule after the build (the paragraph after the
  routes table, the Genesis section, the folder lists); the user asked
  for them to be brought in line, and they were, before the commit.

### 16.7 Validator and masterPod (2026-11-10)

Design settled 2026-11-10 in a planning chat of one round (the plan is
`~/Desktop/Z-TestNet/forclaude/validator-masterpod-stake-plan-1.md`,
FINAL). It grows the plan of this section, which made the list for
moderator and attestor. Why: the wallet's Stake for list offered validator
and masterPod to everyone. The user, 2026-11-10: "Send stake should only
be to dao vote or guardian. Right now it also include validator and
masterpod. We'll actually need to build a list for those, like we did with
moderator and attestor. Unless the user is on that list, then those option
should not show." The list is the `appointments` table: `validator` and
`masterPod` are two more roles on it. Three repos in order: this server
(this subsection, step 1 of the plan: the role check widened, the script's
role list, comments), the validator (anossoftware and its spec, step 2:
the receiving validator refuses a validator or masterPod stake from an
account whose pod is not appointed for it, the check of 2026-11-08 with
two more names) and the wallet (its spec, 4.3, 8.2 and 11, step 3: the
Stake for list offers daoVote and guardian to everyone and each other
purpose only to the pod appointed for it), then the two record folders.
This server's step goes out first (the plan's section 5): a validator on
step 2 that asks a masterpod from before this step never hears one of the
two new roles and refuses every validator and masterPod stake. No new
table, no env variable, no npm package, no new route; no gate, no route
and no answer shape changes. The keyholders, the doormen and the signing
server are not touched. Nothing above this subsection changes except the
items under Files.

#### The two roles

The role check allows four names:

```sql
CHECK (role IN ('moderator', 'attestor', 'validator', 'masterPod'))
```

- `validator`: the pod may stake for the purpose validator.
- `masterPod`: the pod may stake for the purpose masterPod.

The two names are spelled exactly as the validators spell the two stake
purposes, so a validator goes on comparing a pod's role with the purpose
of a stake by `===` (the plan's decision 5). A stake for validator or
masterPod is recorded only: nothing on the validators, on this server or
on the keyholders reads it. What the list decides is who may make one.
From step 2 the receiving validator asks `/get-anos-account` for the
sending account's pod and refuses the stake unless the pod's role is the
purpose, as it does for moderator and attestor since 2026-11-08; without
that check the list would only hide two options in the wallet, and a
stake posted by hand would still pass (decision 4). From step 3 the wallet
reads `role` from `/check-anopod-status` and offers validator or masterPod
only to the pod appointed for it. The two answers keep their shape:
`role` is one of the four names or `null`.

`db/schema.sql` carries the check twice. The `CREATE TABLE` has it for a
database built from nothing. For a database that already has the table,
right after the block's `COMMENT ON` lines, stands the drop-and-add the
file already uses for `challenges_purpose_check` (12.3):

```sql
ALTER TABLE appointments DROP CONSTRAINT IF EXISTS appointments_role_check;
ALTER TABLE appointments ADD CONSTRAINT appointments_role_check
  CHECK (role IN ('moderator', 'attestor', 'validator', 'masterPod'));
```

`appointments_role_check` is the name PostgreSQL gave the column's check
when the table was made. Both lines are idempotent, so the whole file
applies to a live database. The rows already there stay as they are: the
check only got wider, and nothing changes for the moderators and attestors
already appointed.

Appointing is the operator's script, as for a moderator (16.3, decision
10):

```bash
npm run appoint -- <anopod id, 64 hex> validator
npm run appoint -- <anopod id, 64 hex> masterPod
```

The messages take the role's name: `<username> (<id>): appointed as
validator`, `<username> (<id>): is a validator; revoke first`. `npm run
revoke` ends an appointment whatever its role. A database that is dropped
loses its appointments, and they are made again by script.

#### One role per pod

One live role per pod stays (decision 3). The partial unique index
`appointments_one_live_per_pod` is as it was, so a pod holds one of the
four roles or none. A moderator or an attestor works from a pod made for
that work, apart from the personal one. A banker stakes for validator from
the personal pod. The masterPod stake comes from one pod made for it. The
user, 2026-11-10: "So we still only need 1 role per anopod." `appoint`
refuses a pod that holds another role: revoke first, then appoint.

#### The appointment opens nothing

An appointment as `validator` or `masterPod` opens no route on this server
(decision 6). It only lets the pod stake for that purpose. The gates ask
for their own role by name: `mustBeModerator` is `isAppointed(anopodId,
'moderator')` and `mustBeAttestor` is `isAppointed(anopodId, 'attestor')`
(16.2), so both stay shut to a pod that holds one of the two new roles.
`isAttestorPod` and `listAttestorPods` ask for `'attestor'` the same way,
so `/list-attestors` does not list such a pod and no case key is wrapped
to it. `src/auth/require-moderator.js` and `src/auth/require-attestor.js`
did not change.

#### Files

- `db/schema.sql`: in the `appointments` block, the role check of the
  `CREATE TABLE`, the drop-and-add after the `COMMENT ON` lines, the
  block's header comment and the comments of the table and of `role`; the
  file's opening comment names the block among the idempotent ALTERs.
- `scripts/appoint.js`: `ROLES`, the usage line, the header comment.
  `scripts/revoke.js`: the header comment.
- Comments only, no line of code:
  `src/appointments/appointments.queries.js` (the file comment,
  `findLiveRole`, `isAppointed`),
  `src/anos-accounts/anos-accounts.service.js` (`getAnosAccount`) and
  `src/anopods/anopods.service.js` (`status`).
- Here: section 4 (`### appointments`, the SQL and its sentence), section
  5 (the two answers), section 9 (the usage line), 16.1 (the SQL) and 16.3
  (the usage line), each of these two with a dated pointer, and this
  subsection. `README.md`: the scripts table, the tables list, the usage
  line of the Genesis section and the paragraph under it, the two folder
  list lines.

Nothing else in existing code changes. No table, no env variable, no npm
package, no new route.

#### Notes from the build (2026-11-10)

Built from
`~/Desktop/Z-TestNet/forclaude/validator-masterpod-stake-plan-1.md`
section 1, on main at 9310f46 (the account limit). No new npm package, no
test script and no rig (none was asked for). The schema was not applied to
any database for keeps: the user applies it, by psql as the superuser with
`SET ROLE masterpodsoftware`. Until then a database keeps its check of two
roles, and `npm run appoint -- <id> validator` is refused there by that
check. What the plan left open and how it was decided:

- The check's name was read with `\d appointments` on the local database
  before the two lines were written: `appointments_role_check`.
- The drop-and-add got a comment of four lines above it, as the two other
  ALTER pairs of the file have one; the plan gives the two lines only.
  The comment says that the pair is for a database that already has the
  table, and that it is idempotent.
- The file's opening comment now reads "the idempotent ALTERs of the
  appointments block and of the recovery, attestation and marketplace
  blocks at the end". The appointments block is not at the end of the
  file, so "at the end" stays with the three old blocks.
- The comment of `role` names the four and says what the last two do. The
  comment of the table names the three kinds of pod in the plan's words.
- In the header comment of `scripts/appoint.js`, "a pod holding the other
  role" became "another role". The one-line comment of `withArticle`
  still gives its two old examples ("a moderator" or "an attestor"); the
  plan does not name it, so it was left. For the new roles the function
  answers "a validator" and "a masterPod".
- The header comment of `scripts/revoke.js` now says what a revocation
  does for each kind of role: this server refuses a revoked moderator or
  attestor, and the two answers say `null` for the pod's role, whichever
  of the four it was.
- The comment of `getAnosAccount` names the four stakes the validators'
  appointment check is for, not only the four names of `role`: from step
  2 the validators ask at a validator or masterPod stake too.
- The two dated pointers, in 16.1 and 16.3, are a sentence in brackets
  right after the code block. The prose of 16.1 to 16.4 is as written on
  2026-11-08, for the two roles of that day.
- In section 4 the sentence also names the drop-and-add. In section 5
  only the two "Answer" paragraphs changed, and in section 9 only the
  usage line.
- In the README the paragraph under the usage line gained one sentence on
  the two new roles, and "appoint again for the other" became "for
  another".
- Places the plan does not name that still say two roles, left as they
  are and put to the user: in the README the rows of `/check-anopod-status`
  and `/get-anos-account` in the routes table and the sentence above the
  usage line of the Genesis section ("Moderators and attestors are
  appointed the same way"); here the same sentence in section 9, the
  first paragraph of `/get-anos-account` in section 5 ("before accepting
  a stake for moderator or attestor"), and 16.2 and 16.4.
- Checks (1.5): `node --check` on the five changed source files (the two
  scripts, `appointments.queries.js`, the two services), clean. The SQL
  by psql against the local `masterpod` database as the superuser `codex`
  with `SET LOCAL ROLE masterpodsoftware`, one transaction, rolled back.
  Before the two ALTER lines an insert with the role `validator` was
  refused by `appointments_role_check`, the check of two roles. Then the
  whole `appointments` block ran as the file has it (the table and the
  index skipped with their notices, the trigger and the eight comments
  overwritten, the two ALTER lines last), and the check read the four
  roles. An insert with the role `validator` for a throwaway pod id
  passed; a role of `guardian` was refused by `appointments_role_check`;
  a second live row for the first pod id, as `masterPod` with a later
  `appointed_at` (inside one transaction `now()` is one value, so a
  second insert at the default would hit the primary key first), was
  refused by `appointments_one_live_per_pod`. More than the plan asked,
  in the same transaction: `masterPod` passed for a second throwaway pod
  id, and `masterpod` in lower case was refused by the check; for the
  throwaway validator pod the query of `findLiveRole` answered
  `validator`, and the query of `isAppointed` answered false for
  `moderator` and for `attestor`, as the two gates ask it; and the block
  ran twice in a scratch schema, on a table built from nothing, which
  left one role check under the one name, with the four roles. After the
  rollback the table had its four rows (two moderators, two attestors),
  its check of two roles and its old comments as before, and the scratch
  schema was gone. The whole of `db/schema.sql` also ran once in a
  transaction of its own, rolled back, with no error, the way the user
  applies it. No server was booted and neither script was run, so
  `npm run appoint` with one of the new roles and the two routes'
  answers are the user's to see, after the schema is applied.
- Not touched: `src/auth/require-moderator.js`,
  `src/auth/require-attestor.js`, every router, handler and service line
  of code, `package.json`, the three shell scripts.

## 17. The account limit (2026-11-10)

Design settled 2026-11-10 in a planning chat of one round (the plan is
`~/Desktop/Z-TestNet/forclaude/account-limit-plan-1.md`, FINAL). Why:
nothing limited how many anos accounts one pod makes. Every account is a
row on this server and, once a validator accepts it, an account on every
validator's ledger for good. The user, 2026-11-10: "we should limit people
to 20 new accounts per month. A cap like that should not stop legitimate
use, but should stop spammers." A validator accepts a creation only when
this server answers, on `/get-anos-account`, that a vouched pod made the
account, and an account with no row here is dropped. So
`/create-anos-account` is the one gate, and a limit on it cannot be walked
around by posting to a validator: the limit sits on this route and nowhere
else. Two repos in order: this server (this section, step 1 of the plan:
one check in one route) and the wallet (its spec, 4.4 and 8.2, step 2: the
refusal said in one sentence), then the record folder
(`masterpod_software_architecture`, step 3). There is no schema step, no
env variable, no npm package and no new route. The validators, the
doormen, the keyholders and the signing server are not touched. Nothing
above this section changes except the items in 17.4.

### 17.1 The rule

- A pod may make at most 20 new anos accounts in a month.
- A month is the last 30 days, counted back from the moment of the
  request. Not a calendar month: that would allow 20 on the 31st and 20
  more on the 1st, and it needs a time zone.
- The accounts that a recovery opens count like any other. Its "Move your
  money" opens one new account for every old account that holds anos,
  through this same route.
- Every row of the pod's counts, also an account whose creation never
  reached a validator (`submitted_at` null). A row is a row, so unfinished
  creations cannot be used to fill the table.

### 17.2 The check

`createAnosAccount` (`src/anos-accounts/anos-accounts.service.js`) runs it
last. Every check up to and including the `409 account already registered`
for a known account id stays in front of it, so a repeated call for the
same account is still told that it exists. The two numbers are two
constants at the top of the file, `ACCOUNT_LIMIT = 20` and
`ACCOUNT_LIMIT_DAYS = 30`. They are not env variables: the user owns
`.env`, and a change of the number is one line and a restart either way.

The insert runs inside `withTransaction` (`src/db/transaction.js`), on the
one client. First `lockPod(client, anopodId)` holds the pod's own row for
the rest of the transaction:

```sql
SELECT 1 FROM anopods WHERE anopod_id = $1 FOR UPDATE
```

Then `countAccountsSince(client, anopodId, ACCOUNT_LIMIT_DAYS)` answers
the number of the pod's rows of the last 30 days:

```sql
SELECT count(*)::int AS count FROM anos_accounts
WHERE anopod_id = $1 AND created_at > now() - make_interval(days => $2)
```

When the count is `ACCOUNT_LIMIT` or more, the transaction ends with no
insert and the answer is `403 account limit reached`. Otherwise
`insertAccount(fields, client)` writes the row on the same client and the
answer is `201 { accountId }`, as before. A unique violation still answers
`409 account already registered`. The three queries are in
`src/anos-accounts/anos-accounts.queries.js`.

Why the lock: without it, requests of one pod sent at the same moment
would each count the same rows and all pass. With the pod's row locked
they wait for each other: the second counts only after the first has
ended, and its count sees the first one's row. The lock is on the pod's
own row in `anopods`, the way the case tables lock their row first with
`SELECT ... FOR UPDATE`. The refusal is a `403`: this server refuses with
400, 401, 403, 404 and 409, and its HAProxy edge answers 429 for its own
request rate, so 429 is left to the edge.

### 17.3 What is left as it is

- The wallet shows no counter and no "3 of 20". A person only hears of the
  limit when it refuses them, in one sentence: "This anoPod has reached
  the limit for new anos accounts. Try again later." It names no number,
  so it stays true when the constants change.
- Two leftovers are accepted, because no real person reaches the limit:
  - The wallet learns of the limit at the fourth of its six steps
    (`/create-anos-account`), after the break-glass seed went to the
    keyholders at the second. That seed stays with the keyholders,
    unused.
  - A recovery that needs more new accounts than the limit leaves stops
    at the limit with the same sentence. Retry works once the 30 days
    free up.

### 17.4 Files

- `src/anos-accounts/anos-accounts.queries.js`: `lockPod` and
  `countAccountsSince`, new; `insertAccount(fields, db = pool)` takes the
  client as a second argument and runs on it, the way `findAccount` takes
  `db`. `createAnosAccount` is its only caller.
- `src/anos-accounts/anos-accounts.service.js`: the two constants, and in
  `createAnosAccount` the transaction with the lock, the count and the
  insert; the function's comment gains the limit as the last check.
- Here: section 4 (`### anos_accounts`, one sentence), section 5 (`###
  POST /create-anos-account (setup)`, the last check and its refusal) and
  this section. `README.md`: the route row of `/create-anos-account`.

Nothing else in existing code changes: `/list-anos-accounts`,
`/mark-anos-account-submitted`, `/get-anos-account`, the router and the
schema are as they were. No env variable, no npm package, no new route.

### 17.5 Notes from the build

#### Build 1, the masterpod (2026-11-10)

Built from `~/Desktop/Z-TestNet/forclaude/account-limit-plan-1.md` section
1, on main at 0038d5f (the merge of testnet2prep). No new npm package, no
test script and no rig (none was asked for). Nothing was applied to any
database: there is no schema step. What the plan left open and how it was
decided:

- `lockPod` answers nothing, and `createAnosAccount` does not ask whether
  a row was locked: the route's level (`requireSetup`) read the pod's row
  a moment before, and the plan names no refusal for a row that is gone.
- The transaction answers `true` when the row went in and `false` at the
  limit, and the `403` is made right after it, the way `createAnopod`
  (`src/anopods/anopods.service.js`) answers its taken challenge. At the
  limit the transaction ends by `COMMIT` with nothing written
  (`withTransaction` rolls back only on a throw), which frees the lock
  just the same. A unique violation rolls the transaction back and is
  caught outside it, as before.
- The two constants sit after `keyBlobLength`, the last of the constants
  at the top, under one comment, and are not exported: nothing else reads
  them.
- `lockPod` and `countAccountsSince` sit in front of `insertAccount` in
  the queries file, in the plan's order. The service's import of the
  queries became a list over several lines, as `dao.service.js` writes
  its own: seven names on one line would be longer than any import line
  in `src`.
- `countAccountsSince` passes `days` as a plain number, and PostgreSQL
  reads the parameter as the integer that `make_interval(days => ...)`
  takes.
- In section 4 the sentence went on the paragraph under the SQL block,
  the one about the columns. In section 5 the check went on the end of
  the "Checks, in order" paragraph, with its dated sentence after it. The
  README row now ends "`409` on a repeat, `403` at the limit of 20 new
  accounts in 30 days".
- Checks (1.4): `node --check` on the two changed source files
  (`anos-accounts.queries.js`, `anos-accounts.service.js`), clean; every
  name the service imports from the queries file is exported there. The
  SQL by psql against the local `masterpod` database as the superuser
  `codex` with `SET LOCAL ROLE masterpodsoftware`, one transaction,
  rolled back: 20 rows inserted into `anos_accounts` for a throwaway pod
  id (one with no row in `anopods`) and one more row for it with
  `created_at` 31 days back, 21 rows in all; the query of
  `countAccountsSince` read 20 with 30 days, and 21 with 32 days, so it
  is the 30 days that leave the old row out. The query of `lockPod` ran
  for the throwaway id (no row) and for one real local pod (one row,
  held until the rollback). The parameters went untyped (`\bind`), as
  `pg` sends them. After the rollback the throwaway rows were gone and
  the table had its 10 rows as before. No server was booted, so the
  route itself was not called: the `403` over HTTP takes 21 accounts
  from one pod to see, and that run-through is the user's (the plan's
  section 4).
- Not touched: `anos-accounts.router.js`, `anos-accounts.handlers.js`,
  `db/schema.sql`, `package.json`, `.example.env`, every other feature
  folder; in the README everything but the one route row.

## 18. Case chats, the contact phone and the account count (2026-11-11)

Design settled 2026-11-11 and 2026-11-12 in a planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/wallet-case-chats-plan-1.md`, FINAL,
2026-11-12). It began with the user's list of changes found while testing.
Why the chat. The user, 2026-11-11: "All of the cases that attestors do
need to have a 'start chat button'. This is because at the very least, the
attestor needs to be able to talk to the user about when to schedule the
meeting." Why the recovery case: "Right now, when the attetestor opens a
recovery case, a case doesn't show up for the user in the cases section.
So there's no way for the user to even go to the meeting that the attestor
scheduled." Why the phone number: "The user should however be able to give
a phone number as well as the email. Probably an either / or. And the
moderator should be able to see both the email and phone number provided.
This is because people in thailand don't use email too much." Two repos in
order: this server (this section, step 1 of the plan: six small changes)
and the wallet (its spec, steps 2 to 6: Start chat on the three attestor
case pages, the recovery case on the person's Cases page, the phone box,
the recovery wait page, Invite an attestor in a marketplace chat), then
the record folder (`masterpod_software_architecture`) and the deploy notes
(step 7). This server's step goes out first (the plan's section 8).
Against a masterpod of before, the new wallet's Start chat makes a plain
private chat with no case on it, and a recovery opened with a phone number
alone is refused. The other way round nothing breaks: a wallet of before
leaves the new fields alone. No new route, no env variable and no npm
package. The validators, the doormen, the keyholders, the keyholder GUI,
the signing server and the wallet's proxy are not touched. Nothing above
this section changes except the items in 18.3.

### 18.1 The rule

- A room can be about a case. An appointed attestor starts a private chat
  with a person on an attestor case: an assisted trade case, an escrow
  dispute case, or a break-glass case, which is the recovery case as the
  attestors see it. The room is marked with its case (`chat_rooms.case_id`
  and `case_kind`), as a listing chat is marked with its listing, so the
  wallet can give the chat a title that says what it is for.
- Only an appointed attestor makes such a room, and only while the case is
  open or in review. The room takes only a person on that case or an
  appointed attestor, so the attestor who made it can bring a second
  attestor in.
- A case chat is a chat like any other once it is made. It stays when the
  case closes, and a closed case does not stop an invite.
- This server does not count the chats of a case. If an attestor makes two
  chats with one person on one case, both stand; the wallet looks for the
  chat it has.
- Either trader may bring an attestor into the marketplace chat of a
  trade. Until now only a room's creator invited, and in a listing chat
  the creator is the person who pressed Connect, not the listing's owner.
  Now a member of a listing chat who did not start it may invite too: an
  appointed attestor and nobody else. The other trader does not have to
  agree. The attestor reads the whole chat: a room has one room key, and
  `/list-messages` gives a member every message from the first.
- A dispute case names the attestors on it to its two traders, so the
  wallet can list whom to invite. The events a person sees still name no
  attestor.
- The person is told when a recovery case gets its video call: one
  notification, of a kind of its own. A decision and a dismissal show on
  the case page and send nothing.
- A recovery case takes a contact email and a contact phone, and the
  moderators see both. Both are required since 2026-11-12 (18.4): a
  moderator texts first, and the email is there when a text is not
  possible. As the plan had it and as build 1 built it, one of the two
  was enough. A phone is 6 to 32 characters: digits, spaces, `+`, `-` and
  round brackets, with at least 6 digits. It is kept as typed, in plain
  text like the email. The moderator's part of a recovery gets no chat:
  the person has no anoPod to chat from then.
- The recovery pod's answer says how many anos accounts the pod had when
  the case was opened: every `anos_accounts` row of it that is not newer
  than the case, in every status of the case. The wallet's wait page uses
  it to know how many account keys to wait for. That is the count since
  2026-11-12 (18.4). As the plan had it and as build 1 built it, every
  row of the pod's counted, also the new accounts that the finish of the
  recovery makes.

### 18.2 The changes by route

The objects and the checks in full are in the sections named here.

- `/create-chat-room` (setup; section 5): the body takes an optional
  `caseId`. Its checks run after the existing ones and after those of
  `listingId`: `400 bad request shape`, `400 public rooms have no case`,
  `400 a room is about a listing or a case`, `403 not an attestor`, `404
  unknown case`, `409 case closed`. The room is written with `case_id` and
  `case_kind`. The answer stays `201 { chatRoomId }`.
- `/invite-to-chat-room` (setup; section 5): a member of a listing chat
  who is not its creator may invite an appointed attestor; everyone else
  who is not the creator still gets `403 only the creator invites`. On a
  room with a `case_id` the target is a party to the case or an appointed
  attestor, else `403 not a party to the case`, right after `400 invalid
  anopodIdTo`. The body and the answer stay.
- `/list-chat-rooms` (setup; section 5): every room and every invite
  carries `caseId` and `caseKind`, both null on a room without a case.
- `/schedule-break-glass-case` (attestor; 14.4.2 and 14.7): one
  notification to the recovered pod, kind `recoveryCaseScheduled`,
  reference the case id, under the case lock, after the `scheduled` event.
- `/open-recovery-case` (none; 12.4.2): a `contactPhone` is taken beside
  `contactEmail`, and both are required (2026-11-12, 18.4). Check 1 takes
  each of the two absent, null or a string. Check 6 answers
  `400 contactEmail and contactPhone required` when one of the two is
  absent or null, then `400 invalid contactEmail` or
  `400 invalid contactPhone` for one that is not valid. The case row is
  written with both. As build 1 built it, `contactEmail` was optional,
  check 6 answered `400 contactEmail or contactPhone required` only when
  both were absent or null, and the row took null for the one not given.
- `/get-recovery-pod` (recovery; 12.4.3): `contactPhone` beside
  `contactEmail`, each a string or null; and `anosAccounts`, a number:
  the pod's anos accounts made up to the opening of the case (2026-11-12,
  18.4; as build 1 built it, every anos account of the pod's).
- `/list-recovery-cases` and `/get-recovery-case` (moderator; 12.4.4):
  `contactPhone` beside `contactEmail`, on each case of the list and on
  `case`.
- `/list-my-cases` and `/get-my-case` (setup; 13.4.5): a dispute case
  carries `attestors`, a list of `{ anopodId, username }`. A trade case
  gains nothing.

The schema, `db/schema.sql` (section 4 and 12.3). `chat_rooms` gains
`case_id`, `case_kind` and the named check `chat_rooms_case_check`.
`notifications` takes the kind `recoveryCaseScheduled`, in the table and
in the ALTER pair that drops and adds `notifications_kind_check`.
`recovery_cases` gains `contact_phone` and the named check
`recovery_cases_contact_check`, and `contact_email` loses its `NOT NULL`.
The `CREATE TABLE` texts carry all of it for a database built from
nothing. For a database that already has the tables, a new block at the
end of the file, "The case chat block (2026-11-11)", does the same in the
style of the marketplace block:

```sql
ALTER TABLE chat_rooms ADD COLUMN IF NOT EXISTS case_id BYTEA CHECK (octet_length(case_id) = 32);
ALTER TABLE chat_rooms ADD COLUMN IF NOT EXISTS case_kind TEXT CHECK (case_kind IN ('trade', 'dispute', 'recovery'));
ALTER TABLE chat_rooms DROP CONSTRAINT IF EXISTS chat_rooms_case_check;
ALTER TABLE chat_rooms ADD CONSTRAINT chat_rooms_case_check
  CHECK ((case_id IS NULL) = (case_kind IS NULL) AND (case_id IS NULL OR (type = 'private' AND listing_id IS NULL)));
ALTER TABLE recovery_cases ADD COLUMN IF NOT EXISTS contact_phone TEXT
  CHECK (char_length(contact_phone) BETWEEN 6 AND 32 AND contact_phone ~ '^[0-9 +()-]+$'
         AND char_length(regexp_replace(contact_phone, '[^0-9]', '', 'g')) >= 6);
ALTER TABLE recovery_cases ALTER COLUMN contact_email DROP NOT NULL;
ALTER TABLE recovery_cases DROP CONSTRAINT IF EXISTS recovery_cases_contact_check;
ALTER TABLE recovery_cases ADD CONSTRAINT recovery_cases_contact_check
  CHECK (contact_email IS NOT NULL OR contact_phone IS NOT NULL);
```

Every line is idempotent, so the whole file applies to a live database and
a second run changes nothing. The comments of the three new columns are in
that block only, after the columns exist on a live database. There is no
index: nothing reads a room by its case.

### 18.3 Files

- `db/schema.sql`: the columns, the checks, the kind and the block, as
  above; the table comment of `chat_rooms`, the comment of
  `chat_room_invites.anopod_id_from`, the comment before `recovery_cases`,
  its table comment and the comment of `contact_email`; the file's opening
  comment, which names the new block among the idempotent ALTERs; and, on
  the user's word after the build, the comments of `notifications.kind`
  and `notifications.reference_id` and the comment above the ALTER pair of
  `notifications_kind_check`.
- `src/chat/chat.service.js`: `caseOf`, new; `createRoom`; `invite`.
- `src/chat/chat.queries.js`: `insertRoom`, `findRoom`, `listRoomsFor`,
  `listInvitesFor`.
- `src/break-glass/break-glass.service.js`: `scheduleBreakGlassCase`.
- `src/recovery/recovery.service.js`: `isContactPhone`, new;
  `openRecoveryCase`, `getRecoveryPod`, `listRecoveryCases`,
  `getRecoveryCase`.
- `src/recovery/recovery-cases.queries.js`: `COLUMNS`, `caseRow`,
  `insertCase`, the select of `listByStatus`.
- `src/anos-accounts/anos-accounts.queries.js`: `countAccountsOf`, new.
- `src/attesting/attesting.service.js`: `disputeAttestors`, new;
  `personDispute`, `listMyCases`, `getMyCase`; the comment of
  `PERSON_EVENTS`.
- A comment each and no line of code, on the user's word after the build:
  `src/auth/require-attestor.js` (`isAttestorPod`, its new callers) and
  `src/notifications/notifications.queries.js` (`notify`, sixteen kinds).
- Here: section 4 (`### chat_rooms`, `### notifications`, `###
  chat_room_invites, chat_room_join_requests`), section 5 (the three chat
  routes), section 6 (the new kind), 12.3 and 12.4 (`recovery_cases` and
  the four recovery routes), 13.4.5 (the person's two routes), 14.4.2 and
  14.7, and this section; and, on the user's word after the build, 12.1
  (steps 1 and 2), 14.1 (step 6), 14.9, and the five case kinds in section
  4's SQL and in section 6's table. `README.md`: the rows of the ten
  routes, and the lines of `chat_rooms`, `recovery_cases` and
  `notifications` in the tables table; and, on the user's word, the
  break-glass line of "Deferred, by decision".

Nothing else in existing code changes. No new route, no env variable, no
npm package.

### 18.4 Notes from the build

#### Build 1, the masterpod (2026-11-12)

Built from `~/Desktop/Z-TestNet/forclaude/wallet-case-chats-plan-1.md`
section 1, on main at 2a12e91, the merge of pull request 6. Its files are
those of 97b94ab, the commit the plan read. No new npm package, no test
script and no rig (none was asked for). The schema was not applied to any
database for keeps: the user applies the whole file by psql as the
superuser with `SET ROLE masterpodsoftware`, as 13.10 records. It goes on
before this code runs: a masterpod on this code against a database
without the new columns fails every read of a chat room and of a recovery
case. What the plan left open and how it was decided:

- The date. The comments and this section carry 2026-11-11, the day of the
  design, as the block's name does in the plan. The build ran on
  2026-11-12.
- `db/schema.sql`. In the `CREATE TABLE` of `chat_rooms` the two columns
  sit after `listing_id` and the named check after the table's unnamed
  one. In that of `recovery_cases`, `contact_phone` sits after
  `contact_email` and the named check after `updated_at`. On a live
  database `ADD COLUMN` puts a new column last; no code reads a column by
  its place. The three column checks get the names PostgreSQL gives them,
  `chat_rooms_case_id_check`, `chat_rooms_case_kind_check` and
  `recovery_cases_contact_phone_check`, the same on a database built from
  nothing and on a live one. The opening comment now reads "attestation,
  marketplace and case chat blocks at the end".
- `/create-chat-room`. `caseId: null` counts as absent, as `listingId:
  null` does. "A `listingId` in the same body" is a `listingId` that
  passed its own checks, since those run first: a body whose `listingId`
  fails them answers the listing's refusal. `caseOf` asks the three tables
  one after the other, each through its own feature's read, and stops at
  the first row. It writes the kind as the plain words `trade`, `dispute`
  and `recovery`: the attesting service's `TRADE` and `DISPUTE` are
  private to that file.
- `/invite-to-chat-room`. The decoding of `anopodIdTo` moved up, in front
  of the question of who may invite, which needs it now. The creator's
  refusals keep their order: `400 invalid anopodIdTo` still comes after
  `400 marketplace rooms take join requests`. For a caller who is not the
  creator, the membership is asked before the target's appointment. The
  rule is as the plan words it, so any member who is not the creator may
  bring an attestor into a listing chat, also an attestor who was brought
  in earlier. On a case chat whose case row is gone (never, in practice:
  no case is deleted) nobody is a party, and only an attestor can be
  invited.
- `roomAboutListingBy` (`chat.queries.js`) answers a room without the two
  new fields. The plan does not name it. A room about a listing has no
  case, by the table's check, and its one caller asks only whether a room
  came back.
- `/list-chat-rooms`. `caseId` and `caseKind` follow `listing`, in a room
  and in an invite.
- `/schedule-break-glass-case`. The notification is written right after
  the `scheduled` event and before the status, in the one transaction
  under the lock. A second schedule on a case in review writes a second
  event and a second notification, as `/schedule-attestor-case` does with
  `caseScheduled`.
- `/open-recovery-case`. An empty string is a string: it passes check 1
  and is `400 invalid contactEmail` or `400 invalid contactPhone` at check
  6. In check 6 the order is the lookup id, the refusal for no contact at
  all, the email, the phone, then the hybrid key and its blob, so the
  email keeps the place it had. `isContactPhone` is the column's check in
  JavaScript. It measures `value.length`, which is the count of characters
  here, because the pattern takes ASCII only. The server stores the phone
  as sent and does not trim it; the wallet trims.
- `/get-recovery-pod`. `countAccountsOf(anopodId)` has the plan's
  signature and runs on the pool's `query`, as `listAccountsOf` beside it
  does. The service runs it in the same `Promise.all` as its three other
  reads. It counts every row, also an account whose creation never reached
  a validator (the plan's decision 21). `anosAccounts` follows `lookupId`
  in the answer.
- `/list-my-cases` and `/get-my-case`. `disputeAttestors(dispute)` sits
  between `personTrade` and `personDispute` and reads the case's events
  itself. So `/get-my-case` reads them twice: once without usernames for
  the person's events, as before, and once for the list. A pod is looked
  at once, at its first event, and `isAttestorPod` is asked once for it.
  `username` is the event's join on `anopods`, null when the pod's row is
  gone (never, in practice). `/list-my-cases` builds its disputes one
  after the other, as `/list-my-break-glass-moves` builds its cases.
  `attestors` follows `side` in the object.
- Here. Section 4's SQL of `notifications` had the ten kinds of 2026-10-24
  and never took the five case kinds, which 13.3 adds by its ALTER, and
  section 6's table had the same ten. The build put only the new kind
  into each, as the plan says, and put the gap to the user. On the user's
  word both now have all sixteen kinds, as the file does; the five are
  still in 13.3 and 13.7 too. In section 5 the checks of
  `/invite-to-chat-room` now name `400 invalid anopodIdTo`, which the code
  always had, because the new check stands right after it.
- Checks (1.10): `node --check` on the seven changed source files
  (`chat.service.js`, `chat.queries.js`, `break-glass.service.js`,
  `recovery.service.js`, `recovery-cases.queries.js`,
  `anos-accounts.queries.js`, `attesting.service.js`), clean, and at the
  end on `require-attestor.js` and `notifications.queries.js` too, the
  two files in which only a comment changed. The schema
  by psql against the local `masterpod` database as the superuser `codex`
  with `SET LOCAL ROLE masterpodsoftware`, one transaction, rolled back:
  the whole file ran twice with no error. That database is of before this
  step (36 tables, no case columns, `contact_email NOT NULL`), so this is
  the run a live database gets. After the first run `chat_rooms` had the
  two columns, their two checks and `chat_rooms_case_check`;
  `recovery_cases` had `contact_phone` with its check, a nullable
  `contact_email` and `recovery_cases_contact_check`; and
  `notifications_kind_check` had sixteen kinds. The second run changed
  nothing: one fingerprint over every column, check, index, trigger and
  comment of the schema was the same after both runs, and each named check
  was there once. On that database every `CREATE TABLE` is skipped, so the
  texts for a database built from nothing do not run there. For them the
  file ran twice more inside the same transaction, into an empty scratch
  schema (`SET LOCAL search_path`): the 36 tables built from nothing came
  out equal to the live ones after their two runs, with no check, column
  or comment that differs. After the rollback the database was as before:
  the fingerprint of before, no scratch schema, no case columns. No row
  was written, no server was booted and no route was called. The routes
  are the user's to see, with the wallet's steps 2 to 6.
- Places the plan does not name that this step left out of date. The
  build left them as they were, listed them and asked. The user: "Yes,
  update them". They were brought in line before the commit, each with as
  little change as it takes. In `db/schema.sql`: the comment of
  `notifications.kind` names the new kind, the comment of
  `notifications.reference_id` names a `break_glass_cases` row, and the
  comment above the ALTER pair names the kind beside the five case kinds.
  In the code, a comment each: `isAttestorPod`
  (`src/auth/require-attestor.js`) names its new callers, and `notify`
  (`src/notifications/notifications.queries.js`) says sixteen kinds where
  it said ten, which had been out of date since 2026-10-26 (13.10). Here:
  12.1, steps 1 and 2, speak of the contact email or phone; 14.1, step 6,
  says that one notification is sent; 14.9 keeps as deferred only what is
  still not built; and the five case kinds are in section 4's SQL and in
  section 6's table. In the README: the break-glass line of "Deferred, by
  decision". After these the checks of 1.10 ran once more, on the files
  as committed.
- Not touched: every router and handler, `src/marketplace/`,
  `src/appointments/`, `package.json`, `.example.env`, the scripts. In
  `src/auth/` and `src/notifications/` one comment each changed and no
  line of code.

#### The account count and both contacts (2026-11-12)

Two changes the user decided on 2026-11-12, after the plan was final and
its seven steps were committed (this server's step as 68c35da). Built the
same day in one chat from that chat's brief, on main at 68c35da, the
working tree clean: one commit here and one in the wallet (its spec, 12.3
and section 11). No schema step, no new route, no env variable and no npm
package. The validators, the doormen, the keyholders, the signing server
and the wallet's proxy are not touched.

The account count. The plan's 1.7 and its decision 21 had `anosAccounts`
count every `anos_accounts` row of the recovered pod, and build 1 built
that. It was a mistake in the plan, not in the build. The finish's step
Move your money makes a new account for each old account that holds anos
(`/create-anos-account`), so the number went up in the middle of the
finish, while the bankers' shares in the case are for the old accounts
only. The wallet's wait page takes the number as the account keys to wait
for: its line turned to, for instance, "2 of 4 account keys are
complete", and after a reload the finish did not come back. The user,
2026-11-12: "I feel like fix 1 is safe to do, we don't need to worry
about side effects because it's just changing a read." Fix 1 is the name
the planning chat gave this change.

- `countAccountsOf(anopodId, caseId)`
  (`src/anos-accounts/anos-accounts.queries.js`) takes the case's id as a
  second argument. A row counts when its `created_at` is not after the
  `created_at` of the case's `recovery_cases` row:

  ```sql
  SELECT count(*)::int AS count FROM anos_accounts
  WHERE anopod_id = $1
    AND created_at <= (SELECT created_at FROM recovery_cases WHERE case_id = $2)
  ```

  The two times are compared in the SQL. Read into JavaScript each would
  be a `Date`, which keeps the milliseconds and drops the microseconds.
- `getRecoveryPod` (`src/recovery/recovery.service.js`) passes
  `recoveryCase.caseId` as that argument. The answer still carries
  `anosAccounts`, a number, in every status, in its place after
  `lookupId`. Nothing else on the wire changed. The wallet's code did not
  change; the sentences there that said what the number is did.
- Where the brief was silent. The function keeps its name and its first
  argument, and still runs on the pool's `query`, in the service's
  `Promise.all`. The case's time is read by a subquery on the case's
  primary key, inside the one statement. "Not after" is `<=`, so an
  account made at the very time of the case counts. A case id with no
  row makes the comparison null and the count 0 (never, here: the
  route's level has just read the case). An account whose creation never
  reached a validator still counts when it is not newer than the case,
  as in build 1. No index was added: the rows are found by `anopod_id`,
  which has one.

Both contacts. The plan's decision 8 let a person give an email or a
phone, at least one of the two, and build 1 built that. The user,
2026-11-12: "And a phone and not just an email would be great. Thai
people, for example, would great prefer text. However, both should be
required, in case text isn't available." So a recovery case is opened
with a contact email and a contact phone, both: a moderator texts first,
and the email is there when a text is not possible. This takes the place
of decision 8.

- `openRecoveryCase` (`src/recovery/recovery.service.js`), check 6: a
  payload without a `contactEmail` or without a `contactPhone`, absent or
  null, is refused with `400 contactEmail and contactPhone required`. It
  takes the place of `400 contactEmail or contactPhone required`, which
  no code answers any more. Then each one is checked as before:
  `400 invalid contactEmail`, `400 invalid contactPhone`. The order in
  check 6 is as it was: the lookup id, the refusal for a missing
  contact, the email, the phone, the hybrid key and its blob.
- The reason's words are this build's pick. The brief asked for one
  reason that says both are required and left the words open: they are
  the old reason with "and" for "or".
- Check 1 did not change: each of the two is absent, null or a string,
  else `400 bad request shape`. So a missing contact gets the new
  reason, not the shape's. An empty string is still a string: it passes
  check 1 and the new refusal, and is `400 invalid contactEmail` or
  `400 invalid contactPhone`.
- The two lines after the new refusal still begin with `contactEmail !==
  null &&` and `contactPhone !== null &&`. That half is always true now.
  The lines were left as they are: the brief has each contact "checked
  as today".
- `db/schema.sql` was not touched, by the brief: not a column, not a
  check, not a comment. A database may hold cases of before with one
  contact, so each column still takes a null and
  `recovery_cases_contact_check` is still at least one of the two. The
  rule lives in this route and in the wallet's form. The file has the
  1332 lines and the sha256 it had after build 1 (it begins efbf9f8d),
  so the numbers in the deploy notes stand.
- The three reads did not change: `/get-recovery-pod`,
  `/list-recovery-cases` and `/get-recovery-case` answer each contact as
  a string or null.
- Comments: that of `openRecoveryCase` and of its check 6, and that of
  `insertCase` (`src/recovery/recovery-cases.queries.js`), which said
  "null for the one the person did not give". The comment of `caseRow`
  in that file stays: a row's two contacts are each a string or null, at
  least one of them a string, and that is what the table holds.
- The order of a deploy. A wallet that sends both contacts works against
  a masterpod of before build 1: that one keeps the email and drops the
  phone without a word. The other way round does not work any more. A
  wallet of before the plan's step 4 sends the email alone, and this
  server refuses it with the new reason, so between this server's deploy
  and the wallet's nobody opens a recovery case. The plan's section 8
  said that a wallet of before breaks nothing against the new masterpod;
  for `/open-recovery-case` that no longer holds.

Here: 12.1 (steps 1 and 2), 12.3 (the paragraph of `recovery_cases`),
12.4.2 (`/open-recovery-case`: the sentence under the body, check 6, the
writes), 12.4.3 (`/get-recovery-pod`), 18.1 (its last two points), 18.2
(the lines of the two routes) and this note. `README.md`: the rows of
`/open-recovery-case` and `/get-recovery-pod`, and the line of
`recovery_cases` in the tables table. Everything else in section 18 is
as build 1 left it, its notes above included: they say what was built
then.

Checks: `node --check` on the three changed source files
(`anos-accounts.queries.js`, `recovery.service.js`,
`recovery-cases.queries.js`), clean. The count's statement by psql
against the local PostgreSQL as the superuser `codex` with `SET LOCAL
ROLE masterpodsoftware`, in one transaction that was rolled back: the
whole `db/schema.sql` built from nothing into a scratch schema (`SET
LOCAL search_path`), 36 tables; one case opened at 12:00:00.123456 for a
pod with five accounts, made a day before, 56 microseconds before, at the
very time of the case, one microsecond after and an hour after, and one
account of another pod; the statement, its two parameters untyped
(`\bind`) as `pg` sends them, answered 3. It answered 0 for a case id
with no row and 0 for a pod with no account. With the case's time cut to
the millisecond, as a `Date` would hold it, the same comparison answered
1. After the rollback there was no scratch schema and the local database
had its 36 tables. A first try of that run stopped on a quoting mistake
in the check's own file, before the statement ran, and kept nothing
either. No server was booted and no route was called: the run-through is
the user's, with the wallet.

## 19. More than one passkey (2026-11-18)

Design settled 2026-11-17 and 2026-11-18 in a planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/add-passkey-plan-1.md`, FINAL, 2026-11-18).
Why: an anoPod has one passkey. A moderator or an attestor who unlocks with
a YubiKey has no spare, so a lost key means the long recovery. A person who
made their anoPod with a Google passkey and uses Apple devices cannot
unlock in Safari with Face ID. The user: "I'm mostly thinking about yubi
keys, and adding an apple key when you made your account with a google key
for people with apple products. Because people on android already have
their email shared anyways." So a person can add passkeys to their anoPod:
every passkey unlocks the same anoPod and opens the same accounts. Two
repos in order: this server (this section, step 1 of the plan: one table,
two routes, and one change each in `/challenge`, `/unlock` and the finish
of a recovery) and the wallet (its spec, step 2: unlocking with an added
passkey, and the Passkeys page), then the record folders (step 3). This
server's step goes out first (the plan's section 4). With this server
alone deployed nothing changes for anyone: no wallet calls the new routes,
so no added passkey exists. A new wallet against a masterpod of before
shows the refusal on its Passkeys page and works as before everywhere
else. One new env variable, which has the decided value as its default, so
the servers' `.env` needs no line. No npm package. The validators, the
doormen, the keyholders, the keyholder GUI, the signing server and the
wallet's proxy are not touched. Two things the plan does not list were
added on the user's word the same day, after the build's report (19.6):
`/create-anopod` and `/open-recovery-case` look a new passkey's credential
id up in the other passkey tables (19.3), and the places the step had left
out of date were brought in line. For a real passkey the lookups change
nothing: an authenticator makes a new credential id at every registration.
Nothing above this section changes except the items in 19.5.

### 19.1 The rule

A passkey does two jobs. It signs this server's challenge, which proves who
is there. And it gives the wallet a secret that never leaves the device,
the PRF output. Two keys come from that secret: `KEK_prf`, which opens
`blob1` and so the encryption key, and the key blob key, which opens every
account's key blob (the wallet's spec, section 7).

```
main passkey's secret  -+-> KEK_prf opens blob1 (anopods row) ----> the encryption key
                        +-> is the key blob key ------------------> every key blob

added passkey's secret -+-> KEK_prf opens its own blob1 ----------> the same encryption key
                        +-> opens its own wrapped_key_blob_key ---> the same key blob key
```

- A pod can have more than one passkey. Every passkey of a pod unlocks
  that pod and opens the same two keys.
- Nothing a person has already encrypted changes (the plan's decision 2).
  No key blob, no `blob1` and no row of a live pod is rewritten. The first
  passkey stays on the pod's `anopods` row: it is the main passkey. The pod
  keeps the key blob key it has, the one made from the main passkey's PRF
  output. An added passkey is a row of `added_passkeys` (19.2) with its
  own locked copies: the pod's encryption key under its own `KEK_prf`, and
  the pod's key blob key under a key from its own PRF output (section 7).
  This server can open neither.
- The key blob key stays reachable only through a passkey. The encryption
  key, the backup code, the keyholders' shares and this server's stored
  blobs still lead to no signing key (the rule of the break-glass plan,
  section 14).
- Adding needs a fresh tap of a passkey the pod already has, inside the
  add request (decision 3): the session alone does not add a passkey. The
  tap may be by any passkey the pod has, the main one or an added one
  (decision 10).
- One challenge serves both passkey steps of an add, the fresh tap and the
  new passkey's registration, and is tied to the pod it was asked for. It
  lives ten minutes, `ADD_PASSKEY_CHALLENGE_SECONDS` (decision 6): an add
  takes three taps and maybe a new PIN on a security key. The other
  challenges stay at two minutes.
- No route removes a passkey (decision 4), and there is no cap on how many
  a pod has (decision 8).
- The pod is told: one notification per add, kind `passkeyAdded`
  (decision 7; 19.4).
- Everyone whose setup is done may list and add (decision 10): both routes
  are at level setup, for the wallet and for its moderator and attestor
  editions alike.
- The finish of a recovery deletes the pod's added passkeys with the old
  main one (decision 10): one that survived could still open the old key
  blobs.
- A credential id belongs to one passkey of one pod. Three tables hold
  one, each with its own unique key: `anopods` (the main passkey),
  `recovery_pods` (the recovery passkey of a case) and `added_passkeys`. A
  route that writes a new one first looks where a second row with it would
  hurt somebody: `/add-passkey` in `anopods` and `added_passkeys` (the
  plan's check 7), `/create-anopod` in `added_passkeys` and
  `recovery_pods`, and `/open-recovery-case` in `added_passkeys`. The last
  two are not in the plan; they were added on the user's word the same day
  (19.3 and 19.6).
- No QR code work (decision 5). The QR code is a choice in the browser's
  own passkey box; nothing here blocks it, tests it or points people to
  it.
- The old page guard (decision 11; the user: "Keep the guard"). A pod has
  one key blob key for all its accounts, and every passkey has to arrive
  at that same key. A wallet page loaded before the wallet's step does not
  know the locked copy of it. If it unlocked with an added passkey it
  would make a second key blob key from that passkey's secret, one that
  nothing in the pod is locked with: every account would show as lost with
  the old passkey, and an account made there would be locked under a key
  the main passkey cannot make. So the new wallet says `addedPasskeys:
  true` in its `/unlock` payload, and this server refuses an added passkey
  without it: `409 reload the wallet`. An old page keeps working with the
  main passkey.

### 19.2 The table

`db/schema.sql`, a new block after the case chat block, the last thing in
the file: "The added passkeys block (added 2026-11-18, spec section 19)".

```sql
CREATE TABLE IF NOT EXISTS added_passkeys (
  passkey_id                   BYTEA       PRIMARY KEY CHECK (octet_length(passkey_id) = 32),
  anopod_id                    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  pass_key_credential_id       BYTEA       NOT NULL UNIQUE CHECK (octet_length(pass_key_credential_id) BETWEEN 16 AND 1023),
  pass_key_public_key          BYTEA       NOT NULL CHECK (octet_length(pass_key_public_key) <= 1024),
  anopod_encryption_key_blob_1 BYTEA       NOT NULL CHECK (octet_length(anopod_encryption_key_blob_1) BETWEEN 1 AND 1024),
  wrapped_key_blob_key         BYTEA       NOT NULL CHECK (octet_length(wrapped_key_blob_key) BETWEEN 1 AND 1024),
  created_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS added_passkeys_pass_key_public_key_key ON added_passkeys (sha256(pass_key_public_key));
CREATE INDEX IF NOT EXISTS added_passkeys_anopod_id_created_at_idx ON added_passkeys (anopod_id, created_at);
```

One row per passkey a pod added after its first: the passkey, and its own
copies of the pod's encryption key and key blob key. Inserted by
`/add-passkey`; deleted, all of the pod's, by the finish of a recovery.
Never updated, so it has no `updated_at` and no trigger. Stand-alone; no
foreign keys.

- `passkey_id`: random id, 32 raw bytes, minted by `/add-passkey`. The
  wallet keys the passkey's name by it. The names are in the wallet
  settings (the wallet's spec, 4.7), which this server cannot read, so the
  table has no name.
- `anopod_id`: the pod the passkey unlocks. Also the passkey's user
  handle.
- `pass_key_credential_id`: the WebAuthn credential id of the added
  passkey, raw bytes, 16 to 1023 as on `anopods`, unique in this table.
  `/unlock` finds the row by it when no `anopods` row has it.
- `pass_key_public_key`: the added passkey's COSE public key, as the
  WebAuthn library returns it at registration. Unique in this table by the
  index on `sha256(pass_key_public_key)`, as on `anopods`.
- `anopod_encryption_key_blob_1`: the pod's encryption key wrapped under
  this passkey's PRF-derived key, `KEK_prf` (`iv || ciphertext || tag`, 60
  bytes). The server cannot open it; `/unlock` hands it back as `blob1`.
- `wrapped_key_blob_key`: the pod's key blob key wrapped under a key from
  this passkey's PRF output (section 7; 60 bytes). The server cannot open
  it; `/unlock` hands it back as `wrappedKeyBlobKey`.
- `created_at`: when the row was inserted (the add). Set by default, never
  changed.

The second index serves the list and the delete, which both go by
`anopod_id`.

Two checks are widened, each in two places: inline in its `CREATE TABLE`,
for a database built from nothing, and in the drop-and-add pair of its
named check further down the file, for a database that has the table.
`challenges.purpose` takes `addPasskey` (`challenges_purpose_check`), and
`notifications.kind` takes `passkeyAdded` (`notifications_kind_check`). On
`anopods` only comments change: "the one passkey" reads "the main passkey
(the added ones are in added_passkeys)" in the header comment and in the
table's comment, and the comment of `pass_key_credential_id` says where an
added passkey is found. No column of `anopods` changes. Every line is
idempotent, so the whole file applies to a live database and a second run
changes nothing.

### 19.3 The changes by route

**POST /challenge** (none; section 5 and 12.4.2), a sixth purpose,
`addPasskey`.

Body: `{ purpose: "addPasskey", anopodId }`, the pod the passkey is added
to.

Checks, those of `openCase` in its order: `anopodId` is a string, else
`400 bad request shape`; it is 32 bytes, else `400 invalid anopodId`; it is
a pod's id, else `404 unknown anopod`. Since 2026-11-18 (20.2) `openCase`
has three checks more, those of the lookup id; `addPasskey` has none of
them.

Writes: the challenge row with purpose `addPasskey`, bound to that pod,
with `expires_at = now() + ADD_PASSKEY_CHALLENGE_SECONDS` (600); the
expired rows swept, as at every issue.

Answer: `200 { challenge, expiresAt, anopodId }`. It carries no
`username`: that stays `openCase`'s alone. The route stays at level none: a
challenge for an add is useless without the pod's session and one of its
passkeys. The five other purposes are untouched and keep
`CHALLENGE_SECONDS`.

**POST /add-passkey** (setup), new.

Body:

```json
{
  "challenge":         "<hex, from /challenge addPasskey>",
  "assertion":         { "...": "the fresh tap: the authentication PublicKeyCredential.toJSON()" },
  "passkey":           { "...": "the new passkey: the registration PublicKeyCredential.toJSON()" },
  "blob1":             "<hex, 60 bytes>",
  "wrappedKeyBlobKey": "<hex, 60 bytes>"
}
```

`assertion` is as `/unlock` takes it and `passkey` as `/create-anopod`
takes it (section 5). The wallet removes the PRF output
(`clientExtensionResults.prf.results`) from both, and the registration
keeps `prf.enabled`. `blob1` is the pod's encryption key under the new
passkey's `KEK_prf`. `wrappedKeyBlobKey` is the pod's key blob key under
the key of section 7. The wallet makes both from the PRF output of a
sign-in with the new passkey, its third tap (the wallet's spec).

Checks, in order:

1. Shape: `challenge`, `blob1` and `wrappedKeyBlobKey` strings; `assertion`
   an object with an object `response`; `passkey` an object. Else `400 bad
   request shape`.
2. `blob1` 1 to 1024 bytes, else `400 invalid blob1`. `wrappedKeyBlobKey` 1
   to 1024 bytes, else `400 invalid wrappedKeyBlobKey`.
3. The challenge decodes, was issued for `addPasskey`, is unexpired and is
   bound to the caller's pod; else `401 unknown or expired challenge`.
4. No PRF output in the assertion or in the registration, else `400 prf
   output in request`. The registration reports `prf.enabled`, else `400
   passkey without prf`.
5. The fresh tap. The assertion's credential id (`rawId`, base64url) is the
   caller's main passkey (`anopods.pass_key_credential_id`) or an
   `added_passkeys` row of the caller's pod; else `401 unknown passkey`.
   When `response.userHandle` is there it equals the pod's id; else `401
   user handle mismatch`. The library verifies the assertion against that
   passkey's public key and the challenge, as `/unlock` does; else `401
   passkey verification failed`, the reason logged.
6. The new passkey. The library verifies the registration against the same
   challenge, as `/create-anopod` does, and the credential id is 16 to 1023
   bytes; else `401 passkey verification failed`, the reason logged.
7. The new credential id is on no `anopods` row and on no `added_passkeys`
   row; else `409 passkey already registered`.

Writes, one transaction: the challenge taken (gone meanwhile: `401 unknown
or expired challenge`); `INSERT INTO added_passkeys` with a fresh
`passkey_id`; one notification to the pod, kind `passkeyAdded`, reference
the `passkey_id` (19.4). A unique violation answers `409 passkey already
registered`.

Answer: `201 { passkeyId, credentialId, createdAt }`, the two ids hex and
`createdAt` ISO 8601.

**POST /list-passkeys** (setup), new.

Body: `{ }`.

Reads: the caller's row and its `added_passkeys` rows, oldest first
(`ORDER BY created_at, passkey_id`).

Answer: `200 { main: { credentialId }, added: [ { passkeyId, credentialId,
createdAt } ] }`. Credential ids are hex, like every id. `main` is the
passkey on the caller's `anopods` row. It carries no date: the row does not
record when a recovery replaced it. `added` is an empty list for a pod
that never added one.

**POST /unlock** (none, signed by the ephemeral keys inside; section 5),
three changes and nothing else.

Body: the payload may carry `addedPasskeys: true`. The new wallet always
sends it, and a masterpod of before ignores it. It is inside the signed
payload, like every field.

Checks:

- Check 4, the pod by the credential id. When no `anopods` row has the
  credential id, the `added_passkeys` row with it is looked for; with a
  row, the pod is the one that row names. Neither: `401 unknown passkey`,
  as before. An added passkey from a payload whose `addedPasskeys` is not
  `true`: `409 reload the wallet` (19.1, the old page guard). The user
  handle check stays as it is.
- Check 6 verifies against the passkey found: the added row's credential
  id and public key, or the `anopods` row's as before.

Writes: as before. A pod has one live session, whichever passkey opened
it.

Answer: `200 { anopodId, username, vouched, setupComplete, blob1,
wrappedKeyBlobKey, chatPrivateKeyBlob, identityBlob, ephemeralExpiresAt }`.
`blob1` is the added row's `anopod_encryption_key_blob_1` for an added
passkey, the `anopods` row's as before for the main one. `wrappedKeyBlobKey`
is new: the added row's `wrapped_key_blob_key` in hex, `null` for the main
passkey. The wallet opens `blob1` under `KEK_prf` either way. With a
`wrappedKeyBlobKey` it opens that for the key blob key; without one it
makes the key blob key from the PRF output, as before. A person who never
adds a passkey takes the same path as before.

**POST /recover-with-backup-code** (none; 12.4.2), one more write.

Body, Checks and Answer: as 12.4.2.

Writes: inside the one transaction with the case locked, right after the
recovery passkey is copied onto the pod's row, `DELETE FROM added_passkeys
WHERE anopod_id = <the case's pod>`. The `recovered` event's details stay
`{}`. So after a recovery the pod has one passkey again: the recovery
passkey, which is its main one from there.

**POST /create-anopod** (none, signed by the ephemeral keys inside; section
5), one more check. Not in the plan: added on the user's word the same day
(19.6).

Body, Writes and Answer: as section 5.

Checks: a seventh, after the profile and before the writes. The new
credential id is on no `added_passkeys` row and on no `recovery_pods` row;
else `409 key already registered`, the words the route already has for a
taken key. An `anopods` row with it is refused at the write by that
table's unique key, as before.

**POST /open-recovery-case** (none, signed by the ephemeral keys inside;
12.4.2), one more check. Not in the plan either (19.6).

Body, Writes and Answer: as 12.4.2.

Checks: an eighth, after the open case check and before the writes. The
new credential id is on no `added_passkeys` row; else `409 key already
registered`. A `recovery_pods` row with it is refused at the write by that
table's unique key, as before.

Why the two routes look: `/unlock` asks `anopods` first. Without the
lookups in `added_passkeys`, a registration made up with another pod's
added credential id could put that id on an `anopods` row, straight
through `/create-anopod` or through a recovery of the maker's own pod, and
that added passkey would stop unlocking. Without the lookup in
`recovery_pods`, one made up with the recovery passkey's credential id of
an open case could put it on a new pod's row, and that case's finish would
answer `409 key already registered`. A real passkey never meets these
checks: an authenticator makes a new credential id at every registration.

### 19.4 The notification

One kind (section 6):

| kind | to | reference_id |
| ---- | -- | ------------ |
| `passkeyAdded` | the pod a passkey was added to | the new `passkey_id` |

Written by `/add-passkey` inside the transaction of the insert, as section
6's are. The wallet's label for it links to its Passkeys page (the
wallet's spec). With it there are seventeen kinds. (Since 2026-11-21,
section 25, there are twenty-one.)

### 19.5 Files

- `db/schema.sql`: the two widened checks, each inline and in its ALTER
  pair, with the comment over each pair; the comments of
  `challenges.purpose`, `challenges.anopod_id`, `challenges.expires_at`,
  `notifications.kind` and `notifications.reference_id`; on `anopods` the
  header comment, the table's comment and the comment of
  `pass_key_credential_id`; the added passkeys block, new, at the end.
- `src/config/env.js`: `addPasskeyChallengeSeconds`. `.example.env`: its
  line and its comment line.
- `src/auth/challenges.queries.js`: `issue` takes `seconds` as a third
  argument; the file's opening comment and the comment of `find` name the
  recovery routes and `/add-passkey`.
- `src/auth/auth.handlers.js`: `PURPOSES`, the branch that reads
  `anopodId`, the life handed to `issue`, the username line.
- `src/passkeys/`, new: `added-passkeys.queries.js`
  (`findAddedByCredentialId`, `listAdded`, `insertAdded`, `deleteAddedOf`),
  `passkeys.service.js` (`addPasskey`, `listPasskeys`),
  `passkeys.handlers.js` and `passkeys.router.js`.
- `src/app.js`: the passkeys router mounted after the anoPods router, with
  its comment line.
- `src/notifications/notifications.queries.js`: one comment, seventeen
  kinds.
- `src/anopods/anopods.service.js`: `unlock`, the three changes of 19.3;
  `createAnopod`, its seventh check.
- `src/recovery/recovery.service.js`: `recoverWithBackupCode`, the one
  line; `openRecoveryCase`, its eighth check.
- Here: section 2 (the setup row), section 3 (the life of a challenge),
  section 4 (`### anopods`, the first sentence; `### challenges` and
  `### notifications`, the SQL and the text under it), section 5
  (`### POST /challenge` and `### POST /unlock`, a paragraph each;
  `### POST /create-anopod`, check 7), section 6 (the row), section 7 (the
  row), section 8 (the row), section 10 (the last item, and "Several
  passkeys" out of the item on live sessions), 12.4.2
  (`/open-recovery-case`, check 8; `/recover-with-backup-code`, the delete
  in its writes) and this section. `README.md`: the first paragraph, "Who
  may call what", the Endpoints table, the tables table (the rows of
  `anopods`, `added_passkeys` and `notifications`), Configuration, Layout
  and "Deferred, by decision" (the last item, and "Several passkeys" out
  of the item on live sessions).

Nothing else in existing code changes. One new env variable with a
default, no npm package.

### 19.6 Notes from the build

#### Build 1, the masterpod (2026-11-18)

Built from `~/Desktop/Z-TestNet/forclaude/add-passkey-plan-1.md` section 1,
on main at cc09d36, the merge of pull request 8, the working tree clean.
No new npm package, no test script and no rig (none was asked for). The
schema was not applied to any database for keeps: the user applies the
whole file as section 6 of `forclaude/masterpod-deploy-plan-1.md` says. It
goes on before this code runs. On a database without `added_passkeys` this
code fails at the finish of a recovery and at an unlock with a passkey no
pod has, and `/challenge` cannot issue for `addPasskey`. With the lookups
added the same day (below) it also fails at every `/create-anopod` and
every `/open-recovery-case`. What the plan left open and how it was
decided:

- The date. BUILD-DATE is 2026-11-18, the day of the build and of the
  plan's FINAL.
- `db/schema.sql`. In both lists of notification kinds `'passkeyAdded'`
  sits on a line of its own after the case kinds, so the lists keep their
  short lines. The header comment of `anopods` was wrapped again and is
  one line longer; the comment over each ALTER pair is one line longer.
  The file's opening comment is unchanged: it lists the blocks that alter
  a table, and the new block alters none. PostgreSQL names the new table's
  constraints `added_passkeys_pkey`,
  `added_passkeys_pass_key_credential_id_key` and
  `added_passkeys_<column>_check` for the six column checks. After the
  build the file had 1373 lines, 41 more than before, and its sha256 began
  b96a3201. With the comment of `challenges.expires_at` brought in line
  (below) it has the same 1373 lines and its sha256 begins a19592e9.
- `/challenge`. `addPasskey` runs the branch of `openCase`, so its
  refusals are the same and in the same order. (Since 2026-11-18, section
  20, `openCase` has three refusals more, those of the lookup id, and
  `addPasskey` has none of them.) The handler picks the life
  and hands it to `issue`, whose third argument defaults to
  `CHALLENGE_SECONDS`. The route asks for no session, as the plan says, so
  anyone who knows a pod's id can have a challenge issued for that pod; it
  is a row that the next issue sweeps once its ten minutes are over, as an
  `openCase` challenge is after its two.
- `/add-passkey`. A `userHandle` is "there" when it is neither absent nor
  `null`. It must then decode from base64url to the pod's id, so an empty
  string, a string that is not base64url and a value that is not a string
  are `401 user handle mismatch`. A `rawId` that does not decode is `401
  unknown passkey`, as in `/unlock`. Only the caller's own passkeys are
  asked for the fresh tap, so a passkey of another pod, main or added, is
  `401 unknown passkey` too. In check 4 a PRF output in either object is
  asked first (`400 prf output in request`), then `prf.enabled` (`400
  passkey without prf`); `/create-anopod` answers `400 passkey without
  prf` for both, and here the plan names the two reasons. Check 7 asks
  `anopods` first, then `added_passkeys`, and not `recovery_pods`: the
  plan names the two tables. The `passkey_id` is minted before the
  transaction. The transaction answers the new row's `created_at`, or
  nothing when the challenge was gone, and `createdAt` in the answer is
  that value. Whichever unique key a violation is on, the credential id or
  the COSE key, the answer is `409 passkey already registered`. The pod's
  row is not locked: two adds at the same moment each need a challenge and
  a new passkey of their own, and both go in. The two blobs are checked
  for their length only; the server cannot tell whether they open.
- `/list-passkeys` reads nothing from its body, as `/list-anos-accounts`
  reads nothing from its own. (Since 2026-11-20, section 22,
  `/list-anos-accounts` reads one field of its body, `firstKeyBlobs`;
  `/list-passkeys` still reads nothing.) The main passkey comes from
  `req.anopod`, the row the session check has just read.
- `/unlock`. The second lookup runs only when no `anopods` row has the
  credential id, so an unlock with a main passkey costs no query more than
  before. `409 reload the wallet` comes right after `401 unknown passkey`
  and before the user handle check, in the plan's order. An added row
  whose pod's row is gone is `401 unknown passkey` (never, in practice: no
  pod is deleted). `wrappedKeyBlobKey` follows `blob1` in the answer.
- A gap, which the build left as the plan has it and reported.
  `/create-anopod`, `/open-recovery-case` and the finish of a recovery did
  not ask `added_passkeys` for the credential id they write, and the two
  unique keys are one per table. So the same credential id could come to
  stand on an `anopods` row and on an `added_passkeys` row. `/unlock` then
  finds the `anopods` row, and the added passkey answers `401 user handle
  mismatch`. An authenticator makes a credential id at random and never
  twice, so this takes a registration made up by someone who knows another
  pod's added credential id, which only that pod's own devices and this
  server see. (Since 2026-11-18, section 20, anyone who knows the pod's id
  can learn it.) The build put it down for the follow-up list. It was
  closed the same day (below).
- `/recover-with-backup-code`. `deleteAddedOf` answers how many rows went
  and the finish does not use the number. The delete runs at every finish,
  also for a pod that never added a passkey, where it finds no row.
- Here. Section 2's row takes the two routes at its end, in the plan's
  words. In section 5, `### POST /challenge` still names `create` and
  `unlock` in its body line, as it has since 2026-10-24; the sixth purpose
  is a paragraph at its end that points to 12.4.2 for the three recovery
  purposes and to 19.3. `### POST /unlock` takes its paragraph at its end.
  Section 7's row is the last of the table, in the plan's words. Section
  10's three items are one item, the last. In the README the two new
  route rows follow `/complete-setup`, the `added_passkeys` row follows
  `anopods`, the `passkeys/` line follows `anopods/`, and the three
  deferred items are the last item of the list.
- Checks (1.8): `node --check` on the eleven changed or new source files
  (`env.js`, `challenges.queries.js`, `auth.handlers.js`, the four files
  of `src/passkeys/`, `app.js`, `notifications.queries.js`,
  `anopods.service.js`, `recovery.service.js`), clean, on Node 24.22.0.
  Every name these files import from another file of `src` is exported
  there; a throwaway script outside the repo read the files as text, and
  no module was loaded. The schema by psql against the local `masterpod`
  database as the superuser `codex` with `SET ROLE masterpodsoftware`, one
  transaction, rolled back: the whole file ran twice with no error. That
  database is of before the case chats step (36 tables, fifteen
  notification kinds, no case columns), so the runs brought in that step's
  block too. After the first run it had 37 tables. `added_passkeys` had
  its seven columns, each `NOT NULL` and each with its comment, its
  primary key, the unique key on `pass_key_credential_id`, its six column
  checks, the unique index on `sha256(pass_key_public_key)` and the index
  on `(anopod_id, created_at)`, no trigger, and `masterpodsoftware` as its
  owner. `challenges_purpose_check` was there once with six purposes and
  `notifications_kind_check` once with seventeen kinds, and the changed
  comments read as written. The second run changed nothing: one md5 over
  every column, comment, constraint definition, index definition, trigger
  and function of the schema was the same after both runs. In the same
  transaction each of the four statements of `added-passkeys.queries.js`
  ran as a `PREPARE` of its exact text, lifted from the file as text with
  `${COLUMNS}` filled in, its parameters untyped as `pg` sends them, and
  as an `EXECUTE` on throwaway ids. Three inserts each answered
  `created_at`: two rows for one pod id and one row for another. The find
  by credential id answered its row, and no row for an unknown id. The
  list answered the pod's two rows in the order `created_at, passkey_id`.
  The delete of a pod's rows took 2 rows, and the other pod's row stayed.
  The statement of `notify` wrote a row of kind `passkeyAdded`. The
  statement of `issue` wrote a challenge of purpose `addPasskey` with 600
  seconds, and its `expires_at - now()` read 00:10:00. On that database
  every `CREATE TABLE` but the new one is skipped, so the texts for a
  database built from nothing do not run there. For them the file ran
  twice more inside the same transaction, into an empty scratch schema
  (`SET search_path`): 37 tables, the same md5 after both runs, and the
  statements once more on those tables with the same results. The tables
  built from nothing came out equal to the local ones after their two runs
  in everything but one check, `escrow_dispute_evidence_content_type_check`,
  which a kept database keeps with `application/pdf` (section 11, the
  pictures note). After the rollback the database was as before: the md5
  of before, 36 tables, no `added_passkeys`, no scratch schema and no row.
  A first try stopped on a mistake in the check's own file (a `min()` over
  a `bytea`), after the two runs on the local tables and the four
  statements had passed, and kept nothing either. No server was booted and
  no route was called: both new routes and `/unlock` take a passkey, and
  the run-through is the user's (the plan's section 4), with the wallet's
  step 2.
- Places the plan does not name that this step left out of date. The
  build left them as they are and put them to the user. In `db/schema.sql`:
  the comment of `challenges.expires_at`, "Issued + CHALLENGE_SECONDS". In
  `src/auth/challenges.queries.js`: the file's opening comment and the
  comment of `find` name the routes that use a challenge, without
  `/add-passkey`. Here: section 3, "lives `CHALLENGE_SECONDS` (120)";
  section 4, the SQL of `### notifications` with sixteen kinds and "the
  same sixteen kinds" under it, and `### challenges` with the two purposes
  of 2026-10-24; section 10, "Several passkeys or several live sessions
  per pod", and the same line in the README's "Deferred, by decision";
  12.4.2, whose writes of `/recover-with-backup-code` do not name the
  delete; in the README's tables table, the line of `notifications`,
  "sixteen kinds, the newest `recoveryCaseScheduled`". The copies of the
  two ALTER pairs in 12.3 and 13.3 are as their builds left them, with
  five purposes and fifteen kinds. The user had all of them brought in
  line the same day (below).
- Not touched: every other feature folder, `src/auth/webauthn.js`,
  `src/anopods/anopods.queries.js`, the routers and handlers of `auth`,
  `anopods` and `recovery`, `package.json`, the scripts. In
  `src/notifications/` one comment changed and no line of code.

#### After the build's report, the same day (2026-11-18)

The user read the report in the build chat. Of the gap: "sounds like this
should be address immediatly." Of the follow-up list: "Where is this follow
up list? These sounds like fixes I'm going to forget to make." There is no
single list: the house rules name sections at the end of the plans in
`forclaude/`, and the gap stood only in these notes. So the user had the
gap closed and the out-of-date places brought in line at once, before the
commit: "Yes, do it all". Neither is in the plan.

- The lookups (19.3). A credential id is written by three routes:
  `/create-anopod` onto `anopods`, `/open-recovery-case` onto
  `recovery_pods` and from there onto `anopods` at the finish, and
  `/add-passkey` onto `added_passkeys`. Each table has its own unique key,
  and before this step no route looked in another table. Somebody is hurt
  in two cases, both by an `anopods` row. One: another pod's added
  credential id on an `anopods` row, which `/unlock` finds first, so that
  added passkey stops unlocking (the gap above). Two: the recovery
  passkey's credential id of an open case on another pod's `anopods` row,
  so that case's finish runs into the unique key and answers `409 key
  already registered`. Case two is older than this step; the user had it
  closed with the first. `/create-anopod` asks `added_passkeys` (case one)
  and `recovery_pods` (case two). `/open-recovery-case` asks
  `added_passkeys` (case one by way of a recovery of the maker's own pod).
  Each lookup runs after the route's other checks and before its writes,
  so a taken username and an open case answer first, as before. Each
  answers `409 key already registered`, the words both routes have for a
  taken key. `/create-anopod` asks every `recovery_pods` row, whatever its
  case's status: no real passkey brings one of those ids again.
- The finish of a recovery looks nothing up. A credential id that is on a
  `recovery_pods` row can still be made an added passkey of another pod:
  check 7 of `/add-passkey` does not ask `recovery_pods`, as the plan has
  it. At the finish that id then stands on the recovered pod's `anopods`
  row and on the made-up `added_passkeys` row. `/unlock` finds the
  `anopods` row, so the recovered pod unlocks and the made-up row never
  does. A lookup at the finish would turn this into a way to stop
  somebody's recovery, so there is none. `/open-recovery-case` does not
  ask `anopods` either: a recovery passkey made up with a pod's main
  credential id stops only its maker's own finish, at the unique key.
- What the lookups are not. They are a look before the write, not a lock,
  and no unique key spans two tables. A made-up registration that lands
  between the look and the write of another route still goes in. It would
  have to carry a credential id that an authenticator made a moment
  before, which only the device at hand knows.
- Who can know a credential id. No route sends one to anyone but the pod's
  own session at level setup (`/list-passkeys` and the answer of
  `/add-passkey`), and no log line prints one. So a made-up registration
  takes someone who holds the pod's unlocked wallet or one of the servers
  the requests pass through. (Since 2026-11-18, section 20, that no longer
  holds for a pod's main id and its added ids: `/challenge` for `openCase`
  sends them to anyone who knows the pod's id. 20.4 says what still
  refuses them.)
- The order of the deploy matters more with the lookups. The schema goes
  on first, as the plan's section 4 has it. On a database without
  `added_passkeys` every `/create-anopod` and every `/open-recovery-case`
  would fail at its lookup, so nobody could make an anoPod or open a
  recovery case until the schema was applied. The build alone failed only
  at the finish of a recovery and at an unlock with a passkey no pod has.
- The places brought in line, the ten the build had listed (above). In
  `db/schema.sql` the comment of `challenges.expires_at`. In
  `src/auth/challenges.queries.js` the opening comment and the comment of
  `find`: both name the recovery routes and `/add-passkey` now (the
  opening comment had named only `/create-anopod` and `/unlock`). Here:
  section 3; section 4, where `### challenges` has the six purposes in its
  SQL (it had the two of 2026-10-24) and says what `anopod_id` holds for
  each, and `### notifications` has seventeen kinds in its SQL and in its
  text; section 10; 12.4.2, the delete in the writes of
  `/recover-with-backup-code`. In the README the row of `notifications` in
  the tables table and the item on live sessions in "Deferred, by
  decision". Section 5 and 12.4.2 also take the two new checks as numbered
  items, so the lookups leave nothing out of date. The copies of the two
  ALTER pairs in 12.3 and 13.3 and the counts of kinds in the notes of
  earlier builds stay as those builds left them: they are records of
  their day.
- Checks. `node --check` again on the eleven source files, clean, and the
  imports again. The lookups bring no new SQL: `findAddedByCredentialId`
  is the statement the build ran, and the other is `findByCredentialId` of
  `src/recovery/recovery-pods.queries.js`, which `/unlock-recovery-pod`
  has called since the recovery builds. The whole schema file ran twice
  more in one rolled-back transaction on the local `masterpod` database
  and twice into an empty scratch schema, with the statements of 1.4, as
  in the build: no error, and the second run changed nothing either time.
  The output differed from the build's only in the md5 values, by the one
  comment, which read as written, and in the times. After the rollback
  the database was as before. No server was booted and no route was
  called.
- The numbers. `db/schema.sql` has 1373 lines and its sha256 begins
  a19592e9 (b96a3201 after the build). One commit carries the build and
  this.

## 20. The passkey check and the open case check at a case's opening (2026-11-18)

Design settled 2026-11-18 in a planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/recovery-passkey-check-plan-1.md`, FINAL,
2026-11-18). Why: in the first days of production six people opened a
recovery case without having lost their passkey. The user, 2026-11-18:
"they're just confused, didn't know how to use their passkey and thought
that account recovery was something more like forgot password". "Open my
case" makes a new passkey on the device, with the anoPod id as its hidden
user id. A place that stores passkeys keeps one passkey per user id and
site. So where the person's own passkey sits in that same place (the same
iCloud Keychain, the same Google Password Manager account), the new
passkey takes its place and the person's own passkey is gone. That person
is then truly locked out, and needs the case they opened by mistake. No
screen warned of this. Two repos in order: this server (this section,
step 1 of the plan: one change, in `/challenge` for `openCase`) and the
wallet (its spec, step 2: the two recovery pages and their words), then
the record folders (step 3). Either order of the two deploys is safe; the
usual order is kept, this server first (the plan's section 4). With this
server alone deployed nothing changes for anyone: a wallet of before sends
no lookup id and does not read the ids. A new wallet against a masterpod
of before shows its two warnings; its exclude list is empty and its lookup
id is ignored, so both checks do nothing, as before. A wallet page loaded
before the wallet's deploy behaves as before until it is loaded again. No
new route, no table, no line of `db/schema.sql`, no env variable and no
npm package. The validators, the doormen, the keyholders, the signing
servers and the wallet's proxy are not touched. Nothing above this section
changes except the items in 20.3.

### 20.1 The rule

- The passkey check (the plan's decision 1). At "Open my case" the wallet
  hands the device the ids of the passkeys the anoPod already has. The
  browser calls this the exclude list. A device that still holds one of
  them makes no new passkey, so the person's own passkey stays. The user,
  2026-11-18: "do your suggestion 1. stop the replacment before it
  happens. All those steps sound perfect."
- This server gives the wallet those ids (decision 3). Its `/challenge`
  answer for `openCase` carries them: the main passkey first, then the
  added ones, oldest first, in hex, as `/list-passkeys` gives them.
- The open case check (decision 5). A person whose case is already open is
  told so at the birth record step, before any passkey is made. The user:
  "let's add that to the plan when we do. That's definitely something we
  want". Before this change such a person could go through "I'm locked
  out" a second time. The device made a second new passkey, and only then
  did `/open-recovery-case` answer `409 case already open`. In the same
  place the second passkey took the place of the first case's passkey. The
  first case was still open, but the person could no longer continue it,
  and a moderator had to dismiss it.
- The passkey check does not cover that. Its list holds the anoPod's own
  passkeys. The passkey of a case is kept with the case (`recovery_pods`),
  apart, until the recovery ends.
- The way: the wallet sends the lookup id with its `/challenge` request
  for `openCase`. This server asks the question it asks at the very end,
  in check 7 of `/open-recovery-case` (one open case per lookup id), and
  refuses at once: `409 case already open`. Check 7 stays the rule; this
  is the same question asked sooner.
- What the open case check gives out, and to whom. In a recovery this
  server first saw the lookup id when the case was opened. Now it sees the
  lookup id one step earlier, in the same request as the anoPod id, also
  for a person who then opens no case. It uses it for this one question
  and stores nothing. Decision 1 of `forclaude/recovery-lookup-plan-1.md`
  reads: "it stays unable to link a birth record to a pod, as it was
  designed". Who can ask: whoever has a lookup id. A lookup id comes from
  a full birth record, and that person could find out the same before, by
  trying to open a case.
- Not taken: asking by the anoPod id, which this server is given anyway.
  Anyone who knows an anoPod id could then find out that its owner has a
  case open.
- What the passkey check gives out, and to whom. The ids are given out
  without a log-in, because a locked-out person cannot log in. So anyone
  who knows an anoPod id can learn the credential ids of its passkeys, and
  with that how many passkeys it has. A credential id is not a secret: it
  opens nothing without the passkey itself.

### 20.2 The change by route

**POST /challenge** (none; section 5, 12.4.2 and 19.3), for the purpose
`openCase` alone.

Body: `{ purpose: "openCase", anopodId, lookupId }`. `anopodId` is as
before: the anoPod id the keyholders named for the person's lookup id.
`lookupId` is new and optional: that lookup id, 32 bytes, hex like every
id. It is read only when the body has one. The new wallet always sends
it; a wallet page of before sends none and is answered as before.

Checks, in order. The first, the third and the fifth are those of before,
in their place and with their words.

1. `anopodId` is a string, else `400 bad request shape`.
2. `lookupId`, when the body has one, is a string, else `400 bad request
   shape`.
3. `anopodId` is 32 bytes, else `400 invalid anopodId`.
4. `lookupId`, when given, is 32 bytes, else `400 invalid lookupId`, the
   words `/open-recovery-case` has for it.
5. A pod has that id, else `404 unknown anopod`.
6. `lookupId` given, and a case for it is open (status not completed or
   dismissed, the question of check 7 of `/open-recovery-case`, 12.4.2):
   `409 case already open`. No challenge is issued.

Writes: as before; none at a refusal. The lookup id is written nowhere,
at a refusal or at an answer: no row, no event, no notification.

Answer: `200 { challenge, expiresAt, anopodId, username, credentialIds }`.
`credentialIds` is new: the credential ids of the pod's passkeys, a list
of hex strings. The main passkey is first
(`anopods.pass_key_credential_id`). Then come the added ones, oldest first
(the pod's `added_passkeys` rows, `ORDER BY created_at, passkey_id`, read
after the checks and before the challenge is issued). The list always
holds the main one, so it is never empty. The wallet hands it to the
device as the exclude list when it registers the recovery passkey (the
wallet's spec).

`addPasskey` shares the lines that read `anopodId` and stays as it was: a
`lookupId` in its body is not read, and its answer carries no
`credentialIds`. The four other purposes are untouched. The route stays at
level none. `/open-recovery-case` and its eight checks are untouched.

### 20.3 Files

- `src/auth/auth.handlers.js`: two imports, `listAdded` and
  `openCaseExists`; in `challenge()` the three checks of the lookup id,
  the read of the added passkeys and `credentialIds` in the answer; the
  comment over `PURPOSES` and the doc comment of `challenge()`.
- `src/recovery/recovery-cases.queries.js`: the comment of
  `openCaseExists`, which now names who asks. No line of code.
- Here: section 5 (`### POST /challenge`, a paragraph at its end), 12.1
  (step 1 of the flow, in two places), 12.4.2 (the `**POST /challenge**`
  paragraph, and check 7 of `/open-recovery-case`) and this section; and,
  on the user's word after the build, a clause each in 12.10 (the note of
  2026-11-08), in 19.3 (the block on `addPasskey` at `/challenge`) and in
  three notes of 19.6 (20.4). `README.md`: the `/challenge` row of the
  Endpoints table.

Nothing else in existing code changes: not
`src/recovery/recovery.service.js` (check 7 of `/open-recovery-case` stays
the rule), not `src/passkeys/`, not `db/schema.sql`, not `.example.env`.
No new route, no table, no env variable, no npm package.

### 20.4 Notes from the build

#### Build 1, the masterpod (2026-11-18)

Built from
`~/Desktop/Z-TestNet/forclaude/recovery-passkey-check-plan-1.md` section
1, on main at 3de0522, the merge of pull request 9, the working tree
clean. No new npm package, no test script and no rig (none was asked
for). There is no schema step: `db/schema.sql` is not touched, and the
two tables the step reads, `recovery_cases` and `added_passkeys`, are read
by the code of before too. What the plan left open and how it was decided:

- The date. BUILD-DATE is 2026-11-18, the day of the build and of the
  plan's FINAL.
- "The body has one" is the plan's `req.body.lookupId !== undefined`. So
  `lookupId: null` counts as given and is `400 bad request shape`; it is
  not taken as absent, as `caseId: null` is at `/create-chat-room`. An
  empty string is a string: it passes check 2 and is `400 invalid
  lookupId` at check 4. The lookup id is read by `decodeId`, so base64 is
  taken beside hex, as for every id.
- The lines of the lookup id stand inside the branch that `openCase`
  shares with `addPasskey`, each behind one flag, `hasLookupId`: the
  purpose is `openCase` and the body has a `lookupId`. For `addPasskey`
  the flag is false and `req.body.lookupId` is not looked at. The three
  checks of before are the lines they were.
- The plan's line `const added = await listAdded(anopodId);` is `const
  added = purpose === 'openCase' ? await listAdded(anopodId) : [];` in the
  code. The handler serves six purposes, and the answer reads `added`
  after `issue`. So the line stands in the function's own scope, with the
  purpose in it, where the plan puts it: after the checks and before
  `issue`. For the five other purposes no query runs.
- The order of the reads for `openCase` is the pod, the open case question
  (only with a lookup id), the pod's added passkeys, then the challenge.
  That is up to two queries more than before. A read that fails stops the
  request before a challenge row is written.
- `credentialIds` follows `username` in the answer, on a line of its own;
  the line of `username` is as it was. A JSON reader sees `challenge`,
  `expiresAt`, `anopodId`, `username`, `credentialIds`. A pod that never
  added a passkey answers a list of one id.
- This server cannot tell whether the lookup id belongs to the anoPod id
  beside it, and does not try. The `409` answers for the lookup id alone:
  a case open under it stops the request, whichever pod that case names.
  Check 7 of `/open-recovery-case` asks the same way.
- The `409` is a look, not a lock, as check 7 is. A case opened between
  this answer and `/open-recovery-case` is refused there, by check 7 or by
  the partial unique index. A `200` here promises nothing about the
  opening.
- A refusal is logged by its reason alone (`failed: case already open`),
  as every refusal is. No log line prints the lookup id or a credential
  id.
- The comments. The comment over `PURPOSES` gained one sentence at its
  end. The doc comment of `challenge()` gained a paragraph at its end; its
  text of before is unchanged and still true.
- Here. In section 5 the new paragraph is the last of `### POST
  /challenge`. In 12.1 the new sentence stands after the whole sentence
  that names the account, which ends "they typed it)". The plan's "at this
  step" is written "at the `/challenge` request" there, because step 1 of
  that list holds the opening of the case too. In 12.4.2 the new sentences
  stand right after the answer of `openCase`; the answer named just before
  them is the one of before, and `credentialIds` is named in the new
  sentence. In the README the row gained its words at its end.
- Checks (1.4): `node --check` on the two changed source files
  (`src/auth/auth.handlers.js`, `src/recovery/recovery-cases.queries.js`),
  clean, on Node 24.22.0. Then one load of the app with no server, run
  from the build chat's scratch folder as one `node -e` line, with no file
  kept: `src/app.js` imported and `createApp()` called, with made-up
  `PGDATABASE`, `PGUSER` and `PGPASSWORD` and `PGHOST=/nonexistent`. It
  counted 96 routes, as before the step, one of them `/challenge`, and
  ended with exit 0. The step adds two imports across folders, and a wrong
  one would have failed the load. Nothing listened, no database was
  reached and no route was called. No psql: the step adds no SQL, and both
  queries it calls were in use before. So no request was sent to the new
  lines: the run-through is the user's, on a phone, with the wallet's step
  2 (the plan's section 4). After the places below were brought in line,
  both checks ran once more with the same results. The two source files
  had not changed in between.
- Places the plan does not name that this step left out of date. The build
  left them as they were, listed them and asked. The user: "Yes, update
  them". They were brought in line before the commit. Each got one clause
  in brackets that begins "Since 2026-11-18", or one such sentence, and
  its words of before stay. All four are here. 19.3, the block on
  `addPasskey` at `/challenge`: "Checks, those of `openCase` in its
  order". Since this build `openCase` has three checks more, those of the
  lookup id, and `addPasskey` has none of them. 19.6, the note on
  `/challenge`: "`addPasskey` runs the branch of `openCase`, so its
  refusals are the same and in the same order", for the same reason. 19.6
  again, in two notes: "Who can know a credential id. No route sends one
  to anyone but the pod's own session at level setup", and in the note on
  the gap "which only that pod's own devices and this server see". Each of
  the two got its clause. Since this build `/challenge` for `openCase`
  sends a pod's main id and its added ids to anyone who knows the pod's
  id. Those ids are still refused at each route that writes a new passkey,
  by the lookups of 19.3 or by a table's unique key. The one exception is
  the one 19.6 names itself: a recovery passkey made up with a pod's main
  id, which stops only its maker's own finish. And 12.10, the note "The
  lookup through the keyholders (2026-11-08)": the masterpod "stays unable
  to link a birth record to a pod, as designed". Since this build it is
  sent the lookup id in one request with the anoPod id, before any case,
  for the one question, and keeps nothing of it.
- Not touched: every other feature folder, every router,
  `src/recovery/recovery.service.js`, `src/passkeys/`, `db/schema.sql`,
  `.example.env`, `package.json`, the scripts. In `src/recovery/` one
  comment changed and no line of code.

## 21. Seen in chat (2026-11-19)

Design settled 2026-11-19 in a planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/wallet-chat-and-passkey-plan-1.md`, FINAL,
2026-11-19). Why: in a chat of the production wallet nothing said whether
the other person had seen a message. The user, 2026-11-19: "It's unclear
as to whether or not there is a read notification." And, asked which of
two things was meant: "Yes, we want to know if the other person has seen
the message." This server did not know what anyone had read: each device
kept its own list, for its unread dot. So this server now keeps how far
each member of a chat has read, and the wallet shows it as the words
"Sent" and "Seen" under a person's own messages. Two repos in order: this
server (this section, step 3 of the plan: one column, one route, and one
field more in the answer of `/list-chat-rooms`) and the wallet (its spec,
step 4: the report while a chat is on the screen, and the two words), then
the record folder (step 6). Steps 1, 2 and 5 of the plan are the wallet's
alone. Either order of the two deploys is safe; the usual order is kept,
this server first (the plan's section 7). With this server alone deployed
nothing changes for anyone: a wallet of before calls no new route and
ignores the new field. A new wallet against a masterpod of before gets a
`404` for its first report in a chat and reports nothing more until that
chat is opened again; it shows neither "Sent" nor "Seen". The same happens
to a report that reaches a server not yet updated, while the three servers
are updated one after the other. Inside this server's own deploy the order
matters: the schema file goes onto the database before the new code runs
(21.5). One new route and one new column. No table, no env variable and no
npm package. The validators, the doormen, the keyholders, the signing
servers and the wallet's proxy are not touched. Nothing above this section
changes except the items in 21.4.

### 21.1 The rule

- A seen position is the highest message position a member has seen in a
  room. Every message has a position (`chat_room_messages.position`,
  section 4), so one number per member and room says how far that member
  has read. It is 0 until the member's wallet reports one. "Seen" means
  that the chat was open on a visible page after the message arrived; it
  does not mean the person read it.
- The member's own wallet writes it, with `/mark-messages-seen`, and only
  while the chat is on the screen: a chat left open in a hidden tab
  reports nothing (the wallet's spec). The row written is the caller's
  own, found by the session; no route writes another member's position.
- It is never lowered, and never above the room's newest message. A report
  of a lower position changes nothing. A report above the newest message
  stores the newest message's position.
- Every member of the room reads every member's position, in the answer of
  `/list-chat-rooms`. An attestor who was invited into a marketplace chat
  and accepted is a member (section 18): the attestor reads the two
  traders' positions, and they read the attestor's. A person who is only
  invited so far is no member yet: they have no position and read none.
- What this server learns: how far each member of each room has read. It
  keeps the number alone, with no time beside it. It still learns nothing
  of what a message says.

### 21.2 The column

`db/schema.sql`, in two places. Inline in the `CREATE TABLE` of
`chat_room_members`, after `created_at`, for a database built from nothing
(section 4). And in a new block after the added passkeys block, the last
thing in the file, "The seen position block (2026-11-19, spec section
21)", for a database that has the table:

```sql
ALTER TABLE chat_room_members ADD COLUMN IF NOT EXISTS seen_position BIGINT NOT NULL DEFAULT 0 CHECK (seen_position >= 0);
```

- `seen_position`: the highest message position the member has seen in the
  room, 0 until the member's wallet reports one. A `BIGINT`, as
  `chat_room_messages.position` is, `NOT NULL`, default 0, never negative
  (the check). Raised by `/mark-messages-seen`, never lowered, never above
  the room's newest message. `/list-chat-rooms` hands it to every member
  of the room.

Every member row of today gets 0. A new member starts at 0 by the default:
the routes that add a member name no value for it. The column's comment is
in the block only. No index: nothing looks a member up by it. No trigger
and no `updated_at`: the row says how far, not when. The line is
idempotent (`IF NOT EXISTS`), so the whole file applies to a live database
and a second run changes nothing.

### 21.3 The changes by route

**POST /mark-messages-seen** (setup), new.

Body: `{ chatRoomId, position }`. `chatRoomId` is the room, hex like every
id. `position` is a whole number from 1 to 9007199254740991, the largest
whole number JavaScript keeps exact: the highest message position the
caller's wallet has shown.

Checks, in order:

1. The body is an object and `chatRoomId` is a string, else `400 bad
   request shape`.
2. `chatRoomId` is 32 bytes, else `400 invalid chatRoomId`.
3. `position` is a whole number in that range, else `400 invalid
   position`. A body without a `position` gets the same.
4. The caller is a member of the room, else `403 not a member`. A room
   that does not exist gets the same.

Writes, one transaction of one statement: the caller's `chat_room_members`
row, `seen_position = GREATEST(seen_position, LEAST(position, N))`, where
N is the room's newest message position, 0 for a room without a message.
A row that is gone by then (the caller left in between) answers `403 not a
member`. No notification, no event, nothing else.

Answer: `200 { chatRoomId, seenPosition }`. `chatRoomId` is the room in
hex. `seenPosition` is what the row holds afterwards, as a number: the
`position` sent, or the room's newest position when `position` was above
it, or what the row held before when that was higher.

**POST /list-chat-rooms** (setup; section 5), one field more.

Body and Checks: as section 5.

Answer: every entry of a room's `members` is `{ anopodId, username,
seenPosition }`. `seenPosition` is that member's `seen_position`, as a
number, 0 until that member's wallet reports one. The entries of `invited`
stay `{ anopodId, username }`, and so does the `owner` of a `listing`.
Nothing else in the answer changes.

Nothing else changes: not `/send-message` (a message sent does not raise
its sender's position; the sender's wallet reports like any other), not
`/list-messages`, not the routes that add a member.

### 21.4 Files

- `db/schema.sql`: the line in the `CREATE TABLE` of `chat_room_members`;
  the seen position block, new, at the end; and, on the user's word after
  the build, the file's opening comment, which names the new block among
  the idempotent ALTERs, and the table comment of `chat_room_members`.
- `src/chat/chat.queries.js`: `raiseSeenPosition`, new; `listRoomsFor`,
  the third pair in the `json_build_object` of the members, and its doc
  comment.
- `src/chat/chat.service.js`: `markSeen`, new, and the import of
  `raiseSeenPosition`; and, on the user's word after the build, the
  file's opening comment.
- `src/chat/chat.handlers.js`: `markSeenHandler`, new, and the import of
  `markSeen`.
- `src/chat/chat.router.js`: the route's line, the import of
  `markSeenHandler`, and "fourteen" in the comment.
- `src/app.js`: "fourteen" in the comment on the chat router's line. No
  line of code.
- Here: section 4 (`### chat_room_members, chat_hpke`, the line in the SQL
  and a sentence under it), section 5 (`### POST /mark-messages-seen`, new,
  after `/send-message`; `### POST /list-chat-rooms`, the `members` entry
  of the JSON block and a sentence at its end) and this section; and, on
  the user's word after the build, section 1 (the item on `created_at`
  and `updated_at`).
  `README.md`: the Endpoints table (the new row, and the row of
  `/list-chat-rooms`), the row of `chat_room_members` in the tables table,
  and the `chat/` line of the Layout.

Nothing else in existing code changes: not `/send-message`, not
`/list-messages`, not the routes that add a member, not `.example.env`.
One new route and one new column; no table, no env variable, no npm
package.

### 21.5 Notes from the build

#### Build 1, the masterpod (2026-11-19)

Built from
`~/Desktop/Z-TestNet/forclaude/wallet-chat-and-passkey-plan-1.md` section
3, on main at 5f102e2, the merge of pull request 10, the working tree
clean. No new npm package, no test script and no rig (none was asked
for). The schema was not applied to any database for keeps: the user
applies the whole file as section 6 of
`forclaude/masterpod-deploy-plan-1.md` says. It goes on before this code
runs. On a database without the column this code fails every
`/list-chat-rooms`, so every wallet's chat list would fail, and every
`/mark-messages-seen`. The other way round is safe: the code of before
names its columns and never looks at the new one. Both were tried (the
checks below). What the plan left open and how it was decided:

- The date. BUILD-DATE is 2026-11-19, the day of the build and of the
  plan's FINAL.
- `db/schema.sql`. The new line of the `CREATE TABLE` has single spaces,
  and the three lines above it keep their columns, as the plan says. The
  block is the last thing in the file, after the added passkeys block,
  with plain comment lines in the form of the case chat block. PostgreSQL
  names the check `chat_room_members_seen_position_check` on both ways,
  and the column is the table's fourth on both ways. The build left the
  file's opening comment and the table's comment as they were; both were
  brought in line the same day (below).
- `raiseSeenPosition` stands after `isMember`. One statement reads the
  room's newest position and writes the row, so nothing can come between
  the two. It answers the row's value after the write, or no row.
- `markSeen`. `position` is read by `integerOption` with no fallback. So
  an absent `position`, `null`, 0, a negative number, a fraction, a string
  and a number above 9007199254740991 are all `400 invalid position`. The
  room id is read by `decodeId`, so base64 is taken beside hex, as for
  every id, and the answer gives it in hex. The position is checked before
  membership, in the plan's order: a pod outside the room that sends a bad
  position gets the `400`. `isMember` asks first, as in `/send-message`;
  the write then runs in its own transaction, and a row gone in between is
  the second `403 not a member`.
- What the stored number can be. Positions are one sequence for all rooms
  (the identity column of `chat_room_messages`), so the positions of one
  room have gaps. A member can report a position that is no message of
  that room; it is stored when it is not above the room's newest. It then
  says "everything up to here", which is what a reader of the number asks
  (`seenPosition >= position`).
- A room without a message stores 0 for every report and answers `200`
  with `seenPosition: 0`.
- A member who leaves and is let in again starts at 0:
  `/leave-chat-room` deletes the row, and the insert names no value.
- `/list-chat-rooms`. `seenPosition` is the third key of a member, after
  `username`. `json_build_object` writes the `BIGINT` as a JSON number,
  and the `pg` library hands it to the code as a JavaScript number.
- A report writes no log line: `answer()` logs refusals alone (`failed:
  not a member`).
- Here. In section 4 the sentence on the column is a paragraph of its own
  after the paragraph on `chat_hpke`. In section 5 the new route has the
  short form of its neighbours; the numbered checks are in 21.3. The
  sentence of `/list-chat-rooms` is the last of its text, after the
  paragraph on case chats. In the README the new row follows
  `/send-message`, and the three other places have the plan's words.
- Checks (3.5). `node --check` on the four changed files of `src/chat/`
  and on `src/app.js`, clean, on Node 24.22.0. Then one load of the app
  with no server, run from the build chat's scratch folder as one `node
  -e` line, with no file kept: `src/app.js` imported and `createApp()`
  called, with made-up `PGDATABASE`, `PGUSER` and `PGPASSWORD` and
  `PGHOST=/nonexistent`. It counted 97 routes, one more than before the
  step, with `/mark-messages-seen` between `/send-message` and
  `/get-chat-public-keys`, fourteen chat routes, and ended with exit 0.
  Nothing listened and no database was reached. The schema by psql
  against this Mac's PostgreSQL (17.11), as the superuser `codex` with
  `SET LOCAL ROLE masterpodsoftware`, in scratch schemas inside one
  transaction that was rolled back. The file of 5f102e2 went into an
  empty scratch schema first. That is the file GitHub's `main` hands out:
  `git ls-remote` gave 5f102e2 for `main` that day. It made 37 tables,
  `chat_room_members` with its three columns. Rows: three pods, a room
  with two members and three messages (positions 1 to 3), and a second
  room with one member and one message (position 4). Then the new file on
  top. The column was there as the fourth, `bigint`, `NOT NULL`, default
  0, with its check and its comment, and all three member rows held 0.
  The new file once more changed nothing: one md5 over every column,
  constraint, index, trigger, comment and function of the schema was the
  same after both runs. Then the statement of `raiseSeenPosition`, as a
  `PREPARE` of its exact text, lifted from the file as text. For the
  first member, 9007199254740991 answered 3, the newest of that room and
  not the 4 of the other room; 1 after it answered 3. For the second
  member, 1 answered 1 and 2 answered 2. A pod outside the room and a
  room that does not exist answered no row. The SELECT of `listRoomsFor`,
  lifted the same way with `${ROOM_LISTING_COLUMNS}` filled in, answered
  the one room, its `members` with `"seenPosition" : 3` and
  `"seenPosition" : 2`, `json_typeof` `number` for both, and `invited`
  `[]`. An `UPDATE` to -1 was refused by the check. For a database built
  from nothing the new file went alone into a second empty scratch
  schema, twice: 37 tables, the same md5 as the updated schema after both
  runs, and a new member row started at 0. After the rollback the
  database was as before: its 36 tables, no scratch schema, the same md5
  over its columns.
- Beyond the letter of 3.5, with nothing kept: the modules themselves,
  called as a route calls them, in a scratch schema inside a rolled-back
  transaction. A throwaway script outside the repo put a stand-in in the
  place of `src/db/pool.js`: one client, with the transaction of
  `withTransaction` turned into a savepoint, so nothing could commit. On
  the tables of 5f102e2 the new code failed as said above:
  `/list-chat-rooms` with `column m.seen_position does not exist`,
  `/mark-messages-seen` with `column "seen_position" does not exist`,
  while `/send-message` and `/list-messages` answered. With the new file
  on top: every refusal of `markSeen` in its order, the writes as in the
  psql run, both members reading both positions as JavaScript numbers,
  the cases of the notes above (a new member, a member who comes back, a
  room without a message), and `markSeenHandler` with a stand-in for the
  response, `200 { chatRoomId, seenPosition }` and `403 { error: 'not a
  member' }`. 51 results, all as expected. And the other way round: the
  code of 5f102e2, from a copy of that commit's files, on the new tables.
  `/send-message`, `/list-chat-rooms` (the members as before, `{
  anopodId, username }`), `/list-messages` and `/leave-chat-room`
  answered, and the member rows it wrote held 0. No server was booted, no
  request was signed and no route was called over HTTP. The session
  check, the envelope and the wallet are the user's run-through (the
  plan's section 7), with the wallet's step 4.
- Places the plan does not name that this step left out of date. The
  build left them as they are and put them to the user. In
  `db/schema.sql`: the file's opening comment lists the blocks at the end
  whose ALTERs change a table that exists, without the seen position
  block; and the table comment of `chat_room_members` says "Who is in
  which room" and nothing of how far each has read. Here, section 1:
  "Every table has `created_at`, and `updated_at` with the
  `set_updated_at` trigger unless the rows never change (then
  `created_at` only)". A `chat_room_members` row now changes, and the
  table still has `created_at` only, as the plan has it. In
  `src/chat/chat.service.js`: the opening comment lists what the chat
  feature holds, without the seen positions. `docs/build-plan.md`, the
  build plan of 2026-10-24, says "the thirteen routes": a record of its
  day. The user had the first four brought in line the same day (below).
- Not touched: every other feature folder, `.example.env`,
  `package.json`, the scripts. In `src/app.js` one comment changed and no
  line of code.
- The numbers. After the build `db/schema.sql` had 1385 lines, 12 more
  than before, and its sha256 began 72ac460b. With the two comments
  brought in line (below) it has the same 1385 lines and its sha256
  begins a3de2618. Before the step it had 1373 lines and its sha256 began
  a19592e9. It makes 37 tables, as before: the count that the deploy's
  schema line prints does not change with this step.

#### After the build's report, the same day (2026-11-19)

The user read the report in the build chat. It listed the five places
above, with the advice to bring four in line and to leave the old build
plan. The user: "Go ahead and change comments 1 to 4". So the four were
brought in line before the commit, and `docs/build-plan.md` stays as it
is, a record of its day. None of this is in the plan.

- `db/schema.sql`, the file's opening comment. The list of the blocks
  whose ALTERs change a table that exists now ends "marketplace, case chat
  and seen position blocks at the end".
- `db/schema.sql`, the table comment of `chat_room_members`: "Who is in
  which room, and how far each has read (seen_position). Written and
  deleted together with the member's chat_hpke row."
- Here, section 1. The sentence of before stays. A sentence in brackets
  after it, which begins "Since 2026-11-19, section 21", names the one
  exception: a `chat_room_members` row changes when its `seen_position`
  rises, and the table still has `created_at` only.
- `src/chat/chat.service.js`, the opening comment. The list of what the
  chat feature holds gained "how far each member has read (the seen
  positions, since 2026-11-19)". No line of code.
- Checks. All of them ran again, with the same results. `node --check` on
  the five files, clean. The load with no server: 97 routes. The schema
  check in scratch schemas, rolled back: the table's comment read as
  written, the second run changed nothing, and the tables built from
  nothing equalled the updated ones. The two runs of the modules: 51 and
  6 results, all as expected. The md5 over the schema differed from the
  build's by the one table comment. After the rollback the database was
  as before.
- The numbers. `db/schema.sql` has the same 1385 lines, and its sha256
  begins a3de2618 where it began 72ac460b after the build. The schema
  line of the deploy carries the whole hash, so it was written again. One
  commit carries the build and this: the same eight files.

## 22. The first key blob, and the passkey check for the signing servers (2026-11-20)

Design settled 2026-11-19 and 2026-11-20, in a talking chat and a planning
chat (the plan is
`~/Desktop/Z-TestNet/forclaude/second-key-and-signing-passkey-plan-1.md`,
FINAL, 2026-11-20). Why: an anos account has three signing pairs, and the
validators take any two. Pair one and pair two are the person's own; the
third is the wallet pair, which the signing servers hold. The wallet got
pair one and pair two at every login, in one blob per account
(`anos_accounts.key_blob`), and the key that opens that blob stays in the
browser tab. A signing server signed for whoever showed pair one's
signatures. So a copy of what an open tab holds was enough to move the
person's anos, in two ways: with pair one and pair two and no signing
server, or with pair one and a signing server. The user, 2026-11-19: "only
giving the user the first anos key when they log in, and not their
second", and "Making so the signing server required the user to use their
passkey before the signing server would sign the transaction." Each half
of the plan closes one of the two ways, and neither half works alone. The
first half: this server keeps the blob with both pairs as it is, and hands
the wallet a new, small blob with pair one alone, the first key blob. The
second half: a signing server signs only when a passkey answer made for
the exact thing to sign comes with the request, and it asks this server
whether that answer is good. Three repos in order, which is also the order
of the deploys: this server (this section, step 1 of the plan: one column,
two new routes, and a change each in `/create-anos-account` and
`/list-anos-accounts`), the wallet (its spec, step 2: a login stores the
first key blob of each account, and every request to a signing server
carries the passkey's answer), the signing server (its `README.md`, which
is its spec, step 3: it asks `/check-signing-passkey` before it signs),
then the record folders (step 4). With this server alone deployed nothing
changes for anyone: no wallet calls the new routes or sends the new
fields, and no signing server asks. Nothing is enforced until the signing
servers are updated. Inside this server's own deploy the order matters:
the schema file goes onto the database before the new code runs (22.6).
Two new routes and one new column. No table, no env variable and no npm
package. The validators, the doormen, the keyholders, the keyholder GUI
and the wallet's proxy are not touched. Nothing above this section changes
except the items in 22.5.

### 22.1 The rule

- The second key stays here (the plan's decision 2). An account's blob
  with both pairs, `key_blob`, stays under the pod's key blob key, as it
  is today, and once the account has a first key blob this server hands
  `key_blob` to nobody. This is the simple lock. It is this server's rule,
  so a copy of an open tab together with a copy of this server's database,
  or of one of its backups, is the second key. The stronger lock, a second
  secret from the passkey, is not built; it is a line of the
  after-production list.
- Nothing hands the second key out yet (decision 9). The route that hands
  out the blob with both pairs comes later, with the screen where a person
  asks for their second key (section 10). Until then nobody can get their
  second key out, the person included.
- The accounts that exist (decision 14). `key_blob` is kept exactly as it
  is: nothing a person has already encrypted is changed or deleted. At the
  person's next login the wallet makes one new, small blob for each of
  their accounts, with pair one alone. Before it sends the blob, the
  wallet opens it again and compares its keys with the public keys that
  the account's creation names. This server stores the small blob beside
  the old one, in `first_key_blob`, once. From then on it hands the wallet
  only the small one. The person sees nothing of this. When something
  fails, the old blob is still there, the wallet works as before, and the
  next login tries again. A new account is stored the same way: the blob
  with both pairs, as before, and the first key blob, in the one call that
  registers it.
- Two limits of that (decision 14). A copy of a tab made before that login
  already holds both pairs of the accounts the person had then. And until
  a person logs in again, this server still hands their old blob to their
  own wallet.
- A wallet page loaded before the wallet's update (decision 15) keeps its
  old code until the person reloads it, and that code cannot open a first
  key blob. So the wallet of step 2 says `firstKeyBlobs: true` when it
  asks for the list, and a page of before says nothing. Once one of the
  pod's accounts has a first key blob, a call that does not say it is
  refused, `409 reload the wallet` (the old page guard, 22.3). A person
  meets it when they log in on an old page after having logged in
  somewhere with the new wallet. After a reload it works.
- Anyone may ask `/check-signing-passkey`, with no login (decision 6),
  like `/get-anos-account`, the read the validators use to ask which pod
  made an account. The answer is yes or a refusal, it changes nothing, and
  it is of no use without a real passkey answer.
- A signing server that gets no answer from this server signs nothing
  (decision 7). The wallet then asks the other signing server, and when
  that fails too the person is told to try again. The cost: until now a
  wallet tab that was already open could still send while this server was
  down, and once the signing servers ask here it cannot.
- A new anos account needs no passkey answer at the signing server
  (decision 8). It moves no money, this server does not know the account
  yet at that moment (the signing server signs the creation before the
  wallet registers the account here), and the validators already refuse a
  new account unless this server says a vouched pod made it. So
  `/create-anos-account` asks for the session alone, as before, and
  `/check-signing-passkey` is not asked about a creation.

A login, in short (the plan's "How it works"):

```
the row of an account                    what the wallet is handed
key_blob        both pairs (as before)   until the first key blob exists: key_blob
first_key_blob  pair one alone (new)     from then on: first_key_blob, and
                                         key_blob to nobody
```

For each account that has no first key blob yet, the wallet opens the old
blob, wraps pair one's two secrets again alone, checks the new blob
against the account's public keys, and stores it. The old blob is never
written. With both halves of the plan in place a copy of a tab made after
that login holds pair one only, and pair one alone gets no signature from
a signing server.

### 22.2 The column

`db/schema.sql`, in two places. Inline in the `CREATE TABLE` of
`anos_accounts`, after `key_blob`, for a database built from nothing
(section 4). And in a new block after the seen position block, the last
thing in the file, "The first key blob block (2026-11-20, spec section
22)", for a database that has the table:

```sql
ALTER TABLE anos_accounts ADD COLUMN IF NOT EXISTS first_key_blob BYTEA CHECK (octet_length(first_key_blob) BETWEEN 1 AND 1024);
```

- `first_key_blob`: pair one's private halves alone, key1 scalar (32) ||
  postQuantumKey1 seed (32), wrapped under the pod's key blob key: 92
  bytes in practice (section 7). A `BYTEA` that may be null, 1 to 1024
  bytes when it is set (the check). This server cannot open it. Null until
  the wallet stored it, with the account (`/create-anos-account`) or later
  (`/store-first-key-blob`). Written once and never changed: the one
  statement that writes it later writes only where it is null. Once it is
  set, `/list-anos-accounts` hands it to the wallet as `keyBlob` in place
  of `key_blob`.

`key_blob` is never changed: no statement of this server updates it,
before this section or after it. Every account row of today has null in
the new column. The column's comment is in the block only. No index:
nothing looks an account up by it. The table's `updated_at` trigger moves
`updated_at` when a first key blob is stored. The line is idempotent (`IF
NOT EXISTS`), so the whole file applies to a live database and a second
run changes nothing.

Three comments of the file were brought in line with it: the comment over
the `anos_accounts` block, the table's comment and the comment of
`key_blob`. All three said "the pod's encryption key". The key blobs have
been under the key blob key since 2026-11-08 (the wallet's spec, section
7), and the step rewrote the three sentences anyway.

### 22.3 The changes by route

**POST /create-anos-account** (setup; section 5), one optional field more.

Body: as section 5, and `firstKeyBlob`, optional: hex, 1 to 1024 bytes, 92
in practice, pair one's private halves alone under the pod's key blob key.
The wallet of step 2 sends it with every new account. A wallet page of
before sends none, and the row then has none until that pod's next login.

Checks, in order: as section 5, with one more after the check of
`keyBlob`. When the body has a `firstKeyBlob`, it is 1 to 1024 bytes, else
`400 invalid firstKeyBlob`. Only a body without the field counts as none:
a `firstKeyBlob` that is `null`, a number or an empty string gets the
`400`.

Writes: `INSERT anos_accounts`, as section 5, with `first_key_blob` the
blob that was sent, or null.

Answer: `201 { accountId }`, as before.

**POST /list-anos-accounts** (setup; section 5), one field in the body,
one field more in the answer, and one refusal.

Body: `{ firstKeyBlobs }`. `firstKeyBlobs: true` says that the caller's
wallet can open a first key blob. A wallet page of before sends `{}`.

Checks: the old page guard. When `firstKeyBlobs` is not `true` and at
least one of the caller's rows has a first key blob, `409 reload the
wallet`. Anything but the boolean `true` counts as not said. A pod none
of whose rows has a first key blob is answered as before, whatever the
body says.

Reads: the caller's rows, oldest first, as before.

Answer: `200 { accounts: [ { accountId, accountType, keyBlob,
firstKeyOnly, creation, submittedAt, breakGlassBlob, createdAt } ] }`. For
a row that has a first key blob, `keyBlob` is that blob, in hex, and
`firstKeyOnly` is `true`. For a row without one, `keyBlob` is the blob
with both pairs, as before, and `firstKeyOnly` is `false`. The field keeps
its name, so the wallet's code that opens pair one from `keyBlob` does not
change. Once a row has a first key blob, its blob with both pairs is
answered to nobody: this is the only route that ever answered `key_blob`,
and no other route does.

**POST /store-first-key-blob** (setup), new.

Body: `{ accountId, firstKeyBlob }`. `accountId` is one of the caller's
accounts, hex like every id. `firstKeyBlob` is hex, 1 to 1024 bytes, 92 in
practice: pair one's private halves alone under the pod's key blob key.
The wallet sends it at a login, once for each account that has none.

Checks, in order:

1. The body is an object, and `accountId` and `firstKeyBlob` are strings,
   else `400 bad request shape`.
2. `accountId` is 32 bytes, else `400 invalid accountId`.
3. `firstKeyBlob` is 1 to 1024 bytes, else `400 invalid firstKeyBlob`.
4. A row with this `accountId` exists and is the caller's pod's, else
   `404 account not found`.
5. The row has no first key blob yet, else `409 first key blob already
   stored`.

Writes, one statement: `UPDATE anos_accounts SET first_key_blob = <the
blob> WHERE account_id = <the account> AND anopod_id = <the caller> AND
first_key_blob IS NULL`. It writes only where the column is null, so of
two calls at the same moment one writes and the other gets the `409`.
`key_blob` is not touched. No notification, no event.

Answer: `200 { accountId }`, the account in hex.

This server checks the blob's length and nothing else. It cannot open the
blob, so it cannot tell whether pair one is inside; the wallet opens the
new blob and compares its keys with the account's creation before it
sends it (the wallet's spec).

Nothing else changes: not `/mark-anos-account-submitted`, not
`/get-anos-account`, not `/store-break-glass-blob`, and not the routes of
other features that read an account row for its pod, its type or its
creation. They read the new column along with the others and do not use
it.

### 22.4 `/check-signing-passkey`

**POST /check-signing-passkey** (none), new. For the signing servers.
Before a signing server signs for an account, it asks here whether the
passkey answer that came with the request is from a passkey of the pod
that made the account, and is an answer to the challenge the signing
server worked out from the exact thing it is asked to sign. Unsigned, like
`/get-anos-account`: a plain JSON body, no session, and anyone may ask.

Body: `{ accountId, challenge, assertion }`. `accountId` is an anos
account's id, hex like every id. `challenge` is 32 bytes, hex. `assertion`
is the WebAuthn JSON of a passkey's answer to that challenge, the
browser's `PublicKeyCredential.toJSON()`, in the form `/unlock` and
`/add-passkey` take it.

Checks, in order:

1. The body is an object, `accountId` and `challenge` are strings, and
   `assertion` and `assertion.response` are objects, else `400 bad request
   shape`.
2. `accountId` is 32 bytes, else `400 invalid accountId`. `challenge` is
   32 bytes, else `400 invalid challenge`.
3. The answer carries no PRF output (`clientExtensionResults.prf.results`),
   else `400 prf output in request`. The PRF output is the phone's secret
   and reaches no server.
4. The account has a row in `anos_accounts`, and the pod that made it has
   its row in `anopods`, else `404 unknown account`.
5. The passkey that answered (`assertion.rawId`) is one of that pod's: its
   main one, on the pod's `anopods` row, or one it added, an
   `added_passkeys` row of that pod. Else `401 unknown passkey`: a passkey
   nobody has, another pod's passkey and an answer without a `rawId` all
   get it. When the answer carries a user handle, it is the pod's id, else
   `401 user handle mismatch`. An answer without a user handle passes, as
   in `/add-passkey` (19.3): the passkey is matched to the pod by this
   server's own rows.
6. The answer itself verifies, by the check `/unlock` uses
   (`verifyAuthentication` in `src/auth/webauthn.js`): the signature by
   that passkey's stored public key, the challenge in the client data
   equal to the body's `challenge`, the origin one of `WEB_ORIGIN`, the RP
   id `RP_ID`, and user verification. Else `401 passkey verification
   failed`; the library's own reason goes to the log.

Reads: `anos_accounts`, `anopods` and, when the passkey is not the pod's
main one, `added_passkeys`. Writes: nothing. The challenge is the caller's
own, not one of `/challenge`: the `challenges` table is neither read nor
written. So an answer is not used up, and the same answer may be checked
again and gets the same yes.

Answer: `200 { accountId, verified: true }`, the account in hex. A no is a
refusal, `{ error: '<reason>' }` with its status, as everywhere.

Any passkey of the pod is good here, the main one or an added one. The
wallet asks for the one that opened the session (its spec). There is no
limit on how often the route may be asked (section 10).

How the signing server works the challenge out (the plan's decision 17;
the signing server's `README.md` has it once step 3 is built). The
fingerprint of a thing to sign is the SHA-256 of the canonical bytes of
its payload, the same bytes pair one signs and a signing server signs, as
64 lowercase hex characters. The challenge the passkey answers is the
SHA-256 of the fixed label `anos/signing-passkey/v1:` followed by the
fingerprints, joined by commas. For one transfer that is one fingerprint.
For the attestors' "Sign all attestations" on a recovery case it is one
per move. One answer covers at most 100 fingerprints. The wallet sends the
list with its request. The signing server finds the fingerprint of its own
payload in that list, works the challenge out again from the list, and
asks here with the signer's account id, the challenge and the passkey's
answer. So a yes from this server says: a passkey of the pod that made
this account answered for exactly the things in that list. This server
sees the 32 bytes of the challenge. It does not see the list or the
payload.

A passkey answer has no time limit of its own here. The same transfer
cannot be written twice, and the validators refuse a transfer whose date
is more than 10 minutes from their clock; a follow-up carries no such
limit (decision 17). A signing server gives this server 4 seconds to
answer, follows no redirect, and counts a `200` only when it says
`verified: true` (step 3 of the plan).

### 22.5 Files

- `db/schema.sql`: the line in the `CREATE TABLE` of `anos_accounts`; the
  first key blob block, new, at the end; the comment over the
  `anos_accounts` block, the table's comment and the comment of
  `key_blob`; and, on the user's word after the build, the file's opening
  comment, which names the new block among the idempotent ALTERs.
- `src/anos-accounts/anos-accounts.queries.js`: `accountRow` and
  `COLUMNS`, the new column; `insertAccount`, the new field;
  `setFirstKeyBlob`, new.
- `src/anos-accounts/anos-accounts.service.js`: `accountOf` (`keyBlob`,
  `firstKeyOnly`); `createAnosAccount`, the optional `firstKeyBlob`;
  `listAnosAccounts`, the body and the old page guard;
  `storeFirstKeyBlob`, new; the import of `setFirstKeyBlob`; the comment
  of `keyBlobLength` and the file's opening comment.
- `src/anos-accounts/anos-accounts.handlers.js`: `listAnosAccountsHandler`
  hands the body on; `storeFirstKeyBlobHandler`, new, and the import of
  `storeFirstKeyBlob`.
- `src/anos-accounts/anos-accounts.router.js`: the route's line, the
  import of `storeFirstKeyBlobHandler`, and "Four routes" in the comment.
- `src/passkeys/passkeys.service.js`: `checkSigningPasskey`, new, at the
  end; the imports of `findById` and `findAccount`; one sentence in the
  file's opening comment, and, on the user's word after the build, that
  comment's last sentence. `addPasskey` and `listPasskeys` keep their
  bodies: the lookup of check 5 is written out in the new function, not
  shared with `addPasskey`.
- `src/passkeys/passkeys.handlers.js`: `checkSigningPasskeyHandler`, new,
  the import of `checkSigningPasskey`, and the file's opening comment.
- `src/passkeys/passkeys.router.js`: the route's line, with no middleware
  in it, the import of `checkSigningPasskeyHandler`, and the comment.
- `src/app.js`: the comments on the lines of the passkeys router and of
  the anos accounts router. No line of code.
- `src/auth/webauthn.js`: on the user's word after the build, one sentence
  at the end of the file's opening comment. No line of code.
- Here: section 2 (the none row and the setup row), section 4
  (`### anos_accounts`: the first sentence, the line in the SQL and the
  sentence on the lengths), section 5 (`### POST /create-anos-account` and
  `### POST /list-anos-accounts`, a sentence at the end of each), section
  7 (the row of the anos `keyBlob`, and a new row after it), section 10
  (a new last item) and this section; and, on the user's word after the
  build, a sentence in brackets in section 5
  (`### POST /create-anos-account`) and one in 19.6. `README.md`: "Who may
  call what"
  (the none row and the setup row), the Endpoints table (the rows of
  `/create-anos-account` and `/list-anos-accounts`, and two new rows), the
  row of `anos_accounts` in the tables table, the `passkeys/` and
  `anos-accounts/` lines of the Layout, and "Deferred, by decision" (a
  new last item).

Nothing else in existing code changes: not `/get-anos-account`, not
`/mark-anos-account-submitted`, not `/add-passkey`, not `/list-passkeys`,
not `/challenge`, not the code of `src/auth/webauthn.js`, not
`.example.env`. Two new routes and one new column; no table, no env
variable, no npm package.

### 22.6 Notes from the build

#### Build 1, the masterpod (2026-11-20)

Built from
`~/Desktop/Z-TestNet/forclaude/second-key-and-signing-passkey-plan-1.md`
section 1, on main at 521b3bb, the working tree clean. No new npm package,
no test script and no rig (none was asked for). The schema was not applied
to any database for keeps: the user applies the whole file as section 6 of
`forclaude/masterpod-deploy-plan-1.md` says. It goes on before this code
runs. On a database without the column this code cannot answer
`/list-anos-accounts`, so every wallet's account list would fail, and with
it every other route that reads an account row (listed below). The other
way round is safe: the code of before names its columns and never looks at
the new one. Both were tried (the checks below). What the plan left open
and how it was decided:

- The date. BUILD-DATE is 2026-11-20, the day of the build and of the
  plan's FINAL.
- The plan's code blocks are in the files as written. To catch a copying
  mistake, the working tree was compared with a copy of 521b3bb that the
  planning chat's own script had patched (`patch_mp.py`, counted exact
  replacements, the script the plan's code was tried with).
  `db/schema.sql` and the eight source files were equal to it, but for
  the four comments that script does not write: the opening comments of
  `anos-accounts.service.js`, `passkeys.service.js` and
  `passkeys.handlers.js`, and the comment of `passkeys.router.js`.
- Comments. Where the plan gives a comment's new words and not its lines,
  the lines the change does not reach keep their breaks, so the diff shows
  the changed sentence alone. The comment of `createAnosAccount` has the
  breaks of the planning chat's copy.
- `db/schema.sql`. The new line of the `CREATE TABLE` stands after
  `key_blob`, as the plan has it. So on a database built from nothing
  `first_key_blob` is the table's fifth column, and on a database that had
  the table it is the last, the tenth. The code names its columns, so the
  position does not matter. PostgreSQL names the check
  `anos_accounts_first_key_blob_check` on both ways. The block is the last
  thing in the file, after the seen position block, in that block's form.
- `listAnosAccounts` reads `body.firstKeyBlobs` with no shape check of its
  own. It needs none: the session check lets a request through only when
  its `payload.body` is an object (`parseSignedRequest`).
- `storeFirstKeyBlob` reads the row first (`findAccount`), for the `404`
  and the `409`. The `UPDATE` then carries both conditions again, the pod
  and the null, so it cannot write another pod's row or a row that got a
  blob in between; a write that finds no such row is the `409`.
- `checkSigningPasskey`. The checks run in the plan's order, so a body
  with a PRF output is refused before the account is looked up. The
  account id and the challenge are read by `decodeId`, so base64 is taken
  beside hex, as for every id, and the answer gives the account in hex.
  The pod is read by `findById`; an account whose pod row is gone answers
  `404 unknown account`, like an account this server does not know. The
  second lookup, in `added_passkeys`, runs only when the passkey is not
  the pod's main one, so a check with the main passkey costs two reads.
- The log. A yes writes no line: `answer()` logs refusals alone (`failed:
  <reason>`). A failed check 6 also logs the library's reason before it
  (`passkey verification failed: <reason>`), as `/add-passkey` does. For
  a wrong challenge that reason names the two challenges, and for another
  site the origin. Nothing else of a request is logged: no account id, no
  credential id and no signature.
- Here. In section 2 the none row takes the new route after
  `/get-anos-account`, and the setup row takes `/store-first-key-blob`
  after `/list-anos-accounts`, each with "(section 22)", as the plan has
  it. In section 4 the plan's words stand in the place of the old ones, so
  "(which this server cannot open)" now follows "(section 22)". In section
  5 each of the two routes got one sentence at its end that points to
  22.3, in the form of the sentences that point to 19.3 and 20.2. The body
  line of `/list-anos-accounts` there still reads `{}`, and its answer
  line still lists six fields, without `breakGlassBlob`, as before this
  step. The new row of section 7 writes the two bars in the table's own
  form. Section 10 got the four things as one new last item.
- The README. The build put the plan's sentence into the row of
  `/list-anos-accounts`. The old row's words "the creation, `submittedAt`
  and `breakGlassBlob` (null until a recovery stored it)" are not in that
  sentence, so the row no longer named those three; section 5, 12.4.5 and
  22.3 here do. The row got them back the same day (below). In "Who may
  call what" the none row names the new route after `/get-anos-account`,
  with no words around it.
- Checks (1.8). `node --check` on the eight changed `.js` files, clean, on
  Node 24.22.0. Then one load of the app with no server, by a throwaway
  script in the build chat's scratch folder: `src/app.js` imported and
  `createApp()` called, with made-up `PGDATABASE`, `PGUSER` and
  `PGPASSWORD` and `PGHOST=/nonexistent`. It counted 99 routes, where the
  files of 521b3bb count 97, with `/store-first-key-blob` between
  `/list-anos-accounts` and `/get-anos-account`, and
  `/check-signing-passkey` after `/list-passkeys`. Nothing listened and no
  database was reached. The schema by psql against this Mac's PostgreSQL
  (17.11), as the superuser `codex` with `SET LOCAL ROLE
  masterpodsoftware`, in one transaction that was rolled back. First on
  this Mac's own `masterpod` database, which is an old build of 36 tables:
  the new file made it 37 tables, `first_key_blob` a `bytea` that may be
  null, with no default; the new file once more changed nothing. One md5
  over every column, constraint, index, trigger, comment and function of
  the schema was the same after both runs. Then a scratch schema that
  first got the file of 521b3bb: 37 tables, no `first_key_blob`, and one
  account row put in. The new file on top: the column was there as the
  tenth, with its check and its comment, the table's comment and the
  comment of `key_blob` read as written, and the account row kept its
  `key_blob` of 156 bytes and had null in the new column. The new file
  once more changed nothing, by the same md5. After the rollback the
  database was as before: its 36 tables, no scratch schema, the same md5.
- The modules themselves (1.8), called as a route calls them, against that
  scratch schema inside a rolled-back transaction, with the planning
  chat's throwaway script (`check_mp.mjs`) pointed at the working tree. It
  puts a stand-in in the place of `src/db/pool.js`: one client, with the
  transaction of `withTransaction` turned into a savepoint, so nothing
  could commit. The passkey answers were made with `node:crypto`: a P-256
  key, its COSE form as the stored public key, the authenticator data for
  the RP id `localhost` with the flags user present and user verified, and
  a signature over it and the hash of the client data. 37 results, all as
  the plan's table has them. The new code on the tables of 521b3bb failed
  `/list-anos-accounts` with `column "first_key_blob" does not exist`.
  With the new file on top: a creation without `firstKeyBlob` (`201`); the
  list before a store, with and without `firstKeyBlobs` (the blob with
  both pairs, `firstKeyOnly` false); the store's refusals (`404 account
  not found` for another pod's account, `400 bad request shape`, `400
  invalid firstKeyBlob` for 1025 bytes), the store (`200`) and a second
  one (`409 first key blob already stored`); the list without
  `firstKeyBlobs` after it (`409 reload the wallet`) and with it (the
  small blob, `firstKeyOnly` true, the blob with both pairs nowhere in the
  answer); the row after it (`key_blob` as it was); a creation with both
  blobs and its list; `400 invalid firstKeyBlob` for a number; a second
  pod untouched by the first pod's small blobs. The check: `200 {
  accountId, verified: true }` for the pod's passkey, its account and the
  challenge it answered, the same again, and with the pod's id as user
  handle; `401 passkey verification failed` for an answer to another
  challenge, for one made for another site and for one without user
  verification; `401 unknown passkey` for another pod's passkey, for this
  pod's passkey with another pod's account and for a passkey nobody has;
  `404 unknown account`; `401 user handle mismatch`; `400 prf output in
  request`, `400 invalid challenge`, `400 bad request shape`; `200` for a
  passkey the pod added, and `401 unknown passkey` for that passkey with
  another pod's account. The `challenges` table held no row at the end.
- Beyond the letter of 1.8, with nothing kept. (a) The schema: the new
  file alone into a second empty scratch schema, twice. 37 tables, the
  column the fifth, and the same md5 as the updated schema after both runs
  (the md5 leaves the column's position out). The column's check refused
  an empty blob and one of 1025 bytes and took none, 92 bytes and 1024
  bytes. The only difference between this Mac's own tables with the new
  file on top and tables built from nothing was an older check on
  `escrow_dispute_evidence`, which is not this step's. (b) The new code on
  the tables of 521b3bb, call by call: `/create-anos-account`,
  `/store-first-key-blob` and `/check-signing-passkey` failed like the
  list, with the same missing column, because each reads an account row
  through `findAccount`, which names the column. By the code the same
  holds for the other routes that call `findAccount`:
  `/add-noted-transaction`, `/list-anos-account-profiles`,
  `/open-trade-case`, `/open-dispute-case`, `/file-break-glass-moves`, and
  the sign-offs of a recovery case, a trade case, a dispute case and a
  break-glass case. `/get-anos-account`, the validators' read, and
  `/mark-anos-account-submitted` answered: they name their own columns.
  (c) The other way round: the code of 521b3bb, from a copy of that
  commit's files, on the new tables. Its `/create-anos-account`,
  `/list-anos-accounts`, `/get-anos-account` and
  `/mark-anos-account-submitted` answered, and the row it wrote had null
  in the new column. For an account that had a first key blob it handed
  out the blob with both pairs, and the row kept both blobs: that is the
  way back of the plan's section 5. (d) The handlers with a stand-in for
  the response: `200 { accountId }` and `409 { error: 'first key blob
  already stored' }` for the store, `409 { error: 'reload the wallet' }`
  for the list without `firstKeyBlobs` and with the string `"true"`, the
  eight fields of an account in the answer's order, `200 { accountId,
  verified: true }` and `401 { error: 'unknown passkey' }` for the check,
  and `400 bad request shape` for a check with no body at all. (e) A few
  more refusals: `firstKeyBlob` as `null` or an empty string at a creation
  (`400 invalid firstKeyBlob`); at the store a blob that is a number (`400
  bad request shape`), an empty string (`400 invalid firstKeyBlob`), an
  account id of 2 bytes (`400 invalid accountId`) and an account nobody
  made (`404 account not found`); at the check the ids in base64 (`200`),
  an account id of 2 bytes, an assertion without `response`, an answer
  without `rawId` (`401 unknown passkey`), the pod's passkey id with
  another key's signature (`401 passkey verification failed`) and an
  account whose pod row is gone (`404 unknown account`). 37 further
  results, all as expected.
- Not tried. No server was booted, no request was signed and no route was
  called over HTTP: the session check and the envelope are as they were.
  No real passkey, no browser, no phone, no wallet and no signing server
  was part of it. Two stores at the same moment were not raced, since the
  runs use one client: that one writes and the other gets the `409` is
  read from the `UPDATE`, which writes only where the column is null.
- Places the plan does not name that this step left out of date. The
  build left them as they are and put them to the user. In
  `db/schema.sql`: the file's opening comment lists the blocks at the end
  whose ALTERs change a table that exists, without the first key blob
  block. Here, 19.6, a note of the build of 2026-11-18: "`/list-passkeys`
  reads nothing from its body, as `/list-anos-accounts` reads nothing from
  its own"; `/list-anos-accounts` now reads `firstKeyBlobs`. In
  `src/passkeys/passkeys.service.js`: the opening comment ends "Each
  function runs its route's checks in the spec's order (19.3)", and the
  new function's checks are in 22.4. In `src/auth/webauthn.js`, which this
  step does not touch: the opening comment says both verifications expect
  "the challenge the server issued", and `/check-signing-passkey` hands
  `verifyAuthentication` a challenge of the caller's own. One more place
  is older than this step: section 5, `### POST /create-anos-account`,
  says "the encryption key the `keyBlob` is under exists", and the key
  blobs have been under the key blob key since 2026-11-08. The user had
  all five brought in line the same day (below).
- Not touched by the build: every other feature folder, `src/auth/`,
  `.example.env`, `package.json`, the scripts. In `src/app.js` two
  comments changed and no line of code. One comment in
  `src/auth/webauthn.js` changed the same day (below).
- The numbers. After the build `db/schema.sql` had 1404 lines, 19 more
  than before, and its sha256 began dbc98dcc. With its opening comment
  brought in line (below) it has 1405 lines and its sha256 begins
  b65403d0. Before the step it had 1385 lines and its sha256 began
  a3de2618. It makes 37 tables, as before: the count that the deploy's
  schema line prints does not change with this step, so a look at the
  column itself shows that the change landed.

#### After the build's report, the same day (2026-11-20)

The user read the report in the build chat. It listed the five places
above, with the advice to bring all five in line. The user: "go ahead and
change those things you listed." So the five were brought in line before
the commit. None of this is in the plan.

- `db/schema.sql`, the file's opening comment. The list of the blocks
  whose ALTERs change a table that exists now ends "marketplace, case
  chat, seen position and first key blob blocks at the end". The comment
  is one line longer.
- Here, 19.6, a note of the build of 2026-11-18. The sentence of before
  stays. A sentence in brackets after it, which begins "Since 2026-11-20,
  section 22", says that `/list-anos-accounts` now reads one field of its
  body.
- `src/passkeys/passkeys.service.js`, the opening comment. Its last
  sentence now reads "the spec's order (19.3, and 22.4 for
  /check-signing-passkey)". No line of code.
- `src/auth/webauthn.js`, the opening comment. Its sentences stay. One
  sentence at its end, which begins "Since 2026-11-20", says that
  `/check-signing-passkey` hands `verifyAuthentication` a challenge this
  server did not issue: its caller's own. No line of code.
- Here, section 5, `### POST /create-anos-account`. The sentence of before
  stays. A sentence in brackets after it, which begins "Since 2026-11-08",
  says that the `keyBlob` is under the pod's key blob key and no longer
  under the encryption key. This place was out of date before the step.
- `README.md`, the row of `/list-anos-accounts`. This one was not among
  the five. The planning chat, which wrote the plan, read the build's
  report and wrote in the work note that its sentence for the row had
  left out "the creation, `submittedAt` and `breakGlassBlob`" by a slip
  and not by choice. So the row has the old words back, between the blob
  and the `409`: "with the creation, `submittedAt` and `breakGlassBlob`
  (null until a recovery stored it)". Told to the user in the same
  report.
- Checks. All of them ran again, with the same results. `node --check` on
  nine files, the eight of the build and `src/auth/webauthn.js`, clean.
  The load with no server: 99 routes. The schema check in scratch schemas,
  rolled back: the second run changed nothing, and the tables built from
  nothing equalled the updated ones, by the same md5s as before, since a
  comment at the top of the file stores nothing. The two runs of the
  modules: 37 and 37 results, all as expected. After the rollback the
  database was as before.
- The numbers. `db/schema.sql` has 1405 lines, one more, and its sha256
  begins b65403d0 where it began dbc98dcc after the build. The schema line
  of the deploy carries the whole hash, so it was written with this one.
  One commit carries the build and this: twelve files, the eleven of the
  build and `src/auth/webauthn.js`.

## 23. The listing limit (2026-11-20)

Design settled 2026-11-20 in a planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/listing-limit-plan-1.md`, FINAL,
2026-11-20). Why: nothing limited how many listings one pod opens. The
user, 2026-11-20: "it hasn't happened yet, but I'm sure some one is going
to spam and make like 30 marketplace listings. We should limit how many
total can be open at 1 time." `/create-listing` is the only code that
makes a listing, and nothing opens a closed listing again. So the number
of a pod's open listings goes up through this one route, and the limit
sits on it and nowhere else. The same plan has a second half, which is
the wallet's alone: the marketplace's first page stops at 200 listings
with no way to see the rest. The user: "Is there like a scroll more if
200 is not enough for some one? Or like a fetch more or something." That
page gets a Show more button, and this server does not change for it:
`/list-listings` has always taken `offset`. Two repos in order: this
server (this section, step 1 of the plan: one check in one route) and the
wallet (its spec, step 2: the refusal said in one sentence, and Show
more), then the record files (step 3). Either order of the two deploys is
safe; the usual order is kept, this server first (the plan's section 4).
With this server alone deployed the limit holds, and a wallet of before
shows the refusal as it came, "HTTP 403: listing limit reached", in red
on its New listing page. There is no schema step, no env variable, no npm
package and no new route. The validators, the doormen, the keyholders,
the signing servers and the wallet's proxy are not touched. Nothing above
this section changes except the items in 23.4.

### 23.1 The rule

- A pod may have at most 10 listings open at one time (the plan's
  decisions 1 and 2). The user: "write the plan with 10".
- Selling and buying listings count together (decision 5).
- A closed listing does not count (decision 3). The user asked: "If the
  listing is closed, that doesn't count towards the 10 right?" It does
  not. Closing a listing frees a place at once.
- A pod that already has more than 10 open listings on the day the limit
  goes live keeps every one of them (decision 11). It cannot create
  another until it has fewer than 10. The deploy closes nothing.

### 23.2 The check

`createListing` (`src/marketplace/marketplace.service.js`) runs it last.
The checks of the five fields stay in front of it, so a bad price is
still told as a bad price (`400 invalid price`), also to a pod at the
limit. The number is one constant at the top of the file, `LISTING_LIMIT
= 10`. It is not an env variable: the user owns `.env`, and a change of
the number is one line and a restart either way.

The insert runs inside `withTransaction` (`src/db/transaction.js`), on
the one client. First `lockPod(client, anopodId)` holds the pod's own row
in `anopods` for the rest of the transaction. It is the account limit's
function (17.2), imported from
`src/anos-accounts/anos-accounts.queries.js`:

```sql
SELECT 1 FROM anopods WHERE anopod_id = $1 FOR UPDATE
```

Then `countOpenListings(client, anopodId)`, new in
`src/marketplace/listings.queries.js`, answers the number of the pod's
open listings:

```sql
SELECT count(*)::int AS count FROM listings
WHERE anopod_id = $1 AND status = 'open'
```

When the count is `LISTING_LIMIT` or more, the transaction ends with no
insert and the answer is `403 listing limit reached`. Otherwise
`insertListing` writes the row on the same client and the answer is `201
{ listingId, chatRoomId: null }`, as before.

Why the lock: without it, requests of one pod sent at the same moment
would each count the same rows and all pass, so a script that sends
thirty at once could open thirty listings. With the pod's row locked they
wait for each other: the second counts only after the first has ended,
and its count sees the first one's row. `/create-anos-account` locks the
same row for its own count, so a listing and a new account of one pod
sent at the same moment wait for each other too, for the length of one
small transaction. `/close-listing` takes no lock: it only lowers the
count. The refusal is a `403`, as the account limit's is (17.2).

The database does not change. `listings` has one index, on `(status,
created_at DESC)`, and none on `anopod_id`. The count looks through the
open rows, which are few. An index on `anopod_id` is a schema step, left
until the table is large.

### 23.3 What is left as it is

- The wallet shows no counter and no hint ahead of time. A person only
  hears of the limit when it refuses them, in one sentence on the New
  listing page: "You have reached the limit of open listings. Close one
  of your listings to create a new one." It names no number, so it stays
  true when the constant changes. The sentence is the wallet's step 2.
- The limit is on listings that are open at one moment. A person can
  close a listing and post it again, and it then stands at the top of
  Newest again.
- Nothing closes a listing but its owner. A listing whose trade is done
  counts until its owner closes it.

### 23.4 Files

- `src/marketplace/listings.queries.js`: `countOpenListings`, new, after
  `closeListing`.
- `src/marketplace/marketplace.service.js`: the imports of `lockPod` and
  `countOpenListings`, the constant `LISTING_LIMIT`, and in
  `createListing` the transaction with the lock, the count and the
  insert; the function's comment gains the limit as the last check.
- `src/anos-accounts/anos-accounts.queries.js`: the comment of `lockPod`,
  which now names its second user. No line of code.
- Here: section 4 (`### listings`, one sentence), section 5 (`### POST
  /create-listing (setup)`, the last check and its refusal) and this
  section. `README.md`: the route row of `/create-listing`.

Nothing else in existing code changes: `/close-listing`, `/list-listings`
and `/get-listing`, the router, `src/chat/`, `db/schema.sql` and
`.example.env` are as they were. No env variable, no npm package, no new
route.

### 23.5 Notes from the build

#### Build 1, the masterpod (2026-11-20)

Built from `~/Desktop/Z-TestNet/forclaude/listing-limit-plan-1.md` section
1, on main at 3ddd08e, the working tree clean. No new npm package, no
test script and no rig (none was asked for). Nothing was applied to any
database: there is no schema step. What the plan left open and how it was
decided:

- The number and the date. This section is 23, the next free number on
  the build day. BUILD-DATE is 2026-11-20, the day of the build and of
  the plan's FINAL.
- The code. `countOpenListings`, the two imports, the constant and the
  new lines of `createListing` are the plan's, letter for letter, with 23
  where the plan's comments say N. `createListing` has no `try` around
  its transaction, as before: the listing id is 32 random bytes that
  this server makes, so there is no repeat to answer.
- The comments. The doc comment of `createListing` gained the limit at
  its end, in the words of the plan's 1.2 and in the form of the comment
  of `createAnosAccount`: it begins "Last, the listing limit (2026-11-20,
  spec section 23)" and ends "The insert runs in that transaction." The
  comment of `lockPod` gained one sentence at its end: "/create-listing
  locks it too, before it counts the pod's open listings (2026-11-20,
  spec section 23)." Its words of before stay.
- `lockPod` answers nothing, and `createListing` does not ask whether a
  row was locked, as `createAnosAccount` does not (17.5): the route's
  level (`requireSetup`) read the pod's row a moment before.
- The transaction answers `true` when the row went in and `false` at the
  limit, and the `403` is made right after it. At the limit the
  transaction ends by `COMMIT` with nothing written (`withTransaction`
  rolls back only on a throw), which frees the lock just the same.
- `lockPod` stays where it is, in the queries file of the anos accounts,
  and the marketplace's service imports it from there, as the plan says.
  It is the first import line, the place the file's order by path gives
  it. A service that reads another folder's queries file is not new:
  `anos-accounts.service.js` reads the appointments' own.
- The constant sits after `MAX_LIMIT`, under its own comment, and is not
  exported: nothing else reads it. `countOpenListings` sits between
  `closeListing` and `listListings`.
- Here and in the README. In section 4 the sentence went on the end of
  the paragraph under the SQL block. In section 5 the entry of
  `/create-listing` had no "Checks" paragraph. The new one stands between
  the body and "Writes", where the other routes have theirs. It names the
  checks of the fields only as "the fields above": the plan asks for the
  last check and its refusal, so the words of the older refusals are not
  written out there. The README row gained its words at its end, after a
  semicolon.
- Checks (1.5). `node --check` on the three changed source files
  (`src/marketplace/listings.queries.js`,
  `src/marketplace/marketplace.service.js`,
  `src/anos-accounts/anos-accounts.queries.js`), clean, on Node 24.22.0.
  Then one load of the app with no server, run from the build chat's
  scratch folder as one `node -e` line, with no file kept: `src/app.js`
  imported and `createApp()` called, with made-up `PGDATABASE`, `PGUSER`
  and `PGPASSWORD` and `PGHOST=/nonexistent`. It counted 99 routes, the
  count of section 22's build, since the step adds none; four of them are
  the marketplace's. It ended with exit 0. The step adds an import across
  folders, and a wrong one would have failed the load. Nothing listened
  and no database was reached. Then the two statements by psql against
  this Mac's PostgreSQL (17.11), on its `masterpod` database, as the
  superuser `codex`, in one transaction that was rolled back: `CREATE
  SCHEMA scratch_listing_limit AUTHORIZATION masterpodsoftware`, `SET
  LOCAL ROLE masterpodsoftware`, the search path set to the scratch
  schema, and `db/schema.sql` read into it, which made 37 tables. Into
  its `listings` went 10 open rows, five selling and five buying, and one
  closed row, all for one throwaway pod id. The query of
  `countOpenListings` read 10 for that id, and 0 for a second throwaway
  id with no rows. The query of `lockPod` ran for the throwaway id and
  answered no row, since the scratch `anopods` was empty. With a pod's
  row it is the statement `/create-anos-account` has run since
  2026-11-10. The parameters went untyped (`\bind`), as `pg` sends them.
  After the rollback the database was as before: its 36 tables (an older
  build), no listings and no scratch schema.
- One comparison beyond 1.5, with nothing kept. The planning chat had put
  this code into a throwaway copy of 3ddd08e and called the real
  `createListing`, `close` and `list` against a scratch schema: 18
  results, none bad, among them ten creations answered `201`, the
  eleventh `403 listing limit reached`, and a close that freed a place
  (the plan's section 6). That copy was still in its scratch folder. A
  `diff` of the three source files against it: `listings.queries.js` is
  the same byte for byte, and the two others differ in comment lines
  only, three in all (the date where the copy has the word BUILD-DATE,
  and the words of the sentence on `lockPod`). No other file of `src` or
  `db` differs from that copy. So those 18 results were made by the lines
  of code this build has.
- Not tried by the build. No server was booted, no request was signed and
  no route was called over HTTP: the `403` over HTTP takes eleven
  listings from one pod to see, and that run-through is the user's (the
  plan's section 4). Two creations at the very same moment were not
  raced, by the planning chat or by the build: the lock is the account
  limit's, in use since 2026-11-10.
- Places the plan does not name that this step left out of date: none
  found. Looked through: every place here, in `README.md` and in `src`
  that names `/create-listing`, `createListing`, `lockPod`, a limit or a
  refusal of the marketplace.
- Not touched: `marketplace.router.js`, `marketplace.handlers.js`,
  `/close-listing`, `/list-listings` and `/get-listing`,
  `anos-accounts.service.js`, `src/chat/`, every other feature folder,
  `db/schema.sql`, `package.json`, `.example.env`, the scripts; in the
  README everything but the one route row. In
  `src/anos-accounts/anos-accounts.queries.js` one comment changed and no
  line of code.

## 24. The stored selfies made small (2026-11-21)

Design settled 2026-11-21 in a planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/stored-selfies-plan-1.md`, FINAL,
2026-11-21). Why: the user, 2026-11-20: "I just noticed that the selfie
pictures are all in the hundreds of kilobytes ... Seeing as they're
always displayed in small circles anyways, they don't need to be loading
in big pictures." Since 2026-11-21 the wallet sends a new selfie as the
middle of the picture, a square of at most 320 pixels (the wallet's spec,
section 11, the note of that day). That reaches only pods made after the
wallet's deploy. The selfies stored before it stay as they are: on
2026-11-21 production held 539 of them, all `image/jpeg`, 116 MB in all,
226,591 bytes on average, and every page that draws a face loads one.
This section is the one-time job that draws them again, small. It is a
script, `scripts/small-selfies/small-selfies.js`, that the operator
starts by hand on the database server that takes the writes. There is no
route for it, no table and no line of `db/schema.sql`, no env variable,
and no change to this server's own packages. The running server does not
change: under `src` one comment was brought in line, and no line of code.
The masterpod is not stopped for the job. The wallet, the validators, the
doormen, the keyholders and the signing servers are not touched. Nothing
above this section changes except the items in 24.4.

### 24.1 The rule

- One stored picture per pod, as before. No second, smaller copy (the
  plan's decision 1).
- Only a selfie wider or higher than 320 pixels is touched (decision 5).
  It becomes the middle of its picture as a square, as a JPEG named
  `image/jpeg`: 320 by 320 pixels, or as many pixels as its shorter side
  has when that is fewer (400 by 300 becomes 300 by 300). A picture is
  never made larger than it is (decision 2).
- A selfie of 320 pixels or less on both sides is left exactly as it is.
- A PNG or WebP larger than 320 is drawn the same way and becomes a JPEG,
  white under a see-through part.
- A picture that cannot be read is left exactly as it is and named in the
  report, and the job does the others.
- All the pictures are replaced in one go, all or none (decision 4). The
  table is copied aside first, in the same transaction (decisions 3 and
  14).

### 24.2 The drawing and the comparing

The pictures are drawn by the npm library `sharp` 0.35.5 (libvips
8.18.7), with one thread and no cache (decision 13).

The drawing (decision 20). The turn mark of a picture (EXIF orientation)
is applied, as the wallet does it. The middle square is cut and made
smaller in one `resize` with `fit: 'cover'`, which filters as the
wallet's halvings do, with `fastShrinkOnLoad` off. The JPEG is written at
quality 80, colour at half size both ways (4:2:0), not progressive: the
tables Chrome writes at 0.8, so a redrawn selfie weighs what the wallet
in Chrome sends, about 15 KB (decision 6). Nothing else of the old file
is kept: no EXIF and no colour profile (`sharp` turns the colours into
sRGB).

The comparing (decision 12). Before a small picture is kept, the job
compares it with the pod's own original. The original's middle square,
cut out exactly, and the small picture are each brought to 32 by 32 grey
points, and the mean difference of the two sets of points may be at most
4 (of 255). A small picture against its own original comes out near 1. A
picture turned on its side, mirrored or cut from the wrong place comes
out at 57 and more (the plan's section 5). The masterpod's own reader,
`imageSize` (`src/util/images.js`), must also read the small picture as a
JPEG of the expected side. A picture that fails either check is left
exactly as it is and named in the report, like one that cannot be read.
This stands in for a person's look at every face.

### 24.3 The two runs, the copy and the way back

On the database server that takes the writes, as the masterpod user in
the checkout, after `npm ci --ignore-scripts --no-audit --no-fund` in
`scripts/small-selfies/` has fetched `sharp`:

```bash
npm run small-selfies -- look
npm run small-selfies -- write
```

`look` reads every selfie, one at a time, draws it, compares it, prints
the report and writes nothing. `write` does the same and then writes, in
one transaction: the whole table is copied aside as
`public_selfies_before_small` (`CREATE TABLE ... AS SELECT * FROM
public_selfies`); each row to be made small is replaced by an `UPDATE`
that changes the row only while it still holds the bytes that were read
(`WHERE anopod_id = $2 AND sha256(image) = $3`, and one row must have
changed); the rows that differ from the copy are counted and must be as
many as were to be made small; then `COMMIT`. An error on the way ends in
`ROLLBACK` and the line `Nothing was kept.`, so the copy and the small
pictures appear together or not at all. `write` refuses to start while
the copy of an earlier run is still there. With nothing to make small it
prints `Nothing to make small.` and makes no copy. Anything but `look` or
`write` prints the usage line and exits 2.

The report, here with the figures of this Mac's test database:

```
small selfies: look (nothing is written)
selfies read: 10
  to be made small: 10
  left as they are, already 320 pixels or less: 0
  left as they are, cannot be read: 0
  left as they are, the small picture did not match: 0
weight now: 1,781,286 bytes (1.7 MB), after: 155,605 bytes (0.1 MB)
the heaviest small picture: 16,777 bytes
```

Under it stands one line for each row that cannot be read or did not
match: the username, the first eight characters of the id in hex, and the
reason. "After" is the small bytes of the rows to be made small plus the
stored bytes of the rows left as they are. A `write` run then prints
`copy kept as public_selfies_before_small: <n> rows`, `made small: <n>`
and `committed`.

The way back and the end of the copy are plain `psql` lines on that
server, not runs of the script, and they need no `sharp` (decision 15).
Every picture put back, in one go:

```text
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -1 -P pager=off -d masterpod -c "update public_selfies s set content_type = b.content_type, image = b.image from public_selfies_before_small b where b.anopod_id = s.anopod_id and (s.image <> b.image or s.content_type <> b.content_type)" -c "select count(*) as selfies, count(b.anopod_id) as in_the_copy, count(*) filter (where s.image = b.image and s.content_type = b.content_type) as same_as_the_copy, pg_size_pretty(sum(octet_length(s.image))) as weight_in_all from public_selfies s left join public_selfies_before_small b using (anopod_id)"
```

It prints `UPDATE` with the number that was made small, then one row in
which `same_as_the_copy` equals `in_the_copy`. A second run prints
`UPDATE 0`. The copy stays until it is removed, and a new `write` run
needs it gone. The copy removed, once the faces have been seen to be
right (decision 8); this is the one step that cannot be undone:

```text
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -P pager=off -d masterpod -c "drop table public_selfies_before_small" -c "select count(*) as tables from pg_tables where schemaname = 'public'"
```

It prints `DROP TABLE` and the number of tables in `public`, 37 on
production. While the copy is there that number is 38, and the copy takes
the disk space the selfies took before, on each database server.

### 24.4 Files, and what is left as it is

- `scripts/small-selfies/small-selfies.js`, new: the script.
- `scripts/small-selfies/package.json` and
  `scripts/small-selfies/package-lock.json`, new: the script's own
  packages, `sharp` 0.35.5 and nothing else (decision 10). npm fills that
  folder's own `node_modules`, which `.gitignore` already covers and
  which is removed from the server once the job is done (decision 17).
  This server's own `dependencies` and its `package-lock.json` are
  unchanged. The running server never loads `sharp`, and it still never
  opens a picture: `src/util/images.js` reads a header and nothing else.
- `package.json`: the line `small-selfies` in `scripts`, after `revoke`.
- `src/anopods/anopods.service.js`: the comment of `SELFIE_MAX_SIDE`,
  which said what the wallet sent before 2026-11-21. No line of code.
- Here: this section, and one sentence of section 11 ("Pictures: no PDFs
  as evidence, and the selfie check (2026-11-12)") that said the same.
  `README.md`: one row under "Scripts" and one line under "Layout".

Left as it is:

- `updated_at` of a redrawn row shows when it was redrawn: the table's
  trigger sets it. After a put-back it shows the time of the put-back.
  Nothing reads it.
- The comment on `public_selfies.image` in `db/schema.sql` still says
  "The image bytes as uploaded". It is left: `db/schema.sql` is not
  touched by this build.
- The redraw of every new selfie on the server is still on the list for
  after production ("selfies redrawn on the server"). Someone who skips
  the wallet and posts to this server directly can still store a large
  selfie. The job can be run again at any time: it touches only what is
  larger than 320 pixels on a side.
- The recovery selfie and the ID photos are other pictures, locked, and
  are not touched.
- The script and its two package files stay in the repo, as
  `scripts/make-super-seed.js` does.

### 24.5 Notes from the build

#### Build 1, the script (2026-11-21)

Built from `~/Desktop/Z-TestNet/forclaude/stored-selfies-plan-1.md`
section 1, on main at 78aedc4, the working tree clean. Nothing ran
against production or any server of the network, and no `.env` was read.
What the plan left open and how it was decided:

- The number and the date. This section is 24, as the plan names it.
  BUILD-DATE is 2026-11-21, the day of the build and of the plan's FINAL.
- The lock file was made by npm with the plan's line, while the folder
  had no `node_modules`. It holds 32 packages, each with an `integrity`
  line, none with `hasInstallScript`, all from `registry.npmjs.org`,
  among them `@img/sharp-linux-x64` 0.35.5 and
  `@img/sharp-libvips-linux-x64` 1.3.4 (os linux, cpu x64, libc glibc).
  It is byte for byte the lock file the planning chat had made in its
  scratch folder.
- The code. The four functions of the plan's 1.2 (`drawSmall`,
  `marksOfOriginal`, `marksOfSmall`, `apart`) are in the file letter for
  letter, and the SQL statements are the plan's. Around them the build
  wrote `drawAndCompare` (what becomes of one selfie), `readAndDraw` (the
  read of every row), `report`, `copyAndReplace` (the transaction) and
  `copyIsThere`.
- The line of a named row is `<username> (<first eight of the id>):
  cannot be read: <the first line of sharp's message>`, or `<username>
  (<first eight of the id>): did not match:` followed by `the small
  picture is not <n> by <n> pixels` or by `<figure> apart from the
  original, the limit is 4`. A selfie with no row in `anopods` is named
  `no anopod row`.
- With nothing to be made small, the report's last line reads `the
  heaviest small picture: 0 bytes`.
- The report goes to standard output. The usage line, the refusal while
  the copy is there, and an error with its closing line go to standard
  error, as the other scripts print theirs.
- An error before the write's transaction, in either run (the database
  cannot be reached or read), prints the error's message and `Nothing was
  written.`, exit 1. The plan names only errors after `BEGIN`.
- Found in the build, in a scratch schema: when the connection was lost
  in the middle of the write, the process ended with Node's "Unhandled
  'error' event" and never printed `Nothing was kept.` The pool takes its
  error listener off a client it hands out, and `pg` emits `error` on the
  client besides failing the query. So `copyAndReplace` puts an empty
  `error` listener on its client, and a `ROLLBACK` that fails is passed
  over: on a lost connection PostgreSQL ends the open transaction itself.
  With these two a lost connection ends as the plan's 1.2 and 2.5 say:
  the error's message, `Nothing was kept.`, exit 1, and nothing is kept.
- A limit, left as the plan has it. An error at the `COMMIT` itself also
  prints `Nothing was kept.` If the connection is lost in that very
  moment, the script cannot know whether PostgreSQL kept the transaction.
  The count line of the plan's 2.6 says which it is, and a new `write`
  run refuses while the copy is there, so nothing is lost either way.
- Seen in passing, not changed. This server's own `withTransaction`
  (`src/db/transaction.js`) and the scripts `appoint.js`, `revoke.js` and
  `make-super-seed.js` take a client out of the pool the same way, with
  no `error` listener. Tried with a throwaway file on this Mac: when the
  connection is cut while a transaction of `withTransaction` is open, the
  process ends with the same "Unhandled 'error' event". For the running
  server that is the end of the process, and systemd starts it again. Put
  to the user as a fix or a line on the after-production list; nothing
  was changed for it.
- Checks (1.5), on Node 24.22.0, npm 11.19.1 and this Mac's PostgreSQL
  17.11. `node --check` on the script, clean. `npm ci --ignore-scripts
  --no-audit --no-fund` in the folder: `added 6 packages`, 19 MB, `sharp`
  0.35.5 with libvips 8.18.7; `git status --short` listed the three new
  files and no `node_modules`. Then the whole job for real on this Mac's
  test database `masterpod` (10 selfies of 1280 by 720, 1,781,286 bytes,
  36 tables). The script was started from the repo's folder with the
  settings on the line itself (`PGHOST=/tmp PGDATABASE=masterpod
  PGUSER=codex PGPASSWORD=x PGOPTIONS='-c role=masterpodsoftware'`). The
  lines of the plan's 2.6 and 3 were taken out of the plan file by a
  script, with `psql -X -h /tmp` in place of `sudo -u postgres psql -X`.
  In the plan's order: a list of the ten rows (id, type, SHA-256 of the
  picture, `created_at`); `look`: 10 read, 10 to be made small, 0 in the
  three other counts, weight now 1,781,286 bytes, after 155,605, the
  heaviest 16,777; `write`: the same report, a copy of 10 rows, 10 made
  small, committed; the count line: 10 selfies, 152 kB, heaviest 16777, 0
  over 40 KB, 10 made small, 10 in the copy, 1740 kB the copy, with 37
  tables and the copy owned by `masterpodsoftware`; `write` again: the
  refusal, exit 1; the put-back line: `UPDATE 10`, 10 the same as the
  copy, the ten rows equal to the list, and every byte of every picture
  equal to a dump taken before the write; the put-back line again:
  `UPDATE 0`; `look` again: 10 to be made small; the remove line: `DROP
  TABLE`, 36. These are the figures the plan expects, each one. The test
  database ended with every picture as it started, 36 tables and no copy.
  `updated_at` of the ten rows shows the trial's time, as the plan says.
  The trial ran twice with the same output: once before the fix of the
  lost connection and two comment edits, and once on the file as it is.
- Beyond 1.5, with nothing kept. The parts of the script that ten good
  selfies cannot reach were run for real in a scratch schema of the same
  database, owned by `masterpodsoftware`, with a copy of the selfie table
  and its trigger and seventeen made-up rows, the search path set in
  `PGOPTIONS`. `public` was only read. Of 27 rows, 22 were made small, 3
  were left as already small (200 by 150, 320 by 240, 320 by 320) and 2
  were named as cannot be read (words in place of a picture: `Input
  buffer contains unsupported image format`; a JPEG cut off at two
  thirds: `VipsJpeg: premature end of JPEG image`). 321 by 321 became 320
  by 320, 400 by 300 became 300 by 300, 1280 by 200 became 200 by 200. An
  upright 720 by 1280, a phone's 3024 by 4032 and a 4096 by 4096 became
  320 by 320. A PNG and a WebP became JPEGs, a see-through PNG got white
  under it, a JPEG with the turn mark 6 came out turned with no mark, and
  a selfie with no `anopods` row was drawn. Every small file was a
  baseline JPEG, 4:2:0, with no EXIF and no colour profile, and
  `updated_at` moved on the changed rows only. The put-back line gave
  `UPDATE 22` and every row as before, the types of the PNG and WebP rows
  among them. Then four made-up faults in the middle of the write, each
  by a trigger on the scratch table: an `UPDATE` that changes no row
  (`<username> (<id>): the stored selfie is no longer the one that was
  read`), one that leaves the old picture in (`21 selfies differ from the
  copy, where 22 were to be made small`), an error of the database, and
  the connection cut by `pg_terminate_backend` while an `UPDATE` ran.
  Each ended with its message, `Nothing was kept.` and exit 1, with no
  copy and every row as before. Also: a row deleted between the list of
  ids and its own read was skipped; a `write` run with nothing to make
  small printed `Nothing to make small.` and made no copy; a database
  that cannot be reached gave its message and `Nothing was written.`; and
  a scratch copy of the script with the limit lowered to 1.3 named three
  rows as did not match (two test selfies at 1.33 and 1.32, the 4096 by
  4096 noise at 1.65). The scratch schema was dropped, and no file of
  these checks is in the repo.
- Not tried by the build. Nothing on a server and nothing on Linux:
  `sharp` there is the same library in another build, and the look run of
  the plan's 2.4 is its first run there. `npm run small-selfies` itself
  was not started on this Mac, since it reads `.env`; `npm run` with no
  name lists the new entry. No change of leader and no PgBouncer were in
  the trial: the cut connection was a direct one to this Mac's
  PostgreSQL.
- Places the plan does not name that this step left out of date, left as
  they are and put to the user. In the wallet's spec, the note of
  2026-11-21 says the two masterpod sentences are "Still as they are";
  they are brought in line here. The records folder's two lists of this
  server's commands (`rules/configuration.md` and `rules/log_lines.md`)
  do not name the new script, as they do not name `appoint` and `revoke`.
  Older than this step: the after-production details file of the selfies
  quotes two line numbers of this file that were already off.
- Not touched: every file under `src` but the one comment,
  `db/schema.sql`, this server's own `package-lock.json`,
  `src/config/env.js`, `.example.env`, `.gitignore` and the other
  scripts; in `package.json` everything but the one line; in the README
  everything but the row and the line.

## 25. Security alerts (2026-11-21)

Design settled 2026-11-20 and 2026-11-21 in two talking chats and a
planning chat (the plan is
`~/Desktop/Z-TestNet/forclaude/security-alerts-plan-1.md`, FINAL,
2026-11-21). Why, in the user's words (the plan's decision 1): "The real
use case is to prevent a thief." "We would actually want the alert to
originate from the validators." "It would mainly be useful for guarded,
vaulted and assissted accounts." "With spending it's too late to do
anything." "This means a bad trade could be cancelled." A transfer out of
a guarded, a vault or an assisted account waits on the validators before
it is written, and the wallet lets its owner cancel it while it waits.
Until this section the owner saw that it waits only by opening the
wallet: a thief with a copy of the keys could send, and the wait could
run out unseen. Now this server tells
the pod that made the account, by email and by a notification on the
phone, when such a transfer starts to wait, when a recovery is started
for the pod, and when the pod's own list of alerts changes.

Three repos, in the order of the deploys: this server (this section, step
1 of the plan: a pod's list, the report from the validators and the
sender), the wallet (its spec; step 2, the wallet as an app on the Home
Screen, and step 3, the page "Security alerts" with the phone's part and
the bell) and the validators (anossoftware's spec, section 34, step 4:
each validator reports the transfers that wait). Then the record files
(step 5). This server boots and runs without any of the new settings.
Without the two email lines no email is sent and `/add-alert-email`
refuses. Without the two phone lines no notification is sent and
`/add-alert-phone` refuses. Without the validators' keys file their
reports are refused. So this step can be deployed before any of them is
set. No npm package: the scrambling of a notification and its signed
header are Node's own crypto, and the two kinds of outbound call are
`fetch`. The doormen, the keyholders, the keyholder GUI, the signing
servers, the monitor and the wallet's proxy are not touched. Nothing above
this section changes except the items in 25.9.

### 25.1 The rules

From the plan's decisions 4, 5, 13 to 16, 19, 21 and 22:

- What sets an alert off (decision 5): a transfer that starts to wait
  out of a guarded, a vault or an assisted account; a recovery's
  break-glass move; a change of the pod's own list ("a change in
  notifications section would also ring"). And a recovery case that is
  opened for the pod (decision 15). Nothing at a cancel and nothing when
  the transfer is written.
- The month rule (decision 4). The user: "If someone changes their email
  or whatever for notifications, they will continue to receive
  notifications at the old numbers/ email for 1 month. That's it." The
  new one gets them right away. So "Take off" does not take an address
  off: it sets the day it comes off, a month ahead, and until then the
  address gets every alert. "Keep" undoes it.
- An email counts once the person has typed a six-digit code that was
  sent to it, within ten minutes (decision 13). No link in the email.
- What an alert says (decision 14). In an email the amount and the day it
  will be written; the phone's line has the amount. The receiving account
  is not in. No link and no web address. English or Thai: an email in the
  language the wallet showed when the email was added, the phone's line
  in the phone's own language.
- A recovery case opened for a pod says: if you started it, do nothing; a
  moderator checks every recovery on a video call before anything is
  released; if your passkey ever stops working, here is what to tap
  (decision 15).
- Who can see the emails (decision 16). This server keeps each address as
  plain text. Only the person's own logged-in wallet reads it back. No
  route of an attestor, a moderator or a keyholder answers it. The email
  company sees the address and the words and keeps them for a while.
- The list (decision 19): up to 3 emails and 5 phones. Every email and
  phone on the list gets every alert; there are no switches for single
  kinds. The same alerts show under the bell inside the wallet, for every
  pod, with or without an email on the list.
- When an alert cannot be delivered (decision 21): this server keeps
  trying for three days. A phone that can no longer be reached comes off
  the list at once, and the emails are told. An email address that no
  longer exists is not noticed.
- The validators (decision 22): about five minutes after a transfer is
  sent, every validator that holds it tells this server. This server acts
  on the first report and ignores the rest. One validator alone could set
  off a false alert, and it cannot move money.

From the plan's decision 23, the lines that are about this server:

- The key for the phones is one line of `.env`, not a key file. `.env` is
  already the one file that is the same on the three servers and that
  only the user writes. A script makes the line (25.8).
- An email names the account by the start of its id: "open that account
  (its id starts with a1b2c3d4)". A person with two guarded accounts
  could not tell which otherwise. The phone's line does not carry it.
- On the day the first validator takes step 4 it reports every transfer
  that waits at that moment, also one sent days before. So each such
  transfer gets one alert that day.
- The amount is written with commas: "5,000 anos". The day in an email is
  in UTC, because this server does not know a person's time zone.
- The phone's notification has the title "Security alert" and one
  sentence. This server sends the facts; the sentence is made on the
  phone, so that it is in the phone's language.
- A phone that was just turned on gets one notification at once
  (`phoneOn`), so a person sees that it works.
- The code: 5 wrong tries use a code up; a new code can be asked for
  after 60 seconds; a pod is sent 5 codes in 24 hours at most; an address
  that is not confirmed within a day is dropped.
- Three more counts hold a flood back. A pod's list takes 20 changes in
  24 hours; "Keep" is not counted, so that nobody can be kept from saving
  an address. A recovery case that is opened makes an alert once in 24
  hours for one pod, however many cases are opened for it: anybody can
  open one. A validator's reports write 1,000 transfers in 24 hours at
  most.
- One report is enough to set an alert off: the first validator's. The
  others that report the same transfer with the same account, amount,
  kind and day add nothing; it stays one alert. Only a report that says
  something else about the same transfer is not taken as a repeat. It is
  a report of its own and makes an alert of its own. So one validator
  cannot keep a true report from counting by sending a false one first.
- A phone is taken only when the key it hands over is a real key.
  Anything else would make the sender stumble each time it met that
  phone.
- An email that was never confirmed is taken off at once, since it got no
  alert. It counts toward the three while it is there. Emails and phones
  that are coming off count toward the three and the five.
- A change of the list asks for no passkey tap. Taking an address off
  does nothing for a month and is told to that address the same day;
  adding one takes nothing away from the owner.
- Nothing deletes the list at a recovery. After a false recovery the true
  owner's email keeps getting every alert for a month after it was taken
  off.
- A phone is taken only when its delivery address is on one of four
  delivery services: Apple's (`push.apple.com`), Google's
  (`fcm.googleapis.com`), Mozilla's (`push.services.mozilla.com`) and
  Microsoft's (`notify.windows.com`). Without the list a person who is
  logged in could make this server send requests to any address, also one
  inside our own network. Apple's and Microsoft's names are from their
  own pages; Google's and Mozilla's are from the planning chat's
  knowledge and are checked at the first real phone (the plan's 3.9).
- No route answers a phone's delivery address: whoever knows it could
  send to the phone. The wallet's page finds "this phone" in the list by
  the SHA-256 of the address.
- The list names a phone by its kind: `iphone`, `ipad`, `android`,
  `computer`, `other`. The wallet reads the kind when the alerts are
  turned on.
- Tries after a failure: after 1, 2, 4, 8, 16 and 32 minutes, then every
  60 minutes. A notification waits up to 7 days at the delivery service
  for a phone that is switched off.
- A message leaves at once after the event, not at the next minute; the
  minute's run is for the tries and for what comes off after its month.
- An email is plain text: no picture, no formatting, no link.
- A sent message stays in its table as the record that it went out. It
  holds no email address: the address is read from the list when the
  message is sent.
- Under the bell: three kinds for the three events, and one kind,
  `alertSettingsChanged`, for every change of the list.
- Names in code use "alert": the tables `alert_...`, the routes with
  `alert` in them.
- The Thai sentences are written by the build, in the words of the
  wallet's `th.ts`, and are unread by a Thai speaker when they go out.

### 25.2 The four tables

At the end of `db/schema.sql`, one block. Each table has its `COMMENT ON`
lines there. No foreign keys.

```sql
CREATE TABLE IF NOT EXISTS alert_emails (
  email_id        BYTEA       PRIMARY KEY CHECK (octet_length(email_id) = 32),
  anopod_id       BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  email           TEXT        NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
  language        TEXT        NOT NULL CHECK (language IN ('en', 'th')),
  code            TEXT        CHECK (code ~ '^[0-9]{6}$'),
  code_expires_at TIMESTAMPTZ,
  code_tries      INTEGER     NOT NULL DEFAULT 0 CHECK (code_tries >= 0),
  verified_at     TIMESTAMPTZ,
  removes_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS alert_emails_anopod_id_email_key ON alert_emails (anopod_id, lower(email));
```

The emails a pod's alerts go to. `email` is the address as typed, trimmed:
3 to 254 characters with an `@` that is not first, in plain text. One row
per pod and address, compared in lower case; two pods may hold the same
address. `language` is `en` or `th`, the language the wallet showed when
the address was added (or when its last code was asked for); every email
to the address is written in it. `code` is the six-digit code, until it is
typed back or replaced; `code_expires_at` is ten minutes after the code
was made; `code_tries` counts the wrong codes typed against it, and at
five the code is used up. `verified_at` is null until the code was typed
back: alerts go only to a confirmed address. `removes_at` is null, or the
moment the row is deleted: set by `/remove-alert-email` a month ahead,
cleared by `/keep-alert-email`. The row belongs to the pod, not to an
account, and nothing deletes it but its own removal. `updated_at` is kept
by the `alert_emails_set_updated_at` trigger.

```sql
CREATE TABLE IF NOT EXISTS alert_phones (
  phone_id    BYTEA       PRIMARY KEY CHECK (octet_length(phone_id) = 32),
  anopod_id   BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  endpoint    TEXT        NOT NULL CHECK (char_length(endpoint) BETWEEN 20 AND 1024),
  p256dh      BYTEA       NOT NULL CHECK (octet_length(p256dh) = 65),
  auth        BYTEA       NOT NULL CHECK (octet_length(auth) = 16),
  label       TEXT        NOT NULL CHECK (label IN ('iphone', 'ipad', 'android', 'computer', 'other')),
  removes_at  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT alert_phones_anopod_id_endpoint_key UNIQUE (anopod_id, endpoint)
);
CREATE INDEX IF NOT EXISTS alert_phones_endpoint_idx ON alert_phones (endpoint);
```

The phones a pod's alerts go to: one row per browser that allowed
notifications, with what the browser handed the wallet. `endpoint` is the
delivery address the browser's delivery service gave, an https URL on one
of the four services. `p256dh` is the browser's public key for this
subscription, 65 raw bytes: a message is locked to it. `auth` is the
browser's secret, 16 raw bytes. `label` is the kind of device, only for
the list on the wallet's page. `removes_at` as for an email. Two pods used
on one phone hold a row each with the same `endpoint`; the index on
`endpoint` serves the delete of every row of a phone that is gone.
`updated_at` is kept by the `alert_phones_set_updated_at` trigger.

```sql
CREATE TABLE IF NOT EXISTS alert_transfers (
  report_id        BYTEA       PRIMARY KEY CHECK (octet_length(report_id) = 32),
  transaction_id   BYTEA       NOT NULL CHECK (octet_length(transaction_id) = 32),
  account_id       BYTEA       NOT NULL CHECK (octet_length(account_id) = 32),
  anopod_id        BYTEA       CHECK (octet_length(anopod_id) = 32),
  transaction_type TEXT        NOT NULL CHECK (transaction_type IN ('guardedAnosTransfer', 'vaultAnosTransfer', 'assistedAnosTransfer', 'breakGlassTransfer')),
  amount           TEXT        NOT NULL CHECK (amount ~ '^[1-9][0-9]{0,38}$'),
  writes_at        TIMESTAMPTZ,
  validator_id     INTEGER     NOT NULL CHECK (validator_id > 0),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_transfers_transaction_id_idx ON alert_transfers (transaction_id);
CREATE INDEX IF NOT EXISTS alert_transfers_validator_id_created_at_idx ON alert_transfers (validator_id, created_at);
```

The waiting transfers the validators have reported: one row per report
with its own facts. `report_id` is the SHA-256 of the report's facts in
canonical form (the transfer's id, the account, the kind, the amount, the
moment). Validators that report one transfer with the same facts make one
row, written by the first of them; a report that names another account,
amount, kind or moment for the same transfer is a row of its own.
`anopod_id` is the pod that made the sending account, from
`anos_accounts`; null when no pod made it, and then nobody is alerted.
`amount` is in millionths of an anos, a decimal string, as the validator
reported it. `writes_at` is the moment the transfer may be written; null
for a transfer that waits for two attestors alone. `validator_id` is the
validator whose report wrote the row; the second index serves the count
of a validator's rows in 24 hours. Append-only: the
`alert_transfers_append_only` trigger refuses UPDATE and DELETE.
`created_at` only.

```sql
CREATE TABLE IF NOT EXISTS alert_messages (
  message_id   BYTEA       PRIMARY KEY CHECK (octet_length(message_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  kind         TEXT        NOT NULL CHECK (kind IN (
                 'emailCode', 'transferWaiting', 'recoveryMoveWaiting', 'recoveryCaseOpened',
                 'emailAdded', 'emailRemoving', 'emailKept',
                 'phoneAdded', 'phoneRemoving', 'phoneKept', 'phoneUnreachable', 'phoneOn')),
  email_id     BYTEA       CHECK (octet_length(email_id) = 32),
  phone_id     BYTEA       CHECK (octet_length(phone_id) = 32),
  details      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  tries        INTEGER     NOT NULL DEFAULT 0 CHECK (tries >= 0),
  next_try_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at      TIMESTAMPTZ,
  gave_up_at   TIMESTAMPTZ,
  last_error   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT alert_messages_one_destination CHECK ((email_id IS NULL) <> (phone_id IS NULL))
);
CREATE INDEX IF NOT EXISTS alert_messages_due_idx ON alert_messages (next_try_at) WHERE sent_at IS NULL AND gave_up_at IS NULL;
CREATE INDEX IF NOT EXISTS alert_messages_anopod_id_created_at_idx ON alert_messages (anopod_id, created_at DESC);
```

One row per message to one email or one phone, written inside the
transaction of the event it reports and sent by the alert sender (25.6).
A row names an email or a phone, never both and never neither. `details`
is what the kind carries (25.5). `tries` counts the sends that failed;
`next_try_at` is when the sender takes the row next: now at first, later
after each failure. `sent_at` is when the email company or the phone's
delivery service took the message. `gave_up_at` is when the sender
stopped trying: after three days of failures, or when the address or the
phone is gone. `last_error` is the last failure in a few words, with no
address in it. The row holds no address: the address is read from
`alert_emails` or `alert_phones` when the message is sent. Kept after it
is sent. `message_id` is also part of the key the email company is given
so that one try is never sent twice (25.6). `updated_at` is kept by the
`alert_messages_set_updated_at` trigger.

The four notification kinds that come with the tables are in the
`notifications` check: inline in its `CREATE TABLE`, and in the one ALTER
pair after the attestation block. They did not go into a second
drop-and-add at the end of the file. The whole file is applied again at
every deploy; a second block would work the first time, and at the next
deploy the older block, with its old list, would be refused by the first
row of a new kind.

### 25.3 The eight routes of a pod's list

All at level setup, in `src/alerts/alerts.service.js`. The numbers are
constants at the top of that file, not env variables, as the listing
limit is not: `EMAIL_LIMIT = 3`, `PHONE_LIMIT = 5`, `CODE_TRIES = 5`,
`CODE_WAIT_SECONDS = 60`, `CODES_A_DAY = 5`, `CHANGES_A_DAY = 20`,
`PUSH_HOSTS` (the four delivery services) and `PHONE_LABELS` (the five
kinds of device).

#### POST /list-alert-settings (setup)

Body: `{}`. No check.

Answer: `200`

```json
{
  "emails": [ { "emailId": "<hex 32>", "email": "nok@gmail.com", "language": "en", "confirmed": true, "createdAt": "<ISO 8601>", "removesAt": null } ],
  "phones": [ { "phoneId": "<hex 32>", "endpointHash": "<hex 32>", "label": "iphone", "createdAt": "<ISO 8601>", "removesAt": null } ],
  "emailOn": true,
  "pushPublicKey": "<87 characters>",
  "emailLimit": 3, "phoneLimit": 5, "removeMinutes": 43200
}
```

Both lists oldest first. `confirmed` is true once the code was typed.
`removesAt` is null or the moment the row comes off. `endpointHash` is the
SHA-256 of the phone's delivery address; the address itself is never
answered, and neither is a code. `emailOn` is false when the two email
lines are not set. `pushPublicKey` is the public half of this server's
key for the delivery services as base64url, or null when the two phone
lines are not set.

#### POST /add-alert-email (setup)

Body: `{ email, language }`.

Checks, in order: the shape, an object with `email` and `language`
strings (`400 bad request shape`); email is on (`503 email alerts not set
up`); `email`, trimmed, is 3 to 254 characters, matches
`^[^\s@]+@[^\s@]+$` and holds no control character (`400 invalid
email`); `language` is `en` or `th` (`400 invalid language`). Then, in one transaction with the pod's row
locked (`lockPod`, 17.2): the pod has no confirmed row for this address,
compared in lower case (`409 email already listed`); when it has no row
for it at all, it has fewer than 3 rows (`403 email limit reached`); it
was sent fewer than 5 codes in the last 24 hours (`429 too many codes
today`); the latest of them is 60 seconds old or more (`429 wait before a
new code`).

Writes: for a new address `INSERT alert_emails` with a fresh `email_id`.
Then the code: six digits from `randomInt(0, 1_000_000)` of `node:crypto`,
padded with zeros on the left, good for ten minutes, with `code_tries`
0 and the body's language. Then one `alert_messages` row of the kind
`emailCode` to that address. An address that is on the list and not
confirmed yet gets a new code the same way; its old code is replaced.

Answer: `201 { emailId, email, confirmed: false }` for a new row, `200`
with the same body for a new code; `email` is the address as the row
holds it.

#### POST /confirm-alert-email (setup)

Body: `{ emailId, code }`.

Checks, in order: the shape, two strings (`400 bad request shape`);
`emailId` decodes to 32 bytes (`400 invalid emailId`); `code` matches
`^[0-9]{6}$` (`400 invalid code`). Then, in one transaction with the
email's row locked: the row is there and is the caller's (`404 unknown
email`); it is not confirmed yet (`409 email already confirmed`); it has
a code and `code_expires_at` has not passed (`410 code expired`);
`code_tries` is under 5 (`410 code used up`); the code is the row's,
compared with `timingSafeEqual` (`401 wrong code`: the wrong try is
counted first, and the transaction commits, so the count stays); the pod
made fewer than 20 changes of its list in the last 24 hours (`429 too
many changes today`; the code stays good until its ten minutes are over).

Writes: `verified_at` now, the code cleared; then `raiseAlert` (25.5)
with `emailAdded`, which tells every other address of the list.

Answer: `200 { emailId, confirmed: true }`.

#### POST /remove-alert-email (setup)

Body: `{ emailId }`. "Take off."

Checks: the shape (`400 bad request shape`); the id (`400 invalid
emailId`). Then, in one transaction with the email's row locked: the row
is there and is the caller's (`404 unknown email`).

Writes and answers, by the row's state. Not confirmed: the row is
deleted and nobody is told; `200 { emailId, removed: true, removesAt:
null }`. Confirmed and already set to come off: nothing is written; `200
{ emailId, removed: false, removesAt }` with the standing moment.
Confirmed: 20 changes or more in the last 24 hours refuse it (`429 too
many changes today`); otherwise `removes_at` is set
`ALERT_REMOVE_MINUTES` ahead and `raiseAlert` with `emailRemoving` tells
the whole list, the address that comes off too; `200 { emailId, removed:
false, removesAt }`.

#### POST /keep-alert-email (setup)

Body: `{ emailId }`. "Keep."

Checks: as the first three of `/remove-alert-email`.

Writes: when `removes_at` is set, it is cleared and `raiseAlert` with
`emailKept` tells the whole list. When it is null nothing is written.
"Keep" is not counted against the 20 changes: it can only undo a "Take
off", and a person must always be able to save an address.

Answer: `200 { emailId, removesAt: null }` both times.

#### POST /add-alert-phone (setup)

Body: `{ endpoint, p256dh, auth, label }`: what the browser handed the
wallet when the person allowed notifications, and the kind of device.

Checks, in order: the shape, four strings (`400 bad request shape`);
phone alerts are on (`503 phone alerts not set up`); `endpoint` is 20 to
1024 characters of plain ASCII with no blank and no control character,
and parses as a URL whose protocol is `https:` and which has no user
name, no password and no port (`400 invalid endpoint`); its
host is one of the four delivery services or ends with a dot and one of
them (`400 push service not supported`; the handler's log line names the
host and nothing else of the address); `p256dh` decodes to 65 bytes that
are a point on the P-256 curve (`400 invalid p256dh`); `auth` decodes to
16 bytes (`400 invalid auth`); `label` is one of the five (`400 invalid
label`). Then, in one transaction with the pod's row locked: the pod has
no row with this `endpoint` yet (when it has one, nothing is written and
the answer is `200 { phoneId, removesAt }` of that row); it has fewer
than 5 rows (`403 phone limit reached`); it made fewer than 20 changes of
its list in the last 24 hours (`429 too many changes today`).

Writes: `INSERT alert_phones` with a fresh `phone_id`; `raiseAlert` with
`phoneAdded`, which tells every other address of the list; and one
`alert_messages` row of the kind `phoneOn` to the new phone.

Answer: `201 { phoneId, removesAt: null }`.

#### POST /remove-alert-phone (setup)

Body: `{ phoneId }`. As `/remove-alert-email`, without the unconfirmed
case: `400 bad request shape`, `400 invalid phoneId`, `404 unknown
phone`, `429 too many changes today`; `raiseAlert` with `phoneRemoving`.

Answer: `200 { phoneId, removesAt }`, the new moment or the standing one.

#### POST /keep-alert-phone (setup)

Body: `{ phoneId }`. As `/keep-alert-email`: `400 bad request shape`,
`400 invalid phoneId`, `404 unknown phone`; `raiseAlert` with `phoneKept`
when the phone was set to come off; not counted against the 20 changes.

Answer: `200 { phoneId, removesAt: null }`.

### 25.4 POST /report-waiting-transfers (none)

In `src/alerts/validator-reports.js`. For the validators: each one tells
this server of the transfers that have started to wait, as its job sends
them (anossoftware's spec, section 34). The body is a message signed like
a message to another validator:

```json
{
  "payload": {
    "validatorId": 4,
    "transfers": [
      {
        "transactionId":   "<hex 32>",
        "accountId":       "<hex 32, the sending account>",
        "transactionType": "guardedAnosTransfer",
        "amount":          "<millionths of an anos, a decimal string>",
        "writesAt":        "2026-11-27T07:12:00.000Z"
      }
    ]
  },
  "signature": { "key": "<hex 64, P-256 r||s over the canonical bytes of payload>" }
}
```

`transfers` is a list of 1 to 100 entries. `transactionType` is one of
`guardedAnosTransfer`, `vaultAnosTransfer`, `assistedAnosTransfer` and
`breakGlassTransfer`. `writesAt` is null for a transfer that waits for
two attestors alone.

Checks, in order:

1. The validators' keys are loaded (25.8). `503 validator keys not
   loaded`.
2. The shape: `payload` and `signature` objects; `validatorId` a positive
   whole number; `transfers` a list of 1 to 100 objects; `signature.key`
   a string. `400 bad request shape`.
3. `validatorId` is in the keys. `401 unknown validator`.
4. The signature verifies over the UTF-8 bytes of `canonicalize(payload)`
   against that validator's key. `401 bad signature`. A `canonicalize`
   that throws answers the same: it throws on a string that is not well
   formed, and the route is open to anybody.
5. Every transfer: `transactionId` and `accountId` decode to 32 bytes;
   `transactionType` is one of the four; `amount` matches
   `^[1-9][0-9]{0,38}$`; `writesAt` is null or a string that `Date.parse`
   reads. `400 invalid transfer`. One bad entry refuses the whole
   message: the entries are made by our own code.
6. This validator's reports have written fewer than `REPORTS_A_DAY`,
   1,000, rows in the last 24 hours. `429 too many reports today`.

Writes, in one transaction, for each transfer in the order of the list:
the pod that made the account and the account's type are read from
`anos_accounts`, or nothing; `INSERT alert_transfers ... ON CONFLICT
(report_id) DO NOTHING`, with the pod's id or null and with the report's
id, the `canonicalHash` of `{ transactionId, accountId, transactionType,
amount, writesAt }`, the two ids as lowercase hex and `writesAt` as an
ISO string or null. When no row was written, the same facts were reported
before, and nothing more happens for this entry. When a row was written
and the account has a pod: `raiseAlert` (25.5) with `recoveryMoveWaiting`
for a `breakGlassTransfer` and `transferWaiting` for the three others,
with the account's type as this server's own table has it.

Answer: `200 { taken }`, how many rows were written. The log line of a
good report: `validator <id> reported <n> waiting transfers, <taken>
new`.

Nothing is used up and no time is checked: the same message sent again
finds its rows and writes nothing. A validator takes any answer but `200`
as "not taken" and sends the same transfers again a minute later.

### 25.5 raiseAlert

`raiseAlert(client, { anopodId, kind, details, reference, exceptEmailId
= null, exceptPhoneId = null })`, in `src/alerts/alert-events.js`. It runs
on the client of the transaction of the event it reports, like `notify`,
and writes:

1. The bell's row, `notify(client, anopodId, <the bell's kind>,
   reference)`: `transferWaiting`, `recoveryMoveWaiting` and
   `recoveryCaseOpened` under their own names; each of the seven kinds of
   a change of the list under `alertSettingsChanged`. `reference` is 32
   bytes: the account's id for the two transfer kinds, the case's id for
   `recoveryCaseOpened`, the pod's own id for a change of the list.
2. One row of `alert_messages` for each confirmed email and each phone of
   the pod, the ones that are coming off too, without `exceptEmailId` and
   `exceptPhoneId`, each with a fresh id, the kind and `details`.

It returns the number of messages written. The caller calls
`kickAlertSender()` (25.6) after its transaction has committed.

`details`, by kind. Ids are hex, moments are ISO strings:

| kind | details | who is left out |
| ---- | ------- | --------------- |
| `transferWaiting`, `recoveryMoveWaiting` | `{ accountId, accountType, amount, writesAt }`; `writesAt` is null for a transfer that waits for attestors alone | nobody |
| `recoveryCaseOpened` | `{}` | nobody |
| `emailAdded` | `{ emailId }` | the email that was added |
| `emailRemoving` | `{ emailId, removesAt }` | nobody: the address that comes off is told too |
| `emailKept` | `{ emailId }` | nobody |
| `phoneAdded` | `{ phoneId, label }` | the phone that was added |
| `phoneRemoving` | `{ phoneId, label, removesAt }` | nobody |
| `phoneKept` | `{ phoneId, label }` | nobody |
| `phoneUnreachable` | `{ label }` | nobody: the phone's row is gone |

Two kinds do not go through `raiseAlert`, because they go to one address
and not under the bell: `emailCode`, one message to the email that is
being added, and `phoneOn`, one message to the phone that was just added.
Both have `{}` as details.

`recoveryCaseOpened` is raised at most once in 24 hours for one pod.
Before it writes, `raiseAlert` counts the pod's `recoveryCaseOpened`
notifications of the last 24 hours; with one or more it writes nothing
and returns 0. Anybody can open a recovery case for a pod whose id they
know, as often as they like (`/challenge` and `/open-recovery-case` are at
level none, and the one-open-case rule is per lookup id). Without this
count an outsider could make this server write to a pod's whole list
without end.

Who calls it: `/confirm-alert-email`, `/remove-alert-email`,
`/keep-alert-email`, `/add-alert-phone`, `/remove-alert-phone` and
`/keep-alert-phone` (25.3); `/report-waiting-transfers` (25.4); the
sender, for a phone that is gone (25.6); and `openRecoveryCase`
(`src/recovery/recovery.service.js`, 12.4.2), inside its transaction,
after the `opened` event:

```js
await raiseAlert(client, { anopodId, kind: 'recoveryCaseOpened', details: {}, reference: caseId });
```

The finish of a recovery deletes the pod's added passkeys (19.3) and
leaves its alert rows alone.

### 25.6 The sender

`src/alerts/alert-sender.js`, in the shape of the DAO clock (15.5):
`startAlertSender()` (one run now, then one every minute; the timer does
not keep the process alive), `stopAlertSender()`, and `kickAlertSender()`,
which starts a run now and returns at once. `src/server.js` starts it
after the DAO clock and stops it in its shutdown. One run at a time in a
process: a run that is asked for while one is under way runs right after
it. A run that throws logs the error and the next one runs. Three
masterpods run it at once, on prod1, prod2 and prod3; the rows a run
holds are skipped by the others.

A run:

1. What is due to come off, comes off: `DELETE FROM alert_emails WHERE
   removes_at <= now()`, the same for `alert_phones`, and `DELETE FROM
   alert_emails WHERE verified_at IS NULL AND created_at < now() -
   interval '1 day'`. One log line when anything went: `alerts: <n> emails
   and <m> phones came off`.
2. The sending, at most ten rounds. A round is one transaction. It takes
   up to 20 messages that are due and holds them:

   ```sql
   SELECT message_id, anopod_id, kind, email_id, phone_id, details, tries, created_at
   FROM alert_messages
   WHERE sent_at IS NULL AND gave_up_at IS NULL AND next_try_at <= now()
     AND ($2 OR email_id IS NULL) AND ($3 OR phone_id IS NULL)
   ORDER BY next_try_at, message_id
   LIMIT $1
   FOR UPDATE SKIP LOCKED
   ```

   `$2` is whether email is on and `$3` whether the phones are, so a
   message for a part that is off is left in the table. Then the requests
   are made, the ones to phones all at once and the ones to the email
   company one after another, because it limits the requests of one
   second (one it refuses for that is tried again like any other
   failure). Then each outcome is written. A round that took fewer than
   20 messages and raised no alert is the last.

Each message is built and sent on its own. Whatever throws for one
message, while its words are made, its body is scrambled or its request
is sent, is that message's failure and no other's: given up with `could
not be built` when it threw before the request, counted as a failure when
the request threw. A round never ends because of one message, so one bad
row cannot hold the others back.

A message to an email. The row of `alert_emails` is gone: given up,
`address gone`. An `emailCode` whose row has no code any more: given up,
`code no longer needed`. Otherwise the words are made in the row's
language (25.7) and the email is handed to the email company
(`src/alerts/email.js`): `POST https://api.resend.com/emails`, a timeout
of 10 seconds, a redirect not followed, with the headers

```
Authorization: Bearer <RESEND_API_KEY>
Content-Type: application/json
User-Agent: masterpodsoftware
Idempotency-Key: <the message id as hex>-<tries>
```

and the body `{ from: <ALERT_EMAIL_FROM>, to: [<the address>], subject,
text }`. A status from 200 to 299 is `sent`. Anything else is a failure,
told as `status <n>` and the answer's `name` when it has one, or as the
fetch's own error. The email company refuses a request with no
`User-Agent` header. The key holds the try's number: a try whose outcome
was never written, because the server stopped between the send and the
write, is not sent a second time when its row is taken again, and a try
after a failure is a new request.

A message to a phone. The row of `alert_phones` is gone: given up, `phone
gone`. Otherwise the body is `encryptPush(<the UTF-8 bytes of the facts
as JSON>, p256dh, auth)` (`src/alerts/push.js`: RFC 8291 with the content
coding `aes128gcm` of RFC 8188, so that only that phone's browser can
open it) and the request is a `POST` to the row's `endpoint`, a timeout
of 10 seconds, a redirect not followed, with the headers

```
TTL: 604800
Urgency: high
Content-Encoding: aes128gcm
Content-Type: application/octet-stream
Authorization: vapid t=<token>, k=<this server's public key>
```

The token (RFC 8292) is signed with this server's key for the phones.
Its audience is the origin of the phone's delivery address, its contact
is `ALERT_PUSH_CONTACT`, and it ends 12 hours after it was made. One
token is kept per audience and used for 6 hours, then made anew: Apple
asks that a token is not made more often than once an hour. The outcome:

- A status from 200 to 299: `sent`.
- 404 or 410: the phone is gone. Every `alert_phones` row with that
  `endpoint` is deleted, whichever pod's; for each row that went,
  `raiseAlert` for its pod with `phoneUnreachable`; the message is given
  up, `phone unreachable`. The messages that `raiseAlert` wrote are taken
  by the next round of the same run.
- Anything else, also no answer: a failure, `status <n>` or the fetch's
  error.

A failure counts one try and sets the next one:

```sql
UPDATE alert_messages
SET tries = tries + 1,
    last_error = $2,
    next_try_at = now() + make_interval(mins => LEAST(power(2, LEAST(tries, 6)), 60)::int),
    gave_up_at = CASE WHEN created_at < now() - interval '3 days' THEN now() END
WHERE message_id = $1
```

So the tries come after 1, 2, 4, 8, 16 and 32 minutes, then every 60, and
a message that is more than three days old when it fails is given up.

The log lines, one per message, with no email address and no delivery
address in them:

```
alert sent: <kind> by email, pod <first 8 hex>
alert sent: <kind> to a phone, pod <first 8 hex>
alert not sent: <kind> by email, pod <first 8 hex>: <the error>
alert not sent: <kind> to a phone, pod <first 8 hex>: <the error>
alert phone unreachable: pod <first 8 hex>, <label>
```

And one line at boot, from `startAlertSender()`: `alerts: email on, phones
on, 25 validator keys`, with `off` and `no validator keys` where they
apply.

### 25.7 The words

An email's subject and text are in `src/alerts/alert-words.js`, in English
and in Thai. `emailOf(kind, language, facts)` answers `{ subject, text }`;
`facts` are what the sender read: `amount`, `accountType`, `accountId`,
`writesAt`, `removesAt`, `email`, `label`, `code`. A phone is sent facts,
not sentences: `phoneFactsOf(kind, facts)` answers `{ kind }` and, by
kind, `accountType` and `amount`; or `email`; or `label`; and `removesAt`
with the two removing kinds. Nothing else: no account id, no pod id, and
no day of a transfer. The phone's sentence is made on the phone, in the
phone's own language, by the wallet's `public/alerts-worker.js` (the
wallet's spec).

The English is the plan's "What a person sees", letter for letter. Every
alert ends with the same two paragraphs: "We never put a link in an
email. Open the wallet the way you always do." and "This email was sent
by the anoPod wallet. Nobody reads replies to it." The email with the
code ends with the second alone. The Thai is written by the build in the
words of the wallet's Thai dictionary (`web_app/src/app/i18n/th.ts`).
What an email quotes from the wallet's screens is taken from the two
dictionaries as they stand there: "Cancel transfer" (`cancelTransfer`),
"Recover account" (`recoverAccount`), "Security alerts"
(`accountAlerts.title`), "Keep" (`accountAlerts.keep`) and "Account"
(`nav.account`). The kinds of account are the wallet's words for them:
in English "guarded account", "vault account", "assisted account" and
"spending account", in lower case; in Thai the phrases of `accountKinds`.

The rules of the words:

- An amount: millionths as a decimal string, to anos, with commas in the
  whole part and the fraction's zeros dropped: `5000000000` is `5,000`,
  `1500000` is `1.5`. On the digits, with `BigInt`, never through a
  float.
- The start of an account's id: its first 8 hex characters.
- A day and time in an email: `27 November 2026 at 07:12 UTC`, with
  `Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', day: 'numeric', month:
  'long', year: 'numeric' })` and the hour and minute in the 24-hour
  form; for Thai the tag `th-TH-u-ca-gregory`, the wallet's. A day alone,
  for a removal: `21 December 2026`.
- "in 7 days": the hours from now to `writesAt`, rounded up. 48 or more:
  "in N days", N the hours divided by 24 and rounded. 2 to 47: "in N
  hours". Under 2: "within the hour".
- "10 minutes" in the sentence about the cancel is a constant of the
  file, `CANCEL_AFTER_MINUTES = 10`. It copies `LOCK_OFFSET_MINUTES` of
  `anossoftware/network/testnet.env`: when that changes, this changes.
- An email or a phone whose row is gone when the message is sent reads
  "an address that is no longer on the list" and "a device".
- Every kind has words for every case, so that no report can make
  `emailOf` throw. A transfer out of an assisted account reads as the
  assisted email. A transfer out of any other account reads as the
  guarded email with that account's kind in its words; when it has no
  `writesAt`, its second sentence is "It is waiting on the validators." A
  recovery's move reads with the day when it has a `writesAt` and without
  it when it has none, whatever the account's kind.

### 25.8 The settings

Six optional variables (`src/config/env.js`, `env.alerts`; section 8).
Each pair is all or nothing: with both lines the part is on, with neither
it is off, and one line without the other stops the boot. An error names
the variable and never its value.

| variable | default | what it is |
| --- | --- | --- |
| `RESEND_API_KEY` | none: no email is sent | the email company's key |
| `ALERT_EMAIL_FROM` | none | the sender of every email: `anoPod wallet <alerts@wallet.anocloud.com>` on the servers |
| `ALERT_PUSH_PRIVATE_KEY` | none: no notification is sent | the private half of this server's key for the phones' delivery services, 43 characters, made by `scripts/make-alert-push-key.js` |
| `ALERT_PUSH_CONTACT` | none | the contact the delivery services are given, an `https://` or a `mailto:` address: `https://wallet.anocloud.com` on the servers |
| `ALERT_REMOVE_MINUTES` | `43200` | how long an email or a phone that was taken off still gets every alert |
| `VALIDATOR_KEYS_FILE` | `network/validators.json` | the validators' public keys; a path from the repo's root, or a full path |

`.example.env` has the six at its end, each as a comment line, so that a
copy of the file starts a server with the alerts off.

The validators' keys. `network/validators.json` is a committed file: a
JSON list with one entry for each of the 25 entries of
`anossoftware/network/testnet.registry.json`, in the same order, each `{
"id": <the entry's id>, "publicKey": "<the entry's publicKey>" }`, one
entry per line. Nothing else of the registry is in it: no url and no
`active`. A validator's key changes only with the registry. When a
registry entry is added or its key changes, this file gets the same
change, and this server is deployed. `src/alerts/validator-keys.js` reads
the file once, when it is imported, and exports `validatorKeys`: a `Map`
from id to the key's 33 bytes, or `null` when the file does not exist. A
file that is there and does not parse, an entry whose id is not a
positive whole number or whose key does not decode to 33 bytes, or an id
that stands twice, stops the boot, with the file's path and the entry's
place in the error.

The key for the phones:

```bash
npm run make-alert-push-key -- <file>
```

`scripts/make-alert-push-key.js` makes a P-256 key pair and writes ONE
line, `ALERT_PUSH_PRIVATE_KEY=<the private half, 32 bytes as base64url>`,
to `<file>`, for its owner alone (mode 0600); a file that exists is never
overwritten. It prints the file's path and the public half as base64url,
nothing else, and never the private half. With no `<file>` it prints the
usage line and exits 2. It reads no env variable, opens no database and
needs no `node_modules`. The line goes to the end of `.env`, the same on
every server. That file is the one copy of the key outside the servers:
with a new key every phone has to be turned on again.

### 25.9 Files

New:

- `src/alerts/alerts.router.js`: the nine routes, eight behind
  `requireSetup` and `/report-waiting-transfers` with no check in front.
- `src/alerts/alerts.handlers.js`: one handler per route.
- `src/alerts/alerts.service.js`: the eight routes of a pod's list (25.3).
- `src/alerts/validator-reports.js`: `/report-waiting-transfers` (25.4).
- `src/alerts/validator-keys.js`: the validators' public keys (25.8).
- `src/alerts/alerts.queries.js`: every SQL statement of the feature.
- `src/alerts/alert-events.js`: `raiseAlert` (25.5).
- `src/alerts/alert-words.js`: the emails' subjects and texts, and the
  facts a phone is sent (25.7).
- `src/alerts/email.js`: the call to the email company (25.6).
- `src/alerts/push.js`: the scrambling of a notification, the signed
  header, and the check that a phone's key is a key (25.6).
- `src/alerts/alert-sender.js`: the sender (25.6).
- `network/validators.json`: the validators' ids and public keys (25.8).
- `scripts/make-alert-push-key.js`: the key for the phones (25.8).

Changed:

- `db/schema.sql`: the four kinds in the two lists of
  `notifications.kind` and in the comments of `notifications.kind` and
  `notifications.reference_id`, the comment of the ALTER pair, and the
  block of four tables at the end (25.2).
- `src/config/env.js`: `optionalText`, `readAlerts` and `env.alerts`.
  `.example.env`: the six lines.
- `src/recovery/recovery.service.js`: `openRecoveryCase` raises the alert
  inside its transaction and kicks the sender after it; two comments.
- `src/app.js`: the alerts router, mounted after the passkeys router.
  `src/server.js`: the sender started after the DAO clock and stopped
  after it.
- `package.json`: the script line `make-alert-push-key`.
  `package-lock.json` does not change.
- `src/notifications/notifications.queries.js`: the comment of `notify`,
  twenty-one kinds. `src/anos-accounts/anos-accounts.queries.js`: the
  comment of `lockPod`, which now names its third and fourth user. No
  line of code in either.
- Here: section 2 (two rows of the table), section 4 (four entries, and
  `### notifications`), section 5 (nine entries), section 6 (four rows
  and a sentence), section 8 (six rows and a paragraph), section 10 (a
  dated clause) and this section. `README.md`: the Scripts list, the
  table "Who may call what", the Endpoints table, the Database tables
  list, the Configuration table, the Layout and the Deferred list.
- On the user's word of 2026-11-21 (25.11), four more places here:
  section 1 (the statuses of an error), 12.4.2 (the writes of
  `/open-recovery-case`), 15.6 and 19.4 (a dated clause each). And in
  `README.md` the sentence on errors under "Who may call what", beside
  one row of the Database tables list and one line of the Layout.

### 25.10 What is left as it is

What stays: the wallet's two cancel buttons and the validators' cancels;
the bell's poll every 5 seconds; every step of a recovery; the
validators' one other call to this server, `/get-anos-account`; the
doormen's files; the wallet's proxy.

Out of this plan:

- Text messages. The wallet's page says "Coming soon."
- A button for an owner who can still log in, "This recovery is not
  mine"; a cancel of a recovery's move from the wallet.
- Noticing an email address that no longer exists. The email company can
  tell us; nothing listens yet.
- Switches for single kinds of alert; a second person who is told; an
  alert again while a transfer still waits; an alert at a cancel.
- The passkey's answer for a change of the list.
- The words of a privacy policy.

The known limits, as the plan's section 7 has them:

1. One validator alone can set off false alerts, up to 1,000 in 24
   hours, about any account and with amounts it made up, also a false one
   beside a true one. It cannot keep a true report from counting, it
   cannot move money, and an alert carries no link.
2. Whoever is logged in to a person's wallet sees the list with its email
   addresses, can add an email or a phone of their own, which then gets
   the alerts too, and can ask to take one off, up to 20 changes in 24
   hours. They cannot make an address stop getting alerts before the
   month is over, and every address on the list is told of each change
   the same day.
3. Someone who has broken into the wallet's own servers can end a phone's
   notifications on a phone that opens the wallet after that. The emails
   are not touched by it: this server sends them.
4. A person can switch the wallet's notifications off in the phone's
   settings, or take the wallet off the Home Screen. This server learns
   of it only when it next sends to that phone. Then the phone comes off
   the list and the emails are told.
5. An email that never arrives, or lands in a spam folder, is not
   noticed. A notification that the delivery service took and the phone
   never showed is not noticed either. A phone that is switched off for
   more than 7 days misses what was sent meanwhile.
6. An alert about a transfer leaves five to six minutes after the
   transfer was sent, and later when no validator reaches this server. A
   transfer that is written or cancelled before any validator reached
   this server is never reported.
7. Alerts about transfers begin when the first validator has taken step
   4. Until all 25 have it, a transfer is reported by those that have.
8. One alert per transfer. Nothing is said again while it waits, at its
   cancel or when it is written.
9. An account that no pod made, such as the first two of the ledger, has
   nobody to tell.
10. A phone that was lost or sold still gets every alert for a month
    after "Take off". An alert shows an amount and a kind of account, and
    for a change of the list an email address.
11. Two pods that are used on one phone both send their alerts to it, and
    an alert does not say whose it is.
12. A wallet that stays open on the Home Screen keeps the build it was
    opened with until it is closed, as a tab does today.
13. On an iPhone the phone part needs the wallet on the Home Screen, and
    a browser inside another app cannot do it. An email needs neither.
14. The email company sees every address and the words of every alert,
    and keeps them 30 days. This server's database holds the addresses as
    plain text, and so does every copy that is made of it.
15. The Thai sentences are unread by a Thai speaker when they go out.
16. Sent messages and reported transfers stay in their tables for good.
    They are small, and nothing reads them back to a person.
17. The email names an account by the first 8 characters of its id, and
    the day in UTC.
18. Anybody who knows a pod's id can open a recovery case for it (12.9,
    "Limits on opening cases"). The person is then told that a recovery
    was started, once in 24 hours at most, though nobody means to recover
    anything.

### 25.11 Notes from the build

#### Build 1, the masterpod (2026-11-21)

Built from `~/Desktop/Z-TestNet/forclaude/security-alerts-plan-1.md`
section 1, on main at a4965b5, the working tree clean. No new npm package
and no test file in the repo. Nothing was applied to any database, no
server was started, and no email and no notification left the build's
Mac. What the plan left open and how it was decided:

- The number and the date. This section is 25, the number the plan
  names, and it was free on the build day. BUILD-DATE is 2026-11-21.
- The parts that are the plan's letter for letter. `src/alerts/push.js`
  is the planning chat's tried file byte for byte (`diff`). The block of
  four tables is the plan's, with the date in its first line; `diff`
  against the tried file shows the two empty lines in front and nothing
  else. `optionalText`, `readAlerts` and the lines in `env` are the
  plan's. The two helpers stand right above `export const env`.
- `db/schema.sql`. The four kinds went into the `CREATE TABLE` and into
  the one ALTER pair, each as two more lines of the list. The comment of
  `notifications.kind` gained ", or, for a security alert (spec section
  25), transferWaiting, recoveryMoveWaiting, recoveryCaseOpened or
  alertSettingsChanged". The comment of `notifications.reference_id`
  gained the plan's words behind ", or, for a security alert (spec
  section 25),". The file's opening comment, which lists the blocks with
  an ALTER on an older table, is as it was: the new block has none.
- `network/validators.json` was written by a script of the moment from
  `git show 8d1c5cd:network/testnet.registry.json` in `anossoftware` and
  compared afterwards: 25 entries, the same ids in the same order, the
  same keys, and `id` and `publicKey` alone.
- `validator-keys.js`. A file that is there and cannot be read (any error
  but "no such file") stops the boot like one that does not parse. A
  path that does not start with `/` is joined to the repo's root.
- `alerts.queries.js`. Two column lists for each of the two list tables:
  the one the plan gives for `listEmails` and `listPhones`, and one with
  the pod (and, for an email, the code) for the reads of one row. So the
  list route never reads a code. The two counts of the limits are
  `countEmails` and `countPhones`. `removeDue` answers how many emails
  and phones went, the two deletes of emails added together.
- The emails' text. One paragraph is one line, with an empty line
  between two paragraphs: a mail program wraps the lines itself, also on
  a phone. `emailOf` throws on a kind that has no email (`phoneOn` goes
  to a phone alone) and on facts that are not what the kind carries (an
  amount that is no decimal string, an account id that is no string, a
  moment that is no date, a code that is not six digits). Such a message
  is given up as `could not be built`. No report of a validator can make
  it throw: a report's amount and day are checked, and the account's
  kind is this server's own.
- "30 days" in the email about an added address is a literal of the
  words, as the plan has it, and is `ALERT_REMOVE_MINUTES` at its
  default. With another value in `.env` that one sentence still says 30
  days. The day in the email about an address that comes off is always
  the real one.
- The Thai words the build chose for what the wallet does not have yet:
  "การแจ้งเตือนความปลอดภัย" for "Security alerts" and "เก็บไว้" for
  "Keep". The wallet's step 3 writes the same two into `th.ts` as
  `accountAlerts.title` and `accountAlerts.keep`: an email quotes them.
  The device words in Thai are "iPhone", "iPad", "โทรศัพท์ Android",
  "คอมพิวเตอร์" and "อุปกรณ์เครื่องหนึ่ง". In Thai "บัญชี" stands in
  quotes like the page's name, since Thai has no capital letter to mark
  a button by.
- `alerts.service.js`. A text's length is counted as the database counts
  it (a character outside the basic plane is one), after a first look
  that turns away a text of more than twice the limit. The answer of a
  new code names the address as the row holds it, also when it was typed
  in other capitals this time. A phone's delivery address is stored as
  it was sent, so that the hash the wallet makes of it is the hash this
  server answers. A refusal `push service not supported` carries the
  host beside its reason, and the handler logs `alert phone refused,
  delivery service not on the list: <host>`.
- The count of a day's changes is the count of the bell's rows of the
  kind `alertSettingsChanged`, as the plan's statement has it. So a
  "Keep", and a phone that came off because it could not be reached,
  add to the count, though neither is ever refused by it.
- Two counts are read without a lock on the pod's row: the count of
  `recoveryCaseOpened` in `raiseAlert`, and the count of changes in the
  four routes that lock an email's or a phone's row. Requests of one pod
  that arrive at the very same moment can each pass on the same count.
  The count closes behind them: the next request sees their rows. For
  the changes that is a handful at most, one for each row of the list.
  For the recovery alert it was tried (below): eight cases opened for
  one pod at one moment wrote eight alerts, and a ninth a moment later
  wrote none. So "once in 24 hours" holds between cases that follow each
  other, and not between cases opened at the very same moment. With the
  pod's row locked in front of that count (`lockPod`, one line, tried in
  a scratch copy alone) the eight wrote one alert, and all eight cases
  still opened. That lock was put to the user and is NOT built. The
  user, 2026-11-21: "But why would a person every have more than one
  recovery case? They shouldn't even be able to open more than one case.
  If they can, that's a separate bug." They can: the rule is one open
  case for a lookup id (12.4.2, check 7), not for a pod, and this server
  takes any lookup id, so a caller who makes up a lookup id each time
  opens case after case on one pod. A person who uses the wallet has one
  lookup id and so one open case. That is the gap of 12.9, "Limits on
  opening cases", and of the after-production item "recovery rules left
  loose"; the count of 24 hours is a stopgap for it and stays as the
  plan has it.
- `validator-reports.js`. The count of a validator's rows is read before
  the message's rows are written, as the plan's order has it. So the
  message that crosses the 1,000 is still taken whole. Messages of one
  validator that arrive at the very same moment each read the count
  before any of them has written, so the ceiling is 999 rows and 100
  more for each message in flight at that moment.
- `email.js`. The answer's `name` is cut at 60 characters before it goes
  into `last_error`.
- `alert-sender.js`. It exports `runAlertSender()`, a run that can be
  waited for, as the DAO clock exports `tick`; `kickAlertSender()` is the
  same run, not waited for. It also exports `pushKey`, this server's key
  for the phones, which the list route answers the public half of.
  Thirty-two bytes that are no private key of the curve stop the boot
  with `ALERT_PUSH_PRIVATE_KEY is not a private key of the P-256 curve`.
  A round has three parts in a row: each message is made ready (the
  reads are the transaction's), then the requests are made, then each
  outcome is written. A round that raised an alert for a phone that is
  gone is followed by another round, so that the emails about it leave
  in the same run. `stopAlertSender()` also keeps a new round and a kick
  from starting, so that a shutdown is not held up by a run. With email
  and phones both off a run does its first step alone. A token is
  dropped from the kept ones when it is past its 6 hours and another is
  made.
- A message for a part that is off stays in the table and is due. It
  goes out when that part is on again, or is given up at the first
  failure after three days. No such message can be written while a part
  was never on: a list is empty until its part is on. It matters only
  when a line is taken out of `.env` after people have used it.
- No new route and no timer opens a transaction as its first database
  step. A run of the sender begins with the three plain deletes, and
  `/report-waiting-transfers` reads the validator's count with a plain
  query before its transaction; the eight list routes stand behind the
  session check. So none of them can end the process while the database
  turns callers away (the after-production item "the masterpod ends when
  its database connection is cut during a write"). A round does keep its
  transaction open while its requests are made: a second or so as a
  rule, and up to 200 seconds when the email company answers none of 20
  emails, ten seconds for each. A connection that is cut in that time
  ends the process, as it does today for any transaction of this server.
  systemd starts it again and the round's messages are taken again; the
  emails are not sent twice (the key of 25.6), and a phone may get one
  notification twice. While a round waits like that, a new alert on the
  same server waits with it, or is taken within the minute by the run of
  another server; and a restart of that server ends by the ten-second
  net of `src/server.js`.
- `make-alert-push-key.js`. The private half is written as 32 bytes: a
  number that begins with a zero byte comes back shorter from Node, and
  the setting takes exactly 43 characters. It prints `written: <path>`
  and `public key: <87 characters>`. A file that exists already, or one
  that cannot be written, is exit 1 with one line.
- `openRecoveryCase`. The alert is raised after the `opened` event and
  the sender is kicked after the transaction, when the case was written.
  The comment of `recoverWithBackupCode` gained the sentence that the
  finish leaves the alert rows alone.
- Here and in the README. In section 4 the four entries are short and
  point to 25.2, where the tables stand with their columns; in section 5
  the nine entries point to 25.3 and 25.4, as the plan says. Section 8
  gained a paragraph under its table beside the six rows, since four of
  the six have no default.
- Checks (the plan's 1.15), all on Node 24.22.0 and this Mac's
  PostgreSQL 17.11. `node --check` on the eighteen new and changed code
  files: clean. The load with no server, `src/app.js` imported and
  `createApp()` called with made-up `PGDATABASE`, `PGUSER` and
  `PGPASSWORD`: 108 routes, where a copy of a4965b5 has 99; with none of
  the six variables (email off, phones off, 25 validator keys); with all
  six made up (both on); with one line of a pair alone, each pair once,
  which stops with the error of 25.8; and with 32 zero bytes as the key,
  which stops too. The schema, in one transaction that was rolled back,
  with the planning chat's trial file: the file of a4965b5 into a scratch
  schema, a row of an old notification kind, the new file on top twice,
  and a fresh schema from the new file alone. 37 tables became 41, the
  old row was still there, and one md5 over every column, constraint,
  index, trigger and comment was the same for the three shapes; the five
  refusals the tables are meant to give came. `push.js` against the
  example of RFC 8291 section 5, with the planning chat's 20 checks: the
  body equals the standard's byte for byte.
- The real modules over a scratch schema, in a throwaway script outside
  the repo: a stand-in for `src/db/pool.js` (one connection, one
  transaction, rolled back at the end, every BEGIN and COMMIT of the
  code a savepoint), `fetch` replaced, a key for the phones made by the
  repo's own script and two validator keys of the run, in files only
  their owner can read. Each route was called as Express calls its
  handler, with the pod on the request. 219 checks with the settings on
  and 11 with none, none bad. Among them: every English email equal to
  the plan's own text, letter for letter, read out of the plan file;
  every refusal of the eight routes once; the email request's headers
  and body; the request to a delivery service, whose body was opened
  with the phone's own key by code written apart from `push.js`, and
  whose token verifies under the key it carries; a report signed with a
  key of the run and sent twice, also by a second validator, which gave
  one alert; a report with another amount for the same transfer, which
  gave a second row and a second alert; a transfer of an account no pod
  made, which gave a row and no alert; answers of 201, 503, 422, 404 and
  410 and no answer at all, after a 410 both pods' rows of one phone
  gone and their emails told; the waits of 1, 2, 4, 8, 16, 32, 60 and 60
  minutes; 45 messages in one run; a message whose words cannot be made,
  a phone whose stored key is no key and a kind with no email, each
  given up while the good message of the same round went out; the 21st
  change of a day refused and a "Keep" after it not; a body whose string
  is not well formed answered `401 bad signature`; 1,000 rows of one
  validator, then `429`.
- One thing beyond 1.15, in the same script: `openRecoveryCase` was
  called for real, with a passkey registration, a challenge and both
  signatures made for the run. The case opens and the pod's email is
  told; a second case for the same pod on the same day opens and writes
  no second alert; a day later a case makes an alert again; a pod with
  nothing on its list gets the bell's row. And the new code on the
  tables of a4965b5: the alert of a recovery case is refused by the old
  check on `notifications.kind`, so a case could not be opened. That is
  why the schema goes first at the deploy (the plan's 6.2).
- A second thing beyond 1.15: what Node's own `fetch` puts on the wire.
  A listener on 127.0.0.1 alone, on a port of the moment, stood in for
  the email company and for a delivery service, and `fetch` was wrapped
  so that every request went to it and nowhere else. 13 checks, none
  bad: an email's four headers and its body arrive as 25.6 has them,
  Thai letters included; a refusal reads `status 422 validation_error`,
  one that is no JSON `status 403`; a redirect is not followed; a
  notification's five headers arrive, and its body, as it arrived, opens
  with the phone's own key to the facts; a request that gets no answer
  is given up after ten seconds as `The operation was aborted due to
  timeout`, and the message waits for its next try.
- A third thing beyond 1.15: requests at the very same moment, and two
  senders at once. The scratch schema above has one connection, so this
  ran on a PostgreSQL of the moment in the build's scratch folder, on
  127.0.0.1 alone, with the real `src/db/pool.js`, real connections and
  real commits, and `fetch` replaced. For one pod at one moment: 30 new
  phones, 5 went in and 25 were refused at the limit; one new email
  asked 20 times, one row and one code; 10 wrong codes, five counted and
  then `410 code used up`; the right code 6 times, confirmed once; "Take
  off" 12 times, one change and one day in every answer; one transfer in
  25 reports of two validators, every answer `200`, one row and one
  alert. Two processes ran the sender at the same moment over 60
  messages that were due: 60 requests in all, every message sent once.
  And the recovery alert, as said above: eight cases at one moment,
  eight alerts.
- A second reader. A separate agent, told only to find faults, read the
  change against the plan's section 1. It found no place where the code
  departs from 1.6 to 1.13, nothing that can stop the sender, no request
  to an address of a caller's choosing, and no address, code or key in a
  log line or an answer. What it found beside, each run afterwards where
  it could be:
  - A logged-in caller can make two routes answer `500` where a `400`
    is meant. An email address with a zero byte in it passes the plan's
    pattern, and the database takes no zero byte in a text. A delivery
    address with a zero byte fails the same way, and one of about a
    thousand letters outside ASCII that do not compress makes the row of
    the table's unique index too large. Each is rolled back, writes
    nothing and reaches the caller alone. Put to the user with two
    checks that the plan does not have, and BUILT on the user's word of
    2026-11-21 ("That sounds good."): in `alerts.service.js` an email
    with a control character in it is `400 invalid email`
    (`CONTROL_PATTERN`), and a delivery address that is not plain ASCII
    with no blank is `400 invalid endpoint` (`ENDPOINT_PATTERN`). Both
    stand inside the third check of their route (25.3). The three
    requests were run again over the scratch schema and answer so; a
    delivery address of a thousand letters and digits is still taken.
  - A signed report whose day is before 4713 BC passes `Date.parse` and
    is refused by the database: a `500` where `400 invalid transfer` is
    meant, and nothing is written. Only a validator with a real key can
    send it. Left.
  - Two messages that name the same two new transfers in opposite order,
    at the very same moment, can wait for each other. The database ends
    one of them (a `500`); the other commits, so the alert goes out, and
    the first one's next try a minute later answers `200`. Not run.
  - A code can leave after it is dead. An `emailCode` is given up only
    when its row has no code. After four failed tries the fifth comes 15
    minutes after the first, past the code's ten minutes; the email
    still says ten minutes, and the wallet then answers `410 code
    expired`. As the plan has it.
  - One Thai sentence used one word for the list and for an entry of it
    and could be read as "the list that was taken off". Reworded: "an
    email or a phone that is taken off".
- Not tried by the build: an email through the email company, a
  notification through a delivery service, and a request signed by a
  session's keys over HTTP.
- Places the plan does not name that this step left out of date. They
  were left as they were, listed and asked about, and brought in line on
  the user's word of 2026-11-21 ("Okay, we can fix those sentences"). In
  `README.md`: the row `notifications` of the Database tables list now
  says twenty-one kinds; the line of `dao/` in the Layout says "the one
  outbound call to the validators"; the sentence on errors under "Who
  may call what" names `410`, `429` and `503`. Here: section 1 gained
  the three statuses, with the day each came (`503` is of 2026-11-08,
  section 15); the "Writes" of `/open-recovery-case` in 12.4.2 gained
  the alert; 15.6 and 19.4 each gained a clause in brackets that begins
  "Since 2026-11-21", with their words of before staying. Three more
  mentions of "seventeen kinds" stay as they are: they stand in 19.5 and
  19.6 and say what that build changed and what its check saw.
- Two more places of that kind, seen while those were fixed. Left as
  they are and asked about: the sentence "Everything a pod keeps private
  reaches the server as ciphertext", in the opening of `README.md` and
  in section 1 here, though the emails of a pod's alerts are kept as
  plain text (decision 16); and "Notifications for case events" among
  what is not built, in 12.9 here and under "Deferred, by decision" in
  `README.md`, though the opening of a case is now told to the pod.

## 26. Public rooms: a search, and the biggest first (2026-11-22)

Design settled 2026-11-22 in a talking chat and its planning (the plan is
`~/Desktop/Z-TestNet/forclaude/public-rooms-plan-1.md`, FINAL,
2026-11-22). Why: `/list-public-chat-rooms` answered the public rooms
newest first and took no search word, and the wallet's tab "Find public
rooms" showed the 50 newest rooms and no others. The user, 2026-11-22:
"1. Public rooms are searchable. 2. Upload an image for the public room.
3. Should we make it so that public rooms have to have unique names.
Somehow facebook doesn't have a problem with this. I'm on the fence. One
issue is that like 20 people have already made a room called anoTH. So
now people are asking for public group names to be unique." The talk's
answer, which the user took: names stay free; a search, the biggest rooms
first and a picture tell rooms of one name apart, and a hint shows the
rooms that exist before another is made. The plan has five steps. The
search and the order are two repos in order: this server (this section,
step 1 of the plan: one read changes) and the wallet (its spec, step 2:
the tabs of New chat in a new order, a search box and Show more on Find
public rooms, and the hint under the name box of New public room). The
picture is steps 3 and 4 (this server, then the wallet), and the record
files are step 5. This server goes first (the plan's section 6): a wallet
of step 2 against a server of before narrows nothing, because that server
does not read the word. With this server alone deployed, a wallet of
before shows the 50 biggest rooms where it showed the 50 newest, and
nothing else changes for it. There is no schema step, no env variable, no
npm package and no new route. The validators, the doormen, the
keyholders, the signing servers and the wallet's proxy are not touched.
Nothing above this section changes except the items in 26.4.

### 26.1 The rule

- A public room's name stays free: two rooms may carry one name (the
  plan's decision 3). The user's "1. Yes" to the talk's first question.
  Nothing makes a name unique, before this section or after it.
- With no search word the rooms with the most members come first, not
  the newest (decision 5). The user's "3. Yes."
- The search is this server's (decision 8). `/list-public-chat-rooms`
  takes one more optional field, `search`. A room fits when its name
  holds the search word anywhere, capital and small letters alike. That
  also suits Thai, which is written without spaces between words. `%`
  and `_` mean themselves. The word is at most 100 characters, the
  length of a name; the spaces around it are taken off, and an empty
  word means no search.
- The order is: the most members first, then the newest, then the room's
  id (decision 9). It is the same with and without a search word.

### 26.2 The read

`listPublicRooms` (`src/chat/chat.service.js`) checks the body in this
order: it is an object (`400 bad request shape`), `limit` (`400 invalid
limit`), `offset` (`400 invalid offset`) and last, new, `search` (`400
invalid search`). The checks of before stay in front, so a bad limit is
still told as a bad limit, also beside a bad search word. `limit` and
`offset` are as they were: 50 by default and at most 200, and 0.

`searchOption`, new in that file, reads the word:

- no `search`, or null: no search;
- a value that is not a string: `400 invalid search`;
- the spaces around the word are taken off (`trim`);
- more than 100 characters after that (`NAME_MAX_CHARS`, the length of a
  name): `400 invalid search`. Characters are counted as
  `/create-chat-room` counts a name's, so 100 Thai letters fit;
- an empty word, or one of spaces alone: no search.

Then the one statement of `listPublicRooms` (`src/chat/chat.queries.js`).
It takes the word as its third parameter, null for no search:

```sql
SELECT r.chat_room_id, r.name, r.created_at,
       (SELECT count(*)::int FROM chat_room_members m WHERE m.chat_room_id = r.chat_room_id) AS member_count,
       ${PROFILE_COLUMNS}
FROM chat_rooms r
JOIN anopods a ON a.anopod_id = r.creator_anopod_id
WHERE r.type = 'public'
  AND ($3::text IS NULL OR strpos(lower(r.name), lower($3::text)) > 0)
ORDER BY member_count DESC, r.created_at DESC, r.chat_room_id
LIMIT $1 OFFSET $2
```

`${PROFILE_COLUMNS}` is the creator's profile, as before. Two things are
new against the statement of before: the line that begins `AND`, and
`member_count DESC` in front of the two sort keys of before. The answer
has the shape of before, `200 { rooms: [ { chatRoomId, name, creator:
profile, memberCount, createdAt } ] }`, and with no room that fits it is
`200 { rooms: [] }`. (Since 2026-11-22, section 27, the statement also
reads `rp.updated_at AS picture_at` through a left join of
`chat_room_pictures`, and each room of the answer carries `pictureAt`
after `name`. The block above is the statement as this section's build
left it.)

Why the names are compared as text: `strpos` asks whether the name holds
the word, letter for letter, after `lower` has made both small. The word
is never read as a pattern. With `LIKE` or `ILIKE` a `%` or a `_` in the
typed word would stand for other letters, so "100%" would also find a
room called "1000 anos", unless the word were escaped first. Here nothing
needs escaping, and `%` and `_` mean themselves. The word travels as a
parameter, never inside the statement's text, and `$3::text` gives that
parameter its type.

### 26.3 What is left as it is

- Look-alike names stay possible. The rooms called anoTH, about twenty
  by the user's count, all stay; the biggest now stands first.
- A room whose only member is its creator stays in the list for good, at
  its end.
- The search compares letters as they were typed. "anoth" finds "anoTH".
  Thai typed in another order of marks, or a letter with an accent typed
  without it, is not found.
- The number of members is counted for every public room at every read.
  That is quick for hundreds or a few thousand rooms. No index is added,
  and the index of `chat_rooms` on `(type, created_at DESC)` no longer
  gives the list's order (section 4).
- The order moves when a room gains or loses a member between two reads.
  The wallet's Show more (the plan's step 2) leaves out a room that is
  already shown; it can miss a room that moved up past the last row
  shown. The next first read shows it.

### 26.4 Files

- `src/chat/chat.queries.js`: `listPublicRooms` takes `search` as its
  third parameter, null by default, keeps the rooms whose name holds it
  and sorts by the number of members first; its comment says so.
- `src/chat/chat.service.js`: `searchOption`, new, after `integerOption`;
  in `listPublicRooms` the check of `search` after the check of `offset`,
  its refusal, and the word handed on to the query; the function's
  comment names the new field and the new order.
- Here: section 4 (`### chat_rooms`, one sentence), section 5 (`### POST
  /list-public-chat-rooms (setup)`, the body's `search` with its refusal,
  and the order) and this section. `README.md`: the route row of
  `/list-public-chat-rooms`.

Nothing else in existing code changes: the router, the handlers,
`/create-chat-room` and every other chat route, `db/schema.sql` and
`.example.env` are as they were. No env variable, no npm package, no new
route.

### 26.5 Notes from the build

#### Build 1, the masterpod (2026-11-22)

Built from `~/Desktop/Z-TestNet/forclaude/public-rooms-plan-1.md` section
1, on main at 93e8f43, the working tree clean. No new npm package, no
test script and no rig (none was asked for). Nothing was applied to any
database of the network: there is no schema step. What the plan left open
and how it was decided:

- The number and the date. This section is 26, the next free number on
  the build day. BUILD-DATE is 2026-11-22, the day of the build and of
  the plan's FINAL.
- The code. The statement of `listPublicRooms`, the function
  `searchOption`, and in the service's `listPublicRooms` the two new
  lines and the changed call are the plan's, letter for letter, with
  2026-11-22 and 26 where the plan's comments say BUILD-DATE and N.
- The comments. The comment of the query's `listPublicRooms` and the
  comment of `searchOption` are the plan's blocks. The comment above the
  service's `listPublicRooms` is given by the plan in words. It became a
  block comment that reads: "POST /list-public-chat-rooms. Body { limit,
  offset, search }, all optional; the rooms with the most members first,
  and `search` keeps the rooms whose name holds it (2026-11-22, spec
  section 26)."
- Where the new lines sit. `searchOption` stands directly after
  `integerOption`, in front of `caseOf`. The check of `search` stands
  directly after the check of `offset`, in front of the empty line and
  the `return`. It is the last check, so the three refusals of before
  come first, as before.
- Here and in the README. In section 4 the sentence is a paragraph of its
  own at the end of `### chat_rooms`. In section 5 the entry of
  `/list-public-chat-rooms` has no "Checks" paragraph, before or now: the
  new refusal stands in brackets in the "Body" paragraph, the way the
  entry of `/list-messages` names `400 invalid beforePosition`. The
  README row is the plan's sentence with the date.
- Checks (1.4). `node --check` on the two changed source files
  (`src/chat/chat.queries.js`, `src/chat/chat.service.js`), clean, on
  Node 24.22.0. Then the statement by psql, on a PostgreSQL 17.11 that
  was started for this check alone: a data folder of its own in the build
  chat's scratch folder, listening on 127.0.0.1 port 58731 and nowhere
  else, with no socket file. This Mac's own PostgreSQL on port 5432 was
  not touched. One transaction, rolled back: `CREATE SCHEMA
  scratch_public_rooms`, the search path set to it (`SET LOCAL`), and
  `db/schema.sql` read into it, which made 41 tables. Into them went
  three throwaway pods (the statement joins the creator's row), six
  public rooms and one private room, and ten member rows: "anoTH" (the
  oldest, 3 members), "AnoTH traders" (2), a second "anoTH" (1), "100%
  anos" (1), "ห้องคนไทย" (1), "other" (1, the newest of the six), and
  the private room, newer than all of them. The statement was read out of
  `src/chat/chat.queries.js` by a small script, with the profile columns
  of `src/anopods/anopods.queries.js` put in, so what ran is what the
  code sends. It was prepared with untyped parameters (`PREPARE`), as
  `pg` sends them, and the server took the three as `bigint`, `bigint`
  and `text`. 15 results, none bad. With no search word: all six, "anoTH"
  with 3 first, "AnoTH traders" with 2 next, then the four rooms of one
  member with the newest first ("other", "ห้องคนไทย", "100% anos",
  "anoTH"), and the private room in no answer. "anoth" gave three, "%"
  gave one ("100% anos"), "_" gave none, "คนไทย" gave one. `limit` 2 at
  `offset` 0, 2 and 4 gave six different rooms, in the order of the whole
  list, and at `offset` 6 none. After the rollback that database held no
  scratch schema and no table. The scratch PostgreSQL was stopped
  afterwards.
- Two things beyond 1.4, with nothing kept. First a comparison. The
  planning chat had tried this step in a throwaway copy of 93e8f43, with
  the code read out of the plan file by a script (the plan's section 9).
  The build made that copy again with the same script and compared the
  two source files with the working tree by `diff`: they differ in
  comment lines only, in three places (the date and the number where the
  copy has the words BUILD-DATE and N, twice, and the comment above the
  service's `listPublicRooms`, which the plan gives in words). No other
  file of `src` or `db` differs from that copy. Second, the planning
  chat's check of this step ran again, against a copy that holds the two
  built files: the real `createRoom` and `listPublicRooms`, called from a
  script with the pool on a database of the same scratch PostgreSQL that
  holds the tables of `db/schema.sql`. 21 results, none bad, the same 21
  as in the plan's section 9. Among them, what psql cannot show: the
  word "ANOTH" with spaces around it finds the three rooms that "anoth"
  finds; an empty word, a word of spaces and null each give all six; a
  word of 100 characters and one of 100 Thai letters are taken; 101
  characters and a number each give `400 invalid search`; a bad `limit`
  beside a bad `search` is told as `400 invalid limit`. That run stops
  before its first query unless the pool's host and port are the scratch
  PostgreSQL's: this server's default port is 5432, which on this Mac is
  the user's own database.
- Not tried by the build. No server was booted, no request was signed and
  the route was not called over HTTP. The search on the live wallet is
  the user's (the plan's section 6). How long the read takes with
  thousands of public rooms was not measured. A capital letter outside A
  to Z was not tried on a database like production's: `lower` goes by the
  database's locale. The scratch database (`en_US.UTF-8`) made "É" and
  "Ω" small, and under the collation "C" it makes only A to Z small.
  Production's database was made with the locale `C.UTF-8`, by its build
  paper (`Z-TestNet/production_specs_designs`), and this Mac has no such
  locale.
- Places the plan does not name that this step left out of date: none
  found. Looked through: every place here, in `README.md`, in
  `docs/build-plan.md`, in `src`, in `db/schema.sql` and in `scripts`
  that names `/list-public-chat-rooms`, `listPublicRooms`, a public
  room, the index of `chat_rooms`, a search, or a list that is "newest
  first".
- Not touched: `chat.router.js`, `chat.handlers.js`, every other
  function of the two changed files, every other feature folder,
  `db/schema.sql`, `package.json`, `.example.env`, the scripts; in the
  README everything but the one route row.

## 27. A public room's picture (2026-11-22)

Design settled 2026-11-22 in a talking chat and its planning (the plan is
`~/Desktop/Z-TestNet/forclaude/public-rooms-plan-1.md`, FINAL,
2026-11-22; section 26 has the user's words in full and the talk's
answer). Why: a public room's name stays free, about twenty rooms are
called anoTH by the user's count, and a row of the wallet's list showed
only the name, the creator and the number of members to tell two of them
apart. The user, 2026-11-22: "2. Upload an image for the public room."
Two repos in order: this server (this section, step 3 of the plan: one
new table, two new routes, and one field more in the answers of the two
room lists) and the wallet (its spec, step 4: the entry "Room picture" in
the room's menu for the creator of a public room, and the picture drawn
in the chat list, at the conversation's top and in the rows of Find
public rooms), then the record files (step 5). Steps 1 and 2 of the plan
are the search and the order (section 26). This server goes first (the
plan's section 6): a wallet of step 4 against a server of before shows no
picture, and its "Room picture" answers "HTTP 404". With this server
alone deployed nothing changes for anyone: a wallet of before calls
neither new route and does not read the new field. Inside this server's
own deploy the order matters: the schema file goes onto the database
before the new code runs (27.7). One schema block with one new table, and
two new routes. No env variable and no npm package. The validators, the
doormen, the keyholders, the signing servers and the wallet's proxy are
not touched. Nothing above this section changes except the items in 27.5.

### 27.1 The rule

- A public room gets a picture (the plan's decision 2). The user: "2.
  Upload an image for the public room."
- Only the room's creator sets it, in one place: the room's own menu in
  the wallet, by an entry "Room picture" (decision 17). The form "New
  public room" stays a name and "Create", so one place serves a new room
  and the rooms that exist today alike. Asked, with the form as a second
  place as the other choice; the user: "1. yes", the menu only.
- The creator can put another picture in its place at any time, and one
  route does both. Nobody else can set a room's picture (decision 18).
  Asked; the user: "2. yes".
- Only a public room has a picture (decision 19). A private chat, a
  group, a listing chat and a case chat have none: on this server those
  are the rooms of type `private`. An old `marketplace` room has none
  either.
- The creator cannot take the picture away, only put another in its
  place (decision 20). No route deletes a picture.
- The picture is small. The wallet sends the middle of the picked
  picture as a square of at most 320 pixels, a fresh JPEG at 0.8, as it
  sends the public selfie (decision 21); that weighs some 15,000 to
  30,000 bytes. This server takes a picture of one of its three types
  that is at most 320 pixels wide and high and at most 100,000 bytes
  (decision 22). The selfie's limits, 4096 pixels and 10 MB, are what
  let the selfies grow to hundreds of kilobytes (section 24); a room's
  picture starts with the small limits.
- The picture is stored in a table of its own, `chat_room_pictures`, one
  row per room, in the clear like the room's name (decision 23). It is
  handed out by a read of its own, `/get-chat-room-picture`, to any pod
  at level setup, for public rooms only. It never travels inside a list.
- A bad picture is taken down by hand on this server's database for now
  (decision 7). That is a workaround, not the design. The item for a
  real way is on the after-production list, "public rooms: a bad picture
  cannot be taken down". The user: "4. Yes. and yes to adding to after
  production." How it is done by hand is in 27.6.

### 27.2 The table

`db/schema.sql`, one new block, the last thing in the file, after the
security alerts block: "The room picture block (2026-11-22, spec section
27)".

```sql
CREATE TABLE IF NOT EXISTS chat_room_pictures (
  chat_room_id BYTEA       PRIMARY KEY CHECK (octet_length(chat_room_id) = 32),
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
  image        BYTEA       NOT NULL CHECK (octet_length(image) BETWEEN 1 AND 100000),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER chat_room_pictures_set_updated_at
  BEFORE UPDATE ON chat_room_pictures
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();
```

- `chat_room_id`: the room the picture belongs to. It is the primary
  key, so a room has at most one row.
- `content_type`: `image/jpeg`, `image/png` or `image/webp`.
- `image`: the picture's bytes as uploaded, 1 to 100,000 of them. The
  route refuses a heavier picture before the table is asked; the check
  is the table's own last word.
- `created_at`: when the room got its first picture. Never changed.
- `updated_at`: when the picture was last set. The trigger moves it only
  when the row really changes: another picture moves it, and the same
  picture sent again does not. It is what the room lists hand out as
  `pictureAt`.

No index but the primary key's: every read is by the room's id. No
foreign key, as everywhere (section 1): the route checks that the room
exists. No route deletes a row. The table and each column have a `COMMENT
ON`. The block is idempotent (`IF NOT EXISTS` and `OR REPLACE`), so the
whole file applies to a live database and a second run changes nothing.
The file makes 42 tables, one more than before.

### 27.3 The two routes

**POST /set-chat-room-picture** (setup), new.

Body: `{ chatRoomId, picture: { contentType, image } }`. `chatRoomId` is
the room, hex like every id. `picture` is an image in the form of section
1: `contentType` one of the three types, `image` the bytes as base64.

Checks, in order:

1. The body is an object and `chatRoomId` is a string, else `400 bad
   request shape`.
2. The room exists and the caller is its creator, else `403 only the
   creator sets the picture`. A room that does not exist and an id that
   is no id get the same words, as `/invite-to-chat-room` answers them.
3. The room is `public`, else `400 only a public room has a picture`.
4. `picture` is an object, its `contentType` is one of the three, and
   its `image` is base64 of 1 to `MAX_IMAGE_BYTES` bytes, else `400
   invalid picture: <why>` with the words of `decodeImage`
   (`src/util/images.js`): `image must be an object`, `contentType must
   be image/jpeg, image/png or image/webp`, or `image must be base64 of 1
   to 10485760 bytes` (the number is `MAX_IMAGE_BYTES`).
5. The picture is at most 100,000 bytes, else `400 invalid picture:
   image must be at most 100000 bytes`.
6. The bytes begin as a picture of that type does, else `400 invalid
   picture: image must be a picture of its contentType`; and the width
   and the height its own header names are each at most 320 pixels, else
   `400 invalid picture: image must be at most 320 pixels wide and high`.
   This is `pictureProblem`, the selfie's check (section 11, the pictures
   note), with 320 where the selfie has 4096.

Writes, one transaction of one statement: the room's row in
`chat_room_pictures`. A room without a picture gets its row; a room with
one keeps its row and gets the new type and bytes (`INSERT ... ON
CONFLICT (chat_room_id) DO UPDATE`). No notification, no event, nothing
else.

Answer: `200 { chatRoomId, pictureAt }`. `chatRoomId` is the room in hex.
`pictureAt` is the row's `updated_at` after the write, an ISO 8601
string: the value the two lists then carry for the room. The same picture
sent again answers `200` with the `pictureAt` of before.

**POST /get-chat-room-picture** (setup), new.

Body: `{ chatRoomId }`.

Checks, in order:

1. The body is an object and `chatRoomId` is a string, else `400 bad
   request shape`.
2. The room exists and is `public`, else `404 room not found`. A room
   that is not public gets the same words as one that does not exist.
3. The room has a picture, else `404 no picture`.

The caller need not be a member of the room: the picture is as public as
the room's name, which `/list-public-chat-rooms` hands to any pod at this
level. The route writes nothing.

Answer: `200 { chatRoomId, picture: { contentType, image }, pictureAt }`.
`picture` is the stored image in the form of section 1, and `pictureAt`
the row's `updated_at`.

### 27.4 `pictureAt` in the two lists, and what a wallet does with it

`/list-chat-rooms` and `/list-public-chat-rooms` (section 5) each carry
one more field per room, `pictureAt`, after `name`: when the room's
picture was last set, an ISO 8601 string, null for a room without one.
Both statements read it the same way, `rp.updated_at AS picture_at`
through `LEFT JOIN chat_room_pictures rp ON rp.chat_room_id =
r.chat_room_id`. A room has at most one row there, so the join adds no
row to either list. In `/list-chat-rooms` every room of the answer has
the field, and it is null on every room that is not public; the invites
and the join requests of that answer carry none.

Why the field (decision 24): without it a member's wallet could not tell
that a room has a picture, or that it got a new one, short of asking for
every room. `/list-chat-rooms` is the read every wallet makes every 5
seconds, and its weight is on the after-production list ("chat list:
every member of every chat is sent again every 5 seconds"). The field
adds 39 characters to a room with a picture and 17 to a room without.
Asked for that reason; the user: "3. yes". The picture itself never
travels in a list.

What a wallet does with it (decisions 25 and 29; the wallet's step 4): it
reads a picture with `/get-chat-room-picture` once per room and per
`pictureAt` for the life of a tab, five reads at a time. A new picture
has a new `pictureAt`, so it is read again: the members see it within
about 5 seconds, a person on Find public rooms at the next read of the
list. A server of before this section sends no `pictureAt`, and a wallet
reads a missing one as null: no picture, no read.

### 27.5 Files

- `db/schema.sql`: the room picture block, new, at the end.
- `src/chat/chat.queries.js`: the import of `encodeImage`;
  `upsertRoomPicture` and `findRoomPicture`, new, under a new heading
  "Room pictures" after the block "Rooms"; in `listRoomsFor` and in
  `listPublicRooms` the column `rp.updated_at AS picture_at`, the join
  and the field `pictureAt` after `name`; the comment of `listRoomsFor`
  names the field; and, on the user's word after the build, the file's
  opening comment and the comment of `listPublicRooms`.
- `src/chat/chat.service.js`: the imports of `decodeImage`,
  `pictureProblem`, `findRoomPicture` and `upsertRoomPicture`; the
  constants `PICTURE_MAX_SIDE` and `PICTURE_MAX_BYTES`; `setRoomPicture`
  and `getRoomPicture`, new, after `listPublicRooms`; the file's opening
  comment.
- `src/chat/chat.handlers.js`: `setChatRoomPicture` and
  `getChatRoomPicture`, new, after `listPublicChatRooms`, and the two
  imports.
- `src/chat/chat.router.js`: the two routes' lines after
  `/list-public-chat-rooms`, the two imports, and "sixteen" in the
  comment.
- `src/app.js`, on the user's word after the build: "sixteen" in the
  comment on the chat router's line. No line of code.
- `src/util/images.js`, on the user's word after the build: the opening
  comment and the comment of `pictureProblem`, which now name a public
  room's picture beside the selfie. No line of code.
- Here: section 1 (the item on images, one sentence), section 4 (`###
  chat_room_pictures`, new, after `### chat_room_messages`), section 5
  (`### POST /list-chat-rooms` and `### POST /list-public-chat-rooms`,
  `pictureAt` in the answer and a dated sentence each; `### POST
  /set-chat-room-picture` and `### POST /get-chat-room-picture`, new,
  after `/list-public-chat-rooms`) and this section; and, on the user's
  word after the build, a dated clause in 26.2 and one in the pictures
  note of section 11. `README.md`: the Endpoints table (the two new rows,
  and `pictureAt` in the rows of the two lists) and the new row of
  `chat_room_pictures` in "Database tables"; and, on the user's word
  after the build, the `chat/` line of the Layout.

Nothing else in existing code changes: `/create-chat-room` and every
other chat route, `package.json` and `.example.env` are as they were, and
`src/util/images.js` and `src/app.js` changed in comments alone. One new
table and two new routes; no env variable, no npm package.

### 27.6 What is left as it is

- Nobody but the creator can take a room's picture down, and no route
  takes the creator's right away. Until the item of the after-production
  list is built, a bad picture is taken down by hand, on the leader of
  this server's database, with the two lines of the plan's section 8: a
  look-only line that finds the room by a word of its name, and `delete
  from chat_room_pictures where chat_room_id = decode('<the room id>',
  'hex')`. The room, its name, its members and its messages are not
  touched. The members' wallets show the globe again within about 5
  seconds, and Find public rooms at its next read. The planning chat ran
  both lines on a scratch database (the plan's section 9); they have not
  been run on the servers.
- A picture that was taken down by hand can be set again by the creator.
- The creator cannot take the picture away. A room gets no picture at
  its creation. A private chat, a group, a listing chat and a case chat
  get none.
- The picture is not drawn again on this server. The wallet redraws it,
  and this server checks its type, its size in pixels and its bytes. A
  request made by hand can still send any picture inside those limits.
  The same gap is the after-production item "selfies redrawn on the
  server".
- Look-alike names stay possible, and a room can be dressed up as
  official with a picture.
- A person on Find public rooms sees a new picture of a room only at the
  next read of the list.
- The read of every 5 seconds grows by one field per room (27.4).

### 27.7 Notes from the build

#### Build 1, the masterpod (2026-11-22)

Built from `~/Desktop/Z-TestNet/forclaude/public-rooms-plan-1.md` section
3, on main at 6ba4826 (step 1 of the same plan), the working tree clean.
No new npm package, no test script and no rig (none was asked for). The
schema was not applied to any database of the network: the user applies
the whole file as section 6 of `forclaude/masterpod-deploy-plan-1.md`
says, on the leader, before the first restart (the plan's section 6). On
a database without the table this code fails every `/list-chat-rooms`,
the read every wallet makes every 5 seconds, and every
`/list-public-chat-rooms`: the chat would be down for everybody until the
table is there. The other order is safe: the code of before does not
know the table. Both were tried (below). What the plan left open and how
it was decided:

- The number and the date. This section is 27, the next free number on
  the build day. BUILD-DATE is 2026-11-22, the day of the build and of
  the plan's FINAL.
- The code. The schema block, `upsertRoomPicture`, `findRoomPicture`,
  the two constants, `setRoomPicture`, `getRoomPicture`, the two handlers
  and the two router lines are the plan's, letter for letter, with
  2026-11-22 and 27 where the plan's comments say BUILD-DATE and M.
- Where the plan gives a change in words. The import of `encodeImage`
  stands after the import of `toHex`, where the file's order by path puts
  it. The heading "Room pictures" has the form of the file's other
  headings and stands between `roomAboutListingBy`, the last function of
  "Rooms", and the heading "Members and their wrapped keys". In
  `listRoomsFor` the new column follows `r.case_kind` on that column's
  line, and the join stands after the join of the listing's owner, in
  front of the lateral join of the newest message. In
  `listPublicRooms` the new column is the last of the first line of the
  select list, and the join stands after the join of the creator. In
  both, `pictureAt` follows `name` in the room's object. These are the
  places the planning chat's tried copy has (the plan's section 9).
- The comments given in words. The comment of `listRoomsFor` lists
  `pictureAt` after `name` in the room's object and ends: "`pictureAt` is
  when the room's picture was last set, null for a room without one
  (2026-11-22)." The opening comment of `chat.service.js` gained "the
  picture of a public room (since 2026-11-22)" in its list of what the
  chat feature holds. The router's comment says "All sixteen routes".
- The order of the checks in `setRoomPicture`, as the plan's code has it.
  The creator is checked before the room's type. The 100,000 bytes are
  checked before the picture's header is read. A base64 string longer
  than `MAX_IMAGE_BYTES` allows is refused by `decodeImage` before it is
  decoded, as for a selfie.
- `pictureAt` on its way out. `updated_at` keeps millionths of a second.
  The `pg` library hands it to the code as a JavaScript date, which keeps
  thousandths, and `toISOString()` writes it. The answer of
  `/set-chat-room-picture`, the read and both lists go the same way, so
  they give the same string for one row.
- `getRoomPicture` reads the room first and the picture second, in two
  statements with no transaction around them: a picture set between the
  two is simply the one read.
- Here and in the README. In section 1 the sentence is the last of the
  item on images. In section 4 `### chat_room_pictures` stands between
  `### chat_room_messages` and `### listings`, with the `CREATE TABLE`
  and two sentences; the trigger is in 27.2. In section 5 `"pictureAt"`
  stands after `"name"` in the JSON block of `/list-chat-rooms`, and its
  dated sentence is the last of the entry's text, with one sentence more
  on where the picture itself is read; in the entry of
  `/list-public-chat-rooms` `pictureAt` stands after `name` in the
  answer, and the dated sentence is its last. The two new routes have the
  short form of their neighbours; the numbered checks are in 27.3. In the
  README the two new rows follow the row of `/list-public-chat-rooms`,
  and the row of `chat_room_pictures` follows the row of
  `chat_room_messages`. The plan asks for "the count of tables wherever
  the file names it": the README names no such count, so none changed.
- Checks (3.6), the first two. `node --check` on the four changed source
  files of `src/chat/`, clean, on Node 24.22.0. Then one load of the app
  with no server, from the build chat's scratch folder: a small script
  imports `src/app.js` and calls `createApp()`, with made-up
  `PGDATABASE`, `PGUSER` and `PGPASSWORD` and `PGHOST=/nonexistent`. It
  counted 110 routes, two more than a copy of 6ba4826 gave the same way
  (108), sixteen of them the chat's, with the two new ones between
  `/list-public-chat-rooms` and `/list-messages`, and ended with exit 0.
  Nothing listened and no database was reached.
- Checks (3.6), the schema file. By psql on a PostgreSQL 17.11 that was
  started for this build alone: a data folder of its own in the build
  chat's scratch folder, listening on 127.0.0.1 port 58931 and nowhere
  else, with no socket file. This Mac's own PostgreSQL on port 5432 was
  not touched. One transaction, rolled back. The file of 6ba4826 went
  into an empty scratch schema first (`git show HEAD:db/schema.sql`,
  byte for byte the file of the security alerts' commit 93e8f43): 41
  tables, no `chat_room_pictures`. Into them went two pods, two public
  rooms and one private room, four member rows with their wrapped keys,
  and one message. Then the new file on top: 42 tables. The new file
  once more: 42 tables, and one md5 over every column, constraint, index,
  trigger, comment and function of the schema was the same after both
  runs. Every row was still there. The new table had its five columns,
  its primary key and its three checks
  (`chat_room_pictures_chat_room_id_check`,
  `chat_room_pictures_content_type_check`,
  `chat_room_pictures_image_check`), its trigger, and a comment on the
  table and on each column. For a database built from nothing the new
  file went alone into a second empty scratch schema, twice: 42 tables
  and the same md5 as the updated schema, both times.
- Checks (3.6), the statements. The four statements were read out of
  `src/chat/chat.queries.js` by a small script, with
  `${ROOM_LISTING_COLUMNS}` and `${PROFILE_COLUMNS}` filled in from the
  source, so what ran is what the code sends. They were prepared with
  untyped parameters (`PREPARE`), as `pg` sends them; the server took
  the three of `upsertRoomPicture`'s statement as `bytea`, `text` and
  `bytea`. One thing the plan's 3.6 asks for cannot show inside one
  transaction as it stands: "`updated_at` later the second time".
  `now()` is the moment the transaction began and does not move inside
  it. So time was made to pass by hand: between the runs the row's times
  were set back, with the triggers off for that one statement (`SET
  LOCAL session_replication_role = replica`). The statement's first run
  made one row, with both times at that moment. With both times set back
  one hour, the second run, with other bytes and another type, left one
  row with the new bytes, `created_at` where it was and `updated_at` an
  hour later, which it also answered. With `updated_at` set back half an
  hour, the third run, with the same bytes again, answered that earlier
  time and left the row as it was: the trigger did not fire. The table
  itself refused a picture of 100,001 bytes
  (`chat_room_pictures_image_check`), wrote no row for it and took one
  of 100,000 bytes; it also refused a picture of no bytes, a fourth type
  and a room id of 31 bytes. Those five ran through the same statement,
  from a function that catches the refusal and names the check. The
  bytes of this check were made-up bytes: the table does not look into a
  picture, the route does. The statement of `findRoomPicture` gave the
  type, the bytes and `updated_at` for the room with a picture, and no
  row for the room without. The statement of `listRoomsFor` gave the
  creator's three rooms, newest first, `picture_at` on the public room
  with the picture and null on the other public room and on the private
  one, and gave a member who is not the creator the one room with the
  same `picture_at`. The statement of `listPublicRooms` gave the two
  public rooms, the bigger first, `picture_at` on the one and null on the
  other, the private room not among them; the word "plain" gave the one
  room. 43 results, none bad. After the rollback that database held no
  scratch schema and no table.
- Beyond 3.6, with nothing kept in the repo. First a comparison. The
  planning chat had tried this step in a throwaway copy, with the code
  read out of the plan file by a script (the plan's section 9). The
  build made that copy again with the same script, on a copy of 6ba4826,
  and compared the five files with the working tree by `diff`:
  `chat.handlers.js` and `chat.router.js` are the same byte for byte, and
  `db/schema.sql`, `chat.queries.js` and `chat.service.js` differ in
  comment lines only (eight lines with the date and the number where the
  copy has the words BUILD-DATE and M, and the two comments the plan
  gives in words). No other file of `src` or `db` differs from that
  copy.
- Second, the planning chat's check of this step ran again, against a
  copy that holds the built files, with the copy's own pool on a
  throwaway database of the same scratch PostgreSQL, built from the new
  `db/schema.sql`: the real `createRoom`, `setRoomPicture`,
  `getRoomPicture`, `listRooms` and `listPublicRooms`. 35 results, none
  bad, the same 35 as in the plan's section 9. Each call there is a
  transaction of its own, so `pictureAt` moved by itself when another
  picture was set, and stayed for the same picture.
- Third, the two half-deployed states, the same way. The built code on a
  database with the tables of before: `/list-chat-rooms` and
  `/list-public-chat-rooms` both failed with `relation
  "chat_room_pictures" does not exist`. The code of 6ba4826 on the new
  tables: both lists answered, with no `pictureAt`. So the schema line
  goes first.
- Fourth, the two new handlers and the two list handlers of that copy,
  called with a stand-in for the HTTP answer, with real pictures in
  place of made-up bytes behind a true header: a JPEG of 320 by 320 at
  quality 80 (18,575 bytes), a PNG and a WebP, drawn by the `sharp`
  library of `scripts/small-selfies`. 20 results, none bad. `200 {
  chatRoomId, pictureAt }`, then the read with the same bytes and the
  same `pictureAt`, which stood in both lists right after `name`; a PNG
  and then a WebP in its place; `403 { error }` for a member and for a
  stranger; a real JPEG of 321 by 320, a JPEG sent as a PNG and a real
  PNG of 282,077 bytes each refused with its own words; two different
  pictures for one room at the same moment, in ten rooms, every call
  `200` and one row a room. The heaviest JPEG that library makes at 320
  by 320 and quality 80, with every pixel random, weighed 65,356 bytes,
  inside the 100,000. A browser's own JPEG writer was not measured.
- The runs that use the pool stop before their first query unless the
  pool's host and port are the scratch PostgreSQL's: this server's
  default port is 5432, which on this Mac is the user's own database.
  The scratch PostgreSQL was stopped afterwards.
- Not tried by the build. No server was booted, no request was signed
  and no route was called over HTTP: the session check, the envelope and
  the wallet are the user's run-through (the plan's section 6), with the
  wallet's step 4. A photo from a phone was not sent. How long the two
  lists take with thousands of rooms was not measured; each gained one
  join by a primary key.
- Places the plan does not name that this step left out of date. The
  build left them as they are and put them to the user, who had all
  seven brought in line the same day (below). Four comments, no line of
  code: in `src/app.js` the comment on the chat router's line
  says "the fourteen chat routes"; the opening comment of
  `src/chat/chat.queries.js` names the chat tables without
  `chat_room_pictures`; the comment of `listPublicRooms` in that file
  gives a room's object without `pictureAt` (the plan names the comment
  of `listRoomsFor` alone); in `src/util/images.js` the opening comment
  and the comment of `pictureProblem` name the selfie as the picture
  stored in the clear. In `README.md` the `chat/` line of the Layout
  says "the fourteen chat routes". Here, 26.2 shows the statement and
  the answer of `/list-public-chat-rooms` as step 1 left them, and the
  pictures note of 2026-11-12 in section 11 calls the selfie "the one
  picture stored in the clear and shown to everyone". `docs/build-plan.md`
  is a record of 2026-10-24 and is not on this list.
- Not touched by the build: in the four changed source files everything
  the plan does not name; `src/app.js`, `src/util/images.js`, every other
  feature folder, `package.json`, `.example.env`, the scripts; in the
  README everything but the five rows named above. (Comments of
  `src/app.js`, `src/util/images.js` and `src/chat/chat.queries.js` and
  one more line of the README changed afterwards, on the user's word,
  below.)
- The numbers. `db/schema.sql` has 1600 lines, 27 more than before, and
  its sha256 begins d016140c. Before the step it had 1573 lines and its
  sha256 began eb1289b4. It makes 42 tables where it made 41: the count
  that the deploy's schema line prints goes from 41 to 42. That line
  carries the whole hash and stops by itself on any other file. It was
  tried here in a stand-in form on the scratch PostgreSQL, with a copy
  of a local file in place of the download: with the new file it printed
  41, the apply's lines, 42, the owner and 1 for the new table; with the
  file of before it printed `FAILED` and applied nothing.

#### After the build's report, the same day (2026-11-22)

The user read the report in the build chat. It listed the seven places
above, with the advice to bring all of them in line before the commit and
to give the two in older notes a dated clause beside the old words. The
user: "Fix the out of place stuff first". So the seven were brought in
line before the commit. None of this is in the plan, and no line of code
changed.

- `src/app.js`, the comment on the chat router's line: "owns the sixteen
  chat routes".
- `src/chat/chat.queries.js`, the file's opening comment. The list of
  the chat tables now has "chat_room_pictures (since 2026-11-22)" after
  `chat_rooms`.
- `src/chat/chat.queries.js`, the comment of `listPublicRooms`. A room's
  object lists `pictureAt` after `name`, and the comment ends:
  "`pictureAt` is when the room's picture was last set, null for a room
  without one (2026-11-22, spec section 27)."
- `src/util/images.js`. The opening comment says "Public selfies and,
  since 2026-11-22, the pictures of public chat rooms are plaintext".
  The comment of `pictureProblem` names "the selfie and, since
  2026-11-22, a public room's picture" as the pictures stored in the
  clear.
- `README.md`, the `chat/` line of the Layout: "the sixteen chat
  routes".
- Here, 26.2. The words of before stay. A clause in brackets after them,
  which begins "Since 2026-11-22, section 27", says that the statement
  also reads `picture_at` through a left join of `chat_room_pictures`,
  that each room of the answer carries `pictureAt`, and that the block
  there is the statement as that section's build left it.
- Here, the pictures note of 2026-11-12 in section 11. The words of
  before stay. A clause in brackets after them, which begins "Since
  2026-11-22, section 27", says that a public room's picture is a second
  picture stored in the clear, checked the same way with 320 pixels.
- Checks. All of them ran again, with the same results. `node --check`
  on the six changed source files, clean. A `diff` against the copy that
  the checks had run on shows 31 lines in `src`, old and new together,
  every one a comment line, and none in `db/schema.sql`. The load with
  no server: 110 routes. The psql check in one rolled-back transaction:
  the four statements read out of the source were byte for byte the ones
  of before, and it gave the same 43 results, none bad. The real functions
  on a copy of the files as they now stand: 35 results, none bad; the
  two half-deployed states as before. The handlers with real pictures,
  drawn anew: 20 results, none bad. The scratch PostgreSQL was stopped
  again afterwards.
- The numbers. `db/schema.sql` was not touched: the same 1600 lines and
  the same sha256, so the deploy's schema line stands as handed. One
  commit carries the build and this: nine files, the seven of the build
  and `src/app.js` and `src/util/images.js`.

## 28. Stickers (2026-11-23)

Design settled 2026-11-23 in a talking chat (the plan is
`~/Desktop/Z-TestNet/forclaude/stickers-database-plan-1.md`, FINAL,
2026-11-23, on the user's word "Yes, final"). Why: the user, 2026-11-23:
"I want to add the ability for my users to add stickers to their chats,
much like how LINE does it." An earlier try of the same day kept the
stickers as files on the wallet's servers, and the user set it aside: "It
started by building something that would work great for 10 stickers, but
not for a real website." So the stickers are in this server's database,
the pictures too (the user: "1. Yes"). Three steps in order: this server
(this section, step 1 of the plan: three new tables, two new reads, and
the script that puts the stickers in), the wallet (its spec, step 2: the
address `/stickers/<set>/<number>` in the wallet's server program, the
read of the list, and what a person sees), and the stickers themselves
(step 3: the folder of the first 200 is copied onto a masterpod server
and put in with the script, with no commit and no deploy). With this
server alone deployed nothing changes for anyone: no wallet calls the two
reads yet, and the tables are empty. One schema block with three new
tables, two new routes and one new script. No env variable and no npm
package. The validators, the doormen, the keyholders, the signing servers
and the wallet's proxy are not touched. Nothing above this section
changes except the items in 28.6.

### 28.1 The rule

- The stickers are the team's, free and the same for everybody (the
  plan's section 1, point 8). They are stored here in the clear, the
  pictures too (decision 4).
- A sticker belongs to a set. A set has a name: small letters, digits and
  hyphens, at most 32 characters. A sticker has a number in its set: two
  digits, `01` to `99`. The name and the number travel inside every
  message that carries the sticker, so neither is ever changed.
- A sticker's picture is a WebP, still or moving, of at most 150,000
  bytes, at most 370 pixels wide and 320 high (the plan's section 4,
  point 2).
- A picture never changes under its number. A redrawn sticker gets a new
  number (section 4, point 1). This is what lets a phone keep a picture
  for a year (step 2).
- The sets stand in a row, and the stickers of a set stand in an order.
  The database sorts both (the plan's 3.5).
- A sticker has tags: the words that bring it up while a person types.
  They are matched on the phone, from the list (decision 5; the user: "2.
  Yes"). This server never searches the tags, so nothing a person types
  in a chat reaches it.
- The stickers come in by a script that the operator runs on a masterpod
  server (decision 6; the user: "3. Yes"). No route writes a sticker.
- The script adds, and brings in line. It deletes nothing and moves no
  set that is in the row (section 4, point 4). Taking a set or a sticker
  out and moving a set are plain database lines, in 28.5.
- A sticker that somebody sends is an ordinary encrypted message whose
  whole text is `[sticker:<set>/<number>]` (the plan's 3.5). This server
  cannot tell it from any other message, and no chat route changes.

### 28.2 The three tables

`db/schema.sql`, one new block, the last thing in the file, after the
room picture block: "The stickers block (2026-11-23, spec section 28)".

```sql
CREATE TABLE IF NOT EXISTS sticker_sets (
  set_name   TEXT        PRIMARY KEY CHECK (set_name ~ '^[a-z0-9-]{1,32}$'),
  place      INTEGER     NOT NULL CHECK (place >= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER sticker_sets_set_updated_at
  BEFORE UPDATE ON sticker_sets
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS stickers (
  set_name   TEXT        NOT NULL CHECK (set_name ~ '^[a-z0-9-]{1,32}$'),
  number     TEXT        NOT NULL CHECK (number ~ '^[0-9]{2}$' AND number <> '00'),
  place      INTEGER     NOT NULL CHECK (place >= 1),
  image      BYTEA       NOT NULL CHECK (octet_length(image) BETWEEN 1 AND 150000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (set_name, number)
);

CREATE OR REPLACE TRIGGER stickers_set_updated_at
  BEFORE UPDATE ON stickers
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS sticker_tags (
  set_name   TEXT        NOT NULL CHECK (set_name ~ '^[a-z0-9-]{1,32}$'),
  number     TEXT        NOT NULL CHECK (number ~ '^[0-9]{2}$' AND number <> '00'),
  tag        TEXT        NOT NULL CHECK (char_length(tag) BETWEEN 1 AND 100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (set_name, number, tag)
);
```

`sticker_sets`, one row per set:

- `set_name`: the set's name. It is the primary key.
- `place`: the set's place in the row. The sets are handed out by this
  number, the smallest first, and by name where two hold the same number.
  The script gives a new set the highest number plus one.
- `created_at`: when the set was added. `updated_at`: when it was last
  moved in the row.

`stickers`, one row per sticker:

- `set_name` and `number`: the set and the sticker's number in it,
  together the primary key. The number is kept as the two characters that
  travel, `07` and not 7.
- `place`: the sticker's place in its set. The stickers of a set are
  handed out by this number, the smallest first. The script sets it to
  the sticker's line in the set's file, at every run.
- `image`: the picture's bytes, 1 to 150,000 of them. The script checks
  that they are a WebP and how many pixels it has; the table checks the
  weight alone. Never changed.
- `created_at`: when the sticker was added. `updated_at`: when it last
  got another place in its set.

`sticker_tags`, one row per sticker and tag:

- `set_name` and `number`: the sticker.
- `tag`: one tag, a word or several, in small letters, 1 to 100
  characters. The three columns together are the primary key, so a
  sticker holds a tag once. Rows are added and deleted, never changed, so
  the table has `created_at` alone.

A `place` is not unique, in either table. A row of numbers that must
never hold the same number twice cannot be put in a new order one row at
a time, and the lines of 28.5 and the script do exactly that. The order
is still always the same: where two rows hold the same number, the name
or the sticker's number decides. No column says what kind of picture a
sticker is: every one is a WebP. No foreign key, as everywhere (section
1): the script writes a set, its stickers and their tags in one
transaction. No index but the three primary keys: `/sticker-picture`
reads one row by its key, and `/list-stickers` reads all of them. Each
table and each column has a `COMMENT ON`. The block is idempotent (`IF
NOT EXISTS` and `OR REPLACE`), so the whole file applies to a live
database and a second run changes nothing. The file makes 45 tables,
three more than before.

### 28.3 The two routes

**POST /list-stickers** (setup), new.

Body: `{}`. The envelope of section 3, signed like every chat route. The
route has no check of its own and writes nothing.

Answer: `200`, every set in the order of the row, each with its stickers
in their order:

```json
{
  "sets": [
    {
      "name": "bear",
      "stickers": [
        { "number": "02", "tags": ["hello", "hi", "สวัสดี"] },
        { "number": "01", "tags": [] }
      ]
    }
  ]
}
```

One statement reads it, so the answer is the database at one moment, also
while the script writes. It reads no picture. The sets are sorted by
`place` and then by name, the stickers of a set by `place` and then by
number, and the tags of a sticker by their bytes (`COLLATE "C"`), which is
the same order on every machine. A set with no sticker is left out. With
no set at all the answer is `{ "sets": [] }`. The first sticker of a set
is also the set's small picture in the wallet's row of sets.

The wallet asks once after each login, when a conversation is first
opened, and keeps the answer in the page's memory (the plan's 3.3). There
is no timer. With 200 made-up stickers of nine tags each the answer was
23,042 bytes and took 2 milliseconds to read; with 2,000 it was 228,290
bytes and 17 milliseconds (28.8).

**GET /sticker-picture/:set/:number** (none), new.

This server's first `GET` that hands out data. It needs no login: a
sticker is the same for everybody, and a picture on a page is fetched by
its address alone, with nothing signed. `:set` is a set's name and
`:number` a sticker's number, as `/list-stickers` gives them:
`/sticker-picture/bear/07`.

Checks, in order:

1. `:set` has the form of a set's name and `:number` the form of a
   sticker's number, else `404 no sticker`. The database is not asked.
2. There is such a sticker, else `404 no sticker`.

Answer: `200` with the picture's bytes as they are stored, `Content-Type:
image/webp` and the `Content-Length`. This is the one answer of this
server that is not JSON; a refusal is JSON like every other, `{ "error":
"no sticker" }`. An address with a part more or a part less, and a `POST`
to it, get the plain `404 Not Found` of every unknown route.

The answer carries no keep time (`Cache-Control`). The wallet's server
program adds the year when it hands the picture to a phone, and marks an
answer that is not a picture "do not keep" (the plan's 3.4, step 2).
Express adds its own mark of the bytes (`ETag`) and answers `304` with no
body to a caller that sends the mark back (`If-None-Match`).

The doormen count 50 requests in 10 seconds from one address, except from
the wallet's servers. A phone fetches a picture through the wallet's
servers, so that count does not reach it (read in the planning chat; the
doormen do not change).

### 28.4 The script

On a masterpod server, as the masterpod user in the checkout:

```bash
npm run stickers -- look <folder>
npm run stickers -- write <folder>
```

`look` reads the folder and the database, says what it would write and
names every fault. It writes nothing. `write` does the same and then
writes, all of it or nothing. The script reads `.env` like the server and
writes through the server's own pool, so it runs on any of the three
masterpod servers. There is no route for it.

The folder has the form of the page that was written on 2026-11-23 for
the person who makes the stickers
(`~/Desktop/Z-TestNet/forclaude/sticker-set-template/`):

```
all-sets.ts     the list of the sets, in the order of the row
bear.ts         the set "bear": its stickers and their tags
bear/           the pictures of the set: 01.webp, 02.webp, ...
cat.ts
cat/
```

The `.ts` files are read as text and never run: a file that comes from
outside is not run as code on a masterpod server. The reader knows the
form of the two files and nothing more of the language. It passes over
comments, and it does not mind how the lines are broken. In
`all-sets.ts` it reads the lines `import { SET as <NICKNAME> } from
'./<set>';` and the one list `export const ALL_SETS = [ <NICKNAME>, ...
];`. A set stands in both places, once, and the order of the list is the
order of the sets. In a set's file it reads `export const SET = { id:
'<set>', stickers: [ { id: '<number>', tags: [ '<tag>', ... ] }, ... ]
};`. The order of the lines is the order of the stickers. Another key in
an object is passed over. In a folder of pictures a name that begins with
a dot is passed over, and so is everything else in the folder that
`all-sets.ts` does not name.

What a write does:

- A set that is not in the database is added behind the last set of the
  row. Several new sets go in the order of `all-sets.ts`. A set that is
  in the row keeps its place, whatever `all-sets.ts` says.
- A sticker that is not in the database is added, with its picture and
  its tags.
- For a sticker that is in the database, its place in the set and its
  tags are brought in line with the set's file: a tag that is new in the
  file is added, and one that is gone from the file is deleted. This is
  how tags and the order are changed later: edit the file, run the script
  again.
- A tag is stored without the spaces around it and in small letters. An
  empty tag and a second same tag of one sticker are left out.
- A set that is in the database and not in the folder is left as it is.
  So a folder may hold the new sets alone.

A fault stops the run before anything is written. Every fault of the
folder and of the comparison is named in one run, each on a line of its
own:

| The fault | Its line |
| --------- | -------- |
| a file that is not WebP | `bear/01.webp: not a WebP picture` |
| a file above 150,000 bytes | `bear/02.webp: 359,332 bytes, the limit is 150,000` |
| a file above 370 by 320 pixels | `bear/03.webp: 371 by 320 pixels, the limit is 370 by 320` |
| a line with no picture | `bear.ts line 9: sticker 05 has no picture bear/05.webp` |
| a picture with no line | `bear/09.webp: the picture has no line in bear.ts` |
| a number used twice | `bear.ts line 11: the number 06 stands twice` |
| a set's name that is not small letters, digits and hyphens, or longer than 32 | `all-sets.ts: Big_Cat is not a set's name: small letters, digits and hyphens, at most 32 characters` |
| a picture that differs from the stored one under the same number | `cat/01.webp: differs from the picture stored under this number` |
| a sticker that is in the database and missing from the file | `cat.ts: sticker 03 is in the database and has no line in the file` |
| a number that is not two digits, or `00` | `bear.ts line 12: 7 is not a sticker's number: two digits, 01 to 99` |
| a file in a folder of pictures that is not named like `01.webp` | `bear/notes.txt: not a picture named by its number, like 01.webp` |
| the name inside a set's file is not the file's name | `fox.ts: the name inside is wolf, and the file's own name says fox` |
| a tag above 100 characters | `bear.ts line 14: a tag of more than 100 characters` |
| a file or a folder that is not there | `bear.ts is not there`, `cat: the folder of pictures is not there` |
| a file that cannot be read as its form | `dog.ts line 4: a quote mark that is not closed` |

The first nine are the plan's (3.2). The others are what the script needs
to read the folder at all, and the table's own limit for a tag. A file
that cannot be read as its form gets one line, for the first place the
reader does not understand.

The report of a run without a fault, here the first run of the trial:

```
stickers: look (nothing is written)
folder: /tmp/stickers
sets in all-sets.ts: 2
  bear: a new set, place 1 in the row, 5 new stickers (9,542 bytes), 12 tags added
  cat: a new set, place 2 in the row, 3 new stickers (3,460 bytes)
to write: 2 new sets, 8 new stickers (13,002 bytes), 12 tags added
Nothing was written.
```

A set that is in the database has a line like `bear: in the database with
5 stickers: 1 new sticker (6,950 bytes), 4 tags added, 3 tags taken off, 5
stickers moved in the set`, or `nothing to change`. A `write` run prints
the same report and then `committed`, or `Nothing to write.` when the
database already holds what the folder says. With faults both runs print
`faults: <n>`, the lines, and `Nothing was written.`

The write is one transaction on one client: the comparison, the writes,
and the comparison once more, which must find nothing left to write and
no fault, then `COMMIT`. An error on the way ends in `ROLLBACK` and the
lines of the error and `Nothing was written.` A picture is compared by
its SHA-256, which the database works out, so no stored picture travels
to the script.

Exit codes: 0 for a run without a fault; 1 for faults and for an error; 2
with the usage line for anything but `look` or `write` with one folder.
The report goes to standard output; the faults, an error and the usage
line go to standard error. A folder is best given by its full path: npm
starts the script in the checkout, so another path is read from there.
The report's second line shows which folder was read.

### 28.5 Taking out and moving: plain database lines

The script deletes nothing and moves no set. These are plain `psql` lines
on the database server that takes the writes (the leader), as the lines
of 24.3 are. Each write line is one transaction (`-1`). The names in them
(`bear`, `cat`, `dog`, `02`) are examples.

The look, which writes nothing and can run on any of the three: the row
of sets, each with its number of stickers, their weight and its number of
tags.

```text
sudo -u postgres psql -X -P pager=off "dbname=masterpod options='-c default_transaction_read_only=on'" -c "select s.place, s.set_name, count(t.number) as stickers, coalesce(sum(octet_length(t.image)), 0) as bytes, (select count(*) from sticker_tags g where g.set_name = s.set_name) as tags from sticker_sets s left join stickers t using (set_name) group by s.place, s.set_name order by s.place, s.set_name"
```

One sticker out, here `02` of the set `bear`:

```text
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -1 -P pager=off -d masterpod -c "delete from sticker_tags where set_name = 'bear' and number = '02'" -c "delete from stickers where set_name = 'bear' and number = '02'"
```

It prints `DELETE` with the number of the sticker's tags and `DELETE 1`.
A second run prints `DELETE 0` twice.

A set out, here `cat`:

```text
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -1 -P pager=off -d masterpod -c "delete from sticker_tags where set_name = 'cat'" -c "delete from stickers where set_name = 'cat'" -c "delete from sticker_sets where set_name = 'cat'"
```

It prints `DELETE` with the number of the set's tags, `DELETE` with the
number of its stickers and `DELETE 1`.

The row in a new order: the names of all the sets, in the order wanted,
the first one first.

```text
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -1 -P pager=off -d masterpod -c "update sticker_sets s set place = o.place from unnest(array['dog', 'bear', 'cat']) with ordinality as o(set_name, place) where s.set_name = o.set_name" -c "select place, set_name from sticker_sets order by place, set_name"
```

It prints `UPDATE` with the number of sets named and then the row. The
first name gets the place 1, the second 2, and so on. A name that is no
set changes nothing. A set that is left out keeps the number it had, so
name every set.

What follows from these lines:

- The folder has to follow. A sticker that is taken out here and still
  stands in the set's file, with its picture, is put back by the next
  `write`. A set that is taken out and still stands in `all-sets.ts` is
  added again, behind the last set.
- A wallet has the list of its login. It offers a sticker or a set that
  was taken out until its next login.
- A message that carries a sticker that was taken out shows the word
  "Sticker" where the picture can no longer be fetched (the plan's
  section 1, point 7), and a phone that has the picture already keeps
  showing it (step 2).
- A number that was taken out is not given to another picture, for the
  same reason: phones keep the old one.

### 28.6 Files

- `db/schema.sql`: the stickers block, new, at the end.
- `src/stickers/`, new: `stickers.router.js` (the two paths and their
  levels), `stickers.handlers.js`, `stickers.service.js` (`listSets`,
  `getPicture`), `stickers.queries.js` (the SQL of the three tables: the
  two reads of the routes, and the reads and writes of the script) and
  `sticker-rules.js` (the form of a name and of a number, and the limits
  of a picture and of a tag, in one place for the routes and the script).
- `src/app.js`: the import of the stickers router and its line, after
  the chat router's.
- `scripts/stickers.js`, new: the script.
- `package.json`: the line `stickers` in `scripts`, after
  `small-selfies`.
- Here: section 1 (the item on images, one sentence), section 2 (the rows
  of `none` and `setup`), section 4 (`### sticker_sets, stickers,
  sticker_tags`, new, the last entry), section 5 (the sentence on `GET`
  in its opening; `### POST /list-stickers` and `### GET
  /sticker-picture/:set/:number`, new, after `/get-chat-public-keys`) and
  this section. `README.md`: one row under "Scripts"; under "Who may call
  what" the sentence on `GET` and the rows of `none` and `setup`; two
  rows in the Endpoints table; three rows in "Database tables"; one line
  each for `stickers/` and `stickers.js` in the Layout.

Nothing else in existing code changes: every other route, `.example.env`
and this server's `dependencies` are as they were. Three new tables, two
new routes, one new script; no env variable, no npm package.

### 28.7 What is left as it is

- No route writes, deletes or moves a sticker. An upload page for the
  team is a later step if it is wanted (the plan's section 6).
- No shop, no sets that people make themselves, no search bar over the
  stickers (the plan's section 6).
- The list is read whole at each login. A phone that keeps the list
  between logins and asks only for what is new is worth it at some
  thousands of stickers; a file store for the pictures in place of the
  database at tens of thousands (the plan's section 6).
- This server looks into no picture on its way out, and into none on its
  way in: the script checks a picture, and the table checks its weight.
  Somebody who writes into the database by hand can store anything of up
  to 150,000 bytes.
- The picture read has no limit of its own. The doormen's count holds for
  every caller but the wallet's servers.
- A sticker message is ciphertext like every message. This server cannot
  count which stickers are sent.
- The script reads the form of the page of 2026-11-23. If the first 200
  come in another form, the script is changed to read that form (the
  plan's 3.2).

### 28.8 Notes from the build

#### Build 1, the masterpod (2026-11-23)

Built from `~/Desktop/Z-TestNet/forclaude/stickers-database-plan-1.md`,
its sections 3, 4 and 7 and step 1 of section 5, on main at a11fffe, the
working tree clean. The plan holds no code, so all of the code is the
build's. No new npm package, and no test script in the repo. The schema
was not applied to any database of the network: the user applies the
whole file as section 6 of `forclaude/masterpod-deploy-plan-1.md` says,
on the leader, and then pulls and restarts the three servers. What the
plan left open and how it was decided:

- The number and the date. This section is 28, as the planning chat had
  read it. BUILD-DATE is 2026-11-23, the day of the build and of the
  plan's FINAL.
- The columns. The plan's table gives what each table holds, not its
  columns. The set's name is `set_name` in all three tables. A sticker's
  number is two characters of text, as it travels in a message, in an
  address and in a file's name, so it is never turned into a number and
  back. A place is a whole number from 1. A sticker has no column for the
  kind of picture, and a set none for "shown": the plan has neither.
- A place is not unique (28.2). The smallest way that lets the lines of
  28.5 and the script give a new order one row at a time.
- A set's name is at most 32 characters. The plan says small letters,
  digits and hyphens; the 32 is the page's of 2026-11-23.
- The tags. The plan names no fault for a tag. The page asks for small
  letters, so the script stores a tag in small letters and without the
  spaces around it, and leaves out an empty one and a repeat. The table
  takes a tag of 1 to 100 characters, and the script names a longer one
  as a fault, so that a `write` never fails at the table's check after a
  clean `look`. The tags of a sticker come out in the order of their
  bytes, not in the file's order: the plan's table has no place for a
  tag, and nothing reads their order.
- The answer of `/list-stickers`. The plan gives its content; the names
  `sets`, `name`, `stickers`, `number` and `tags` are the build's, after
  the plan's own words. A set with no sticker is left out, so a wallet
  never has a set without a small picture.
- The picture read. A name or a number that cannot be one is answered
  `404 no sticker` without a read of the database: text with a zero byte
  would otherwise come back from PostgreSQL as an error, which is a
  `500`. The answer carries no keep time; that is the wallet's server
  program's to add (step 2).
- Where the code is. The stickers have a folder of their own (the plan's
  section 7). The script is one file, like `scripts/appoint.js`, with no
  folder and no package file of its own: it draws nothing, and
  `imageSize` (`src/util/images.js`) reads a WebP's width and height. Its
  SQL is in `src/stickers/stickers.queries.js` beside the routes', as the
  appointments' is.
- How the `.ts` files are read. As text, by a small reader of their form
  (28.4), and not by running them: a file from outside is not run as code
  on a masterpod server. The reader takes any layout of the lines, so a
  file that an editor has laid out anew still reads.
- `look` asks the database too. It has to: which sets are new, which
  stickers are new and whether a stored picture differs is only known
  there.
- Faults beyond the plan's nine (28.4): the ones without which the folder
  cannot be read as what it is, and the tag's length. A fault ends either
  run with exit 1.
- The second comparison inside the write's transaction is the build's, in
  the manner of the count in `scripts/small-selfies`: the script commits
  only what it has read back.
- The client of the write has an `error` listener, and a `ROLLBACK` that
  fails is passed over, as in `scripts/small-selfies` (24.5): with these
  a connection that is cut in the middle ends in the error's line and
  `Nothing was written.`
- A limit, as in 24.5. An error at the `COMMIT` itself also prints
  `Nothing was written.` If the connection is lost in that very moment,
  the script cannot know whether PostgreSQL kept the transaction. A
  `look` run says which it is: `to write: nothing` when it was kept.
- Checks, the code. `node --check` on the six new files and on
  `src/app.js`, clean, on Node 24.22.0. A type checker's read of
  `src/app.js` and `scripts/stickers.js` (`tsc --checkJs`, TypeScript
  6.0.3 from the wallet's folder) named no unknown name, no wrong count
  of arguments and no missing export or module, in the new files or the
  old.
- Checks, the schema file. By psql on a PostgreSQL 17.11 that was started
  for this build alone: a data folder of its own in the build chat's
  scratch folder, listening on 127.0.0.1 port 59631 and nowhere else,
  with no socket file. This Mac's own PostgreSQL on port 5432 was not
  touched. Each apply ran as the deploy's line runs it, in one
  transaction after `SET ROLE masterpodsoftware`, into a database that
  the role owns. The file of a11fffe into an empty database: 42 tables.
  The new file on top: 45 tables, one owner. The new file once more: 45
  tables, and one md5 over every column, constraint, index, trigger,
  comment and function was the same after both runs. The new file alone
  into a second empty database, twice: 45 tables and that same md5, both
  times. The three tables had their fourteen columns, three primary keys
  and nine checks, the two triggers, and a comment on each table and each
  column. The tables' own checks were asked directly, fifteen statements
  through a function that catches the refusal and names the check: a
  picture of 150,001 bytes and one of none were refused and one of
  150,000 taken; the numbers `00` and `1`, a place of 0, a name with a
  capital letter, one of 33 characters and one with a line end in it, an
  empty tag and a tag of 101 Thai characters were refused, and a name of
  32 characters and a tag of 100 Thai characters taken; a sticker's tag a
  second time and a sticker's number a second time were refused by the
  primary keys.
- Checks, the script. The real file, started as `node
  scripts/stickers.js` with the settings on the line, as the role
  `masterpodsoftware`, on made-up folders with real WebP pictures that
  the `sharp` of `scripts/small-selfies` drew: a lossy still, a lossless
  still, a still with a see-through part, three moving ones, and one of
  exactly 370 by 320 pixels. The first folder (two sets, eight stickers,
  the lines of one set not in the order of its numbers; tags with a
  capital letter, a repeat, spaces around, an empty one, an apostrophe,
  two words and Thai; a comment behind a line; a `.DS_Store`, a
  `__MACOSX` folder and a page beside the files): `look` printed the
  report of 28.4 and left no row; `write` printed it and `committed`; the
  rows held the two sets at the places 1 and 2, the stickers at the
  places of their lines, every picture byte for byte, and the twelve tags
  in small letters, with no repeat and no empty one; `look` again: `to
  write: nothing`; `write` again: `Nothing to write.` The second folder
  (the first set with one new sticker on its first line, another order
  and changed tags; the second set as it was; a third set, named first in
  `all-sets.ts`): `1 new set, 3 new stickers (8,242 bytes), 5 tags
  added, 3 tags taken off, 5 stickers moved in the set`, and `committed`.
  The new set stood at place 3, behind the two that were there. The five
  stickers had their new places, `updated_at` had moved on those five
  alone, `created_at` and every picture were as before, the nine tag rows
  that stayed were the rows of the first write, and the two set rows of
  before were untouched. The first folder once more then named the new
  sticker as in the database and with no line in the file.
- Checks, the faults. One folder with every fault of 28.4's table except
  the last two rows: both runs named 20 faults in one go and left every
  row as it was (one md5 over the rows before and after). Six more
  folders, for the two last rows: no `all-sets.ts`; a nickname in the
  list with no import line; an import line that is not in the list; no
  list; one set under two nicknames; and one folder with a set whose file
  is missing, a set whose folder of pictures is missing, a quote mark
  that is not closed and tags that are no list. Each was named with its
  file and, where it has one, its line. A folder that is not there is
  named as that. An `all-sets.ts` with an empty list is no fault: `to
  write: nothing`.
- Checks, a write that fails in the middle, each by a trigger of the
  trial on a scratch database of its own: the database refuses a row
  after several were written; the connection is cut by
  `pg_terminate_backend` while a sticker is written; a tag is changed on
  its way in, so that the second comparison finds a difference. Each
  ended with its line (the last with `After the write the database does
  not hold what the folder says.`), `Nothing was written.` and exit 1,
  with no row in any of the three tables. The same folder was then
  written whole. A database that cannot be reached gave its message and
  `Nothing was written.`; no word, a wrong word, no folder and a word too
  many gave the usage line and exit 2.
- Checks, `npm run stickers` itself, as the server's line starts it
  (`bash -c 'cd <checkout> && npm run --silent stickers -- look
  <folder>'`), in a copy of the working tree with a made-up settings file
  for the scratch database. The repo's own `.env` was not read. Both
  runs gave the reports above, and the exit codes 1 and 2 reached the
  shell through npm.
- Checks, the two reads, over HTTP. The app of the working tree
  (`createApp()`), listening on 127.0.0.1 with its own pool on the
  scratch database; `src/server.js` was not started, so no clock ran.
  Three pods were written for the run, one with setup, one vouched
  without setup and one not vouched, each with session keys made for the
  run, and the requests were signed with them as a wallet signs
  (P-256 and ML-DSA-87 over the canonical bytes). 31 results after the
  first write and 34 after the second, none bad. `/list-stickers`: `400
  bad request shape` with no envelope; `403 anopod not vouched`; `403
  setup not complete`; `401 path mismatch` for a request signed for
  another path; `401 bad signature` for a body changed after the
  signing; `200` with the sets, the stickers and the tags in their
  order; `401 replay` for the same request again; a `GET` to it `404`.
  `/sticker-picture`: every sticker of the list `200`, `image/webp`, its
  bytes equal to the file's, the still and the moving ones alike; a
  `HEAD` `200` with the length and no body; `404 no sticker` for a
  number and a set that are not there, a capital letter, a number of one
  and of three digits, `00`, `.webp` behind the number, a zero byte and
  a quote mark in the name, and a name of 33 characters; the plain `404
  Not Found` for an address with no number or a part too many and for a
  `POST`. A plain HTTP client that sent the answer's `ETag` back got
  `304` with no body. The pods of the run were deleted again.
- Checks, the load. The app counted 112 routes, two more than a copy of
  a11fffe gave the same way (110).
- Checks, the two half-deployed states, each with the real app over
  HTTP. The built code on a database with the tables of before: the two
  new reads answered `500`, and a signed `/list-chat-rooms` answered
  `200`. Nobody calls the two reads before the wallet's step, so this
  order would break nothing; the sheet's order stays all the same, the
  schema line first. The code of a11fffe on the new tables: `404 Not
  Found` for both new paths, everything else as before.
- Checks, times and weights, with made-up lots on that same scratch
  PostgreSQL, each picture a real WebP of about 26,000 bytes with nine
  tags. 200 stickers in 8 sets: `look` 0.3 seconds, `write` 0.4; the list
  23,042 bytes, read in 2 milliseconds; a picture read in 0.2
  milliseconds; the three tables 5.6 MB on disk. 2,000 stickers in 40
  sets: `write` 1.1 seconds; the list 228,290 bytes, read in 17
  milliseconds; the tables 53 MB. These are this Mac's figures, with no
  PgBouncer between.
- Checks, the lines of 28.5, with this Mac's psql and the scratch server
  in place of `sudo -u postgres psql ... -d masterpod`: the look; the
  look's refusal of a write (`cannot execute DELETE in a read-only
  transaction`); a sticker out (`DELETE 4`, `DELETE 1`, then `DELETE 0`
  twice); a set out; the row in a new order (`UPDATE 2` and the row), with
  a name that is no set, and with a set left out. The script then offered
  to put back what the folder still held, as 28.5 says.
- The runs that use the pool stop before their first query unless the
  pool's host and port are the scratch PostgreSQL's, and the database and
  the role of the trial do not exist on this Mac's own PostgreSQL. The
  scratch PostgreSQL was stopped afterwards, and no file of these checks
  is in the repo.
- Not tried by the build. Nothing on a server, nothing on Linux and
  nothing through PgBouncer. `src/server.js` was not booted. No wallet
  called the reads: the wallet's part is step 2. No picture from the
  person who makes the stickers was read: the 200 are still to come, and
  the form of their files is taken from the page of 2026-11-23. Two
  `write` runs at the same moment were not tried; the second would fail
  at a primary key and write nothing.
- Not touched: everything under `src` but the new folder and the two
  lines of `src/app.js`; `.example.env`, `src/config/env.js`, the other
  scripts and this server's `package-lock.json`; in `package.json`
  everything but the one line.
- The numbers. `db/schema.sql` has 1666 lines, 66 more than before, and
  its sha256 begins 9894ae57. Before the step it had 1600 lines and its
  sha256 began d016140c. It makes 45 tables where it made 42: the count
  that the deploy's schema line prints goes from 42 to 45. That line
  carries the whole hash and stops by itself on any other file. It was
  tried here in a stand-in form on the scratch PostgreSQL, with a copy of
  a local file in place of the download: with the new file it printed
  42, the apply's lines, 45, the owner and 3 for the three new tables;
  with the file of before it printed `FAILED` and applied nothing. The
  lines that put a folder of stickers onto a server (the copy with `scp`
  into `/tmp`, then `look` and `write` as the masterpod user) were tried
  the same way, with this Mac's own file server in place of the
  connection; none of them has run on a server.

## 29. The chat list: only what is new (2026-11-24)

Design settled 2026-11-23 in a talking chat and its planning (the plan is
`~/Desktop/Z-TestNet/forclaude/chat-list-plan-1.md`, FINAL, 2026-11-24, on
the user's word "Yes, final"). Why: a wallet asks `/list-chat-rooms` every
5 seconds, on every page while a person is logged in, and got the whole
list each time: every chat with the caller's wrapped key and every member.
Counted from the form of the answer, that is 21.8 KB for a person with
five chats of two people and 55 KB with nine such chats and a room of 100
people, every 5 seconds. The user, 2026-11-23: "Usually the user's phone
would check to see if there's new data it doesn't have and grab that." So
this server now numbers every change of a chat list with one counter, and
a wallet that sends the highest number it has gets only what changed after
it. Two steps in order: this server (this section, step 1 of the plan: one
schema block, one field more in the request of `/list-chat-rooms` and two
in its answer, one field more in the request of `/list-messages` and two
in its answer) and the wallet (its spec, step 2: the timer's read with
`since`, the answer put into the list in memory, and the read positions
from the open chat's read). With this server alone deployed nothing
changes for anyone: a wallet of before sends no `since` and no `seenSince`
and gets the answers of before, the first with two fields in front that it
does not read. A wallet of step 2 against a server of before gets an
answer with no `seq` and takes it as the whole list (the plan's section
7). Inside this server's own deploy the order matters: the schema file
goes onto the database before the new code runs (29.8). One schema block:
one sequence, five columns on four tables, five functions and nine
triggers. No table, no route, no env variable and no npm package. The
validators, the doormen, the keyholders, the signing servers and the
wallet's proxy are not touched: no request is added. Nothing above this
section changes except the items in 29.6.

### 29.1 The rule

- The read of every 5 seconds is sent only what is new (the plan's
  decision 1). The user: "Usually the user's phone would check to see if
  there's new data it doesn't have and grab that."
- The way is the one told on 2026-11-23 (decision 2): one counter in this
  server's database, numbers that take the counter's next value when
  something of a chat list changes, and `since` in the request. The user:
  "that seems like a solid step in the right direction".
- A page that is loaded again reads everything once (decision 3). The
  user: "on a phone refresh it will grab all a new, that's okay for now".
  So a request with no `since` gets everything, and this server keeps
  nothing about what a wallet holds. The number travels in the request.
- Keeping the list on the phone between two loads of the page is a later
  subject (decision 4), and not in this section.
- A chat is sent whole, as three fields, or not at all (the plan's 3.2).
  Whole, when its people or its facts changed: the wallet then has every
  member, every invited person, the picture's time and the listing again.
  As three fields, `chatRoomId`, `lastMessage` and `lastPosition`, when
  only a message came. Not at all otherwise.
- An invite or a join request is sent when it was written after the
  number the wallet sent.
- What was taken away is not sent: a chat the caller left, an invite that
  was answered, a request that was answered. Every answer says how many
  chats, open invites and open requests the caller has now (`counts`). A
  wallet that holds another number reads the whole list once.
- How far each member has read leaves the read of every 5 seconds (the
  plan's 3.4). Only the chat that is open draws it, and in a room of 100
  people every message makes up to 99 positions move. The open chat's own
  read, `/list-messages`, which a wallet makes every 3 seconds, hands them
  out: every member's when the chat is opened, afterwards only the
  positions that rose.
- A chat that is sent whole still carries every member's read position,
  as before (the plan's section 4, point 3). So a wallet that was not
  updated works as before.
- Triggers in the database set the numbers (the plan's 3.1). No route
  that writes a chat changes, and the writes of a server that still runs
  the code of before are numbered too.
- What this server learns: nothing new. A number says that something
  changed and after which other change it was numbered.
- One gap is known and is left as it is (decision 5). It is told in 29.7.

### 29.2 The counter, the five numbers and their triggers

`db/schema.sql`, in two places. Inline in the `CREATE TABLE` of
`chat_rooms`, `chat_room_members`, `chat_room_invites` and
`chat_room_join_requests`, each new column the last of its table, for a
database built from nothing (section 4). And in a new block, the last
thing in the file, after the stickers block: "The chat change block
(2026-11-24, spec section 29)", for a database that has the tables. The
block without its comments:

```sql
CREATE SEQUENCE IF NOT EXISTS chat_change_seq;

ALTER TABLE chat_rooms ADD COLUMN IF NOT EXISTS message_seq BIGINT NOT NULL DEFAULT 0 CHECK (message_seq >= 0);
ALTER TABLE chat_rooms ADD COLUMN IF NOT EXISTS people_seq BIGINT NOT NULL DEFAULT 0 CHECK (people_seq >= 0);
ALTER TABLE chat_room_invites ADD COLUMN IF NOT EXISTS change_seq BIGINT NOT NULL DEFAULT 0 CHECK (change_seq >= 0);
ALTER TABLE chat_room_join_requests ADD COLUMN IF NOT EXISTS change_seq BIGINT NOT NULL DEFAULT 0 CHECK (change_seq >= 0);
ALTER TABLE chat_room_members ADD COLUMN IF NOT EXISTS seen_seq BIGINT NOT NULL DEFAULT 0 CHECK (seen_seq >= 0);

UPDATE chat_room_invites SET change_seq = nextval('chat_change_seq') WHERE change_seq = 0;
UPDATE chat_room_join_requests SET change_seq = nextval('chat_change_seq') WHERE change_seq = 0;
UPDATE chat_room_members SET seen_seq = nextval('chat_change_seq') WHERE seen_position > 0 AND seen_seq = 0;

CREATE OR REPLACE FUNCTION set_change_seq()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.change_seq := nextval('chat_change_seq');
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION set_seen_seq()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.seen_seq := nextval('chat_change_seq');
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION set_room_message_seq()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE chat_rooms SET message_seq = nextval('chat_change_seq') WHERE chat_room_id = NEW.chat_room_id;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION set_room_people_seq()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    UPDATE chat_rooms SET people_seq = nextval('chat_change_seq') WHERE chat_room_id = OLD.chat_room_id;
  ELSE
    UPDATE chat_rooms SET people_seq = nextval('chat_change_seq') WHERE chat_room_id = NEW.chat_room_id;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION set_listing_rooms_people_seq()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE chat_rooms SET people_seq = nextval('chat_change_seq') WHERE listing_id = NEW.listing_id;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE TRIGGER chat_room_invites_set_change_seq
  BEFORE INSERT ON chat_room_invites
  FOR EACH ROW
  EXECUTE FUNCTION set_change_seq();

CREATE OR REPLACE TRIGGER chat_room_join_requests_set_change_seq
  BEFORE INSERT ON chat_room_join_requests
  FOR EACH ROW
  EXECUTE FUNCTION set_change_seq();

CREATE OR REPLACE TRIGGER chat_room_members_set_seen_seq
  BEFORE UPDATE ON chat_room_members
  FOR EACH ROW
  WHEN (OLD.seen_position IS DISTINCT FROM NEW.seen_position)
  EXECUTE FUNCTION set_seen_seq();

CREATE OR REPLACE TRIGGER chat_room_messages_set_room_message_seq
  AFTER INSERT ON chat_room_messages
  FOR EACH ROW
  EXECUTE FUNCTION set_room_message_seq();

CREATE OR REPLACE TRIGGER chat_room_members_set_room_people_seq
  AFTER INSERT OR DELETE ON chat_room_members
  FOR EACH ROW
  EXECUTE FUNCTION set_room_people_seq();

CREATE OR REPLACE TRIGGER chat_room_invites_set_room_people_seq
  AFTER INSERT OR DELETE ON chat_room_invites
  FOR EACH ROW
  EXECUTE FUNCTION set_room_people_seq();

CREATE OR REPLACE TRIGGER chat_room_pictures_set_room_people_seq
  AFTER INSERT ON chat_room_pictures
  FOR EACH ROW
  EXECUTE FUNCTION set_room_people_seq();

CREATE OR REPLACE TRIGGER chat_room_pictures_set_room_people_seq_on_change
  AFTER UPDATE ON chat_room_pictures
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_room_people_seq();

CREATE OR REPLACE TRIGGER listings_set_listing_rooms_people_seq
  AFTER UPDATE ON listings
  FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION set_listing_rooms_people_seq();
```

`chat_change_seq` is the one counter: a PostgreSQL sequence that begins at
1. No route reads it; triggers take its next value. A number is never
given twice, and a later write always gets a higher number than an
earlier one: the sequence has the default cache of 1, so the numbers are
handed out in the order they are asked for, whichever connection asks. A
number that a failed write took is not given again and leaves a hole.
Every number is a `BIGINT`, `NOT NULL`, default 0, never negative (the
check). 0 means "never numbered".

| Column | It takes the counter's next value when | The trigger |
| ------ | -------------------------------------- | ----------- |
| `chat_rooms.message_seq` | a message is written in the room | `chat_room_messages_set_room_message_seq`, after the insert of the message |
| `chat_rooms.people_seq` | a member joins or leaves | `chat_room_members_set_room_people_seq`, after the insert or the delete of a member row |
| | an invite to the room is made or answered | `chat_room_invites_set_room_people_seq`, after the insert or the delete of an invite |
| | the room's picture is set | `chat_room_pictures_set_room_people_seq`, after the insert of the room's first picture, and `chat_room_pictures_set_room_people_seq_on_change`, after an update that changed the row |
| | the room's listing is closed | `listings_set_listing_rooms_people_seq`, after an update that changed a listing's `status`: every room with that `listing_id`, each with a number of its own |
| `chat_room_invites.change_seq` | the invite is written | `chat_room_invites_set_change_seq`, before the insert |
| `chat_room_join_requests.change_seq` | the request is written | `chat_room_join_requests_set_change_seq`, before the insert |
| `chat_room_members.seen_seq` | the member's `seen_position` changes | `chat_room_members_set_seen_seq`, before an update that changes it |

What follows from the triggers:

- A new room has a `people_seq` from its first moment: `/create-chat-room`
  writes the room and its creator's member row in one transaction, and
  the member row numbers the room.
- An invite that is accepted numbers its room twice in one transaction,
  for the new member row and for the invite's end. The room keeps the
  higher number.
- A join request numbers itself and not its room: a room's entry in the
  list does not hold the requests. An approval numbers the room, by the
  new member row. A request that is declined numbers nothing; the
  creator's `counts` fall.
- The same picture set again changes nothing in its row, so it numbers
  nothing and `pictureAt` stays (section 27).
- A report of a seen position that does not raise it changes nothing in
  the row, so it numbers nothing.
- An open invite's entry also shows its room's listing. It is not
  numbered again when that listing is closed (the plan's section 7): the
  wallet's Requests page draws the listing's side, quantity and currency,
  and not whether it is open.
- A member who leaves and is let in again starts with `seen_seq` 0, as
  with `seen_position` 0 (21.5).
- The triggers' writes of a room's row also move that row's `updated_at`
  (`chat_rooms_set_updated_at`). Nothing reads it.
- Two messages sent in one room at the same moment now wait for each
  other: each writes the room's row, and the second waits until the first
  is committed. Across rooms nothing waits.
- No transaction locks two rooms' rows but the close of a listing, which
  numbers the rooms of that one listing. So the triggers add no way for
  two transactions to wait for each other in a circle (tried, 29.8).

On its first run on a database of before, the block numbers once what is
there: every open invite, every open join request, and every member row
with a `seen_position` above 0. A room keeps 0 in both numbers until its
next change. The three `UPDATE`s find nothing at a second run: a row
written since the first run has its number from a trigger. The comments
of the sequence and of the five columns are in the block only. No index:
`message_seq` changes with every message, and nothing looks a row up by
one of the numbers. The block is idempotent (`IF NOT EXISTS` and `OR
REPLACE`), so the whole file applies to a live database and a second run
changes nothing. The file makes 45 tables, as before.

### 29.3 The changes of `/list-chat-rooms`

**POST /list-chat-rooms** (setup; section 5), one field more in the body
and two in the answer.

Body: `{ since }`, optional. `since` is a whole number from 0 to
9007199254740991, the largest whole number JavaScript keeps exact: the
`seq` of the last answer the wallet put into its list. A body without
`since`, or with `since` `null`, asks for everything. A `since` of 0 is a
`since`.

Checks, in order:

1. The body is an object, else `400 bad request shape`. The session check
   (section 3) has refused any other body before the route is reached.
2. `since`, when it is there, is a whole number in that range, else `400
   invalid since`.

What the route then does:

1. One statement reads the numbers of everything in the caller's list:
   `message_seq` and `people_seq` of every room the caller is a member
   of, and `change_seq` of every open invite to the caller and of every
   open join request on a room the caller created. Each of its three
   parts has the joins of its list, so it counts exactly the rows that
   list hands out. It is one statement, so the numbers are the list at
   one moment.
2. `seq` is the highest of these numbers, 0 when there is none. It is
   never the counter's own value: the counter also counts the changes of
   everybody else. `counts` is how many rooms, invites and join requests
   that statement saw.
3. With no `since`: the three lists are read whole, by the three
   statements of before.
4. With `since`: a room whose `people_seq` is above `since` is read
   whole. A room whose `people_seq` is not above it and whose
   `message_seq` is, is read as three fields. An invite or a request
   whose `change_seq` is above it is read as before. Each of these is one
   statement for the ids that the first statement named, and a statement
   with no id to read is not sent. When nothing is above `since`, the
   route has asked the database once.

The first statement decides, and what is sent is read after it. If one of
the later statements sees something newer, the wallet's next read sends it
again, which harms nothing. The other order could lose a change: a `seq`
above a change that the lists did not yet hold. The read opens no
transaction of its own.

Answer: `200`, the same five keys with and without `since`:

```json
{
  "seq": 9120,
  "counts": { "rooms": 10, "invites": 0, "joinRequests": 0 },
  "rooms": [],
  "invites": [],
  "joinRequests": []
}
```

This is the answer when nothing is new, 105 bytes as it travels.

- `seq`: the number to send as the next `since`, as a number.
- `counts`: `{ rooms, invites, joinRequests }`, how many of each the
  caller has now.
- `rooms`: with no `since`, every room, each in the form of section 5.
  With `since`, the rooms that changed, in the order of the whole list
  (the newest room first). An entry is a whole room, in that same form,
  or the three fields `{ chatRoomId, lastMessage, lastPosition }`, with
  `lastMessage` and `lastPosition` as a whole room has them. A room is
  never in the answer twice. (Since 2026-11-24, later the same day,
  section 31: `lastMessage` is the room's newest message as it stands
  now, with two fields more, `editPosition` and `deleted`, and it is never
  an edit or a delete of a message; `lastPosition` is the highest position
  of any row of the room. An edit or a delete is a row written in the
  room, so it raises the room's `message_seq` as a message does, and the
  room's three fields travel for it too. The example below shows a
  `lastMessage` of before that section.)
- `invites` and `joinRequests`: with no `since`, all of them. With
  `since`, the ones written after it, each in the form of section 5,
  the oldest first.

A room with a new message, as it travels (about 540 bytes with a short
message):

```json
{
  "seq": 9121,
  "counts": { "rooms": 10, "invites": 0, "joinRequests": 0 },
  "rooms": [
    {
      "chatRoomId": "<hex 32 bytes>",
      "lastMessage": { "messageId": "<hex>", "position": 4711, "senderAnopodId": "<hex>", "message": "<base64>", "createdAt": "2026-11-24T18:25:48.652Z" },
      "lastPosition": 4711
    }
  ],
  "invites": [],
  "joinRequests": []
}
```

What a reader of the answer has to know:

- `seq` can be lower than the `since` that was sent. That happens when
  the entry that held the highest number is gone (the caller left that
  room, or answered that invite, or the request was answered), and when
  the database was put back from a backup. The plan has the wallet read
  the whole list then (its section 4, point 4).
- With `since`, `counts` can differ from what the wallet holds after it
  put the answer in: something was taken away on another phone. The
  wallet then reads the whole list once.
- With no `since`, `counts` is what the first statement saw, and the
  lists are read after it. A room that came in between is in `rooms` and
  not yet in `counts.rooms`; its number is above `seq`, so the next read
  with `since` sends it again.
- A `since` of 0 is answered as a `since`: a room that still holds 0 in
  both numbers is not sent. A wallet's first read after a page load or a
  login therefore sends no `since` (the plan's 3.3).
- Fields that the route does not know are passed over, as before.

Nothing else of the route changes. A request with no `since` gets the
answer of before, byte for byte, with `"seq":<n>,"counts":{...},` in
front: about 60 bytes more.

### 29.4 The changes of `/list-messages`

**POST /list-messages** (setup; section 5), one field more in the body
and, with it, two in the answer.

Body: `{ chatRoomId, afterPosition, beforePosition, limit, seenSince }`.
`seenSince` is optional: a whole number from 0 to 9007199254740991, the
`seenSeq` of the last answer the wallet got for this room, or 0 when the
room is opened. A body without it, or with `seenSince` `null`, gets the
answer of before.

Checks, in order: as before (`400 bad request shape`, `400 invalid
chatRoomId`, `400 invalid afterPosition`, `400 invalid beforePosition`,
`400 invalid limit`), then `seenSince`, when it is there, is a whole
number in that range, else `400 invalid seenSince`; then the caller is a
member of the room, else `403 not a member`.

Answer without `seenSince`: `200 { messages }`, as before, byte for byte.

Answer with `seenSince`: `200 { messages, seen, seenSeq }`.

```json
{
  "messages": [],
  "seen": [ { "anopodId": "<hex 32 bytes>", "seenPosition": 4711 } ],
  "seenSeq": 9615
}
```

- `messages`: as before. `afterPosition`, `beforePosition` and `limit`
  mean what they meant.
- `seen`: the members of the room whose `seen_seq` is above `seenSince`,
  each as `{ anopodId, seenPosition }`, in the order of a room's members
  (the first who joined first). The caller's own row is among them when
  it changed. With `seenSince` 0 it is every member who has seen
  anything; a member whose position is still 0 is left out.
- `seenSeq`: the highest `seen_seq` of the room's members, 0 when no
  member has seen anything. It is the number to send as the next
  `seenSince`.

One statement reads `seen` and `seenSeq`, so they are the room at one
moment. It runs after the statement of the messages. `seenSeq` can be
lower than the `seenSince` sent, when the member who held the highest
number left the room; the next read then sends some positions again,
which harms nothing. An entry of `seen` is about 100 bytes. A room of 100
people in which 99 have read is 9.7 KB once, when the chat is opened;
after that an answer with no new message and no new position is 40 bytes.

Nothing else changes: not `/mark-messages-seen`, not `/send-message`, and
not the `seenPosition` of each member in a room that `/list-chat-rooms`
sends whole.

### 29.5 What a wallet does with it

The wallet's part is step 2 of the plan and is written in the wallet's
spec. In short, as this server's answers are meant to be read (the plan's
3.3, 3.4 and section 7):

- The wallet keeps its list in memory, as before, and the number `seq`
  beside it. The first read after a page load or a login has no `since`.
  Every later read from the timer, and the read at the opening of the
  Chat page, sends `since`.
- What comes back is put into the list: a whole room takes the place of
  the one the wallet has, or is added at the front; three fields change
  that room's newest message; an invite or a request is added at the
  end. Three fields for a room the wallet does not hold lead to a read of
  the whole list.
- Then the wallet counts its list. A number that differs from `counts`,
  or a `seq` below the `since` it sent, leads to a read of the whole
  list, once.
- An answer is put in only if the wallet's number is still the `since`
  the request was sent with. An answer with no `seq`, from a server that
  still runs the code of before, is taken as the whole list.
- The read after a person's own action (accept, decline, create, invite,
  leave, set a picture, the marketplace's buttons) stays a read of the
  whole list, once for each tap.
- The open chat's read sends `seenSince`: 0 when the chat is opened, then
  the `seenSeq` of the last answer. The positions are written into the
  same list in memory, so "Seen" and "Seen by" are drawn by the code of
  before.

### 29.6 Files

- `db/schema.sql`: the five columns in the four `CREATE TABLE`s; the chat
  change block, new, at the end; and the file's opening comment, which
  names the new block among the idempotent ALTERs.
- `src/chat/chat.queries.js`: `listChangeNumbersFor`,
  `listNewestMessagesFor` and `listSeenSince`, new; in `listRoomsFor`,
  `listInvitesFor` and `listJoinRequestsForCreator` a second parameter,
  the ids to keep, with one condition in each statement and a sentence in
  each comment.
- `src/chat/chat.service.js`: `listRooms`, which now takes the body;
  `listRoomMessages`, the check of `seenSince` and the second form of the
  answer; the comments of both; the three imports.
- `src/chat/chat.handlers.js`: `listChatRooms` hands the body on.
- Here: section 4 (`### chat_rooms`, `### chat_room_members, chat_hpke`
  and `### chat_room_invites, chat_room_join_requests`: the new columns in
  the SQL and a paragraph each), section 5 (`### POST /list-chat-rooms`:
  the body, `seq` and `counts` in the JSON block and a dated paragraph;
  `### POST /list-messages`: `seenSince` in the body and a dated
  paragraph) and this section. `README.md`: the rows of
  `/list-chat-rooms` and `/list-messages` in the Endpoints table, the
  rows of the four tables in "Database tables", and a sentence on the
  sequence above that table.

Nothing else in existing code changes: no route that writes, not
`src/chat/chat.router.js`, not `src/marketplace/`, not `src/app.js`, not
`package.json`, not `.example.env`. One sequence, five columns, five
functions and nine triggers; no table, no route, no env variable, no npm
package.

### 29.7 What is left as it is

- The requests going up. Every signed request carries an ML-DSA-87
  signature, 4,627 bytes sent as hex, so one request is 9.6 KB. A wallet
  sends three every 5 seconds (`/list-notifications`,
  `/check-anopod-status`, `/list-chat-rooms`): 28.9 KB up, before and
  after this section (the plan's section 6).
- `/list-notifications` answers the newest 100 notifications whole every
  5 seconds. Not touched.
- This server's work on a request. It still checks both signatures and
  writes the nonce, and it reads one small row for each room of the
  caller.
- Reads of the whole list. A page load, a login and the read after a
  person's own action still get everything, once each.
- Keeping the list on the phone between two loads of the page.
- The members leaving the chat list altogether, with a read that hands
  out a room's members a page at a time: the wider way, named on
  2026-11-22.
- A room that is sent whole carries every member, also when one person
  joined a room of 100: 16.4 KB, once for each such change and member.
- One gap, on the after-production list on the user's word ("We can add
  that one line to the after production list"). A write takes its number
  first and is committed a moment later. If two writes happen within a
  few milliseconds and are committed in the other order than their
  numbers, a read that falls between the two commits can skip the one
  with the lower number. A person then misses one change of one chat (a
  dot, a line of the chat list, a name, a reader under "Seen by") until
  that chat's next change or until the page is loaded again. Two writes
  of one room cannot do it: each writes the room's row, so the second
  waits for the first and gets the higher number (tried, 29.8). It needs
  two writes of two rows: two rooms, or two members' read positions in
  one room. A new room, a new invite or a new request that is skipped
  this way is still found at the wallet's next read, by `counts`. The
  open chat's read of new messages has the same trait since before this
  section. The item's line is "chat: of two changes
  written at the same instant, a phone can miss one" in
  `~/Desktop/Z-TestNet/after_production_todos/things-to-do-after-production.md`.
  The build did not try for it (the plan's section 7).

### 29.8 Notes from the build

#### Build 1, the masterpod (2026-11-24)

Built from `~/Desktop/Z-TestNet/forclaude/chat-list-plan-1.md`, its
sections 3.1, 3.2, 3.4 and 7 and step 1 of section 5, on main at 73f2551,
the working tree clean. The plan holds no code, so all of the code is the
build's. No new npm package, and no test script in the repo. The schema
was not applied to any database of the network: the user applies the
whole file as section 6 of `forclaude/masterpod-deploy-plan-1.md` says, on
the leader, and then pulls and restarts the three servers, the leader
last. The file goes on before the new code runs. On a database without
the block the built code fails every `/list-chat-rooms`, the read every
wallet makes every 5 seconds: the chat would be down for everybody until
the block is there. The other order is safe: the code of before names its
columns and never looks at the new ones, and the triggers number its
writes. Both were tried (below). What the plan left open and how it was
decided:

- The number and the date. This section is 29, the next free number on
  the build day. The date is 2026-11-24, the day of the build and of the
  plan's FINAL.
- The block's name, "The chat change block", is after the counter's name,
  which is the plan's.
- The columns are inline too. The plan says to follow the seen position
  block, and that block has its column inline in the `CREATE TABLE` as
  well, for a database built from nothing. Each new column is the last
  of its table on both ways, so a database built from nothing and one
  that got the block hold their columns in the same order. A column has
  the form of `seen_position`: `BIGINT NOT NULL DEFAULT 0` with a check
  that it is not negative. PostgreSQL names the five checks
  `chat_rooms_message_seq_check`, `chat_rooms_people_seq_check`,
  `chat_room_invites_change_seq_check`,
  `chat_room_join_requests_change_seq_check` and
  `chat_room_members_seen_seq_check` on both ways.
- Five functions and nine triggers, each trigger named after its table
  and its function, as `chat_rooms_set_updated_at` is. `set_change_seq`
  serves the invites and the join requests, and `set_room_people_seq`
  serves the member rows, the invites and the pictures. A picture has two
  triggers, because a trigger's `WHEN` cannot name the old row at an
  insert. The two that set a number on their own row fire before the
  write; the ones that number a room fire after it.
- "A changed row" of `chat_room_pictures` is read as the table's own
  `updated_at` trigger reads it (`OLD.* IS DISTINCT FROM NEW.*`): the
  same picture again numbers nothing. A listing numbers its rooms at any
  change of `status`; today only `/close-listing` changes it, from `open`
  to `closed`.
- The first run's numbering is three plain `UPDATE`s that take the rows
  whose number is still 0. No mark of a first run is kept anywhere: a
  second run finds no such row.
- The first statement of `/list-chat-rooms` is one `SELECT` over a `UNION
  ALL` of three, with the joins of the three lists, so that `counts`
  always equals the lengths of the three lists of a whole read made at
  the same moment. It also gives the rooms' order, by `created_at DESC`
  and then the id, as the whole list has it.
- The order of `rooms` in an answer with `since`. The plan names none. It
  is the order of the whole list, so a whole room and a room of three
  fields stand as they stand in the list.
- The numbers on their way out. PostgreSQL hands a `BIGINT` to the `pg`
  library as text, and the code makes a number of it. That is exact up to
  9007199254740991, the limit of `since`; at 1,000 changes a second the
  counter reaches it in 285,000 years.
- `since` and `seenSince` are read by `integerOption`, as `afterPosition`
  is. So an absent one and `null` mean "none", and a negative number, a
  fraction, a text, `true`, a list, an object and a number above the
  limit are `400 invalid since` or `400 invalid seenSince`. `listRooms`
  checks that the body is an object, in the manner of
  `/list-public-chat-rooms`; over HTTP that check cannot refuse, because
  the session check has refused such a body before.
- The three list statements each got one condition, `($2::bytea[] IS NULL
  OR <id> = ANY($2::bytea[]))`, and their functions a second parameter
  that is `null` by default. With `null` a statement reads everything,
  and PostgreSQL plans it as it planned the statement of before (tried).
  This keeps one statement for a room's whole form, whether it is read
  for a whole list or for one room that changed.
- `listNewestMessagesFor` holds a copy of the lines of `listRoomsFor`
  that make `lastMessage` and `lastPosition`. `listRoomsFor` keeps its
  body but for the condition.
- `/list-messages`. `seenSince` is checked after `limit`, with the other
  values and before the member check, so a pod outside the room that
  sends a bad one gets the `400`. The statement of the read positions
  runs after the statement of the messages. `seenSeq` follows the rule of
  `seq`: the highest number the statement saw, never the counter's own
  value.
- `db/schema.sql`, the file's opening comment. Its list of the blocks
  whose ALTERs change a table that exists now ends "case chat, seen
  position, first key blob and chat change blocks at the end". The plan
  does not name the sentence; it would have been untrue with the new
  block, and it sits in a file of this commit, so the build brought it
  in line and said so in its report.
- Here and in the README. In section 4 each new column stands in its
  table's SQL as in the file, with one paragraph for it at the end of the
  entry. In section 5 the body and the JSON block of `/list-chat-rooms`
  and the body of `/list-messages` name the new fields, and each entry
  ends with a dated paragraph. In the README the two rows of the
  Endpoints table and the four rows of "Database tables" each gained a
  clause, and a sentence above that table names the sequence.
- Places the plan does not name that this step left out of date: none
  that the build found. Read for it: every sentence of this file, of the
  README and of `src` that names `/list-chat-rooms` or `/list-messages`.
  The comment of `chat_room_members.seen_position` and 21.1 say that
  `/list-chat-rooms` hands a member's position to every member of the
  room; that is still so for a room that is sent whole. Sections 21 and
  27 say what their own builds changed and stay as records.

The checks. All of them ran from empty databases on the files as they
were handed over. The tools are outside the repo, in the build chat's
scratch folder, and none of them is kept in it.

- The code. `node --check` on the three changed files, clean, on Node
  24.22.0. One load of the app with no server and no database
  (`createApp()` with made-up settings): 112 routes, sixteen of them the
  chat's, as a copy of 73f2551 gave the same way. A type checker's read
  of `src/app.js` (`tsc --checkJs`, TypeScript 6.0.3 from the wallet's
  folder) named no unknown name, no wrong count of arguments and no
  missing export or module, and in the three chat files no finding that
  the same read of 73f2551 does not have, apart from "implicitly has an
  'any' type", which it says of every parameter of this plain JavaScript.
- The scratch PostgreSQL. A PostgreSQL 17.11 that was started for this
  build alone: a data folder of its own in the build chat's scratch
  folder, listening on 127.0.0.1 port 60731 and nowhere else, with no
  socket file. This Mac's own PostgreSQL on port 5432 was not touched.
  Every apply of a schema file ran as the deploy's line runs it: one
  transaction after `SET ROLE masterpodsoftware`, into a database that
  the role owns. Every tool that uses this server's pool stops before its
  first query unless the pool's host and port are the scratch
  PostgreSQL's.
- A database as it is live today. The file of 73f2551 into an empty
  database: 45 tables, no sequence of ours. It was then filled through
  that commit's own routes, over HTTP with signed requests: seven pods
  and, between them, a chat of two with messages and two read positions,
  a group with an open invite and a third read position, a public room
  with a picture and an open join request, a listing with a chat about
  it and an open invite to its owner, a chat with an open invite, a chat
  with no message, and a pod with nothing. 6 rooms, 12 messages, 10
  member rows of which 3 hold a read position, 3 open invites, 1 open
  join request.
- The schema file. The new file on top of that database: 45 tables. One
  md5 over every column, constraint, index, trigger, function, sequence,
  comment and owner of the schema came from 1,190 lines before and from
  1,222 after: the 32 new lines are the 5 columns, their 5 checks, the 5
  functions, the 9 triggers, the sequence, its owner and the 6 comments,
  and no line of before was changed or gone. The first run numbered
  exactly what the plan says: the 3 open invites (1 to 3), the open join
  request (4) and the 3 member rows with a read position (5 to 7). The 7
  other member rows and all 6 rooms kept 0, and the counter stood at 7.
  The new file once more: the same md5, the same number in every row and
  the counter still at 7. The new file alone into a second empty
  database, twice: 45 tables and that same md5, both times.
- The two half-deployed states, each with the real app over HTTP and
  signed requests. The built code on the tables of before:
  `/list-chat-rooms` answered `500` with and without `since` (`column
  r.message_seq does not exist` in the server's log), and `/list-messages`
  with `seenSince` answered `500` (`column "seen_seq" does not exist`);
  `/list-messages` with no `seenSince`, `/send-message`,
  `/mark-messages-seen` and `/list-public-chat-rooms` answered. So the
  schema line goes first. The code of 73f2551 on the new tables:
  `/list-chat-rooms` answered the keys of before, and the same with a
  `since` in the body, which that code does not know; `/list-messages`
  with a `seenSince` answered the messages alone; and its writes were
  numbered by the triggers: a message numbered its room (8), a read
  position its member row (9), an invite itself and its room (10 and
  11), and an accepted invite its room again (13).
- A wallet of today. The code of 73f2551 and the built code were started
  in one process on one database and asked the same as the same seven
  pods. `/list-chat-rooms` with `{}`: the built code's answer is the
  answer of before, byte for byte, with `"seq":<n>,"counts":{...},` in
  front, 58 or 59 bytes more, and `counts` are the lengths of the three
  lists. `/list-messages` with no `seenSince`, in three forms of the
  request for each of 11 memberships: byte for byte the answer of before.
  The wallet of today keeps the answer of `/list-chat-rooms` whole and
  reads `rooms`, `invites` and `joinRequests` out of it
  (`web_app/src/app/services/session.service.ts`, read, not changed), so
  two fields more do nothing there.
- The walk. The built code on the updated database, over HTTP with
  signed requests, each pod with a wallet's number of its own. 85
  results, none bad. With no `since`: everything, `seq` the highest of
  the caller's own numbers and not the counter. Asked again with `since`:
  nothing, 101 bytes. A message: that room as three fields to both
  members, nothing to a pod outside it. An invite accepted: the room
  whole to every member and to the new one, whose `counts` say one room
  more and one invite fewer. An invite made: the invite to the invited
  pod, the room whole to its members. An invite declined: nothing to the
  pod that declined, with `counts` one lower than its wallet holds and
  `seq` below its `since`. A join request: to the room's creator alone,
  and the room's numbers did not move. The request approved: the room
  whole to the creator, the members and the new one. The request
  declined: nothing, `counts` one lower, `seq` below `since`. A member
  who leaves: the room whole to the others, nothing to the one who left.
  Another picture: the room whole with the new `pictureAt`; the same
  picture again: nothing. The listing closed: its chat whole to its
  member, and the open invite to that chat is not sent again. A message
  and an invite in one room between two reads: the room once, whole.
  Messages in two rooms: two entries of three fields, in the list's
  order. `since` 0: every room with a number, and not the room that
  still holds 0 and 0, which `counts` still counts. A `since` far above
  every number: nothing, and `seq` below it. Seven bad values of `since`:
  each `400 invalid since`; `null`: the whole list. `/list-messages`:
  with no `seenSince` the messages alone; with 0 the members who had read
  before the schema file, with those positions; asked again with the
  `seenSeq`: nobody, `{"messages":[],"seen":[],"seenSeq":6}`; one member
  reads on: that member alone and a higher `seenSeq`; a report of a
  lower position: nobody; `beforePosition` with `seenSince`: both parts;
  five bad values: each `400 invalid seenSince`; a pod outside the room:
  `403 not a member`, and with a bad value the `400`. None of the read
  positions reached `/list-chat-rooms`. A body with no signature and a
  request signed for another path were refused as before. At the end no
  number stood in two rows.
- Made-up wallets. A script holds the plan's rules for a wallet (3.3 and
  section 7) and tries whether this server's answers are enough to keep
  a list right. It makes many random changes, one after the other, each
  by its route's own service function: messages, read positions, new
  rooms, invites and their answers, join requests and their answers,
  members leaving, pictures, chats about a listing, listings closed.
  After each change every pod's two wallets ask as a wallet will: one
  after every change, with one chat "open" for its read positions, and
  one only now and then, like a second phone. What a wallet then holds
  is compared with a read of the whole list. Five rounds of 3,000 steps
  with five seeds: 91,166 comparisons, none different, 75,208 of them
  with an open chat's read positions; every new room, invite and request
  was in the answer itself and none was left to `counts`; a wallet read
  the whole list 4,473 times, 4,340 of them for a count that differed
  and 133 for a `seq` below its `since`, and never for three fields of a
  room it did not hold. Then one round with each of the nine triggers
  taken away from the database: all nine rounds came out bad, so the
  rounds notice a missing trigger, and each trigger is needed.
- Writes at the same moment. Six bursts of 174 signed calls at once
  through the app's own pool of ten connections: messages by several
  people in the same rooms, read positions, invites answered, members
  leaving, and a listing closed, twice at once, while messages were sent
  in the four rooms about it. 1,044 calls: 992 answered `200` or `201`
  and 52 a refusal of their route (`403 not a member`, `409 already
  closed`); none `500`, no line in the server's log, PostgreSQL's own
  count of deadlocks 0, no number in two rows. Each of eight wallets
  that were away during a burst was right after one read with its
  `since` of before.
- Who waits for whom, with two transactions held open. A second message
  in the same room waited for the first and, committed later, left the
  higher number. An invite to a room waited for a message in it. A
  message in another room did not wait, and neither did a second
  member's read position in the same room. In the case of two rooms the
  one committed second held the lower number: the condition of the gap
  of 29.7, seen and left as it is.
- What travels, with values of the real lengths (a wrapped key of 1661
  bytes, a short message, the counter first set to 9000). A person with
  five chats of two people: 21,462 bytes for the whole list, 104 with
  `since` and nothing new, 540 with one new message. A person with nine
  such chats and a room of 100 people: 54,690 bytes whole, 105 with
  `since` and nothing new, 541 for a new message in the room of 100, and
  16,364 when someone joins it (that room whole, 101 members). The read
  positions of that room, by `/list-messages` with no new message:
  9,741 bytes once when the chat is opened and 99 members have read, 40
  bytes when nobody read further, 137 when one did.
- Times, on this Mac, the database on the same machine and no PgBouncer
  between, each the average of some hundred calls of the route's own
  function. The person with ten rooms: 1.05 milliseconds for a whole
  read and 0.29 with `since` and nothing new, which is one statement.
  On a database with 20,000 rooms, 100,000 member rows and 300,000
  messages, for a pod in 50 rooms of five people: the whole list is
  233,195 bytes and took the code of 73f2551 1.58 milliseconds; the
  built code's whole read took 2.60, because its first statement runs
  before the three of before, which run side by side; a read with
  `since` and nothing new is 105 bytes and took 0.99. Most of the first
  statement's time there is one walk through `chat_rooms` for the rooms
  the caller created: no index names a room's creator, and the statement
  of before for the join requests walks the table the same way.
  PostgreSQL planned the three list statements of a whole read exactly
  as it planned them at 73f2551. A message sent, one after the other in
  one chat: 0.13 milliseconds with the code of 73f2551 on the tables of
  before and 0.16 with the built code and its trigger.
- The schema file on many rows. On that database of 20,000 rooms the
  file's first run, with 62,500 rows to number (2,000 invites, 500
  requests, 60,000 member rows with a read position), took 0.56 seconds,
  psql's start included, and a second run 0.08 seconds. For that time
  the chat tables are held and requests wait.
- The lines for the servers, in stand-in form on the scratch PostgreSQL,
  with a copy of a local file in place of the download. Every line's
  syntax was read by bash and by dash. The schema line carries the whole
  hash of the new file and prints `OK`, 45, the apply's lines, 45, the
  owner, 5 for the new columns and 9 for the new triggers; a second run
  prints the same; with the file of before as the download it prints
  `FAILED` and applies nothing. A look-only line prints the counter and
  how many invites, requests and member rows hold a number, and refuses
  a write. None of these lines has run on a server.
- Not tried by the build. Nothing on a server, nothing on Linux, nothing
  on PostgreSQL 16, which the servers run (the block uses `CREATE OR
  REPLACE TRIGGER`, as the file does since its first version, and
  nothing newer), and nothing through PgBouncer. `src/server.js` was not
  booted: the app was started by `createApp()`. No wallet called the
  routes: the wallet's part is step 2. The gap of 29.7 was not tried
  for. Whether a wallet's two answers that arrive in the other order
  than they were asked can leave an older read position in its list is
  the wallet's to settle in step 2: this server sends each answer whole
  and true for its moment.
- Not touched: every route that writes, `src/chat/chat.router.js`,
  `src/marketplace/`, `src/app.js`, every other feature folder,
  `package.json`, `.example.env`, the scripts.
- The numbers. `db/schema.sql` has 1824 lines, 158 more than before, and
  its sha256 begins 0d713e9a. Before the step it had 1666 lines and its
  sha256 began 9894ae57. It makes 45 tables, as before: the count that
  the deploy's schema line prints does not change with this step, so
  that line also counts the five new columns and the nine new triggers.

## 30. Joy, the wallet's AI (2026-11-24)

Design settled 2026-11-24 in a talking chat with the user, with no plan
file: the chat's messages are the plan, and the user's word for the build
was "Let's do it." The work note of that talk is
`~/Desktop/Z-TestNet/forclaude/notes/project-wallet-ai-joy.md`. What it
is: a member writes to an AI in the wallet, named Joy, as they would to
any AI chat. The user: "Basically they're getting AI for free. They can
use it for whatever the hell they would use the free version of CHATgpt
for." The answers are written by a model of the company Anthropic,
Claude Haiku 5.5, which this server calls for every message. Two steps in
order: this server (this section) and the wallet (its spec: a Joy tab,
the chat, the memory file's page). With this server alone deployed
nothing changes for anyone: no wallet calls the new routes. One feature
folder, `src/joy/`; two tables; three routes; five env variables; one
file of text, `joy/shared-memory.md`; and one npm package,
`@anthropic-ai/sdk`, this server's first new package since the build of
2026-10-24. The validators, the keyholders, the signing servers and the
doormen are not touched. Nothing above this section changes except the
items in 30.9.

### 30.1 The rules

- Day one is one thing. The user: "For day one, I want a joy tab, and
  there is a chat where members can chat with Joy." And: "Remember,
  simple set up at first, 1 task, use AI in my web app".
- Only vouched members. The user: "Of course only vouched members can
  use it". The three routes are at level setup, as every chat route is.
- A memory file for each member. The user: "The user needs a memory file
  like i have one on my computer so that Joy knows who they are and shit
  like that." Joy reads it with every message and adds to it herself.
  The member reads it, changes it and empties it in the wallet.
- The memory file is encrypted on the phone, as a note is (the chat's
  question, the user: "Okay."). This server stores a blob it cannot
  open.
- A conversation is stored nowhere on this server. The wallet holds it
  and sends it with every message. The user: "Because chat's dont't
  really need to be saved." The wallet keeps the one chat that is under
  way in the browser, so a reload does not lose it (its spec). Saved
  chats are a later build, on the after-production list ("Joy: saved
  chats").
- The answer is a stream (the user: "3. Yes."). The doormen in front of
  this server end a request that waits 30 seconds for a byte (`timeout
  server 30s` in their HAProxy settings), and a long answer in one piece
  can take longer. A stream keeps bytes moving.
- 300 messages a day for one pod (the user: "4. Yes."). The user's own
  words before: "we can set an accounts limit really high, incase some
  butt head is trying to blast it."
- A basic shared memory file from the start. The user: "Probably do want
  to have a basic share memory file to start with. Like you say, I'm
  Joy, etc..." It is a file of this repository for now (30.7).
- Cost is not the first aim. The user: "It will add to the cost, but
  tha'ts okay, I want this to be cool, not just cheap."

### 30.2 What this server keeps, and what passes through it

Kept, in the database:

- The member's memory file, as one blob under the pod's encryption key
  (`joy_memories`). This server cannot open it.
- For each pod and each day, the number of messages sent to Joy and the
  tokens Anthropic counted for them (`joy_usage`). No text.

Passing through, kept nowhere:

- The conversation and the opened memory file. The wallet sends both in
  the clear with every message, inside the signed request. They pass
  through this server's memory on their way to Anthropic. They are
  written into no table and no log.

So this is the one place where something a pod keeps private reaches
this server readable. It has to: Anthropic's model reads the text.
The wallet says so to the member on the Joy tab (its spec).

### 30.3 Tables

`joy_memories`, one row per pod, replaced in place:

| Column | Type | Notes |
| ------ | ---- | ----- |
| `anopod_id` | `BYTEA` | Primary key, 32 bytes. The pod |
| `memory_blob` | `BYTEA` | Not null, at most 32768 bytes. Ciphertext of the memory file, made by the wallet |
| `created_at`, `updated_at` | `TIMESTAMPTZ` | As every table |

`joy_usage`, one row per pod and day:

| Column | Type | Notes |
| ------ | ---- | ----- |
| `anopod_id` | `BYTEA` | 32 bytes. The pod |
| `day` | `DATE` | The day, in UTC. Primary key with `anopod_id` |
| `messages` | `INTEGER` | The messages the pod sent Joy that day; 0 or more |
| `input_tokens` | `BIGINT` | `usage.input_tokens` of Anthropic's answers, summed |
| `output_tokens` | `BIGINT` | `usage.output_tokens`, the model's thinking included, summed |
| `cache_read_tokens` | `BIGINT` | `usage.cache_read_input_tokens`, summed |
| `cache_write_tokens` | `BIGINT` | `usage.cache_creation_input_tokens`, summed |
| `created_at`, `updated_at` | `TIMESTAMPTZ` | As every table |

Both have the `set_updated_at` trigger and a `COMMENT ON` for the table
and every column. No foreign keys, as everywhere.

The memory file itself is text of at most 10240 bytes (UTF-8). Its blob
may be up to 32768 bytes, because the wallet wraps the text in JSON
before it encrypts it, and JSON can double a text.

### 30.4 Routes

All three at level setup. The caller is `req.anopod`.

**`POST /get-joy-memory`**. Body `{ }`. Answers `200 { memoryBlob,
updatedAt }`: the blob in hex and when it was last set, both `null`
before the first set.

**`POST /set-joy-memory`**. Body `{ memoryBlob }`, hex or base64, 1 to
32768 bytes. Checks: the shape (`400 bad request shape`); the blob's
length (`400 invalid memoryBlob`). Writes the pod's one row whole.
Answers `200 { updatedAt }`. A member empties the file by setting the
blob of an empty file.

**`POST /ask-joy`**. Body:

```
{
  messages: [ { role: "user" | "assistant", text: "..." }, ... ],
  memory:   "<the member's memory file, as text>"
}
```

`messages` is the conversation, oldest first, with the member's new
message last. Checks, in order:

1. The shape: `messages` an array, `memory` a string. `400 bad request
   shape`.
2. The messages: 1 to 200; each with `role` `user` or `assistant` and a
   `text` that is a string with more than spaces in it; the first and
   the last are the member's. `400 invalid messages`. Two messages of
   the same role may follow each other.
3. The texts together are at most 120,000 bytes. `400 conversation too
   long`.
4. `memory` is at most 10240 bytes. `400 memory too long`.
5. Joy is on (`ANTHROPIC_API_KEY` is set). `503 joy is off`.
6. The pod's count of the day (UTC) is below `JOY_DAILY_MESSAGES`. `429
   daily limit reached`. Passing this check raises the count by one, in
   the same statement, so two requests at the same instant cannot both
   take the last place.

A refusal of these checks is answered as every route answers one. Past
them the answer has status `200` and the type `application/x-ndjson;
charset=utf-8`, with `Cache-Control: no-store`. It is a stream of lines,
each one JSON object with a line break after it:

```
{ "text": "..." }                       a piece of Joy's answer, as it is written
{ "done": true, "stop": "end", "memory": null }
                                        the last line of an answer that ended
{ "error": "joy busy" }                 the last line of an answer that failed
```

- `stop` is `end`, `length` (the model reached `JOY_MAX_TOKENS`, so the
  answer is cut off) or `refused` (Anthropic's safety check stopped the
  answer).
- `memory` is the member's whole memory file after Joy changed it, as
  text, or `null` when she changed nothing. The wallet encrypts it and
  stores it with `/set-joy-memory`.
- `error` is `joy busy` (too many calls in a minute at Anthropic, or
  Anthropic is overloaded or failing), `joy unavailable` (Anthropic
  cannot be reached, the key is refused, the credit or the spend limit
  is used up, or Anthropic does not take the request) or `joy was cut
  off` (the connection to Anthropic dropped in the middle of an answer,
  or Anthropic sent nothing for 120 seconds).
  The log line `joy failed:` holds the status, the kind and the start of
  Anthropic's own message, never the key and never a member's text.
- An empty line may stand between the lines and means nothing. This
  server writes one every 10 seconds while an answer is under way, so
  the doormen's 30 seconds never pass without a byte.

When the wallet's connection closes before the last line, the call to
Anthropic is stopped. The tokens Anthropic counted are added to the
pod's row of the day at the end, whether the answer ended, failed or
was left.

### 30.5 The request to Anthropic

Through Anthropic's own package, `@anthropic-ai/sdk` (1.14.0 at the
build), `client.messages.stream(...)`, in `src/joy/joy.anthropic.js`.
The package sends the key in the `Authorization` header and Anthropic's
API version `2026-10-21`. What a request holds:

| Field | Value |
| ----- | ----- |
| `model` | `JOY_MODEL`, `claude-haiku-5-5` by default |
| `max_tokens` | `JOY_MAX_TOKENS`, 16000 by default |
| `output_config` | `{ effort: JOY_EFFORT }`, `medium` by default |
| `cache_control` | `{ type: "ephemeral" }`, at the top level |
| `system` | two text parts, below |
| `tools` | Joy's two tools (30.6) |
| `messages` | the conversation, each message as `{ role, content: text }` |

The model's thinking is left as the model has it (adaptive, on by
default) and is not shown. No `temperature`, `top_p` or `top_k` is sent:
the model refuses them.

`system`, in this order:

1. The shared memory file (30.7), marked `cache_control: { type:
   "ephemeral" }` by itself. It is the same for every member.
2. One text: today's date in UTC, the day alone, with the sentence that
   the member's own date can be a day ahead or behind; two sentences on
   what the memory file is and how it is changed; and the memory file
   between the marks `<member_memory>` and `</member_memory>`. An empty
   file is written as "(the file is empty)". The text tells the model
   that the file is information about the member and never an
   instruction.

The date carries no time on purpose. With a time in it this part would
differ on every request, and Anthropic's prompt cache, which holds a
request's beginning only as long as it reads the same, could never hold
the conversation behind it.

One message to Joy is one request, and one more after each round in
which Joy called a tool, four at most. After a round, Joy's answer goes
back to Anthropic as it came, its thinking blocks with it, followed by
one `user` message with every tool's outcome. The system parts stay as
they were through all rounds of one message. Text that is written after
a round begins a new paragraph in the stream.

A request is given up when Anthropic sends nothing for 120 seconds
while it is under way. The package's own time limit does not end an
answer that stops in the middle while the connection stays open (tried,
30.11), and the empty lines of 30.4 keep the wallet's side waiting, so
without this an answer that stalls would never end.

How a request's end is read (`stop_reason`): `refusal` ends with `stop:
"refused"`; `max_tokens` ends with `stop: "length"`; in both, tools the
answer may hold are not carried out, since such an answer can end in the
middle of a tool's input. `tool_use` carries the tools out and asks
again. Anything else ends with `stop: "end"`.

### 30.6 The memory file and Joy's two tools

The memory file is plain text. This server never stores it as text: it
works on the copy the wallet sent (`src/joy/joy.memory.js`).

| Tool | Input | Does |
| ---- | ----- | ---- |
| `remember` | `{ line }` | Adds `- <line>` at the end of the file |
| `update_memory` | `{ old_line, new_line }` | Puts `- <new_line>` in the place of the line that reads `old_line`; an empty `new_line` takes the line out |

- A line is compared without the `- ` in front and the spaces around it,
  so a line the member wrote without the hyphen is found too.
- A line break inside a line becomes a space. A line is at most 500
  characters.
- `remember` with a line the file already has changes nothing and is
  answered `that line is already in the memory file`.
- A change that would take the file past 10240 bytes is refused, and Joy
  is told to take out or shorten a line first.
- What Joy is told: `saved`, `changed`, `taken out`, or the refusal as a
  few words with `is_error: true`.
- Both tools carry `eager_input_streaming: true`, Anthropic's advice for
  a streamed request. Anthropic then hands a tool's input over as the
  model wrote it, unchecked. So the input is checked here, and one that
  is not the object the tool asks for is told back in Anthropic's own
  form for it, `{ "INVALID_JSON": "<the input>" }`.

Anthropic also offers a ready-made memory tool, which works on a folder
of files and makes the model look into the folder before it answers.
Joy has one file, and it is in every request already, so two small tools
of our own are the shorter way.

### 30.7 The shared memory file

`joy/shared-memory.md`, at the repository's root: who Joy is, how she
answers, what she cannot do yet and what she never asks for. It is read
once, when the server starts, and stands at the beginning of every
request, the same for every member. An empty file stops the boot. The
whole file goes to the model, so it holds no note for a reader of the
repository.

What it says today, in short: Joy is an AI and says so; she answers in
the member's language, shortly, in plain text with no Markdown (the
wallet shows her words as they are); she cannot look anything up, see
pictures or act in the wallet; she has not been taught how the wallet
works and says so, and never guesses at passkeys, recovery or sending;
she never asks for a passkey, recovery details, a key or a password.

A shortcut that fits a file of about twenty lines: a change to it is a
commit and this server's update on the three servers. When the file
grows into the wallet's how-to, it moves into the database, so that it
can be changed without an update. That is not built.

### 30.8 Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `ANTHROPIC_API_KEY` | none: Joy is off | Anthropic's API key |
| `JOY_MODEL` | `claude-haiku-5-5` | The model that writes Joy's answers |
| `JOY_EFFORT` | `medium` | How hard the model thinks before it answers: `low`, `medium` or `high`; anything else stops the boot |
| `JOY_MAX_TOKENS` | `16000` | The most tokens one request to Anthropic may write, the model's thinking included |
| `JOY_DAILY_MESSAGES` | `300` | How many messages one pod may send Joy in one day (UTC) |

This server boots and runs without any of them. Without the key,
`/ask-joy` answers `503 joy is off`, nothing is sent to Anthropic and
nothing is counted; the two memory routes work. So this step can be
deployed before the key is set. The key is read in `src/config/env.js`
like every setting and handed to the package; no error prints it.

### 30.9 Files

- New: `src/joy/joy.router.js`, `joy.handlers.js`, `joy.service.js`,
  `joy.queries.js`, `joy.anthropic.js`, `joy.memory.js`;
  `joy/shared-memory.md`.
- `db/schema.sql`: one block at the end, the two tables with their
  triggers and comments.
- `src/app.js`: the router is mounted, after the wallet memory router.
- `src/config/env.js`: `optionalChoice`, `readJoy`, and `joy` in `env`.
- `package.json`, `package-lock.json`: `@anthropic-ai/sdk`, and the
  seven packages it brings.
- `.example.env`: the five variables, each as a comment line.
- `README.md`: the three routes, the two tables, the five variables,
  the folder and the file in their lists, and the three routes in the
  row of level setup.
- Above this section: the three routes in the row of level setup in
  section 2, and the five variables with one paragraph in section 8.

### 30.10 What was decided in the build, and what is left

Decided while building, each a small thing the talk had not named:

- The last line of an answer carries `stop` beside `memory`, so the
  wallet can tell a member that an answer was cut off or refused.
- Today's date is in the request, as a day in UTC. Joy would otherwise
  take the year her training ended for the present. The member's own
  clock is not sent.
- `medium` for the model's effort, its own default, and 16000 tokens
  for one request. Both are settings.
- A message is counted before Anthropic is called. A message that then
  fails is counted too.
- 120 seconds of silence from Anthropic end a request (30.5).
- The sizes: 200 messages and 120,000 bytes for one request, 500
  characters for a line of the memory file. 120,000 bytes keep one
  request far under the 100,000 tokens above which Anthropic's price
  for this model is five times as high.

Left as it is:

- Joy cannot look anything up on the internet, and takes no pictures or
  files.
- She knows nothing of the wallet. The shared memory file tells her to
  say so.
- The memory file is the last one written. A member who writes to Joy
  on two devices at the same moment can lose a line that one of them
  saved.
- When an answer fails after Joy saved a line in an earlier round of
  the same message, that line is lost: the changed file travels in the
  last line only.
- Nothing reads `joy_usage` but the daily limit. A look at the numbers
  is a psql line.

### 30.11 Notes from the build

#### Build 1, the masterpod (2026-11-24)

- Built in the working tree of `~/Desktop/Z-TestNet/masterpodsoftware`
  on top of 305fe5e, in the talking chat itself, on the user's word.
- No real call to Anthropic was made: no key existed yet. Everything
  below ran against a stand-in for Anthropic's API on this Mac, a small
  server that answers `POST /v1/messages` with a stream in Anthropic's
  form. The package was pointed at it by `ANTHROPIC_BASE_URL`. So the
  form of the request is checked against Anthropic's reference and the
  package's own types, and the first real answer is the proof that is
  still owed.
- The load. `createApp()` with made-up settings and no key: 115 routes,
  three more than before, each of the three with the three checks of
  level setup in front of its handler. A `JOY_EFFORT` of `max` stops
  the boot with the variable's name.
- The trial. The working tree's app on a scratch PostgreSQL of its own
  (port 57931, never this Mac's own server), called over HTTP with
  requests signed as a wallet signs them, 81 checks, none failed: the
  refusals of a pod that is not vouched and of one without setup on all
  three routes; the memory file's two routes with their limits (32768
  bytes taken, 32769 refused); the thirteen refusals of `/ask-joy`'s
  checks, none of which reached the stand-in or the count; a plain
  answer line by line; every field of the request to Anthropic; Joy
  saving a line (two requests, her answer going back whole with its
  thinking block, the outcome in one message, the new file in the last
  line); two tools in one answer; a tool input of the wrong kind; a
  model that never stops calling tools (four requests, then the end);
  a refused and a cut-off answer; a refused key, a used-up spend limit,
  a rate limit and an overloaded Anthropic, each as its reason; a
  connection dropped in mid-answer; an empty line after 10 seconds of
  silence; the call to Anthropic stopped when the caller went away; the
  daily limit, with twenty requests at the same instant and five places
  left (five answered, fifteen refused); and the two tools by
  themselves. With no key: `503 joy is off`, nothing counted, the
  memory routes working.
- The watch on silence. First the fault: with the package's time limit
  set to 3 seconds, a stand-in that sent half an answer and then nothing
  left the call waiting after 9 seconds. Then the watch, in a copy of
  the code with its 120 seconds set to 2: the half answer came, the call
  ended after 2.0 seconds as `joy was cut off` and was closed at the
  stand-in; an answer of forty pieces over 6 seconds, never 2 seconds
  silent, came whole.
- The schema file. On top of a database built from the file of before:
  45 tables, then 47, and 47 again after a second run. Its schema as
  `pg_dump` prints it is the same as that of a database built from the
  new file alone.
- A type checker's read of the whole app (`tsc --checkJs`): none of the
  kinds that mean a real mistake.
- The trial's tools are kept nowhere in this repository.
- The numbers. `db/schema.sql` has 1876 lines, 52 more than before, and
  its sha256 begins 9ae0fd66. Before the step it had 1824 lines and its
  sha256 began 0d713e9a. It makes 47 tables where it made 45.
- The deploy has three things the usual update does not: the schema
  file goes onto the database before the new code runs; `npm ci` runs
  on each server, since `package-lock.json` changed; and the key goes
  into `.env` on each server, before or after, since Joy is off without
  it.
- Left, and asked about: two sentences say that everything a pod keeps
  private reaches this server as ciphertext (the README's second
  paragraph, and section 1's last bullet). What a member writes to Joy
  does not. They were not changed in this build.

## 31. A person edits and deletes their own chat messages (2026-11-24)

Design settled 2026-11-24 in a talking chat, in two rounds of four
questions, and its planning (the plan is
`~/Desktop/Z-TestNet/forclaude/chat-edit-delete-plan-1.md`, FINAL,
2026-11-24, on the user's word "Final"). What it is: in a chat, a person
gives a message of their own a new text, or deletes it, and the others in
the chat see the new text, or a line that a message was deleted. The user,
in the talk's first message: "In the marketplace, editing and deleting of
chats must be disabled, because those chats could end up being evidence. I
believe we don't have edits or deletes open on the chats, so what we might
have to do instead, is hide editied or deleted chats so they don't show in
the wallet, and the edited chat just replaces the old one in the chat
box." So an edit or a delete is a new row beside the message, which this
server marks as what it is, and nothing that is stored is ever changed or
removed. Two steps in order: this server (this section, step 1 of the
plan: one schema block, two routes, two fields more on every row of
`/list-messages`, and a new form of `lastMessage` in `/list-chat-rooms`)
and the wallet (its spec, step 2: the menu on a person's own message, the
two requests, and how an edit and a delete are drawn). With this server
alone deployed nothing changes for anyone: no wallet sends the two new
requests, so no edit and no delete is in the table, every answer carries
the new fields with nothing in them, and a wallet of before passes them
over. Inside this server's own deploy the order matters: the schema file
goes onto the database before the new code runs (31.9). One schema block:
two columns, one check, one index, and one column made nullable. Two
routes. No table, no trigger, no counter, no env variable and no npm
package. The validators, the doormen, the keyholders, the signing servers
and the wallet's proxy are not touched: nothing between a wallet and this
server keeps a list of paths (31.9). Nothing above this section changes
except the items in 31.7.

### 31.1 The rule

- An edit or a delete is a new row (the plan's decision 1). Two routes
  write it, `/edit-message` and `/delete-message`, and two columns mark
  it. No row is ever changed or removed. This server knows which rows are
  edits and deletes, so it is this server that refuses them. The user:
  "1. yes".
- Editing and deleting are off in a chat about a listing, in an old
  marketplace room and in a chat about an attestor case (decision 2).
  This server refuses them there, for a wallet and for a request made by
  hand. The user: "those chats could end up being evidence"; "2. yes".
- The others see the small word "edited" on an edited message and a grey
  line for a deleted one (decision 3; "3. yes"). That is the wallet's
  part. This server hands out which rows are edits and deletes.
- This server keeps every row for good. Once a message is edited or
  deleted, it no longer hands the old ciphertext out. The old row itself
  still goes out, with its sender, its time and its `position`, so the
  new text or the grey line stays in the old place (decision 4; "4.
  yes").
- An edit within 15 minutes of sending, by this server's clock against
  the message's `created_at`. A delete at any time (decision 5). The
  user: "Alright, that sounds good".
- A person edits and deletes only their own messages (decision 7). The
  creator of a public room may do no more than a member. The user: "Yeah,
  you can only edit or delete your own. We'll talk about something like
  room admins later".
- `lastMessage` of `/list-chat-rooms` is the chat's newest message as it
  stands now: with the newest edit's ciphertext, or marked as deleted. It
  is never an edit or a delete itself. `lastPosition` stays the chat's
  highest position (decision 8). The user: "Sounds good". So in a wallet
  an edit or a delete lights no unread dot, plays no sound and moves no
  chat in the list.
- A message can be edited more than once, each time within 15 minutes of
  when it was first sent (the plan's section 4, point 1). The time is
  compared with the message's own `created_at`, so a second edit needs no
  rule of its own.
- One rule decides which ciphertext is no longer handed out (point 8; the
  rule is in 31.4). It also takes an earlier edit's text out once a newer
  edit is there.
- A delete has no ciphertext (point 9). `message` may be null on a delete
  and nowhere else, and a check in the database holds that.
- Both statements that make `lastMessage` take the new form (point 7), so
  the first read after a login and the read of every 5 seconds show the
  same line for a chat.
- Decision 6, the tap that opens the menu, and the points 2 to 6, 10 and
  11 of the plan's section 4 are the wallet's.
- What this server learns that it did not know: which rows are edits and
  deletes, of which message, by whom and when. It still cannot read a
  message, and an edit is a message's ciphertext like any other. It
  cannot tell a sticker from a text, so "a sticker has no Edit" is the
  wallet's menu alone.

### 31.2 The two columns, the check and the index

`db/schema.sql`, in two places. Inline in the `CREATE TABLE` of
`chat_room_messages`, for a database built from nothing (section 4): the
two new columns after `created_at`, `message` without its `NOT NULL`, and
the named check. And in a new block, the last thing in the file, after
the block of Joy's two tables: "The message edit block (2026-11-24, spec
section 31)", for a database that has the table. The block without its
comments:

```sql
ALTER TABLE chat_room_messages ADD COLUMN IF NOT EXISTS kind TEXT CHECK (kind IN ('edit', 'delete'));
ALTER TABLE chat_room_messages ADD COLUMN IF NOT EXISTS target_message_id BYTEA CHECK (octet_length(target_message_id) = 32);
ALTER TABLE chat_room_messages ALTER COLUMN message DROP NOT NULL;
ALTER TABLE chat_room_messages DROP CONSTRAINT IF EXISTS chat_room_messages_edit_delete_check;
ALTER TABLE chat_room_messages ADD CONSTRAINT chat_room_messages_edit_delete_check
  CHECK ((kind IS NULL) = (target_message_id IS NULL) AND (message IS NULL) = (kind IS NOT DISTINCT FROM 'delete'));
CREATE INDEX IF NOT EXISTS chat_room_messages_target_message_id_idx ON chat_room_messages (target_message_id) WHERE target_message_id IS NOT NULL;
```

| New column | What it holds |
| ---------- | ------------- |
| `kind` | `edit` or `delete`. Null on a message. |
| `target_message_id` | The `message_id` of the message that the edit or the delete is about, 32 bytes. Null on a message. |

So the table holds three kinds of row, and the named check allows these
three and nothing else:

| The row | `kind` | `target_message_id` | `message` |
| ------- | ------ | ------------------- | --------- |
| a message, as every row of before | null | null | the text's ciphertext |
| an edit | `edit` | the message it is about | the new text's ciphertext |
| a delete | `delete` | the message it is about | null |

`chat_room_messages_edit_delete_check` says two things. The two new
columns are set together or not at all. And `message` is null on a delete
and nowhere else: `kind IS NOT DISTINCT FROM 'delete'` is false for a
message, whose `kind` is null, where a plain `=` would give null and let
the row pass. Each new column also has a check of its own, which
PostgreSQL names `chat_room_messages_kind_check` and
`chat_room_messages_target_message_id_check` on both ways. There is no
foreign key (section 1): the two routes keep `target_message_id` to a
message of the same room.

Each row takes its `position` from the table's one identity counter, as
every row does. No trigger and no counter is new. An edit or a delete is
an `INSERT`, so the trigger of section 29,
`chat_room_messages_set_room_message_seq`, raises the room's `message_seq`
for it as for a message: the room's three fields travel once to every
member's wallet with its next read with `since` (31.5).

The index is on `target_message_id`, for the rows that have one: both
reads look up the rows that name a message (31.4, 31.5), and a message's
own row is not in it. The comments of the two columns are in the block
only, like the index: on a live database the columns do not exist before
the block.

The block is idempotent: `ADD COLUMN IF NOT EXISTS`, a `DROP NOT NULL`
that changes nothing on a nullable column, a drop-and-add of the named
check under its one name, as the case chat block does it, and `CREATE
INDEX IF NOT EXISTS`. So the whole file applies to a live database and a
second run changes nothing. On a database of before every row passes the
check: `kind` and `target_message_id` are null, and `message` is not. At
every run of the file the added check reads every row of the table once
(31.9 has the time). The code of before names its four columns in its
`INSERT`, so it runs on the new table. The file makes 47 tables, as
before.

### 31.3 The two new routes

Both are at level setup, as every chat route is (section 2), and a wallet
sends them the way it sends `/send-message`.

**POST /edit-message** (setup). Body:

```json
{ "chatRoomId": "<hex 32 bytes>", "messageId": "<hex 32 bytes>", "message": "<base64>" }
```

`messageId` is the message to edit, and `message` the new text's
ciphertext, with the limits of `/send-message`: base64 of 1 to 65536
bytes.

**POST /delete-message** (setup). Body:

```json
{ "chatRoomId": "<hex 32 bytes>", "messageId": "<hex 32 bytes>" }
```

A body of the wrong shape gets a `400`, as on every route, in this order:
`chatRoomId` and `messageId` are strings, and for an edit `message` is one
too, else `400 bad request shape`; `chatRoomId` decodes to 32 bytes, else
`400 invalid chatRoomId`; `messageId` decodes to 32 bytes, else `400
invalid messageId`; and for an edit `message` is base64 of 1 to 65536
bytes, else `400 message must be base64 of 1 to 65536 bytes`, the words of
`/send-message`. Then six checks, in this order, and the first that fails
answers:

| | The check | When it fails |
| - | --------- | ------------- |
| 1 | The caller is a member of the room. | `403 not a member` |
| 2 | The room is not about a listing (`chat_rooms.listing_id`), is not an old marketplace room (`type = 'marketplace'`) and is not about an attestor case (`case_id`). | `403 editing and deleting are off in this chat` |
| 3 | `messageId` is a message of that room: a row with no `kind`, so not an edit and not a delete. | `404 message not found` |
| 4 | The caller wrote it. | `403 not your message` |
| 5 | No delete names it yet. | `409 message deleted` |
| 6 | Only for an edit: the database's clock is at most 15 minutes past the message's `created_at`. | `409 too late to edit` |

How they run. Checks 1 and 2 are two plain reads, of the member row and
of the room's row. Checks 3 to 6 and the write are one transaction:

1. `SELECT ... FOR UPDATE` reads the message's row, by its id, its room
   and `kind IS NULL`, and locks it until the transaction ends. No row:
   check 3 fails. The same statement works out check 6 inside the
   database, as `now() > created_at + 15 minutes`. `now()` is the clock
   that stamped `created_at`. Three servers run this code, and none of
   their own clocks is asked.
2. The row's sender is compared with the caller (check 4).
3. A second statement looks for a row of the room with `kind` `delete`
   that names the message (check 5).
4. For an edit, the answer of step 1 decides check 6.
5. One `INSERT` writes the new row: a new random `message_id`, the room,
   the caller as sender, the `kind`, the message's id in
   `target_message_id`, and for an edit the new ciphertext. A delete's
   `message` is null. Nothing else is written, and no notification, as
   for a message.

A check that fails inside the transaction ends it with nothing written.

Answer: `201 { messageId, position }`, the new row's id and position, as
`/send-message` answers.

What the lock gives. Two requests about one message go one after the
other: the second waits at step 1 until the first has ended, and then
sees what the first wrote. So of two deletes sent in the same instant one
is written and the other gets `409 message deleted`. Of an edit and a
delete sent in the same instant, the one that reaches the lock first is
written first: when that is the edit, both are written, the edit with the
lower position; when it is the delete, the edit gets `409 message
deleted`. An edit is never written after a delete, so a delete is always
the last row that names a message. The lock is on the message's row
alone. A request about another message does not wait at it, and a read of
the room never waits for it.

What follows from the checks:

- A person who has left a room is no member, so the two routes refuse
  them, and what they wrote there stays as it is. A room that does not
  exist has no member either: `403 not a member`.
- The id of an edit or of a delete is no message (`404 message not
  found`): an edit cannot be edited or deleted by its own id. So is the
  id of a message of another room, also one the caller is in.
- The 15 minutes count from the message, also for a second edit. A
  message that is exactly 15 minutes old can still be edited. The number
  is `EDIT_MINUTES` in `src/chat/chat.service.js`.
- A delete has no time limit.
- Where editing and deleting are off, they are off for every member and
  every message of the room, and check 2 answers before the message is
  looked at.

### 31.4 The changes of `/list-messages`

**POST /list-messages** (setup; section 5). The request is the one of
before: the open chat's read of every 3 seconds with `afterPosition`, and
the read with `beforePosition` when a chat opens and for older messages.
The answer's `messages` now holds every row of the room in the order of
`position`, all three kinds, and each row has two fields more:

```json
{ "messageId", "position", "senderAnopodId", "message", "createdAt", "kind", "targetMessageId" }
```

- `kind`: null on a message, `"edit"` or `"delete"` on a row about one.
- `targetMessageId`: the message an edit or a delete is about, hex; null
  on a message.
- `message`: the ciphertext, base64, or null.

One rule decides about the ciphertext: **a row goes out with `message:
null` once a later row of the room names the same message.** A message is
named by its own id; an edit and a delete name their target. So an edited
or deleted message goes out without its text. An edit goes out without
its text once a newer edit, or a delete, of the same message is there. A
delete never has one. Everything else of such a row goes out as before:
its id, its `position`, its sender and its time.

A message that was edited once, and its edit:

```json
{ "messageId": "a1…", "position": 4102, "senderAnopodId": "9c…", "message": null, "createdAt": "…", "kind": null, "targetMessageId": null }
{ "messageId": "d7…", "position": 4117, "senderAnopodId": "9c…", "message": "…", "createdAt": "…", "kind": "edit", "targetMessageId": "a1…" }
```

The same two rows after the message was deleted, and the delete:

```json
{ "messageId": "a1…", "position": 4102, "senderAnopodId": "9c…", "message": null, "createdAt": "…", "kind": null, "targetMessageId": null }
{ "messageId": "d7…", "position": 4117, "senderAnopodId": "9c…", "message": null, "createdAt": "…", "kind": "edit", "targetMessageId": "a1…" }
{ "messageId": "f3…", "position": 4130, "senderAnopodId": "9c…", "message": null, "createdAt": "…", "kind": "delete", "targetMessageId": "a1…" }
```

What a reader of the answer has to know:

- `afterPosition`, `beforePosition` and `limit` count every row. A page
  of 50 rows can hold fewer than 50 messages.
- A row with no `kind` and no `message` is a message whose text stands in
  a later row, or that is deleted. The row that says which has a higher
  `position`. A wallet reads a chat from its newest rows backwards, so it
  mostly holds that row already. When it does not, because the row was
  written after the position the wallet asked below, or because `limit`
  cut the answer before it, the wallet's next read with `afterPosition`
  brings it (the plan's section 7).
- The reading rule on both sides is the same (the plan's section 7): a
  message is deleted when a delete names it; otherwise its text is the
  newest edit's; otherwise its own.
- The old ciphertext stays in the table. This server hands it to nobody
  any more, a member of the room included.
- `seenSince`, `seen` and `seenSeq` (29.4) are as before. A seen position
  counts every row too: `/mark-messages-seen` raises it up to the room's
  highest position, which can be an edit's or a delete's.

The statement of each of the two reads names the same columns for a row
and, for each row it sends, asks the index of 31.2 once whether a later
row of the room names the same message. An entry is 35 bytes longer than
before (`,"kind":null,"targetMessageId":null`).

### 31.5 The changes of `/list-chat-rooms`

**POST /list-chat-rooms** (setup; section 5; 29.3). The request is the
one of before. Two statements make `lastMessage` and `lastPosition`:
`listRoomsFor`, for a room that is sent whole, and
`listNewestMessagesFor`, for the three fields of a room in which only a
row is new. Until this section both took the row with the room's highest
`position`. Now, in both:

- `lastMessage` is the room's newest message, never an edit or a delete:
  the newest row with no `kind`. It is null for a room without a message.

  ```json
  { "messageId", "position", "senderAnopodId", "message", "createdAt", "editPosition", "deleted" }
  ```

  `messageId`, `position`, `senderAnopodId` and `createdAt` are that
  message's own. `message` is the ciphertext of the newest edit when the
  message was edited, its own when it was not, and null when it was
  deleted. `editPosition` is the `position` of the newest edit, null for
  a message that was never edited. `deleted` is true when a delete names
  the message, else false.
- `lastPosition` is the highest `position` of any row of the room, 0 for
  a room with none, as before.

The message of 31.4, edited once, as its room's newest:

```json
"lastMessage": { "messageId": "a1…", "position": 4102, "senderAnopodId": "9c…", "message": "…", "createdAt": "…", "editPosition": 4117, "deleted": false }, "lastPosition": 4117
```

What a reader of the answer has to know:

- `lastPosition` is above `lastMessage.position` whenever the room's
  newest row is an edit or a delete, of the newest message or of an older
  one. An older message that is edited leaves `lastMessage` as it was and
  raises `lastPosition`.
- A newest message that is deleted stays the room's `lastMessage`, with
  `message` null and `deleted` true. The answer does not go back to the
  message before it.
- `editPosition` stays what it was when an edited message is deleted.
- An edit or a delete raises the room's `message_seq` (31.2). So a read
  with `since` gets that room's three fields once, about 570 bytes with a
  short text, and a read without `since` has the same `lastMessage` in
  the whole room. That is how a wallet's chat list follows an edit.
  Nothing new is needed for it.
- `seq`, `counts`, the invites and the join requests are as in 29.3.

The two statements share one piece of SQL for these fields, and one
function makes the object from a row, so that they cannot come apart. A
`lastMessage` is 36 bytes longer than before
(`,"editPosition":null,"deleted":false`).

### 31.6 What a wallet does with it

The wallet's part is step 2 of the plan and is written in the wallet's
spec. In short, as this server's answers are meant to be read (the plan's
3.5 and section 7):

- In an open chat a message is drawn as a bubble, and an edit or a delete
  never is. The page keeps, for each message, the newest row that names
  it: a delete means the grey line, an edit means the edit's text and the
  word "edited".
- The person's own edit or delete is drawn at once, from the `201`.
  Everyone else gets the row with their next read of the room.
- In the chat list the line under a chat's name is `lastMessage.message`
  decrypted, or "Message deleted" when `deleted` is true. The time and
  the order go by `lastMessage.createdAt`, the message's own time.
- The unread dot goes by `lastMessage`'s sender and `position`, which an
  edit or a delete does not move. The sound has to compare
  `lastMessage.position` where it compared `lastPosition` (the plan's
  section 4, point 6).
- "Seen" under a person's own edited message is counted from the edit's
  `position` (point 5).
- The menu shows only where this server would say yes; a refusal as too
  late or as deleted gets a sentence of the wallet's own.

A wallet of before step 2 passes the new fields over. It meets a row
without ciphertext only once somebody has edited or deleted, which needs
a wallet of step 2. What it then draws is read in the wallet's code by
the plan (its section 4, point 10) and is step 2's to try.

### 31.7 Files

- `db/schema.sql`: in the `CREATE TABLE` of `chat_room_messages` the two
  columns, `message` without `NOT NULL` and the named check; the message
  edit block, new, at the end; the file's opening comment, which names
  the new block among the idempotent ALTERs; and, on the user's word
  after the build, six older comments (31.9).
- `src/chat/chat.queries.js`: `lockMessage`, `messageDeleted` and
  `insertMessageChange`, new, after `insertMessage`; `MESSAGE_ROW_COLUMNS`
  and `messageFromRow`, new, which `listMessages` and `listMessagesBefore`
  now use for their columns and their rows, with the two fields and the
  rule of 31.4; `LAST_MESSAGE_COLUMNS`, `LAST_MESSAGE_JOINS` and
  `lastMessageFromRow`, new, which `listRoomsFor` and
  `listNewestMessagesFor` now use in place of their own copies of the
  join of the newest row; the comments of these four functions, and a
  sentence in the comment of `raiseSeenPosition`.
- `src/chat/chat.service.js`: `editMessage` and `deleteMessage`, new,
  after `sendMessage`, and `changeMessage`, which holds what the two
  share; the constants `EDIT_MINUTES` and `EDITS_OFF`; three imports; the
  file's opening comment; and a sentence in the comments of `listRooms`,
  `listRoomMessages` and `markSeen`.
- `src/chat/chat.handlers.js`: `editMessageHandler` and
  `deleteMessageHandler`, new, after `sendMessageHandler`, and the two
  imports.
- `src/chat/chat.router.js`: the two routes' lines after `/send-message`,
  the two imports, and "eighteen" in the comment.
- `src/app.js`, on the user's word after the build: "eighteen" in the
  comment on the chat router's line. No line of code.
- Here: section 4 (`### chat_room_messages`: the new columns and the
  check in the SQL and a paragraph), section 5 (`### POST
  /list-chat-rooms`: a dated paragraph; `### POST /list-messages`: the
  two fields in the answer and a dated paragraph), 29.3 (a dated clause
  on `lastMessage`) and this section. `README.md`: the rows of
  `/edit-message` and `/delete-message` in the Endpoints table, after
  `/send-message`; and, on the user's word after the build, five older
  places (31.9).

Nothing else in existing code changes: not `insertMessage` and
`sendMessage`, not `raiseSeenPosition` and `lastPosition`, which count
every row of a room and stay as they are, no line of code in
`src/app.js`, not `package.json`, not `.example.env`. Two columns, one check, one index and
two routes; no table, no trigger, no counter, no env variable, no npm
package.

### 31.8 What is left as it is

The plan's section 6, as far as it is this server's:

- The `refuse_change` trigger on `chat_room_messages`. The database
  itself would still take an `UPDATE` or a `DELETE` of a row: only this
  server's code never sends one. On the user's word ("Add that to the
  after production todos list") it is the line "chat messages: the
  database itself does not refuse a change" in
  `~/Desktop/Z-TestNet/after_production_todos/things-to-do-after-production.md`.
- Room admins. Nobody edits or deletes another person's message, a
  public room's creator included. It is the block "Room admins, added
  2026-11-24" under the line "chat rooms: nobody can be taken out" of
  the same list.
- Replying to a message: the line "chat: reply to a message, and the
  three options on a phone" of the same list. A reply is also a message
  that names another message, so `target_message_id` could serve it
  later. Nothing of it is built here, and the reading rule of 31.4 would
  have to leave a reply out.
- A history of a message's earlier texts. This server keeps the rows and
  hands the old ciphertext to nobody.
- Taking a text back from someone who has read it. A wallet that had the
  chat open has the old text, and this server cannot take it away.
- Editing or deleting after leaving a room, and in the three kinds of
  room of 31.1.
- The gap of 29.7: of two rows written in the same instant, a wallet can
  miss one. An edit and a delete are rows like any other. A wallet that
  misses one keeps the old text, or leaves that message out, until the
  chat is opened again. It is the line "chat: of two changes written at
  the same instant, a phone can miss one" of the same list.
- A limit on how many edits one message takes in its 15 minutes. Each
  edit is a row, and nothing limits how many requests one person sends,
  messages included: the line "limits against flooding" of the same
  list.

### 31.9 Notes from the build

#### Build 1, the masterpod (2026-11-24)

Built from `~/Desktop/Z-TestNet/forclaude/chat-edit-delete-plan-1.md`,
its sections 3.1 to 3.4, the points 1, 7, 8 and 9 of its section 4, step
1 of its section 5 and its section 7, on main at 5ca9e41, the working
tree clean. The plan holds no code, so all of the code is the build's. No
new npm package, and no test script in the repo. The schema was not
applied to any database of the network: the user applies the whole file
as section 6 of `forclaude/masterpod-deploy-plan-1.md` says, on the
leader, and then pulls and restarts the three servers, the leader last.
The file goes on before the new code runs. On a database without the
block the built code fails every `/list-messages` and every
`/list-chat-rooms` that has a room to send: the chat would be down for
everybody until the block is there. The other order is safe: the code of
before names its columns and never looks at the new ones. Both were tried
(below). What the plan left open and how it was decided:

- The number and the date. The plan says "a new section 30": 29 was the
  last section when it was written. Joy's build took 30 a few hours
  later the same day (5ca9e41), so this section is 31, the next free
  number on the build day. The wallet's spec has the same thing: the
  plan's "a new 4.18" is taken by Joy there. The date is 2026-11-24, the
  day of the build and of the plan's FINAL.
- The block's name, "The message edit block". The file's opening comment
  lists the blocks whose ALTERs change a table that exists; the plan
  says the new one joins that list, and it does.
- The columns inline. The two new columns are the last of the table on
  both ways, so a database built from nothing and one that got the block
  hold their columns in the same order. The line of `message` lost its
  `NOT NULL` and nothing else.
- The check. The plan asks for a check that `message` is null on a
  delete and nowhere else. The one named check also holds that `kind`
  and `target_message_id` are set together: the plan's 3.1 says so of
  the three kinds of row, and it costs nothing more. It reads both ways:
  a delete has no ciphertext, and every other row has one. Its name is
  not `chat_room_messages_message_check` or
  `chat_room_messages_kind_check`: PostgreSQL gave those to the columns'
  own checks. It is dropped and added at every run, as
  `chat_rooms_case_check` and `notifications_kind_check` are, which is
  the file's way to make a named check idempotent.
- The index is partial, `WHERE target_message_id IS NOT NULL`, as
  `chat_rooms_listing_id_idx` is: "for the rows that have one".
- `400 invalid messageId`. The plan's table has the six refusals and
  says that a body of the wrong shape gets a `400`. A `messageId` that
  is no id is answered like a `chatRoomId` that is none, in the words of
  the neighbours `/send-message` and `/list-messages`.
- Check 2 reads the room after the member check. A room that does not
  exist never gets there: it has no member.
- Checks 3 and 4 run inside the transaction too, with the locked row,
  though the plan asks that only of check 5: one read of the message's
  row serves checks 3, 4 and 6, and it has to be the locked one.
- The 15 minutes. `now()` is the moment the request's transaction began,
  the same function that stamps `created_at`. A request that waits at
  the lock for another one is judged by the moment it began. The
  comparison is `now() > created_at + 15 minutes`: exactly 15 minutes is
  still in time.
- "An edit and a delete of one message that arrive in the same instant
  cannot both pass" (the plan's section 7) is read as 31.3 tells it: the
  one that reaches the lock first is written first, and an edit that
  comes second is refused. A delete that comes second, after an edit, is
  written: the plan's check 5 asks only that no delete names the message
  yet. What cannot happen is an edit after a delete, or two deletes.
- `editPosition` of a deleted message. The plan gives `editPosition` as
  "the `position` of the newest edit, `null` for a message that was
  never edited". A deleted message that was edited keeps it.
- "Names the same message" is read within the room, as the plan's rule
  says ("a later row of the chat"): each of the three lookups also
  compares `chat_room_id`. The routes write an edit or a delete only
  into its message's room, so this changes no answer.
- One piece of SQL for a row and one for `lastMessage`. `listMessages`
  and `listMessagesBefore` each had their own copy of the columns and of
  the lines that make a row's object, and so had `listRoomsFor` and
  `listNewestMessagesFor` for the newest row (29.8). Each pair now uses
  one constant and one function of the file, in the manner of
  `ROOM_LISTING_COLUMNS` and `listingFromRow`, because the plan's point
  7 wants the two statements to give the same `lastMessage`. In
  `listRoomsFor` the join of the newest row now names the room through
  the member row (`cm.chat_room_id`), which is the same room.
- Three lookups for `lastMessage` where there was one: the room's
  highest position, its newest row with no `kind`, and that message's
  newest edit and its delete, the last two through the new index. The
  newest message is found by walking back from the room's newest row
  past the edits and deletes above it.
- `insertMessage` is untouched, and `insertMessageChange` beside it
  writes the six columns of an edit or a delete.
- Here and in the README. In section 4 the SQL of `###
  chat_room_messages` is the file's, with one paragraph at the end of
  the entry. In section 5 the answer of `/list-messages` names the two
  new fields, and both entries end with a dated paragraph. In 29.3 the
  clause stands in brackets after the sentence on the three fields.
  Section 5 has no entry of its own for the two new routes: the plan
  names the dated clauses of the two reads there, and the two routes
  are in 31.3, as Joy's three routes are in 30.4 alone. The README's two
  new rows follow the row of `/send-message`.
- Places the plan does not name that this step leaves saying less than
  is true. In the four files of `src/chat/`, which the plan names whole,
  the build brought the comments in line: the comments of `listRooms`,
  `listRoomMessages`, `markSeen` and `raiseSeenPosition` each gained a
  sentence, and no line of their code changed. In the files that the
  plan names with their places, or does not name, twelve sentences were
  left as they are and asked about in the build's report. In
  `src/app.js`, the comment on the chat router's line ("the sixteen chat
  routes"). In `README.md`, five: the `chat/` line of the Layout ("the
  sixteen chat routes"); in "Database tables" the row of
  `chat_room_messages` ("Ciphertext messages, numbered by `position`")
  and the row of `chat_rooms` ("the counter's value at the room's last
  message"); and in the Endpoints table the rows of `/list-messages` and
  `/list-chat-rooms`, which do not know the edits and the deletes. In
  `db/schema.sql`, six comments: of the table `chat_room_messages`
  ("Messages, ciphertext under the room key"), of its `position`
  ("Counts up with every message written") and of its `message`, which
  does not say that it is null on a delete; of `chat_rooms.message_seq`
  and, in the chat change block's opening comment, the sentence on it
  ("when a message is written in the room": an edit or a delete raises
  it too); and of `chat_room_members.seen_position` ("never above the
  room's newest message": the newest row can be an edit or a delete).
  Read for it: every sentence of this file, of the README, of `src` and
  of the schema file that names `/list-messages`, `/list-chat-rooms`,
  `/send-message`, `/mark-messages-seen`, `lastMessage`, `message_seq`
  or `chat_room_messages`. Sections 21 and 29 say what their own builds
  changed and stay as records, but for the one clause in 29.3. (The
  twelve were brought in line the same day, on the user's word: "After
  the build's report", below.)

The checks. All of them ran from empty databases on the files as they
were handed over. The tools are outside the repo, in the build chat's
scratch folder, and none of them is kept in it.

- The code. `node --check` on the four changed files, clean, on Node
  24.22.0. One load of the app with no server and no database
  (`createApp()` with made-up settings): 117 routes, eighteen of them
  the chat's; a copy of 5ca9e41 gave 115 and sixteen the same way. A
  type checker's read of `src/app.js` (`tsc --checkJs`, TypeScript 6.0.3
  from the wallet's folder) named no unknown name, no wrong count of
  arguments and no missing export or module, and in the four chat files
  no kind of finding that the same read of 5ca9e41 does not have, apart
  from "implicitly has an 'any' type".
- The scratch PostgreSQL. A PostgreSQL 17.11 that was started for this
  build alone: a data folder of its own in the build chat's scratch
  folder, listening on 127.0.0.1 port 62731 and nowhere else, with no
  socket file. This Mac's own PostgreSQL on port 5432 was not touched.
  Every apply of a schema file ran as the deploy's line runs it: one
  transaction after `SET ROLE masterpodsoftware`, into a database that
  the role owns. Every tool that uses this server's pool stops before
  its first query unless the pool's host and port are the scratch
  PostgreSQL's.
- A database as it is live today. The file of 5ca9e41 into an empty
  database: 47 tables. It was then filled through that commit's own
  routes, over HTTP with signed requests: seven pods and, between them,
  a chat of two, a group, a public room with a picture, a chat about a
  listing, a chat with an open invite and a chat with no message. Two
  old marketplace rooms, one of them with its listing, and a chat about
  an attestor case were written by SQL, with two members and two
  messages each: no route makes a marketplace room any more, and a case
  chat needs an appointed attestor and an open case. 9 rooms and 18
  messages.
- The schema file. The new file on top of that database: 47 tables. One
  md5 over every column, constraint, index, trigger, function, sequence,
  comment and owner of the schema came from 1,266 lines before and from
  1,274 after: 8 are new, the 2 columns, their 2 checks, the named
  check, the index and the 2 comments, and six changed, `message` from
  not nullable to nullable and the five older comments of "After the
  build's report", below. One md5 over every message row's
  id, position, sender, ciphertext and time was the same before and
  after: no row was touched. The new file once more: both md5 the same.
  The new file alone into a second empty database, twice: 47 tables and
  that same md5 of the catalog, both times. The check by hand on that
  empty database, ten inserts: a message with ciphertext, an edit with
  ciphertext and a delete without were taken; a message without, an
  edit without, a delete with ciphertext, a `kind` without a target and
  a target without a `kind` were refused by the named check, another
  `kind` and a target of 31 bytes by the columns' own.
- The two half-deployed states, each with the real app over HTTP and
  signed requests. The built code on the tables of before:
  `/list-messages` answered `500` (`column m.kind does not exist` in the
  server's log); `/list-chat-rooms` answered `500` with no `since` and
  with a `since` below a room's number (`column msg.kind does not
  exist`), and `200` with a `since` and nothing new, which is the one
  statement that names no new column; `/edit-message` and
  `/delete-message` answered `500`; `/send-message`,
  `/mark-messages-seen` and `/list-public-chat-rooms` answered. So the
  schema line goes first. The code of 5ca9e41 on the new tables: a
  message sent (`201`; its row has no `kind`, no target and a
  ciphertext), read back by `/list-messages` with the five fields of
  before, named by `/list-chat-rooms` as `lastMessage` in the form of
  before, and marked seen; `/edit-message` answered `404`, since that
  code has no such route.
- A wallet of today, with no edit and no delete in the table. The code
  of 5ca9e41 and the built code were started in one process on one
  database and asked the same as the same seven pods.
  `/list-chat-rooms` with `{}` and with `since` 0: the built code's
  answer is the answer of before, byte for byte, with
  `,"editPosition":null,"deleted":false` in each `lastMessage`, 36 bytes
  for each chat that has a message. `/list-messages` in four forms of
  the request for each of 16 memberships: the answer of before, byte for
  byte, with `,"kind":null,"targetMessageId":null` in each row, 35 bytes
  a row.
- The walk. The built code on the updated database, over HTTP with
  signed requests. 95 results, none bad. Before any edit: both reads
  carry the new fields with nothing in them, in the plan's order. Twelve
  bodies of the wrong shape: each its `400`, nothing written. Check 1: a
  pod outside the chat, and a chat that does not exist. Check 2: an edit
  and a delete of one's own message in a chat about a listing, in an old
  marketplace room without and with its listing, and in a chat about an
  attestor case, each `403 editing and deleting are off in this chat`,
  the rows as they were. Check 3: an id that names nothing, one's own
  message of another chat, an edit's id and a delete's id. Check 4: the
  other person's message, and a public room's creator on a member's
  message. An edit: `201` with the new row's id and a higher position;
  the new row in the table an edit that names the message, by the
  caller, with the new ciphertext; the message's own row in the table
  as it was, with its old ciphertext; no notification. The other
  person's read with `afterPosition`: the edit alone. The whole read:
  the message's row still there, with its sender, time and position and
  without ciphertext, every other row with its own. `/list-chat-rooms`:
  `lastMessage` the message itself with the edit's ciphertext and
  `editPosition`, `lastPosition` the edit's; with `since` that chat
  alone as three fields with the same `lastMessage`; nothing else of the
  chat's entry changed; nothing for a pod outside. A second edit: the
  first edit goes out without ciphertext and is still in the table;
  `lastMessage` has the second's. A seen position rises to an edit's
  position. A delete: `201`; a row with no ciphertext; the three
  ciphertexts still in the table; the whole read hands all four rows
  out without ciphertext; `lastMessage` the message itself with
  `message` null, `deleted` true and the `editPosition` of before.
  Check 5: an edit and a delete of a deleted message. Check 6: an edit
  of a message whose `created_at` was set back 16 minutes, refused;
  set back 14 minutes, taken, and refused again at 16, since a second
  edit goes by the message's own time; a delete at 16 minutes and one
  at 400 days, taken. The order of the checks where two fail at once,
  five pairs. An older message edited: `lastMessage` stays the newest
  message as it was and `lastPosition` is the edit's; then deleted;
  then the newest message deleted with no edit before (`editPosition`
  null, `deleted` true); then a new message. `beforePosition` with a
  limit of 3: two deletes and a message. An edit and a delete in a
  public room by the member who wrote the message. A person who left a
  chat: both refused. An edit of 65536 bytes taken, one of 65537
  refused. At the end both reads of every chat of every pod were
  worked out again from the table's rows by the plan's rule and were
  equal, and both statements gave the same `lastMessage`.
- An edit and a delete in the same instant. With two transactions held
  open and the routes' own statements: a second request about the same
  message waited at the lock before it had looked for a delete, and,
  once the first was committed, saw the delete the first had written;
  a read of the chat did not wait; a request about another message of
  the chat did not wait at the lock, and its write waited for the first
  one's write, as two messages sent in one chat do (29.2); a request
  about a message of another chat waited for nothing. Then the real
  routes over HTTP, 100 rounds, each with five messages changed at the
  same moment through the app's pool of ten connections. An edit and a
  delete of one message at once, 200 times: the delete was written
  every time, and the edit was written before it, with the lower
  position, or refused as deleted, about half and half. Two deletes at
  once, 100 times: one `201` and one `409 message deleted`. Four edits
  and two deletes at once, 100 times: one delete written, every written
  edit below it. The table afterwards: 402 deleted messages, none with
  two deletes, none with an edit above its delete; PostgreSQL's own
  count of deadlocks 0. The same rounds against a scratch copy of the
  code with `FOR UPDATE` taken out came out bad: 180 messages with two
  deletes and 176 with an edit after the delete. So the rounds notice a
  missing lock, and the lock is needed.
- Random people. Five rounds of 3,000 steps with five seeds, over HTTP
  with signed requests: seven people send messages, messages get 16
  minutes old, and a random person asks for an edit or a delete of a
  random row of a random chat, or of an id that names nothing. A script
  holds the six checks in their order and says for each request what
  the answer must be. 9,587 requests, none answered otherwise: 976
  written, 1,800 `not a member`, 3,417 off in that chat, 1,902 `message
  not found`, 957 `not your message`, 345 `message deleted`, 190 `too
  late to edit`. After each round the table held exactly the rows the
  script had counted, no edit or delete stood in one of the three kinds
  of chat, and both reads of every chat equalled the rule worked out
  from the table.
- Many rows. A database with 20,000 rooms, 100,000 member rows and
  400,000 messages, 100,000 of them in one room; the table with its
  index is 149 MB. The schema file's first run on it took 0.7 seconds
  at one try and 0.9 at another, psql's start included, and a later run
  0.11 seconds, where the file of before takes 0.07 on tables that have
  it. For that time the table is held and requests wait. Of a later
  run, the dropped and added check is 24 milliseconds, one read of the
  400,000 rows. The same
  reads by the code of 5ca9e41 and by the built code, with no edit and
  no delete in the table, each the middle of five turns of 100 calls of
  the route's own function, on this Mac, the database on the same
  machine and no PgBouncer between: the whole list of a pod in 50 rooms
  2.06 milliseconds before and 2.33 now; the three fields of its 50
  rooms 0.25 and 0.41; the newest 50 rows of the room of 100,000
  messages 0.16 and 0.19; 200 rows from its middle 0.43 and 0.46; a
  read with nothing new 0.05 and 0.07. Then 44,000 edits and 20,000
  deletes were written into it by SQL, 16,000 of them above the newest
  message of the room of many rows: the index on `target_message_id` is
  3.7 MB for the 64,000 rows; PostgreSQL planned no walk through the
  whole table for any of the four statements, each lookup goes through
  one of the two indexes; that room's three fields took 1.1
  milliseconds, against 0.19 for a room of 15 messages, which is the
  walk back past 16,000 rows; and both reads of all 50 rooms of that
  pod, 116,750 rows, equalled the rule worked out from the table.
- The way back, for the day it is asked. The code of 5ca9e41 on a table
  that holds an edit answers: it hands the message out with its old
  ciphertext and the edit as a second message. On a table that holds a
  delete it answers `500` for that chat's `/list-messages`, and `500`
  for `/list-chat-rooms` of every member of that chat for as long as
  the delete is the chat's newest row (`Cannot read properties of null`
  in the server's log): that code takes every row for a ciphertext. So
  once a wallet of step 2 has been in use, this server cannot go back
  to the code of before this step without that. Until then no delete
  is in the table, and the way back is as for any update.
- The lines for the servers, in stand-in form on the scratch
  PostgreSQL, with a copy of a local file in place of the download.
  Every line's syntax was read by bash and by dash. The schema line
  carries the whole hash of the new file and prints `OK`, 47, the
  apply's 586 lines, 47, the owner, 2 for the new columns and 1 for the
  new index; a second run prints the same; with the file of before as
  the download it prints `FAILED` and applies nothing. The look line
  asks a server's own port for `/delete-message` with the body `{}`:
  the built code answers `{"error":"bad request shape"}` and the code
  of before `{"error":"Not Found","path":"/delete-message"}`. None of these lines
  has run on a server.
- Not tried by the build. Nothing on a server, nothing on Linux,
  nothing on PostgreSQL 16, which the servers run (the block uses
  nothing newer than the file had), and nothing through PgBouncer.
  `src/server.js` was not booted: the app was started by `createApp()`.
  No wallet called the routes: the wallet's part is step 2, and what a
  wallet of before draws for an edit and a delete (the plan's section
  4, point 10) is that step's to try. The gap of 29.7 was not tried
  for.
- Not touched: `insertMessage` and every route of before but the two
  reads, `src/app.js` but for one word of a comment (below),
  `src/marketplace/`, every other feature folder,
  `package.json`, `.example.env`, the scripts. Nothing between a wallet
  and this server names a path: the wallet's server program forwards
  everything under `/api/masterpod` (read at web_app 6aee7e7), and the
  written copy of the doormen's file has no rule by path (the plan's
  section 7; not read again by the build).
- The numbers. `db/schema.sql` has 1914 lines, 38 more than before, and
  its sha256 begins 90711297, with the six comments of "After the
  build's report", below. Before the step it had 1876 lines and its
  sha256 began 9ae0fd66. It makes 47 tables, as before: the count that
  the deploy's schema line prints does not change with this step, so
  that line also counts the two new columns and the new index.

#### After the build's report, the same day (2026-11-24)

The user read the report in the build chat. It listed the twelve
sentences above, with the advice to bring them in line before the commit.
The user: "go ahead and do the updates to the files and then bring me the
new paste to commit". So the twelve were brought in line before the
commit, by a small script that changes an old sentence only where it
stands exactly once. None of this is in the plan, and no line of code
changed.

- `src/app.js`, the comment on the chat router's line: "owns the eighteen
  chat routes".
- `README.md`, five places. The `chat/` line of the Layout: "the eighteen
  chat routes". In "Database tables", the row of `chat_room_messages`
  names the edits and the deletes, each a row of its own, and says that
  no row is ever changed or removed; the row of `chat_rooms` says that
  `message_seq` follows an edit and a delete too. In the Endpoints table
  the rows of `/list-messages` and `/list-chat-rooms` each gained a
  clause that begins "since section 31".
- `db/schema.sql`, six comments. Of the table `chat_room_messages`: the
  edits and the deletes, each a row of its own, and that no row is ever
  updated or deleted. Of its `position`: it counts up with every row
  written. Of its `message`: a message's text or an edit's new text,
  null on a delete and nowhere else. Of `chat_rooms.message_seq`, and
  the sentence on it in the chat change block's opening comment, which
  is one line longer for it: an edit or a delete raises it too. Of
  `chat_room_members.seen_position`: never above the room's newest row,
  which can be an edit or a delete. Five of the six are `COMMENT ON`
  statements, so the deploy's schema line writes the new words into the
  database. No statement was added or taken away.
- Checks. All of them ran again from empty databases on the files as
  they now stand, and the list above has what this last run gave. A
  `diff` against the files as the report had handed them shows 12 lines
  out and 13 in, in these three files, every one a comment or a line of
  the README, and none in `src/chat/`. `node --check` on `src/app.js`,
  clean.
- The numbers. `db/schema.sql` has 1914 lines, one more than the report
  handed, and its sha256 begins 90711297, where it began a495bdc1. The
  deploy's schema line carries the new hash; the line of the build's
  report would print `FAILED` and apply nothing. One commit carries the
  build and this: eight files, the seven of the build and `src/app.js`.
