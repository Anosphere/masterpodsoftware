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
  plaintext.
- Every table has `created_at`, and `updated_at` with the `set_updated_at`
  trigger unless the rows never change (then `created_at` only). Every table
  and column gets a `COMMENT ON`. No foreign keys, as in anossoftware; the
  services keep the references straight.
- Errors are `{ error: '<reason>' }` with `400` for a bad shape or value,
  `401` for anything wrong with the signature or the session, `403` for a
  caller who may not do this, `404` for a thing that does not exist, `409`
  for a conflict with what is already there. Reasons are short lowercase
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
| none | Plain JSON body, no signature. | `/challenge`, `/check-username`, `/get-anopod-session-keys`, `/get-anos-account`, and `/create-anopod`, `/unlock`, which are signed by the ephemeral keys inside them |
| session | Signed by the pod's current ephemeral keys (section 3). Vouched or not. | `/search-usernames`, `/send-vouch-request`, `/check-anopod-status`, `/list-notifications`, `/mark-notifications-read`, `/get-anopod-profile` |
| vouched | session, and `anopods.vouched` is true. | `/list-vouch-requests`, `/approve-vouch-request`, `/decline-vouch-request`, `/complete-setup`, `/add-to-security-bucket-one`, `/add-to-security-bucket-two`, `/list-security-records` |
| setup | vouched, and setup is complete (`anopod_encryption_key_blob_2` is set, so the pod has chat keys). | every chat and marketplace route; `/create-anos-account`, `/mark-anos-account-submitted`, `/list-anos-accounts`; the six wallet memory routes, `/add-noted-transaction` to `/set-wallet-settings` (2026-11-07); the person's two break-glass routes, `/file-break-glass-moves` and `/list-my-break-glass-moves` (2026-11-08, section 14); the six DAO routes, `/create-dao-proposal` to `/list-dao-votes` (2026-11-08, section 15) |

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
`CHALLENGE_SECONDS` (120) in the `challenges` table and is deleted inside the
transaction that uses it.

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

One row per anoPod: profile, the one passkey, the one live session, vouch
state, and the key material that arrives at setup. The eight setup columns
(`identity_blob` added 2026-10-25 for the wallet) are all null until
`/complete-setup` and all set afterwards; the `num_nulls` check enforces
that. `vouched_by` on the seed tables is text so it can hold
either a hex anopod id or the word `genesis`.

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
  purpose    TEXT        NOT NULL CHECK (purpose IN ('create', 'unlock')),
  anopod_id  BYTEA       CHECK (octet_length(anopod_id) = 32),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Single use. For `create`, `anopod_id` is the id the server minted for this
sign-up; it becomes the row's id at the write. For `unlock` it is null.
Issuing a challenge also deletes the expired ones.

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
                        'joinRequest', 'joinApproved', 'joinDeclined')),
  reference_id        BYTEA       NOT NULL CHECK (octet_length(reference_id) = 32),
  read_at             TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notifications_anopod_id_created_at_idx ON notifications (anopod_id, created_at DESC);
```

`notification_number` is the row's random id. `reference_id` says which
thing (section 6). Read, never deleted.

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
halves under the pod's encryption key (which this server cannot open), the
signed creation as it went to the validator, and when a validator answered
it. No foreign keys, never deleted. The masterpod never verifies anos
signatures; the validators do.

```sql
CREATE TABLE IF NOT EXISTS anos_accounts (
  account_id   BYTEA       PRIMARY KEY CHECK (octet_length(account_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  account_type TEXT        NOT NULL CHECK (account_type IN ('spending', 'guarded', 'vault', 'assisted')),
  key_blob     BYTEA       NOT NULL CHECK (octet_length(key_blob) <= 1024),
  creation     JSONB       NOT NULL,
  submitted_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS anos_accounts_anopod_id_idx ON anos_accounts (anopod_id);
```

`account_id` is the SHA-256 of key1 + postQuantumKey1, as the validators
compute it. `key_blob` is 156 bytes in practice (section 7). `submitted_at`
is null until `/mark-anos-account-submitted`. Since 2026-11-10 the account
limit counts a pod's rows by `created_at`: at most 20 in the last 30 days
(section 17).

### noted_transactions

Added 2026-11-07 for the wallet (its spec, section 4.6). One row per ledger
transaction a pod noted for its tax records: the ledger's own facts in the
clear (the transaction, the pod's account, the other side as the wallet
shows it, the position, the time, the amount of anos and whether they left
the account), since the masterpod already links a pod to its accounts and
every validator holds the chain; and the private part, the kind, the money,
the currency, the memo and the tag, as one blob under the pod's encryption
key, which this server cannot open. One note per pod and transaction,
enforced by the unique rule. The ledger facts never change after the row is
written, only the blob; the row is deleted when the person removes the
note. Stand-alone: no foreign keys.

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
  UNIQUE (anopod_id, transaction_id)
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
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((type = 'public') = (name IS NOT NULL))
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

### chat_room_members, chat_hpke

```sql
CREATE TABLE IF NOT EXISTS chat_room_members (
  chat_room_id BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
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

### chat_room_invites, chat_room_join_requests

```sql
CREATE TABLE IF NOT EXISTS chat_room_invites (
  invite_id      BYTEA       PRIMARY KEY CHECK (octet_length(invite_id) = 32),
  chat_room_id   BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id_from BYTEA       NOT NULL CHECK (octet_length(anopod_id_from) = 32),
  anopod_id_to   BYTEA       NOT NULL CHECK (octet_length(anopod_id_to) = 32),
  hpke_key       BYTEA       NOT NULL CHECK (octet_length(hpke_key) <= 4096),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (chat_room_id, anopod_id_to)
);
CREATE INDEX IF NOT EXISTS chat_room_invites_anopod_id_to_idx ON chat_room_invites (anopod_id_to);

CREATE TABLE IF NOT EXISTS chat_room_join_requests (
  join_request_id BYTEA       PRIMARY KEY CHECK (octet_length(join_request_id) = 32),
  chat_room_id    BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id       BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (chat_room_id, anopod_id)
);
```

An invite carries the wrapped room key until it is answered; accept moves
it into `chat_hpke`, decline drops it. A join request carries nothing; the
creator's approval brings the wrapped key.

### chat_room_messages

```sql
CREATE TABLE IF NOT EXISTS chat_room_messages (
  message_id       BYTEA       PRIMARY KEY CHECK (octet_length(message_id) = 32),
  chat_room_id     BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  sender_anopod_id BYTEA       NOT NULL CHECK (octet_length(sender_anopod_id) = 32),
  position         BIGINT      GENERATED ALWAYS AS IDENTITY,
  message          BYTEA       NOT NULL CHECK (octet_length(message) <= 65536),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS chat_room_messages_room_position_idx ON chat_room_messages (chat_room_id, position);
```

`message` is ciphertext under the room key. `position` orders messages and
drives pagination (`afterPosition`). The sender is the verified caller;
there is no per-message signature, by decision.

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
both rows.

## 5. Routes

Every route is a `POST` with a JSON body. Level `none` routes take the body
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
   `selfie` decodes within the image rules. `409 username taken`, else
   `400` with the field.

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

Body: `{ type, name, hpkeKey, listingId }`: `type` is `private` or `public`;
`name` required for `public`, absent for `private`; `hpkeKey` is the
creator's own wrapped copy of the new room key (section 7); `listingId`
(optional, 2026-11-06) is the listing a `private` room is about: how a
person connects with a listing's owner. The room is made, then the owner is
invited with /invite-to-chat-room as for any private room, and accepts or
declines the invite.

Checks for `listingId`, after the existing ones: `type` is `private` (`400
public rooms have no listing`); the listing exists (`404 listing not
found`) and is open (`409 listing closed`); the caller is not its owner
(`400 your own listing`); the caller has no room about it yet, a room it
created with this `listing_id` (`409 room already open`).

Writes: `chat_rooms` (with `listing_id` when given), `chat_room_members`
(creator), `chat_hpke` (creator).

Answer: `201 { chatRoomId }`.

### POST /invite-to-chat-room (setup)

Body: `{ chatRoomId, anopodIdTo, hpkeKey }`.

Checks: the room exists and the caller is its creator (`403 only the
creator invites`); the room is `private` or `public` (`400 marketplace
rooms take join requests`); the target exists and has completed setup
(`409 invitee has no chat key`); the target is not a member (`409 already a
member`); no open invite to the target for this room (`409 invite already
open`).

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

Body: `{}`.

Answer:

```json
{
  "rooms": [ { "chatRoomId", "type", "name", "listingId", "listing", "creatorAnopodId", "hpkeKey",
               "members": [ { "anopodId", "username" } ], "invited": [ { "anopodId", "username" } ],
               "lastMessage", "lastPosition", "createdAt" } ],
  "invites": [ { "inviteId", "chatRoomId", "type", "name", "listingId", "listing", "from": profile, "createdAt" } ],
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

### POST /list-public-chat-rooms (setup)

Body: `{ limit, offset }`, optional, defaults 50 (max 200) and 0.

Answer: `200 { rooms: [ { chatRoomId, name, creator: profile, memberCount,
createdAt } ] }`, type `public` only, newest first.

### POST /list-messages (setup)

Body: `{ chatRoomId, afterPosition, beforePosition, limit }`;
`afterPosition` defaults to 0, `limit` to 100 (max 200). `beforePosition`
is optional, 1 or more: when it is given, the answer is the newest `limit`
messages whose position is below it, and `afterPosition` is ignored (`400
invalid beforePosition` for a bad value); this is how a room opens at its
newest messages and loads older ones (2026-11-05).

Checks: the caller is a member (`403 not a member`).

Answer: `200 { messages: [ { messageId, position, senderAnopodId, message,
createdAt } ] }`, ascending by position, `position` as a number.

### POST /send-message (setup)

Body: `{ chatRoomId, message }`, `message` base64 of at most 65536 bytes.

Checks: member (`403 not a member`).

Writes: `chat_room_messages`.

Answer: `201 { messageId, position }`.

### POST /get-chat-public-keys (setup)

Body: `{ anopodIds: [ ... ] }`, 1 to 50.

Answer: `200 { keys: [ { anopodId, chatPublicKey, chatPublicKeyPq } ] }`,
only for pods whose setup is complete; the others are left out.

### POST /create-listing (setup)

Body: `{ side, quantity, currency, country, price }`: `side` `buy` or
`sell`; `quantity` a decimal string of millionths of an anos, above zero;
`currency` three uppercase letters; `country` two uppercase letters; `price`
a decimal string, above zero, at most 8 decimals. `hpkeKey`, the owner's
wrapped copy of a room key, is optional since 2026-11-06 and ignored when
present (a string, else `400 bad request shape`), so an older client still
gets its listing.

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
key the `keyBlob` is under exists.

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
this transaction (`409 already noted`), the unique rule as the backstop (a
unique violation on the insert answers the same `409`).

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
`to`, newest `transacted_at` first, then the highest `position`, 1001 rows
at most.

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

Every notification is written inside the transaction of the event it
reports. The phone polls `/list-notifications` and marks what it has shown.

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
| anos `keyBlob` (2026-10-25) | key1 scalar (32) `\|\|` postQuantumKey1 seed (32) `\|\|` key2 scalar (32) `\|\|` postQuantumKey2 seed (32) under the encryption key: 156 bytes; opened only to sign |
| `noteBlob` (2026-11-07) | a JSON object `{ v: 1, kind, money, currency, memo, tag }` as UTF-8 under the encryption key; a few hundred bytes; the wallet's `wrapJson` |
| `settingsBlob` (2026-11-07) | a JSON object `{ v: 1, protect }` under the encryption key; the wallet's `wrapJson` |

Keys live in RAM and die with the tab. Nothing secret is stored on the phone.

## 8. Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `WEB_ORIGIN` | `http://localhost:4200` | The web app's origin: CORS allow-list and the WebAuthn expected origin |
| `RP_ID` | `localhost` | WebAuthn relying party id |
| `EPHEMERAL_KEY_HOURS` | `12` | Life of a session's ephemeral keys |
| `CHALLENGE_SECONDS` | `120` | Life of a challenge |
| `TIMESTAMP_WINDOW_SECONDS` | `120` | Allowed clock difference on a signed request, each way |
| `MAX_IMAGE_BYTES` | `10485760` | Largest image, decoded |
| `MAX_IMAGES_PER_REQUEST` | `5` | Images per bucket request |
| `VALIDATOR_URLS` | `http://localhost:3001` to `3005` | The validators asked for the DAO stake list, comma-separated, tried in order; on the servers the doormen's URLs (section 15.7) |
| `DAO_PROPOSE_MIN_VOTES` | `1` | The least DAO votes (whole staked anos) a pod needs in the snapshot to post a proposal |
| `DAO_PROPOSAL_PERCENT` | `15` | The percent of all DAO votes a pending proposal needs in support to go to a vote; at most 100 |
| `DAO_PASS_PERCENT` | `50` | For must be more than this percent of the votes cast; at most 99, so a tie fails |
| `DAO_PENDING_MINUTES` | `10080` | How long a proposal may collect support (a week) |
| `DAO_VOTE_MINUTES` | `20160` | How long an open proposal takes votes (two weeks) |

All have defaults, so the existing `.env` keeps working. The JSON body
limit is computed from the last two: `MAX_IMAGES_PER_REQUEST *
MAX_IMAGE_BYTES * 1.4 + 1 MB`.

`WEB_ORIGIN` became a list and `RECOVERY_POD_URL_BASE` was added in section
12.7 (2026-10-26).

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
- Several passkeys or several live sessions per pod.
- Purging pods that never got vouched, and their usernames.
- Removing a member from a room and rotating the room key.
- Editing a listing, a profile or a selfie.
- Push delivery of notifications and messages; the phone polls.
- Generic encrypted object storage, anoSphere, the anos interface.
- Anti-abuse limits on `/challenge` and `/create-anopod`.

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
for the person's tax records: the ledger's facts in the clear, the private
part as a blob this server cannot open) and `wallet_settings` (one
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
   that they typed it). Then a contact email, and they register a passkey.
   The masterpod opens a recovery case and a recovery pod for it (12.4.2).
   Of the birth record only the lookup id reaches the server; the email is
   the one plaintext fact about the person the masterpod keeps.
2. A moderator (12.2) sees the case, schedules a video call (the meeting
   link shows to the person in the app; the email is for the moderator to
   write by hand, nothing is sent), pulls the bucket one key from three
   keyholders (their moderator routes answer synchronously; nothing changes
   there), reads the case pod's bucket one rows (12.4.4) and compares the
   selfie with the person on the call. A mismatch is a dismissal with a
   preset reason. Then bucket two the same way.
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
   usual; stores each break-glass seed on its account row; deposits a new
   backup code with the keyholders and then rotates the backup code on the
   masterpod (12.4.5; the deposit first since 2026-11-10,
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
  contact_email TEXT        NOT NULL CHECK (char_length(contact_email) BETWEEN 3 AND 254 AND position('@' IN contact_email) > 1),
  status        TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'inReview', 'approved', 'delivering', 'completed', 'dismissed')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
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
the account found before any case opens. `unlockCase` and `recover` take
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
    "passkey":            { "...": "the registration PublicKeyCredential.toJSON(), prf.results removed" },
    "hybridKey":          { "x25519": "<hex 32>", "mlkem": "<hex 1568>" },
    "hybridKeyBlob":      "<hex, 124 bytes>",
    "ephemeralAuthKey":   "<hex 33>",
    "ephemeralAuthKeyPq": "<hex 2592>"
  },
  "signatures": { "ecdsa": "<hex>", "mldsa": "<hex>" }
}
```

Checks:

1. Shape; `400 bad request shape`.
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
6. `lookupId` 32 bytes, `contactEmail` 3 to 254 characters with an `@` not
   first, `hybridKey` 32 and 1568 bytes, `hybridKeyBlob` 1 to 1024 bytes;
   `400 invalid <field>`.
7. No case for this lookup id is open (status not completed or dismissed);
   `409 case already open`.

Writes: `INSERT INTO recovery_cases` (status `open`), `INSERT INTO
recovery_pods` (credential id, COSE key, ephemeral keys with
`ephemeral_expires_at = now() + EPHEMERAL_KEY_HOURS`, the hybrid key, the
blob), the `opened` event, the challenge consumed. A unique violation on
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
dies now; the recovery passkey is the pod's passkey from here); the
`recovered` event. A unique violation is `409 key already registered`.

Answer: `200 { anopodId, username, recovered: true }`. The phone then
unlocks the pod through `/challenge` (unlock) and `/unlock` with the same
passkey: `blob1` opens under the same `KEK_prf`.

#### 12.4.3 Level recovery

**POST /get-recovery-pod**. Body `{}`. The person's view of their case.

Answer: `200 { caseId, status, username, contactEmail, lookupId, hybridKey,
hybridKeyBlob, blob2, events: [ { kind, details, createdAt } ], shares: [ {
shareId, keyholderId, shareType, keyId, share, receivedAt } ] }`. `blob2` is
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
lastName, contactEmail, approvals, createdAt, updatedAt } ] }`,
`approvals` the count of distinct pods with an `approvalSigned` event.

**POST /get-recovery-case**. Body `{ caseId }`; `404 unknown case`.

Answer: `200 { case: { caseId, status, lookupId, contactEmail, createdAt,
updatedAt }, profile, events: [ { eventId, kind, anopodId, username,
details, createdAt } ], shares: [ { keyholderId, shareType, keyId,
receivedAt } ], bankerPacket: { lookupId, url, hybridKey } }`. `profile` is
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
and stays unable to link a birth record to a pod, as designed. Where the
plan was silent the simplest thing was chosen and is recorded here.

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
   `/add-dispute-evidence`): screenshots, photos of receipts, PDFs. Each
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
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp', 'application/pdf')),
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
transactionId, accountId, accountIdTo, side, status, createdAt, updatedAt }
] }`, `side` `seller` or `buyer`.

**POST /get-my-case**. Body `{ caseId }`; `404 unknown case`, also when
the caller's pod is not a party.

Answer for a trade: `200 { kind: "trade", case: { caseId, transactionId,
accountId, status, lookupIdShared, createdAt, updatedAt }, events }`. For
a dispute: `200 { kind: "dispute", case: { caseId, transactionId,
accountId, accountIdTo, side, caseKey, status, createdAt, updatedAt },
events, evidence: [ { evidenceId, contentType, file, keyForMe, createdAt }
] }`, the caller's own rows only. `events` is the person's subset of 13.5:
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
each `contentType` one of the four, each `file` base64 of at most
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
  the four content types or larger than `MAX_IMAGE_BYTES`.
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
   `/list-my-break-glass-moves`: the lost account's card shows it. No
   notification is sent (14.7).

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
Writes the `scheduled` event with `{ at, meetLink }` and `status =
'inReview'` when it was `open`. Answer: `200 { caseId, status }`. No
notification: the person's wallet reads the event from
`/list-my-break-glass-moves`.

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

None. The person's wallet reads the case's progress from
`/list-my-break-glass-moves`, and the attestors list the cases; no
notification kind is added (the plan's decision 14).

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
  when the case moves; the attestor edition and the person's wallet read
  the case.
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
6: `400`, `413`, `429 too many requests`, `502`, `504`), a timeout, a body
of the wrong shape. When every URL failed, null. The read is public and
unsigned: everything in it is on the public chain, and this server has no
anos account or validator key to sign with. The doormen's certificates are
Let's Encrypt, so the fetch verifies them as any other.

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
