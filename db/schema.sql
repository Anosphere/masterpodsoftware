-- db/schema.sql
--
-- The whole database schema, built from nothing. scripts/setup-db.sh applies
-- it to the database named in .env.
--
-- Safe to run again on a database that already has it: tables use IF NOT
-- EXISTS, functions and triggers use OR REPLACE, comments just overwrite.
-- It never alters a table that already exists, though, apart from the
-- idempotent ALTERs of the recovery, attestation and marketplace blocks at
-- the end. After changing this file, rebuild the local database from scratch
-- with
--
--   npm run db:reset
--
-- Naming conventions:
--   * PostgreSQL folds unquoted identifiers to lowercase, so everything is
--     lowercase snake_case. camelCase or Capitalised names would have to be
--     double-quoted in every query forever.
--   * Table names are plural nouns (a row is one pod, the table holds pods).
--
-- Storage conventions (the same as anossoftware, so the two schemas read
-- alike):
--   * Hashes and public keys are raw bytes, stored as BYTEA, not as hex text.
--     Where the length is fixed by the algorithm, a CHECK enforces it.
--     Encode to hex or base64 at the API boundary.
--   * Money is BIGINT in millionths of a unit (6 implied decimals), never
--     floats.
--
-- Timestamps: every table has created_at and updated_at (TIMESTAMPTZ).
-- PostgreSQL has no "ON UPDATE CURRENT_TIMESTAMP", so one reusable trigger
-- function stamps updated_at, attached to every table. The WHEN clause on each
-- trigger skips the write when an UPDATE changed nothing, so updated_at only
-- moves on real changes:
--
--   CREATE OR REPLACE TRIGGER <table>_set_updated_at
--     BEFORE UPDATE ON <table>
--     FOR EACH ROW
--     WHEN (OLD.* IS DISTINCT FROM NEW.*)
--     EXECUTE FUNCTION set_updated_at();
--
-- Comments live in the database itself and show up in psql with \d+ <table>.

-- IF NOT EXISTS raises a NOTICE for every table that is already there. On a
-- re-run that is one line of noise per table, so only warnings and up show.
SET client_min_messages = warning;

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- Refuses UPDATE and DELETE on append-only tables (security_images,
-- security_info): a row is the record of what was written, once.
CREATE OR REPLACE FUNCTION refuse_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;


-- ---------------------------------------------------------------------------
-- anopods: one row per anoPod.
--
-- Profile, the one passkey, the one live session (the ephemeral keys), the
-- vouch state, and the key material that arrives at setup. The eight setup
-- columns are all null until /complete-setup and all set afterwards; the
-- num_nulls check enforces that. Long keys get their unique index on
-- sha256(column) so every value stays unique without a 2.6 KB index entry.
-- identity_blob (added 2026-10-25 for the wallet) is the pod's public ledger
-- id and lookup id under its encryption key; the server cannot read it.
-- ---------------------------------------------------------------------------

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

CREATE OR REPLACE TRIGGER anopods_set_updated_at
  BEFORE UPDATE ON anopods
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  anopods                              IS 'One row per anoPod: profile, the one passkey, the one live session, vouch state, and the key material that arrives at setup.';
COMMENT ON COLUMN anopods.anopod_id                    IS 'Random id, 32 raw bytes, minted by /challenge for the sign-up; also the passkey''s user handle.';
COMMENT ON COLUMN anopods.first_name                   IS 'Public profile, 1 to 100 characters.';
COMMENT ON COLUMN anopods.last_name                    IS 'Public profile, 1 to 100 characters.';
COMMENT ON COLUMN anopods.username                     IS 'Public, unique, lowercase: 3 to 32 of a-z, 0-9 and _.';
COMMENT ON COLUMN anopods.pass_key_credential_id       IS 'WebAuthn credential id of the pod''s one passkey, raw bytes. /unlock finds the row by it.';
COMMENT ON COLUMN anopods.pass_key_public_key          IS 'The passkey''s COSE public key, as the WebAuthn library returns it at registration.';
COMMENT ON COLUMN anopods.ephemeral_auth_key           IS 'P-256 public key of the live session, 33 bytes compressed or 65 uncompressed. Signs every session request.';
COMMENT ON COLUMN anopods.ephemeral_auth_key_pq        IS 'ML-DSA-87 public key of the live session, 2592 bytes.';
COMMENT ON COLUMN anopods.ephemeral_expires_at         IS 'When the session keys stop verifying: registered + EPHEMERAL_KEY_HOURS. A new unlock replaces the keys and the date.';
COMMENT ON COLUMN anopods.vouched                      IS 'True once a super seed, or two seeds, have vouched for the pod.';
COMMENT ON COLUMN anopods.anopod_encryption_key_blob_1 IS 'The pod''s encryption key wrapped under the passkey PRF-derived key (iv || ciphertext || tag, 60 bytes). Null until setup.';
COMMENT ON COLUMN anopods.anopod_encryption_key_blob_2 IS 'The same key wrapped under the backup-code-derived key (60 bytes). Null until setup; set means setup is complete.';
COMMENT ON COLUMN anopods.backup_code_public_key       IS 'P-256 public key derived from the backup code, for recovery later. Null until setup.';
COMMENT ON COLUMN anopods.backup_code_public_key_pq    IS 'ML-DSA-87 public key derived from the backup code, 2592 bytes. Null until setup.';
COMMENT ON COLUMN anopods.chat_public_key              IS 'P-256 public key of the chat key pair, 33 or 65 bytes. Room keys are wrapped to it. Null until setup.';
COMMENT ON COLUMN anopods.chat_public_key_pq           IS 'ML-KEM-1024 public key of the chat key pair, 1568 bytes. Null until setup.';
COMMENT ON COLUMN anopods.chat_private_key_blob        IS 'The chat key pair''s private half (P-256 scalar || ML-KEM seed) wrapped under the encryption key, 124 bytes. Null until setup.';
COMMENT ON COLUMN anopods.identity_blob                IS 'The public ledger id (32) || lookup id (32) wrapped under the encryption key (iv || ciphertext || tag, 92 bytes). Null until setup. The server cannot read it; /unlock hands it back.';
COMMENT ON COLUMN anopods.created_at                   IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN anopods.updated_at                   IS 'When the row last changed. Maintained by the anopods_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- public_selfies: one plaintext selfie per anoPod.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public_selfies (
  anopod_id    BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  content_type TEXT        NOT NULL CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
  image        BYTEA       NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER public_selfies_set_updated_at
  BEFORE UPDATE ON public_selfies
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  public_selfies              IS 'One plaintext selfie per anoPod, written with the pod at creation. Public by design; not unique. No route changes it yet.';
COMMENT ON COLUMN public_selfies.anopod_id    IS 'The pod the selfie belongs to.';
COMMENT ON COLUMN public_selfies.content_type IS 'image/jpeg, image/png or image/webp.';
COMMENT ON COLUMN public_selfies.image        IS 'The image bytes as uploaded, at most MAX_IMAGE_BYTES.';
COMMENT ON COLUMN public_selfies.created_at   IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN public_selfies.updated_at   IS 'When the row last changed. Maintained by the public_selfies_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- challenges: single-use WebAuthn challenges handed out by /challenge.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS challenges (
  challenge  BYTEA       PRIMARY KEY CHECK (octet_length(challenge) = 32),
  purpose    TEXT        NOT NULL CHECK (purpose IN ('create', 'unlock', 'openCase', 'unlockCase', 'recover')),
  anopod_id  BYTEA       CHECK (octet_length(anopod_id) = 32),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  challenges            IS 'Single-use WebAuthn challenges from /challenge. Deleted inside the transaction that uses one; the expired ones are swept when a new one is issued.';
COMMENT ON COLUMN challenges.challenge  IS 'Random, 32 raw bytes. The phone passes it to WebAuthn.';
COMMENT ON COLUMN challenges.purpose    IS 'create for a sign-up, unlock for a session; openCase, unlockCase and recover for the recovery routes (spec 12.4.2).';
COMMENT ON COLUMN challenges.anopod_id  IS 'For create, the id minted for this sign-up, which becomes the row''s id at the write; for openCase, the pod the username named. Null for unlock, unlockCase and recover.';
COMMENT ON COLUMN challenges.expires_at IS 'Issued + CHALLENGE_SECONDS.';
COMMENT ON COLUMN challenges.created_at IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- nonces: the replay cache of signed session requests.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS nonces (
  anopod_id  BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  nonce      BYTEA       NOT NULL CHECK (octet_length(nonce) BETWEEN 16 AND 32),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (anopod_id, nonce)
);

COMMENT ON TABLE  nonces            IS 'One row per (pod, nonce) seen on a verified session request. A second request with the same nonce is a replay. Swept when expired.';
COMMENT ON COLUMN nonces.anopod_id  IS 'The pod whose session keys signed the request, or, for a recovery request, the case id of the recovery pod whose keys did.';
COMMENT ON COLUMN nonces.nonce      IS 'The request''s nonce, 16 to 32 raw bytes.';
COMMENT ON COLUMN nonces.expires_at IS 'Seen + twice TIMESTAMP_WINDOW_SECONDS; a request dated outside the window is refused before it gets here.';
COMMENT ON COLUMN nonces.created_at IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- vouch_requests: open requests to be vouched for.
-- ---------------------------------------------------------------------------

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

CREATE OR REPLACE TRIGGER vouch_requests_set_updated_at
  BEFORE UPDATE ON vouch_requests
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  vouch_requests                 IS 'Open vouch requests only: one waiting request per requester and seed. Approve and decline delete the row.';
COMMENT ON COLUMN vouch_requests.vouch_id_number IS 'Random id, 32 raw bytes. Becomes the vouch''s id on approval.';
COMMENT ON COLUMN vouch_requests.anopod_id_from  IS 'The requester.';
COMMENT ON COLUMN vouch_requests.anopod_id_to    IS 'The seed or super seed asked to vouch.';
COMMENT ON COLUMN vouch_requests.created_at      IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN vouch_requests.updated_at      IS 'When the row last changed. Maintained by the vouch_requests_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- vouches: the record of an approval.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vouches (
  vouch_id_number       BYTEA       PRIMARY KEY CHECK (octet_length(vouch_id_number) = 32),
  anopod_id_vouched_by  BYTEA       NOT NULL CHECK (octet_length(anopod_id_vouched_by) = 32),
  anopod_id_vouched_for BYTEA       NOT NULL CHECK (octet_length(anopod_id_vouched_for) = 32),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (anopod_id_vouched_by, anopod_id_vouched_for)
);
CREATE INDEX IF NOT EXISTS vouches_anopod_id_vouched_for_idx ON vouches (anopod_id_vouched_for);

COMMENT ON TABLE  vouches                       IS 'One row per approved vouch request. Never changes. Two rows, or one by a super seed, make a pod vouched.';
COMMENT ON COLUMN vouches.vouch_id_number       IS 'The request''s vouch_id_number.';
COMMENT ON COLUMN vouches.anopod_id_vouched_by  IS 'The seed or super seed that approved.';
COMMENT ON COLUMN vouches.anopod_id_vouched_for IS 'The requester.';
COMMENT ON COLUMN vouches.created_at            IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- seeds and super_seeds: the pods that may vouch.
--
-- A pod vouched by a super seed joins seeds with vouched_by = that super
-- seed's hex id. Super seeds are made only by scripts/make-super-seed.js,
-- vouched_by = 'genesis'. vouched_by is text so it can hold either.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS seeds (
  anopod_id        BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  date_became_seed TIMESTAMPTZ NOT NULL DEFAULT now(),
  trust_score      INTEGER     NOT NULL DEFAULT 0,
  vouched_by       TEXT        NOT NULL CHECK (vouched_by = 'genesis' OR vouched_by ~ '^[0-9a-f]{64}$'),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER seeds_set_updated_at
  BEFORE UPDATE ON seeds
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  seeds                  IS 'Pods that may vouch: those a super seed vouched for. Stand-alone; no foreign keys.';
COMMENT ON COLUMN seeds.anopod_id        IS 'The seed.';
COMMENT ON COLUMN seeds.date_became_seed IS 'When the pod became a seed.';
COMMENT ON COLUMN seeds.trust_score      IS 'Starts at 0. Nothing reads it yet.';
COMMENT ON COLUMN seeds.vouched_by       IS 'Hex id of the super seed whose approval made this pod a seed, or genesis.';
COMMENT ON COLUMN seeds.created_at       IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN seeds.updated_at       IS 'When the row last changed. Maintained by the seeds_set_updated_at trigger.';

CREATE TABLE IF NOT EXISTS super_seeds (
  anopod_id              BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  date_became_super_seed TIMESTAMPTZ NOT NULL DEFAULT now(),
  trust_score            INTEGER     NOT NULL DEFAULT 0,
  vouched_by             TEXT        NOT NULL CHECK (vouched_by = 'genesis' OR vouched_by ~ '^[0-9a-f]{64}$'),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER super_seeds_set_updated_at
  BEFORE UPDATE ON super_seeds
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  super_seeds                        IS 'Pods made by the genesis script. One approval by a super seed vouches a pod and makes it a seed.';
COMMENT ON COLUMN super_seeds.anopod_id              IS 'The super seed.';
COMMENT ON COLUMN super_seeds.date_became_super_seed IS 'When the pod became a super seed.';
COMMENT ON COLUMN super_seeds.trust_score            IS 'Starts at 0. Nothing reads it yet.';
COMMENT ON COLUMN super_seeds.vouched_by             IS 'genesis for the first super seeds; otherwise the hex id of the pod that vouched.';
COMMENT ON COLUMN super_seeds.created_at             IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN super_seeds.updated_at             IS 'When the row last changed. Maintained by the super_seeds_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- notifications: what the phone polls.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS notifications (
  notification_number BYTEA       PRIMARY KEY CHECK (octet_length(notification_number) = 32),
  anopod_id           BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  kind                TEXT        NOT NULL CHECK (kind IN (
                        'vouchRequest', 'vouchApproved', 'vouchDeclined', 'vouched',
                        'chatInvite', 'inviteAccepted', 'inviteDeclined',
                        'joinRequest', 'joinApproved', 'joinDeclined',
                        'tradeCaseOpened', 'disputeCaseOpened', 'caseScheduled',
                        'caseDecided', 'caseDismissed')),
  reference_id        BYTEA       NOT NULL CHECK (octet_length(reference_id) = 32),
  read_at             TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notifications_anopod_id_created_at_idx ON notifications (anopod_id, created_at DESC);

CREATE OR REPLACE TRIGGER notifications_set_updated_at
  BEFORE UPDATE ON notifications
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  notifications                     IS 'One row per event a pod should hear about, written inside the transaction of the event it reports. Read, never deleted.';
COMMENT ON COLUMN notifications.notification_number IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN notifications.anopod_id           IS 'The pod notified.';
COMMENT ON COLUMN notifications.kind                IS 'What happened: vouchRequest, vouchApproved, vouchDeclined, vouched, chatInvite, inviteAccepted, inviteDeclined, joinRequest, joinApproved, joinDeclined, or, for an attestor case (spec 13.7), tradeCaseOpened, disputeCaseOpened, caseScheduled, caseDecided or caseDismissed.';
COMMENT ON COLUMN notifications.reference_id        IS 'The thing the kind is about: a vouch_id_number, the pod''s own anopod_id (vouched), an invite_id, a chat_room_id, a join_request_id, or the case id of an assisted_trades or escrow_disputes row.';
COMMENT ON COLUMN notifications.read_at             IS 'When the phone marked it read; null while unread.';
COMMENT ON COLUMN notifications.created_at          IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN notifications.updated_at          IS 'When the row last changed. Maintained by the notifications_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- security_images and security_info: the security buckets.
--
-- Bucket one is security_images with type = 1. Bucket two is security_images
-- with type = 2 plus security_info with type = 2. Everything here is
-- ciphertext under keys the keyholders hold, not the pod. Append-only,
-- enforced by the refuse_change triggers. key_id (added 2026-10-25 for the
-- wallet) names the bucket key a row is encrypted under: the same 32 bytes
-- the pod deposited with the key's shares on the keyholders, so a moderator
-- holding the shares of key key_id knows which rows it opens.
-- ---------------------------------------------------------------------------

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

COMMENT ON TABLE  security_images              IS 'Encrypted images of the security buckets, under keys the keyholders hold. Append-only (security_images_append_only).';
COMMENT ON COLUMN security_images.image_id     IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN security_images.anopod_id    IS 'The pod the image belongs to.';
COMMENT ON COLUMN security_images.type         IS '1 for bucket one, 2 for bucket two.';
COMMENT ON COLUMN security_images.content_type IS 'The plaintext''s type: image/jpeg, image/png or image/webp.';
COMMENT ON COLUMN security_images.image        IS 'Ciphertext (iv || ciphertext || tag), at most MAX_IMAGE_BYTES.';
COMMENT ON COLUMN security_images.key_id       IS 'The bucket key the image is encrypted under, 32 raw bytes: the keyId the pod deposited with the key''s shares on the keyholders.';
COMMENT ON COLUMN security_images.created_at   IS 'When the row was inserted. Set by default, never changed.';

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

COMMENT ON TABLE  security_info            IS 'Encrypted texts of security bucket two, under the bucket key. Append-only (security_info_append_only).';
COMMENT ON COLUMN security_info.info_id    IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN security_info.anopod_id  IS 'The pod the text belongs to.';
COMMENT ON COLUMN security_info.type       IS 'The bucket, 1 or 2. Only bucket two writes texts today.';
COMMENT ON COLUMN security_info.info       IS 'Ciphertext of the text (iv || ciphertext || tag), at most 65536 bytes.';
COMMENT ON COLUMN security_info.key_id     IS 'The bucket key the text is encrypted under, 32 raw bytes: the keyId the pod deposited with the key''s shares on the keyholders.';
COMMENT ON COLUMN security_info.created_at IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- chat_rooms: one row per chat room.
-- ---------------------------------------------------------------------------

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

CREATE OR REPLACE TRIGGER chat_rooms_set_updated_at
  BEFORE UPDATE ON chat_rooms
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  chat_rooms                   IS 'One row per chat room: private (invites only; about a listing when listing_id is set, one such room per person who connects, since 2026-11-06), public (browsable by name, join requests) or marketplace (the old one-per-listing rooms, join requests; none made since 2026-11-06, the existing ones stay).';
COMMENT ON COLUMN chat_rooms.chat_room_id      IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN chat_rooms.creator_anopod_id IS 'The pod that made the room. It invites, answers join requests and cannot leave.';
COMMENT ON COLUMN chat_rooms.type              IS 'private, public or marketplace.';
COMMENT ON COLUMN chat_rooms.name              IS 'Plaintext name, 1 to 100 characters, public rooms only; the others have none.';
COMMENT ON COLUMN chat_rooms.created_at        IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN chat_rooms.updated_at        IS 'When the row last changed. Maintained by the chat_rooms_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- chat_room_members and chat_hpke: who is in a room, and their wrapped key.
--
-- A member row and its chat_hpke row are always written and deleted
-- together.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS chat_room_members (
  chat_room_id BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (chat_room_id, anopod_id)
);
CREATE INDEX IF NOT EXISTS chat_room_members_anopod_id_idx ON chat_room_members (anopod_id);

COMMENT ON TABLE  chat_room_members              IS 'Who is in which room. Written and deleted together with the member''s chat_hpke row.';
COMMENT ON COLUMN chat_room_members.chat_room_id IS 'The room.';
COMMENT ON COLUMN chat_room_members.anopod_id    IS 'The member.';
COMMENT ON COLUMN chat_room_members.created_at   IS 'When the member joined. Set by default, never changed.';

CREATE TABLE IF NOT EXISTS chat_hpke (
  chat_room_id BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id    BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  hpke_key     BYTEA       NOT NULL CHECK (octet_length(hpke_key) <= 4096),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (chat_room_id, anopod_id)
);

COMMENT ON TABLE  chat_hpke              IS 'For each member of each room, the room key wrapped to that member''s chat public key. Stored as delivered; only that member can open it.';
COMMENT ON COLUMN chat_hpke.chat_room_id IS 'The room.';
COMMENT ON COLUMN chat_hpke.anopod_id    IS 'The member the key is wrapped to.';
COMMENT ON COLUMN chat_hpke.hpke_key     IS 'Ephemeral P-256 public key (33) || ML-KEM-1024 ciphertext (1568) || room key under the derived key (60): 1661 bytes. At most 4096.';
COMMENT ON COLUMN chat_hpke.created_at   IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- chat_room_invites and chat_room_join_requests: how a pod gets into a room.
--
-- An invite carries the wrapped room key until it is answered: accept moves
-- it into chat_hpke, decline drops it. A join request carries nothing; the
-- creator's approval brings the wrapped key.
-- ---------------------------------------------------------------------------

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

COMMENT ON TABLE  chat_room_invites                IS 'Open invites to private and public rooms, each carrying the wrapped room key until answered. One open invite per room and invitee.';
COMMENT ON COLUMN chat_room_invites.invite_id      IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN chat_room_invites.chat_room_id   IS 'The room.';
COMMENT ON COLUMN chat_room_invites.anopod_id_from IS 'The inviter: the room''s creator.';
COMMENT ON COLUMN chat_room_invites.anopod_id_to   IS 'The invitee.';
COMMENT ON COLUMN chat_room_invites.hpke_key       IS 'The room key wrapped to the invitee''s chat public key (see chat_hpke.hpke_key).';
COMMENT ON COLUMN chat_room_invites.created_at     IS 'When the row was inserted. Set by default, never changed.';

CREATE TABLE IF NOT EXISTS chat_room_join_requests (
  join_request_id BYTEA       PRIMARY KEY CHECK (octet_length(join_request_id) = 32),
  chat_room_id    BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  anopod_id       BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (chat_room_id, anopod_id)
);

COMMENT ON TABLE  chat_room_join_requests                 IS 'Open requests to join a public or marketplace room. One open request per room and requester; approve and decline delete the row.';
COMMENT ON COLUMN chat_room_join_requests.join_request_id IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN chat_room_join_requests.chat_room_id    IS 'The room.';
COMMENT ON COLUMN chat_room_join_requests.anopod_id       IS 'The requester.';
COMMENT ON COLUMN chat_room_join_requests.created_at      IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- chat_room_messages: ciphertext under the room key.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS chat_room_messages (
  message_id       BYTEA       PRIMARY KEY CHECK (octet_length(message_id) = 32),
  chat_room_id     BYTEA       NOT NULL CHECK (octet_length(chat_room_id) = 32),
  sender_anopod_id BYTEA       NOT NULL CHECK (octet_length(sender_anopod_id) = 32),
  position         BIGINT      GENERATED ALWAYS AS IDENTITY,
  message          BYTEA       NOT NULL CHECK (octet_length(message) <= 65536),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS chat_room_messages_room_position_idx ON chat_room_messages (chat_room_id, position);

COMMENT ON TABLE  chat_room_messages                  IS 'Messages, ciphertext under the room key. The sender is the verified caller; there is no per-message signature.';
COMMENT ON COLUMN chat_room_messages.message_id       IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN chat_room_messages.chat_room_id     IS 'The room.';
COMMENT ON COLUMN chat_room_messages.sender_anopod_id IS 'The member who sent it.';
COMMENT ON COLUMN chat_room_messages.position         IS 'Counts up with every message written, across all rooms. Orders a room''s messages and drives afterPosition.';
COMMENT ON COLUMN chat_room_messages.message          IS 'Ciphertext of the UTF-8 text (iv || ciphertext || tag), at most 65536 bytes.';
COMMENT ON COLUMN chat_room_messages.created_at       IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- listings: the marketplace.
-- ---------------------------------------------------------------------------

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

CREATE OR REPLACE TRIGGER listings_set_updated_at
  BEFORE UPDATE ON listings
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  listings              IS 'Marketplace listings, always anos for a fiat currency. Until 2026-11-06 each listing owned one marketplace chat room; since then the people who connect each get a private room about it (chat_rooms.listing_id).';
COMMENT ON COLUMN listings.listing_id   IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN listings.chat_room_id IS 'The listing''s old marketplace room, made with it until 2026-11-06. Null for every listing made since.';
COMMENT ON COLUMN listings.anopod_id    IS 'The owner.';
COMMENT ON COLUMN listings.side         IS 'buy or sell, from the owner''s side.';
COMMENT ON COLUMN listings.quantity     IS 'Millionths of an anos (6 implied decimals).';
COMMENT ON COLUMN listings.currency     IS 'ISO 4217 code, three uppercase letters.';
COMMENT ON COLUMN listings.country      IS 'ISO 3166-1 alpha-2 code, two uppercase letters.';
COMMENT ON COLUMN listings.price        IS 'Per anos, in currency; up to 8 decimals.';
COMMENT ON COLUMN listings.status       IS 'open or closed. A closed listing takes no new join requests and no new rooms about it; an old listing''s room and its members stay.';
COMMENT ON COLUMN listings.created_at   IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN listings.updated_at   IS 'When the row last changed. Maintained by the listings_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- anos_accounts: one row per anos account a pod made (added 2026-10-25 for
-- the wallet). The masterpod keeps the account's private halves for the pod
-- (key_blob, under the pod's encryption key, which the server cannot open)
-- and the signed creation as it went to the validator, and records when a
-- validator answered the creation (submitted_at). /get-anos-account answers
-- the validators' binding check from it: the pod that made the account and
-- whether it is vouched. The masterpod never verifies anos signatures; the
-- validators do. Stand-alone: no foreign keys; rows are never deleted.
-- ---------------------------------------------------------------------------

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

CREATE OR REPLACE TRIGGER anos_accounts_set_updated_at
  BEFORE UPDATE ON anos_accounts
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  anos_accounts              IS 'One row per anos account a pod made: the pod, the type, the private halves under the pod''s encryption key, the signed creation, and when a validator answered it. Never deleted. Stand-alone; no foreign keys.';
COMMENT ON COLUMN anos_accounts.account_id   IS 'The anos account id: SHA-256 of key1 + postQuantumKey1, as the validators compute it. 32 raw bytes.';
COMMENT ON COLUMN anos_accounts.anopod_id    IS 'The pod that made the account.';
COMMENT ON COLUMN anos_accounts.account_type IS 'spending, guarded, vault or assisted.';
COMMENT ON COLUMN anos_accounts.key_blob     IS 'Pair one and pair two''s private halves (key1 scalar || postQuantumKey1 seed || key2 scalar || postQuantumKey2 seed) wrapped under the pod''s encryption key, 156 bytes. The server cannot open it.';
COMMENT ON COLUMN anos_accounts.creation     IS 'The signed creation transaction, all eight signatures, exactly as posted to the validator.';
COMMENT ON COLUMN anos_accounts.submitted_at IS 'When a validator answered the creation (/mark-anos-account-submitted). Null until then.';
COMMENT ON COLUMN anos_accounts.created_at   IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN anos_accounts.updated_at   IS 'When the row last changed. Maintained by the anos_accounts_set_updated_at trigger.';



-- ---------------------------------------------------------------------------
-- Recovery (added 2026-10-26, spec section 12): a locked-out person opens a
-- recovery case; the case gets a recovery pod of its own (a passkey, a
-- session, a hybrid key the bankers encrypt shares to); the keyholders post
-- shares to it; everything that happens to a case is an event. Four tables,
-- one column on anos_accounts, the challenges check widened. The two ALTERs
-- at the end are the one place this file changes a table that already
-- exists; both are idempotent, so npm run db:setup applies the whole block
-- to a live database.
-- ---------------------------------------------------------------------------

-- recovery_cases: one row per case. The lookup id the person recomputed,
-- the pod the typed username named, the contact email (the one plaintext
-- fact about the person this server keeps) and the status. Nothing else
-- about a case is a column: everything that happens is a recovery_events
-- row. The partial unique index is the one-open-case-per-lookup-id rule.

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

CREATE OR REPLACE TRIGGER recovery_cases_set_updated_at
  BEFORE UPDATE ON recovery_cases
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  recovery_cases               IS 'One row per recovery case: the lookup id the person recomputed, the pod the typed username named, the contact email and the status. Everything that happens to a case is a recovery_events row. One open case per lookup id (the partial unique index).';
COMMENT ON COLUMN recovery_cases.case_id       IS 'Random id, 32 raw bytes, minted by /open-recovery-case. The recovery pod, the shares and the events hang off it.';
COMMENT ON COLUMN recovery_cases.lookup_id     IS 'The lookup id (wallet docs/public-ledger-id.md section 6) the person recomputed on their device, 32 raw bytes. The public ledger id is never stored.';
COMMENT ON COLUMN recovery_cases.anopod_id     IS 'The pod the typed username named: the one being recovered.';
COMMENT ON COLUMN recovery_cases.contact_email IS 'Where a moderator can reach the person: 3 to 254 characters with an @ that is not first. The one plaintext fact about the person this server keeps. Nothing is sent; the moderator writes by hand.';
COMMENT ON COLUMN recovery_cases.status        IS 'open, inReview, approved, delivering, completed or dismissed (spec 12.5). completed and dismissed are final.';
COMMENT ON COLUMN recovery_cases.created_at    IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN recovery_cases.updated_at    IS 'When the row last changed. Maintained by the recovery_cases_set_updated_at trigger.';


-- recovery_pods: one per case, keyed like the case. The recovery passkey
-- (registered with user handle = the pod's id, so it can become the pod's
-- passkey at the finish), the recovery session (ephemeral keys, replaced at
-- every /unlock-recovery-pod), the hybrid public key the bankers encrypt
-- shares to, and the private halves under the passkey's PRF-derived key,
-- which the server cannot open. Long keys get their unique index on
-- sha256(column), as on anopods.

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

CREATE OR REPLACE TRIGGER recovery_pods_set_updated_at
  BEFORE UPDATE ON recovery_pods
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  recovery_pods                        IS 'One recovery pod per case, keyed like the case: the recovery passkey, the recovery session, the hybrid public key the bankers encrypt shares to, and the hybrid pair''s private halves under the passkey''s PRF-derived key, which the server cannot open.';
COMMENT ON COLUMN recovery_pods.case_id                IS 'The case this pod belongs to; the primary key.';
COMMENT ON COLUMN recovery_pods.anopod_id              IS 'The pod being recovered. Also the recovery passkey''s user handle, so the passkey can become the pod''s at the finish.';
COMMENT ON COLUMN recovery_pods.pass_key_credential_id IS 'WebAuthn credential id of the recovery passkey, raw bytes. /unlock-recovery-pod finds the row by it. Unique here; the same id appears on anopods after the finish.';
COMMENT ON COLUMN recovery_pods.pass_key_public_key    IS 'The recovery passkey''s COSE public key, as the WebAuthn library returns it at registration.';
COMMENT ON COLUMN recovery_pods.ephemeral_auth_key     IS 'P-256 public key of the recovery session, 33 bytes compressed or 65 uncompressed. Signs every recovery request.';
COMMENT ON COLUMN recovery_pods.ephemeral_auth_key_pq  IS 'ML-DSA-87 public key of the recovery session, 2592 bytes.';
COMMENT ON COLUMN recovery_pods.ephemeral_expires_at   IS 'When the recovery session keys stop verifying: registered + EPHEMERAL_KEY_HOURS. /unlock-recovery-pod replaces the keys and the date.';
COMMENT ON COLUMN recovery_pods.hybrid_key_x25519      IS 'X25519 public key of the recovery hybrid pair, 32 bytes. With the ML-KEM key, what the bankers encrypt shares to.';
COMMENT ON COLUMN recovery_pods.hybrid_key_mlkem       IS 'ML-KEM-1024 public key of the recovery hybrid pair, 1568 bytes.';
COMMENT ON COLUMN recovery_pods.hybrid_key_blob        IS 'The hybrid pair''s private halves (x25519 secret || ml-kem seed) wrapped under the recovery passkey''s PRF-derived key (iv || ciphertext || tag, 124 bytes). The server cannot open it; /unlock-recovery-pod hands it back.';
COMMENT ON COLUMN recovery_pods.created_at             IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN recovery_pods.updated_at             IS 'When the row last changed. Maintained by the recovery_pods_set_updated_at trigger.';


-- recovery_shares: what the keyholders posted to a case's recovery pod, as
-- posted: a Shamir share of the backup code or of a break-glass seed,
-- encrypted to the pod's hybrid key, opened on the person's device only.
-- Append-only; the unique key makes a banker's second send of the same
-- share a no-op.

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

COMMENT ON TABLE  recovery_shares              IS 'What the keyholders posted to a case''s recovery pod, as posted: a Shamir share of the backup code or of a break-glass seed, encrypted to the pod''s hybrid key. Append-only; a banker''s second send of the same share is a no-op (the unique key).';
COMMENT ON COLUMN recovery_shares.share_id     IS 'Random id, 32 raw bytes, minted by /receive-recovery-share.';
COMMENT ON COLUMN recovery_shares.case_id      IS 'The case the share was posted to.';
COMMENT ON COLUMN recovery_shares.keyholder_id IS 'The keyholder that posted it, 1 to 99.';
COMMENT ON COLUMN recovery_shares.lookup_id    IS 'The lookup id the keyholder sent; equals the case''s.';
COMMENT ON COLUMN recovery_shares.share_type   IS 'backupcode or breakglasskey: which secret the share belongs to.';
COMMENT ON COLUMN recovery_shares.key_id       IS 'The key id the shares were deposited under with the keyholders, 32 raw bytes. Three shares of one key id combine.';
COMMENT ON COLUMN recovery_shares.share        IS 'The keyholder''s hybrid wire (keyholder spec 7.1): a 33-byte share encrypted to the recovery pod''s hybrid key, 1661 bytes. Opened on the person''s device only.';
COMMENT ON COLUMN recovery_shares.created_at   IS 'When the share arrived. Set by default, never changed.';


-- recovery_events: the audit trail of a case, append-only. One row per
-- thing that happened (spec 12.5); anopod_id is the moderator who acted,
-- null for the person's, the server's and the keyholders' events; details
-- holds what the kind carries. A new duty later is a new kind in the
-- check, not a new column.

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

COMMENT ON TABLE  recovery_events            IS 'The audit trail of a case, append-only: one row per thing that happened (spec 12.5). anopod_id is the moderator who acted, null for the person''s, the server''s and the keyholders'' events.';
COMMENT ON COLUMN recovery_events.event_id   IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN recovery_events.case_id    IS 'The case the event belongs to.';
COMMENT ON COLUMN recovery_events.kind       IS 'opened, scheduled, bucketOneViewed, bucketTwoViewed, approvalSigned, rejectionSigned, approved, dismissed, shareReceived, recovered or completed. A new duty later is a new kind, not a new column.';
COMMENT ON COLUMN recovery_events.anopod_id  IS 'The moderator who acted. Null for the person''s, the server''s and the keyholders'' events.';
COMMENT ON COLUMN recovery_events.details    IS 'What the kind carries (spec 12.5): {} for opened, approved, recovered and completed; { at, meetLink } for scheduled; { keyIds } for the bucket views; { accountId, note, signedAt, signatures } for a sign-off; { reason, note } for dismissed; { keyholderId, shareType, keyId } for shareReceived.';
COMMENT ON COLUMN recovery_events.created_at IS 'When the row was inserted. Set by default, never changed.';


-- The break-glass column on anos_accounts, and the challenges check widened
-- to the three recovery purposes. Both idempotent: IF NOT EXISTS, and a
-- drop-and-add of the check under its one name.

ALTER TABLE anos_accounts ADD COLUMN IF NOT EXISTS break_glass_blob BYTEA CHECK (octet_length(break_glass_blob) <= 1024);

COMMENT ON COLUMN anos_accounts.break_glass_blob IS 'The account''s 32-byte break-glass seed wrapped under the pod''s encryption key (60 bytes), stored at the finish of a recovery (/store-break-glass-blob). Null until then. The server cannot open it.';

ALTER TABLE challenges DROP CONSTRAINT IF EXISTS challenges_purpose_check;
ALTER TABLE challenges ADD CONSTRAINT challenges_purpose_check
  CHECK (purpose IN ('create', 'unlock', 'openCase', 'unlockCase', 'recover'));


-- ---------------------------------------------------------------------------
-- Attestation (added 2026-10-26, spec section 13): an attestor pod (a pod
-- named attestor... that a super seed vouched for, 13.2) opens a case on an
-- assisted trade waiting for attestations or on a disputed escrow, works it
-- and signs the validators' own follow-up object; the person shares their
-- lookup id, the parties upload evidence; everything that happens to a case
-- is an attestor_events row. Five tables, and the notifications check
-- widened to the five case kinds, inline in its CREATE TABLE above and by
-- the ALTER pair at the end, both idempotent, so npm run db:setup applies
-- the whole block to a live database. No foreign keys; the services keep
-- the references straight.
-- ---------------------------------------------------------------------------

-- assisted_trades: one case per assisted trade. transaction_id is the
-- trade's id on the validators, account_id the sender's anos account,
-- anopod_id the pod that made it (from anos_accounts), opened_by the
-- attestor pod that opened the case, lookup_id what the person shared: null
-- until then and null again once the case is decided or dismissed. The
-- partial unique index is the one-open-case-per-trade rule; a dismissed
-- trade can get a new case. Nothing else about a case is a column:
-- everything that happens is an attestor_events row.

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

CREATE OR REPLACE TRIGGER assisted_trades_set_updated_at
  BEFORE UPDATE ON assisted_trades
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  assisted_trades                IS 'One case per assisted trade waiting for attestations on the validators: the trade, the sender''s account and pod, the attestor pod that opened the case, the lookup id the person shared, the status. Everything that happens to a case is an attestor_events row. One open case per trade (the partial unique index).';
COMMENT ON COLUMN assisted_trades.case_id        IS 'Random id, 32 raw bytes, minted by /open-trade-case. The events and the notifications name it.';
COMMENT ON COLUMN assisted_trades.transaction_id IS 'The assisted transfer''s transaction id on the validators, 32 raw bytes. The attestations the attestors sign name it.';
COMMENT ON COLUMN assisted_trades.account_id     IS 'The sender''s anos account, the assisted account the transfer spends from.';
COMMENT ON COLUMN assisted_trades.anopod_id      IS 'The pod that made the sender''s account (anos_accounts.anopod_id at open): the person the case is about, the party notified.';
COMMENT ON COLUMN assisted_trades.opened_by      IS 'The attestor pod that opened the case.';
COMMENT ON COLUMN assisted_trades.lookup_id      IS 'The lookup id the person shared (/share-lookup-id), 32 raw bytes, what the attestor pulls the bucket keys from the keyholders by. Null until shared; null again once the case is decided or dismissed.';
COMMENT ON COLUMN assisted_trades.status         IS 'open, inReview, decided or dismissed (spec 13.5). decided and dismissed are final.';
COMMENT ON COLUMN assisted_trades.created_at     IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN assisted_trades.updated_at     IS 'When the row last changed. Maintained by the assisted_trades_set_updated_at trigger.';


-- escrow_disputes: one case per disputed escrow. account_id and anopod_id
-- are the seller and their pod, account_id_to and anopod_id_to the buyer
-- and theirs, disputed_by whichever of the two signed the dispute (as the
-- validator reported it), opened_by the attestor pod, case_key_x25519 and
-- case_key_mlkem the public halves of the case key the evidence is
-- encrypted to (spec 13.6). The private halves are never on this row: they
-- sit in escrow_dispute_keys, wrapped to each attestor pod.

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

CREATE OR REPLACE TRIGGER escrow_disputes_set_updated_at
  BEFORE UPDATE ON escrow_disputes
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  escrow_disputes                 IS 'One case per disputed escrow on the validators: the escrow, the seller''s and the buyer''s accounts and pods, who disputed, the attestor pod that opened the case, the public halves of the case key the evidence is encrypted to, the status. Everything that happens to a case is an attestor_events row. One open case per escrow (the partial unique index).';
COMMENT ON COLUMN escrow_disputes.case_id         IS 'Random id, 32 raw bytes, minted by /open-dispute-case. The keys, the evidence, the events and the notifications name it; also the aad of every keyForCase.';
COMMENT ON COLUMN escrow_disputes.transaction_id  IS 'The escrow transfer''s transaction id on the validators, 32 raw bytes. The verdicts the attestors sign name it.';
COMMENT ON COLUMN escrow_disputes.account_id      IS 'The seller''s anos account: the escrow transfer''s sender.';
COMMENT ON COLUMN escrow_disputes.account_id_to   IS 'The buyer''s anos account: the escrow transfer''s receiver.';
COMMENT ON COLUMN escrow_disputes.anopod_id       IS 'The pod that made the seller''s account (anos_accounts.anopod_id at open): a party, notified, uploads evidence.';
COMMENT ON COLUMN escrow_disputes.anopod_id_to    IS 'The pod that made the buyer''s account: the other party.';
COMMENT ON COLUMN escrow_disputes.disputed_by     IS 'Whichever of the two accounts signed the escrowDispute, as the validator reported it.';
COMMENT ON COLUMN escrow_disputes.opened_by       IS 'The attestor pod that opened the case and made the case key.';
COMMENT ON COLUMN escrow_disputes.case_key_x25519 IS 'X25519 public key of the case''s hybrid pair, 32 bytes (spec 13.6). With the ML-KEM key, what every keyForCase is encrypted to.';
COMMENT ON COLUMN escrow_disputes.case_key_mlkem  IS 'ML-KEM-1024 public key of the case''s hybrid pair, 1568 bytes.';
COMMENT ON COLUMN escrow_disputes.status          IS 'open, inReview, decided or dismissed (spec 13.5). decided and dismissed are final.';
COMMENT ON COLUMN escrow_disputes.created_at      IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN escrow_disputes.updated_at      IS 'When the row last changed. Maintained by the escrow_disputes_set_updated_at trigger.';


-- escrow_dispute_keys: the case's private key wrapped to each attestor
-- pod's chat public key, exactly as chat_hpke holds a room key for a member
-- (a longer plaintext, the 96 secret bytes, so 1725 bytes in practice and
-- up to 4096). Written at open for every attestor pod and by
-- /share-case-key afterwards; every row of a case is deleted in the
-- transaction that decides or dismisses it, so no row changes.

CREATE TABLE IF NOT EXISTS escrow_dispute_keys (
  case_id     BYTEA       NOT NULL CHECK (octet_length(case_id) = 32),
  anopod_id   BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  wrapped_key BYTEA       NOT NULL CHECK (octet_length(wrapped_key) <= 4096),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, anopod_id)
);

COMMENT ON TABLE  escrow_dispute_keys             IS 'For each attestor pod holding a dispute case''s private key, that key wrapped to the pod''s chat public key, as chat_hpke holds a room key. Written at open and by /share-case-key; every row of a case is deleted when the case is decided or dismissed.';
COMMENT ON COLUMN escrow_dispute_keys.case_id     IS 'The dispute case.';
COMMENT ON COLUMN escrow_dispute_keys.anopod_id   IS 'The attestor pod the key is wrapped to.';
COMMENT ON COLUMN escrow_dispute_keys.wrapped_key IS 'The case pair''s 96 secret bytes (x25519 secret || ml-kem seed) wrapped as a room key is (spec 13.6): ephemeral P-256 public key (33) || ML-KEM-1024 ciphertext (1568) || the secret under the derived key (124): 1725 bytes. At most 4096. Only that pod can open it.';
COMMENT ON COLUMN escrow_dispute_keys.created_at  IS 'When the row was inserted. Set by default, never changed.';


-- escrow_dispute_evidence: one row per file a party uploaded to a dispute
-- case. The file is ciphertext under a fresh content key; the row carries
-- that key twice: under the uploader's pod encryption key (their own copy,
-- which stays for good) and encrypted to the case key (the attestors' copy,
-- set to null in the transaction that decides or dismisses the case). The
-- server can open none of it. Supplying a file to a later case copies the
-- row with a new case-key wrap; nothing is re-sent.

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

CREATE OR REPLACE TRIGGER escrow_dispute_evidence_set_updated_at
  BEFORE UPDATE ON escrow_dispute_evidence
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  escrow_dispute_evidence              IS 'One row per file a party uploaded to a dispute case: the ciphertext under a fresh content key, that key under the uploader''s pod encryption key (stays) and encrypted to the case key (nulled when the case is decided or dismissed). The server can open none of it. A party sees only their own rows; the attestors see both sides.';
COMMENT ON COLUMN escrow_dispute_evidence.evidence_id  IS 'Random id, 32 raw bytes, minted by /add-dispute-evidence. A copy made for a later case gets its own.';
COMMENT ON COLUMN escrow_dispute_evidence.case_id      IS 'The dispute case the row belongs to.';
COMMENT ON COLUMN escrow_dispute_evidence.anopod_id    IS 'The uploader: the seller''s or the buyer''s pod.';
COMMENT ON COLUMN escrow_dispute_evidence.content_type IS 'The plaintext''s type: image/jpeg, image/png, image/webp or application/pdf.';
COMMENT ON COLUMN escrow_dispute_evidence.file         IS 'The file''s bytes under the content key (iv || ciphertext || tag), at most MAX_IMAGE_BYTES plus the overhead.';
COMMENT ON COLUMN escrow_dispute_evidence.key_for_me   IS 'The content key under the uploader''s pod encryption key (iv || ciphertext || tag, 60 bytes). The uploader''s copy; stays for good.';
COMMENT ON COLUMN escrow_dispute_evidence.key_for_case IS 'The content key encrypted to the case key as a share is encrypted to a keyholder (keyholder spec 7.1, aad the case id), 1660 bytes. The attestors'' copy; null once the case is decided or dismissed.';
COMMENT ON COLUMN escrow_dispute_evidence.created_at   IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN escrow_dispute_evidence.updated_at   IS 'When the row last changed (the case-key copy removed). Maintained by the escrow_dispute_evidence_set_updated_at trigger.';


-- attestor_events: the log of both kinds of case, and since 2026-11-08 of
-- the break-glass cases too (section 14), append-only. One row per
-- thing that happened (spec 13.5); anopod_id is the acting pod, an attestor
-- or a party, null for the server's own events (decided, lookupIdCleared,
-- evidenceDeleted); details holds what the kind carries, the signed
-- follow-up objects included. A new duty later is a new kind in the check,
-- not a new column.

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

COMMENT ON TABLE  attestor_events            IS 'The log of the attestor cases (assisted_trades, escrow_disputes and, since 2026-11-08, break_glass_cases), append-only: one row per thing that happened (spec 13.5 and 14.5). anopod_id is the acting pod, an attestor or a party; null for the server''s own events.';
COMMENT ON COLUMN attestor_events.event_id   IS 'Random id, 32 raw bytes.';
COMMENT ON COLUMN attestor_events.case_id    IS 'The case the event belongs to: an assisted_trades, an escrow_disputes or a break_glass_cases row (a case id names one row in one table).';
COMMENT ON COLUMN attestor_events.kind       IS 'opened, lookupIdShared, evidenceAdded, scheduled, bucketOneViewed, bucketTwoViewed, caseKeyShared, attestationSigned, verdictSigned, decided, lookupIdCleared, evidenceDeleted, sent or dismissed. A new duty later is a new kind, not a new column.';
COMMENT ON COLUMN attestor_events.anopod_id  IS 'The acting pod: an attestor, or a party (lookupIdShared, evidenceAdded). Null for the server''s own events: decided, lookupIdCleared, evidenceDeleted.';
COMMENT ON COLUMN attestor_events.details    IS 'What the kind carries (spec 13.5): { transactionId, accountId } or { transactionId, accountId, accountIdTo, disputedBy, keyHolders } for opened; {} for lookupIdShared and lookupIdCleared; { evidenceIds } for evidenceAdded; { at, meetLink } for scheduled; { keyIds } for the bucket views; { anopodId } for caseKeyShared; { attestorId, attestation } for attestationSigned and { arbitratorId, verdict, object } for verdictSigned, the whole signed follow-up object included; { attestorIds } or { verdict, arbitratorIds } for decided; on a break-glass case (spec 14.5) { moves } for opened and { attestorId, attestations } for attestationSigned, the whole objects in move order; { evidence, keys } (the counts) for evidenceDeleted; { validator, results } for sent; { reason, note } for dismissed.';
COMMENT ON COLUMN attestor_events.created_at IS 'When the row was inserted: the statement''s clock (clock_timestamp()), so events one transaction writes keep their order.';


-- The notifications check widened to the five case kinds of spec 13.7.
-- Idempotent: a drop-and-add of the check under its one name, as the
-- challenges check above.

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('vouchRequest', 'vouchApproved', 'vouchDeclined', 'vouched',
                  'chatInvite', 'inviteAccepted', 'inviteDeclined',
                  'joinRequest', 'joinApproved', 'joinDeclined',
                  'tradeCaseOpened', 'disputeCaseOpened', 'caseScheduled',
                  'caseDecided', 'caseDismissed'));


-- The marketplace block (2026-11-06): chat_rooms.listing_id, the listing a
-- room is about, with its index and a backfill for the old marketplace
-- rooms, and listings.chat_room_id made nullable, since a listing no longer
-- gets a room of its own. The column and the nullable chat_room_id are also
-- inline in the two CREATE TABLEs above, for a fresh database; the index
-- and the column comment are here only, after the column exists on a live
-- one. All idempotent: IF NOT EXISTS, an UPDATE that finds nothing the
-- second time, a DROP NOT NULL that changes nothing on a nullable column.

ALTER TABLE chat_rooms ADD COLUMN IF NOT EXISTS listing_id BYTEA CHECK (octet_length(listing_id) = 32);
CREATE INDEX IF NOT EXISTS chat_rooms_listing_id_idx ON chat_rooms (listing_id) WHERE listing_id IS NOT NULL;
UPDATE chat_rooms r SET listing_id = l.listing_id FROM listings l
 WHERE l.chat_room_id = r.chat_room_id AND r.listing_id IS NULL;
ALTER TABLE listings ALTER COLUMN chat_room_id DROP NOT NULL;

COMMENT ON COLUMN chat_rooms.listing_id IS 'The listing the room is about, 32 raw bytes, or null. Set on a private room made by /create-chat-room with a listingId (2026-11-06) and, by the marketplace block''s backfill, on every old marketplace room.';


-- ---------------------------------------------------------------------------
-- The wallet memory block (added 2026-11-07, wallet spec 4.6 and 4.7): what
-- a wallet remembers for its pod. noted_transactions: one row per ledger
-- transaction the person noted for their tax records, the ledger's own facts
-- in the clear (the masterpod already links a pod to its accounts and the
-- validators hold the chain) and the private part, the kind, the money, the
-- currency and the memo, under the pod's encryption key, which this server
-- cannot open. wallet_settings: one row per pod, one blob of the small things
-- the wallet remembers (the Protect your passkey answer first), under the same
-- key. Stand-alone: no foreign keys. A note is deleted when the person removes
-- it; the settings row is replaced in place.
-- ---------------------------------------------------------------------------

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

CREATE OR REPLACE TRIGGER noted_transactions_set_updated_at
  BEFORE UPDATE ON noted_transactions
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  noted_transactions                  IS 'One row per ledger transaction a pod noted for its tax records: the ledger''s facts in the clear and the private part (the kind, the money, the currency, the memo) under the pod''s encryption key. One note per pod and transaction. Deleted when the person removes it. Stand-alone; no foreign keys.';
COMMENT ON COLUMN noted_transactions.note_id          IS 'Random id, 32 raw bytes, minted by /add-noted-transaction.';
COMMENT ON COLUMN noted_transactions.anopod_id        IS 'The pod that noted it.';
COMMENT ON COLUMN noted_transactions.transaction_id   IS 'The transaction''s id on the validators, 32 raw bytes.';
COMMENT ON COLUMN noted_transactions.account_id       IS 'The pod''s anos account the transaction belongs to (an anos_accounts row of the pod''s).';
COMMENT ON COLUMN noted_transactions.other_account_id IS 'The other side of the transaction as the wallet shows it (the receiver when the pod sent, the sender when it received), or null when there is none.';
COMMENT ON COLUMN noted_transactions.position         IS 'The transaction''s position on the ledger, as /list-transactions answers it.';
COMMENT ON COLUMN noted_transactions.transacted_at    IS 'When the validators wrote the transaction (createdAt).';
COMMENT ON COLUMN noted_transactions.amount           IS 'Millionths of an anos, as the ledger says it.';
COMMENT ON COLUMN noted_transactions.sent             IS 'True when the anos left the pod''s account, false when they came in or nothing moved.';
COMMENT ON COLUMN noted_transactions.note_blob        IS 'Ciphertext of the private part (iv || ciphertext || tag), at most 4096 bytes: a JSON object with the kind, the money, the currency, the memo and the tag, under the pod''s encryption key (wallet spec 7). The server cannot open it.';
COMMENT ON COLUMN noted_transactions.created_at       IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN noted_transactions.updated_at       IS 'When the row last changed. Maintained by the noted_transactions_set_updated_at trigger.';

CREATE TABLE IF NOT EXISTS wallet_settings (
  anopod_id     BYTEA       PRIMARY KEY CHECK (octet_length(anopod_id) = 32),
  settings_blob BYTEA       NOT NULL CHECK (octet_length(settings_blob) <= 16384),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER wallet_settings_set_updated_at
  BEFORE UPDATE ON wallet_settings
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  wallet_settings               IS 'One row per pod: the small things its wallet remembers, as one encrypted JSON object (the Protect your passkey answer first; wallet spec 7). Written whole by /set-wallet-settings. The server cannot open it.';
COMMENT ON COLUMN wallet_settings.anopod_id     IS 'The pod.';
COMMENT ON COLUMN wallet_settings.settings_blob IS 'Ciphertext of the settings object (iv || ciphertext || tag), at most 16384 bytes, under the pod''s encryption key.';
COMMENT ON COLUMN wallet_settings.created_at    IS 'When the row was inserted. Set by default, never changed.';
COMMENT ON COLUMN wallet_settings.updated_at    IS 'When the row last changed. Maintained by the wallet_settings_set_updated_at trigger.';


-- ---------------------------------------------------------------------------
-- The break-glass block (added 2026-11-08, spec section 14): the recovery
-- case as the attestors see it. The key blobs of a pod's anos accounts open
-- under a key from the passkey's PRF output alone (wallet spec 7, 2026-11-08),
-- so a lost passkey kills the old accounts' keys for good. At the finish of
-- the recovery the wallet makes a new account of the same type for each old
-- account that holds anos, posts a breakGlassTransfer for each to a
-- validator, signed by the account's break-glass pair (anossoftware spec 22),
-- and files the moves here (/file-break-glass-moves). Two attestors list the
-- case beside the trades, check the person once more against the recovery
-- case's two moderator approvals and sign one attestation per move; the
-- deciding attestor's app posts them to a validator. break_glass_cases: one
-- row per recovery case the finish filed moves for, keyed by the recovery
-- case's own id. break_glass_moves: one row per move, append-only. The
-- attestors' actions are attestor_events rows with the case id (the kinds
-- scheduled, bucketOneViewed, bucketTwoViewed, attestationSigned, decided,
-- sent and dismissed; opened records the filing), as trades and disputes
-- already share that log. No foreign keys; the services keep the references
-- straight.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS break_glass_cases (
  case_id    BYTEA       PRIMARY KEY CHECK (octet_length(case_id) = 32),
  anopod_id  BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  status     TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'inReview', 'decided', 'dismissed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS break_glass_cases_status_created_at_idx ON break_glass_cases (status, created_at DESC);

CREATE OR REPLACE TRIGGER break_glass_cases_set_updated_at
  BEFORE UPDATE ON break_glass_cases
  FOR EACH ROW
  WHEN (OLD.* IS DISTINCT FROM NEW.*)
  EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  break_glass_cases            IS 'One row per recovery case whose finish filed break-glass moves: the recovery case seen by the attestors. The recovered pod and the status; the moves are break_glass_moves rows, everything that happens is an attestor_events row with this case id. Stand-alone; no foreign keys.';
COMMENT ON COLUMN break_glass_cases.case_id    IS 'The recovery case''s id (recovery_cases.case_id), 32 raw bytes: a break-glass case is the recovery case seen by the attestors. Written by /file-break-glass-moves at the finish; the moves and the attestor_events of the case name it.';
COMMENT ON COLUMN break_glass_cases.anopod_id  IS 'The recovered pod: the person whose old accounts the moves empty, the caller of /file-break-glass-moves (recovery_cases.anopod_id).';
COMMENT ON COLUMN break_glass_cases.status     IS 'open, inReview, decided or dismissed (spec 14.5), the statuses of a trade case. decided and dismissed are final.';
COMMENT ON COLUMN break_glass_cases.created_at IS 'When the row was inserted (the first filing). Set by default, never changed.';
COMMENT ON COLUMN break_glass_cases.updated_at IS 'When the row last changed. Maintained by the break_glass_cases_set_updated_at trigger.';

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

COMMENT ON TABLE  break_glass_moves                IS 'One row per break-glass move a recovery''s finish filed: the breakGlassTransfer on the validators, the old account it empties, the new account of the same type it fills, the type. One move per transaction (the primary key). Append-only; the attestors sign one attestation per row.';
COMMENT ON COLUMN break_glass_moves.transaction_id IS 'The breakGlassTransfer''s transaction id on the validators, 32 raw bytes. The attestations the attestors sign name it.';
COMMENT ON COLUMN break_glass_moves.case_id        IS 'The break-glass case the move belongs to: a break_glass_cases row, and so a recovery_cases row.';
COMMENT ON COLUMN break_glass_moves.account_id     IS 'The old account, whose keys died with the passkey: the move''s sender (an anos_accounts row of the recovered pod''s).';
COMMENT ON COLUMN break_glass_moves.account_id_to  IS 'The new account the finish made: the move''s receiver (an anos_accounts row of the same pod''s, of the same type).';
COMMENT ON COLUMN break_glass_moves.account_type   IS 'spending, guarded, vault or assisted: the type both accounts have, checked at filing (the validators check it again).';
COMMENT ON COLUMN break_glass_moves.created_at     IS 'When the row was inserted (the filing). Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- The DAO voting block (added 2026-11-08, spec section 15): plain-text
-- proposals and stake-weighted votes, the ledger of the DAO. One staked anos
-- of the daoVote purpose is one vote (anossoftware spec 2): a pod's weight is
-- the whole anos of dao_vote_stake summed over its anos accounts, read from a
-- validator (/list-dao-stakes) and boiled down to one weight per pod when a
-- proposal is posted and again when it goes to a vote. dao_proposals: one row
-- per proposal, pending while it collects support like a petition, open while
-- it takes votes, then accepted, rejected or expired. dao_votes: one row per
-- pod per stage, a support in the pending stage or a vote for or against in
-- the official stage, append-only; the row keeps the voter's weight, so the
-- archive stands on its own. dao_snapshot_weights: the weights of the
-- proposal's current snapshot, replaced when the proposal goes open and
-- deleted when it finishes, so no trigger on it. A clock in the masterpod
-- (src/dao/dao-clock.js) runs the expiry, the flip to open and the close
-- every minute. No foreign keys; the service keeps the references straight.
-- ---------------------------------------------------------------------------

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

COMMENT ON TABLE  dao_proposals                IS 'One row per DAO proposal (spec 15.3): plain text, the proposer''s pod, the status, the current snapshot''s total, the support needed, the stage times and the result. Pending while it collects support, open while it takes votes, then accepted, rejected or expired; never deleted. Stand-alone; no foreign keys.';
COMMENT ON COLUMN dao_proposals.proposal_id    IS 'Random id, 32 raw bytes, minted by /create-dao-proposal.';
COMMENT ON COLUMN dao_proposals.anopod_id      IS 'The proposer''s pod. One pending proposal per pod at a time: the partial unique index dao_proposals_one_pending_per_pod_idx.';
COMMENT ON COLUMN dao_proposals.title          IS 'Plain text, 1 to 100 characters, trimmed, shown as typed.';
COMMENT ON COLUMN dao_proposals.body           IS 'Plain text, 1 to 5000 characters, trimmed, shown as typed; no links, no formatting.';
COMMENT ON COLUMN dao_proposals.status         IS 'pending (collecting support), open (taking votes), accepted, rejected or expired (spec 15.5). The flip and the clock move it; the last three are final. Expired proposals leave the lists but stay here.';
COMMENT ON COLUMN dao_proposals.snapshot_total IS 'All DAO votes (whole anos, never millionths) in the current snapshot: the posting snapshot''s total while pending, replaced by the fresh snapshot''s when the proposal goes open.';
COMMENT ON COLUMN dao_proposals.snapshot_at    IS 'The validator''s asOf of the current snapshot; replaced together with snapshot_total.';
COMMENT ON COLUMN dao_proposals.needed         IS 'The support (whole anos) that takes the proposal to a vote: max(1, ceil(the posting snapshot''s total * DAO_PROPOSAL_PERCENT / 100)). Never changes.';
COMMENT ON COLUMN dao_proposals.pending_until  IS 'When the pending stage ends: the posting + DAO_PENDING_MINUTES. A proposal still pending then expires.';
COMMENT ON COLUMN dao_proposals.opened_at      IS 'When the proposal went open (the flip). Null before.';
COMMENT ON COLUMN dao_proposals.vote_closes_at IS 'When the vote ends: opened_at + DAO_VOTE_MINUTES. Null before the flip.';
COMMENT ON COLUMN dao_proposals.decided_at     IS 'When the proposal finished: the close (accepted or rejected) or the expiry. Null before.';
COMMENT ON COLUMN dao_proposals.result_for     IS 'The votes for (whole anos) at the close. Null before it, and on an expired proposal.';
COMMENT ON COLUMN dao_proposals.result_against IS 'The votes against (whole anos) at the close. Null before it, and on an expired proposal.';
COMMENT ON COLUMN dao_proposals.created_at     IS 'When the row was inserted (the posting). Set by default, never changed.';
COMMENT ON COLUMN dao_proposals.updated_at     IS 'When the row last changed. Maintained by the dao_proposals_set_updated_at trigger.';

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

COMMENT ON TABLE  dao_votes             IS 'One row per pod per stage of a DAO proposal (spec 15.3): a support while the proposal was pending, a vote for or against while it was open, each with the pod''s weight at the time. Append-only: one action per pod per stage, no undo. Every row is public.';
COMMENT ON COLUMN dao_votes.proposal_id IS 'The proposal (a dao_proposals row).';
COMMENT ON COLUMN dao_votes.anopod_id   IS 'The pod that supported or voted. One row per pod per stage: the primary key.';
COMMENT ON COLUMN dao_votes.stage       IS 'pending: a support, given while the proposal collected support. official: a vote, given while it was open. A support is not a vote; everyone votes fresh.';
COMMENT ON COLUMN dao_votes.vote        IS 'for or against. In the pending stage always for (the check): a support.';
COMMENT ON COLUMN dao_votes.weight      IS 'The pod''s DAO votes (whole anos) in the proposal''s snapshot at the time: the posting snapshot in the pending stage, the fresh one in the official stage. Kept here, so the archive stands once the snapshot rows are gone.';
COMMENT ON COLUMN dao_votes.created_at  IS 'When the row was inserted. Set by default, never changed.';

CREATE TABLE IF NOT EXISTS dao_snapshot_weights (
  proposal_id BYTEA  NOT NULL CHECK (octet_length(proposal_id) = 32),
  anopod_id   BYTEA  NOT NULL CHECK (octet_length(anopod_id) = 32),
  weight      BIGINT NOT NULL CHECK (weight >= 1),
  PRIMARY KEY (proposal_id, anopod_id)
);

COMMENT ON TABLE  dao_snapshot_weights             IS 'The current snapshot of a DAO proposal (spec 15.6): one row per pod with DAO votes, as a validator answered them when the proposal was posted, replaced by a fresh read when it goes open, deleted when it finishes. The weight a support or a vote is recorded with. No trigger: the service replaces and deletes these rows.';
COMMENT ON COLUMN dao_snapshot_weights.proposal_id IS 'The proposal (a dao_proposals row).';
COMMENT ON COLUMN dao_snapshot_weights.anopod_id   IS 'A pod with DAO votes in the snapshot. Pods at 0 have no row.';
COMMENT ON COLUMN dao_snapshot_weights.weight      IS 'The pod''s DAO votes (whole anos): the millionths of dao_vote_stake summed over the pod''s anos accounts, floored.';
