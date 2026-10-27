import { PROFILE_COLUMNS, profileFromRow } from '../anopods/anopods.queries.js';
import { pool } from '../db/pool.js';
import { toHex } from '../util/ids.js';
import { encodeImage } from '../util/images.js';

/**
 * SQL for the vouch_requests table: the open requests only. Ids are 32-byte
 * Buffers, matching the BYTEA columns.
 */

/** Writes an open request from `anopodIdFrom` to the seed `anopodIdTo` on `client`. */
export async function insertRequest(client, vouchIdNumber, anopodIdFrom, anopodIdTo) {
  await client.query(
    `INSERT INTO vouch_requests (vouch_id_number, anopod_id_from, anopod_id_to)
     VALUES ($1, $2, $3)`,
    [vouchIdNumber, anopodIdFrom, anopodIdTo],
  );
}

/** The open request with this id, as { vouchIdNumber, anopodIdFrom, anopodIdTo, createdAt }, or null. */
export async function findRequest(vouchIdNumber, db = pool) {
  const { rows } = await db.query(
    `SELECT vouch_id_number, anopod_id_from, anopod_id_to, created_at
     FROM vouch_requests WHERE vouch_id_number = $1`,
    [vouchIdNumber],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    vouchIdNumber: row.vouch_id_number,
    anopodIdFrom: row.anopod_id_from,
    anopodIdTo: row.anopod_id_to,
    createdAt: row.created_at,
  };
}

/** True when `anopodIdFrom` already has an open request to `anopodIdTo`. */
export async function requestOpen(anopodIdFrom, anopodIdTo, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM vouch_requests WHERE anopod_id_from = $1 AND anopod_id_to = $2) AS open`,
    [anopodIdFrom, anopodIdTo],
  );
  return rows[0].open;
}

/** Deletes the request on `client`: approve and decline both end here. */
export async function deleteRequest(client, vouchIdNumber) {
  await client.query('DELETE FROM vouch_requests WHERE vouch_id_number = $1', [vouchIdNumber]);
}

/**
 * The open requests addressed to `anopodIdTo`, oldest first, each in its
 * wire form: { vouchIdNumber, from: { profile..., selfie }, createdAt }. The
 * selfie is the requester's public selfie, { contentType, image }, so the
 * seed sees who is asking; null for a pod without one.
 */
export async function listOpenFor(anopodIdTo) {
  const { rows } = await pool.query(
    `SELECT r.vouch_id_number, r.created_at, ${PROFILE_COLUMNS},
            ps.content_type AS selfie_content_type, ps.image AS selfie_image
     FROM vouch_requests r
     JOIN anopods a ON a.anopod_id = r.anopod_id_from
     LEFT JOIN public_selfies ps ON ps.anopod_id = a.anopod_id
     WHERE r.anopod_id_to = $1
     ORDER BY r.created_at, r.vouch_id_number`,
    [anopodIdTo],
  );
  return rows.map((row) => ({
    vouchIdNumber: toHex(row.vouch_id_number),
    from: {
      ...profileFromRow(row),
      selfie:
        row.selfie_image === null
          ? null
          : encodeImage({ content_type: row.selfie_content_type, image: row.selfie_image }),
    },
    createdAt: row.created_at.toISOString(),
  }));
}
