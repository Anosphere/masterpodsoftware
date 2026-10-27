import { query } from '../db/pool.js';
import { randomId, toHex } from '../util/ids.js';
import { encodeImage } from '../util/images.js';

/**
 * SQL for the security_images and security_info tables. Both are
 * append-only (db/schema.sql), so there are inserts and one list, nothing
 * else. Ids are 32-byte Buffers.
 */

/**
 * Writes one security_images row per image on `client`, for `anopodId` in
 * bucket `type`, every row under the bucket key `keyId` (a 32-byte Buffer).
 * `images` are { contentType, bytes } from decodeImage. Returns the new
 * image ids, in order.
 */
export async function insertImages(client, anopodId, type, keyId, images) {
  const ids = [];
  for (const { contentType, bytes } of images) {
    const imageId = randomId();
    await client.query(
      `INSERT INTO security_images (image_id, anopod_id, type, content_type, image, key_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [imageId, anopodId, type, contentType, bytes, keyId],
    );
    ids.push(imageId);
  }
  return ids;
}

/**
 * Writes one security_info row per text on `client`, for `anopodId` in
 * bucket `type`, every row under the bucket key `keyId` (a 32-byte Buffer).
 * `infos` are Buffers of ciphertext. Returns the new info ids, in order.
 */
export async function insertInfo(client, anopodId, type, keyId, infos) {
  const ids = [];
  for (const info of infos) {
    const infoId = randomId();
    await client.query(
      'INSERT INTO security_info (info_id, anopod_id, type, info, key_id) VALUES ($1, $2, $3, $4, $5)',
      [infoId, anopodId, type, info, keyId],
    );
    ids.push(infoId);
  }
  return ids;
}

/**
 * Everything in both tables for `anopodId`, oldest first, in wire form:
 * { images: [ { imageId, type, contentType, image, keyId, createdAt } ],
 *   info: [ { infoId, type, info, keyId, createdAt } ] }.
 */
export async function listFor(anopodId) {
  const [images, info] = await Promise.all([
    query(
      `SELECT image_id, type, content_type, image, key_id, created_at
       FROM security_images WHERE anopod_id = $1 ORDER BY created_at, image_id`,
      [anopodId],
    ),
    query(
      `SELECT info_id, type, info, key_id, created_at
       FROM security_info WHERE anopod_id = $1 ORDER BY created_at, info_id`,
      [anopodId],
    ),
  ]);
  return {
    images: images.rows.map((row) => ({
      imageId: toHex(row.image_id),
      type: row.type,
      ...encodeImage(row),
      keyId: toHex(row.key_id),
      createdAt: row.created_at.toISOString(),
    })),
    info: info.rows.map((row) => ({
      infoId: toHex(row.info_id),
      type: row.type,
      info: row.info.toString('base64'),
      keyId: toHex(row.key_id),
      createdAt: row.created_at.toISOString(),
    })),
  };
}
