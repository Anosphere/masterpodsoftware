import { query } from '../db/pool.js';
import { encodeImage } from '../util/images.js';

/** SQL for the public_selfies table: one plaintext selfie per pod. */

/** Writes the pod's selfie on `client`, with the pod itself. */
export async function insertSelfie(client, anopodId, contentType, bytes) {
  await client.query(
    'INSERT INTO public_selfies (anopod_id, content_type, image) VALUES ($1, $2, $3)',
    [anopodId, contentType, bytes],
  );
}

/** The pod's selfie in its wire form, { contentType, image }, or null. */
export async function findSelfie(anopodId) {
  const { rows } = await query('SELECT content_type, image FROM public_selfies WHERE anopod_id = $1', [
    anopodId,
  ]);
  return rows.length === 0 ? null : encodeImage(rows[0]);
}
