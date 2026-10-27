import { env } from '../config/env.js';
import { withTransaction } from '../db/transaction.js';
import { decodeId, toHex } from '../util/ids.js';
import { decodeBase64, decodeImage } from '../util/images.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { insertImages, insertInfo, listFor } from './security.queries.js';

/**
 * The security buckets: bucket one takes images, bucket two images and
 * texts, all ciphertext under keys the pod does not keep. The server checks
 * shapes and sizes and stores; it never opens anything. Every add names the
 * key its rows are under, keyId (wallet spec 4.2): the same 32 bytes the pod
 * deposited with the key's shares on the keyholders, stored on every row
 * the request writes and answered by the list.
 */

const BAD_SHAPE = 'bad request shape';

/** Bucket numbers, as the `type` column has them. */
const BUCKET_ONE = 1;
const BUCKET_TWO = 2;

/** Bucket two takes up to 20 texts per request, each at most 65536 bytes. */
const MAX_INFO_PER_REQUEST = 20;
const MAX_INFO_BYTES = 65536;

/**
 * Decodes an array of image objects. Returns { images } with
 * { contentType, bytes } each, or { reason } naming the first bad one.
 */
function decodeImages(images) {
  const decoded = [];
  for (const [i, image] of images.entries()) {
    const result = decodeImage(image);
    if (result.reason) return { reason: `images[${i}]: ${result.reason}` };
    decoded.push(result);
  }
  return { images: decoded };
}

/**
 * Decodes an array of { info } objects, info base64 of at most 65536 bytes.
 * Returns { infos } as Buffers, or { reason }.
 */
function decodeInfos(infos) {
  const decoded = [];
  for (const [i, entry] of infos.entries()) {
    const bytes = isObject(entry) ? decodeBase64(entry.info, MAX_INFO_BYTES) : null;
    if (bytes === null) return { reason: `info[${i}]: info must be base64 of 1 to ${MAX_INFO_BYTES} bytes` };
    decoded.push(bytes);
  }
  return { infos: decoded };
}

/** POST /add-to-security-bucket-one. Body { keyId, images }, 1 to MAX_IMAGES_PER_REQUEST images. */
export async function addToBucketOne(anopod, body) {
  if (!isObject(body) || !Array.isArray(body.images)) return refuse(400, BAD_SHAPE);
  const keyId = decodeId(body.keyId);
  if (keyId === null) return refuse(400, 'invalid keyId');
  if (body.images.length < 1 || body.images.length > env.maxImagesPerRequest) {
    return refuse(400, `images must hold 1 to ${env.maxImagesPerRequest} images`);
  }
  const { images, reason } = decodeImages(body.images);
  if (reason) return refuse(400, reason);

  const imageIds = await withTransaction((client) => insertImages(client, anopod.anopodId, BUCKET_ONE, keyId, images));
  return ok(201, { imageIds: imageIds.map(toHex) });
}

/**
 * POST /add-to-security-bucket-two. Body { keyId, images, info }, each array
 * optional, at least one entry overall.
 */
export async function addToBucketTwo(anopod, body) {
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  const rawImages = body.images ?? [];
  const rawInfo = body.info ?? [];
  if (!Array.isArray(rawImages) || !Array.isArray(rawInfo)) return refuse(400, BAD_SHAPE);
  const keyId = decodeId(body.keyId);
  if (keyId === null) return refuse(400, 'invalid keyId');
  if (rawImages.length > env.maxImagesPerRequest) {
    return refuse(400, `images must hold at most ${env.maxImagesPerRequest} images`);
  }
  if (rawInfo.length > MAX_INFO_PER_REQUEST) return refuse(400, `info must hold at most ${MAX_INFO_PER_REQUEST} entries`);
  if (rawImages.length + rawInfo.length === 0) return refuse(400, 'nothing to add');
  const decodedImages = decodeImages(rawImages);
  if (decodedImages.reason) return refuse(400, decodedImages.reason);
  const decodedInfos = decodeInfos(rawInfo);
  if (decodedInfos.reason) return refuse(400, decodedInfos.reason);

  const { imageIds, infoIds } = await withTransaction(async (client) => ({
    imageIds: await insertImages(client, anopod.anopodId, BUCKET_TWO, keyId, decodedImages.images),
    infoIds: await insertInfo(client, anopod.anopodId, BUCKET_TWO, keyId, decodedInfos.infos),
  }));
  return ok(201, { imageIds: imageIds.map(toHex), infoIds: infoIds.map(toHex) });
}

/** POST /list-security-records. Everything in both tables for the caller. */
export async function listRecords(anopod) {
  return ok(200, await listFor(anopod.anopodId));
}
