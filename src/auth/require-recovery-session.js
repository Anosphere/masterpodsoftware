import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { findById as findCase } from '../recovery/recovery-cases.queries.js';
import { findByCaseId as findPod } from '../recovery/recovery-pods.queries.js';
import { decodeId } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { answer, refuse } from '../util/result.js';
import { insertNonce } from './nonces.queries.js';
import { BAD_SHAPE, hasSignatureShape, verifySignatures } from './signed-request.js';

/** A nonce is 16 to 32 bytes. */
const nonceLength = (n) => n >= 16 && n <= 32;

/**
 * Checks the recovery envelope of spec 12.4.1: the section 3 envelope with
 * `caseId` in place of `anopodId`. Returns { payload, signatures } or
 * { reason }.
 */
function parseRecoveryRequest(body) {
  if (!isObject(body) || !isObject(body.payload) || !hasSignatureShape(body.signatures)) {
    return { reason: BAD_SHAPE };
  }
  const { payload, signatures } = body;
  for (const field of ['caseId', 'path', 'timestamp', 'nonce']) {
    if (typeof payload[field] !== 'string') return { reason: BAD_SHAPE };
  }
  if (!isObject(payload.body)) return { reason: BAD_SHAPE };
  return { payload, signatures };
}

/**
 * Level "recovery" of spec 12.2: the eight checks of section 3 run against
 * the recovery_pods row the case id names (its ephemeral keys, its expiry),
 * the nonce stored under the case id. On success `req.recoveryPod` is the
 * row (recovery-pods.queries.js podRow), `req.recoveryCase` the case
 * (recovery-cases.queries.js caseRow) and `req.body` is `payload.body`.
 */
export async function requireRecoverySession(req, res, next) {
  // 1. Shape.
  const parsed = parseRecoveryRequest(req.body);
  if (parsed.reason) return answer(res, refuse(400, parsed.reason));
  const { payload, signatures } = parsed;

  // 2. The recovery pod, by its case.
  const caseId = decodeId(payload.caseId);
  const pod = caseId === null ? null : await findPod(caseId);
  if (pod === null) return answer(res, refuse(401, 'unknown case'));

  // 3. The recovery session is alive.
  if (pod.ephemeralExpiresAt.getTime() <= Date.now()) {
    return answer(res, refuse(401, 'session expired'));
  }

  // 4. The signed path is this route.
  if (payload.path !== req.baseUrl + req.path) return answer(res, refuse(401, 'path mismatch'));

  // 5. The timestamp is within the window, either way.
  const timestamp = Date.parse(payload.timestamp);
  if (Number.isNaN(timestamp) || Math.abs(timestamp - Date.now()) > env.timestampWindowSeconds * 1000) {
    return answer(res, refuse(401, 'timestamp outside window'));
  }

  // 6. Both signatures, by the recovery session keys on the row.
  if (!verifySignatures(payload, signatures, pod.ephemeralAuthKey, pod.ephemeralAuthKeyPq)) {
    return answer(res, refuse(401, 'bad signature'));
  }

  // 7. The nonce is new, kept under the case id (nonces.anopod_id).
  const nonce = decodeBytes(payload.nonce, nonceLength);
  if (nonce === null) return answer(res, refuse(400, 'invalid nonce'));
  const expiresAt = new Date(Date.now() + 2 * env.timestampWindowSeconds * 1000);
  if (!(await insertNonce(caseId, nonce, expiresAt))) return answer(res, refuse(401, 'replay'));

  // 8. The caller's pod and case, and the route's object.
  const recoveryCase = await findCase(caseId);
  if (recoveryCase === null) return answer(res, refuse(401, 'unknown case'));
  req.recoveryPod = pod;
  req.recoveryCase = recoveryCase;
  req.body = payload.body;
  next();
}
