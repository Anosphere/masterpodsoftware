import { findById } from '../anopods/anopods.queries.js';
import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { decodeId } from '../util/ids.js';
import { answer, refuse } from '../util/result.js';
import { insertNonce } from './nonces.queries.js';
import { parseSignedRequest, verifySignatures } from './signed-request.js';

/** A nonce is 16 to 32 bytes. */
const nonceLength = (n) => n >= 16 && n <= 32;

/**
 * The session middleware of spec section 3. Runs the eight checks in order
 * and stops at the first failure; on success `req.anopod` is the caller's
 * anopods row (anopods.queries.js anopodRow) and `req.body` is
 * `payload.body`, the route's own object, so a handler reads the caller
 * from req.anopod and nothing else.
 */
export async function requireSession(req, res, next) {
  // 1. Shape.
  const parsed = parseSignedRequest(req.body);
  if (parsed.reason) return answer(res, refuse(400, parsed.reason));
  const { payload, signatures } = parsed;

  // 2. The pod.
  const anopodId = decodeId(payload.anopodId);
  const anopod = anopodId === null ? null : await findById(anopodId);
  if (anopod === null) return answer(res, refuse(401, 'unknown anopod'));

  // 3. The session is alive.
  if (anopod.ephemeralExpiresAt.getTime() <= Date.now()) {
    return answer(res, refuse(401, 'session expired'));
  }

  // 4. The signed path is this route.
  if (payload.path !== req.baseUrl + req.path) return answer(res, refuse(401, 'path mismatch'));

  // 5. The timestamp is within the window, either way.
  const timestamp = Date.parse(payload.timestamp);
  if (Number.isNaN(timestamp) || Math.abs(timestamp - Date.now()) > env.timestampWindowSeconds * 1000) {
    return answer(res, refuse(401, 'timestamp outside window'));
  }

  // 6. Both signatures, by the session keys on the row.
  if (!verifySignatures(payload, signatures, anopod.ephemeralAuthKey, anopod.ephemeralAuthKeyPq)) {
    return answer(res, refuse(401, 'bad signature'));
  }

  // 7. The nonce is new. It is kept twice the window, past which the
  //    timestamp check refuses the request anyway.
  const nonce = decodeBytes(payload.nonce, nonceLength);
  if (nonce === null) return answer(res, refuse(400, 'invalid nonce'));
  const expiresAt = new Date(Date.now() + 2 * env.timestampWindowSeconds * 1000);
  if (!(await insertNonce(anopodId, nonce, expiresAt))) return answer(res, refuse(401, 'replay'));

  // 8. The caller, and the route's object.
  req.anopod = anopod;
  req.body = payload.body;
  next();
}
