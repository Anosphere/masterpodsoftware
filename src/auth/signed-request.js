import { canonicalize } from '../crypto/canonical.js';
import { ECDSA_P256, ML_DSA_87, decodeSignature, verifySignature } from '../crypto/signatures.js';
import { isObject } from '../util/is-object.js';

/**
 * The signed request envelope of spec section 3: { payload, signatures },
 * with signatures = { ecdsa, mldsa } over the RFC 8785 canonical bytes of
 * payload, made with the pod's ephemeral keys. Both must verify.
 */

/** The reason every shape failure answers with. */
export const BAD_SHAPE = 'bad request shape';

/**
 * Checks the envelope of a session request: `payload` an object with string
 * anopodId, path, timestamp and nonce and an object body; `signatures` with
 * string ecdsa and mldsa. Returns { payload, signatures } or { reason }.
 * /create-anopod and /unlock have payloads of their own and check them
 * themselves, with hasSignatureShape for the signatures.
 */
export function parseSignedRequest(body) {
  if (!isObject(body) || !isObject(body.payload) || !hasSignatureShape(body.signatures)) {
    return { reason: BAD_SHAPE };
  }
  const { payload, signatures } = body;
  for (const field of ['anopodId', 'path', 'timestamp', 'nonce']) {
    if (typeof payload[field] !== 'string') return { reason: BAD_SHAPE };
  }
  if (!isObject(payload.body)) return { reason: BAD_SHAPE };
  return { payload, signatures };
}

/** True when `signatures` is an object with string ecdsa and mldsa. */
export function hasSignatureShape(signatures) {
  return isObject(signatures) && typeof signatures.ecdsa === 'string' && typeof signatures.mldsa === 'string';
}

/**
 * True when both signatures verify over the canonical bytes of `payload`:
 * `ecdsa` by the P-256 key `ecdsaKey`, `mldsa` by the ML-DSA-87 key
 * `mldsaKey`, both keys raw Buffers (from the anopods row, or decoded from
 * the payload of /create-anopod and /unlock). A key or signature that does
 * not decode is simply false.
 */
export function verifySignatures(payload, signatures, ecdsaKey, mldsaKey) {
  if (!ecdsaKey || !mldsaKey) return false;
  const ecdsa = decodeSignature(ECDSA_P256, signatures.ecdsa);
  const mldsa = decodeSignature(ML_DSA_87, signatures.mldsa);
  if (ecdsa === null || mldsa === null) return false;

  let message;
  try {
    message = Buffer.from(canonicalize(payload), 'utf8');
  } catch {
    return false;
  }
  return (
    verifySignature(ECDSA_P256, ecdsaKey, message, ecdsa) &&
    verifySignature(ML_DSA_87, mldsaKey, message, mldsa)
  );
}
