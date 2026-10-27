import { canonicalize } from '../crypto/canonical.js';
import { ECDSA_P256, ML_DSA_87, decodePublicKey, decodeSignature, verifySignature } from '../crypto/signatures.js';
import { isObject } from '../util/is-object.js';

/**
 * The signatures an anos account makes over a follow-up (spec 13.4.2): the
 * validators' any-two-pairs rule (anossoftware src/accounts/account-signatures.js),
 * copied here over this repository's verifySignature. The payload is signed
 * as its RFC 8785 canonical bytes; the keys to verify with come from the
 * account's stored creation (anos_accounts.creation.payload.publicKeys),
 * never from the object itself.
 */

/**
 * The key pairs that may sign for an account: pair 1, pair 2 and the wallet
 * pair, each a classical P-256 key with its post-quantum ML-DSA-87 partner.
 * `name` is the field of both the signatures object and the creation's
 * publicKeys. An object signed by a pair carries both keys' signatures: a
 * pair with only one present is a malformed object.
 */
export const SIGNING_PAIRS = Object.freeze([
  Object.freeze([
    { name: 'key1', algorithm: ECDSA_P256 },
    { name: 'postQuantumKey1', algorithm: ML_DSA_87 },
  ]),
  Object.freeze([
    { name: 'key2', algorithm: ECDSA_P256 },
    { name: 'postQuantumKey2', algorithm: ML_DSA_87 },
  ]),
  Object.freeze([
    { name: 'walletKey', algorithm: ECDSA_P256 },
    { name: 'walletPostQuantumKey', algorithm: ML_DSA_87 },
  ]),
]);

/** The eight role names of a creation: what a signatures object may hold fields under. The break-glass pair never signs a follow-up. */
export const SIGNATURE_ROLES = Object.freeze([
  'key1', 'postQuantumKey1', 'key2', 'postQuantumKey2',
  'walletKey', 'walletPostQuantumKey', 'breakGlassKey', 'breakGlassPostQuantumKey',
]);

/** How many of SIGNING_PAIRS a follow-up needs: any two. */
export const MIN_SIGNING_PAIRS = 2;

/**
 * The pairs of SIGNING_PAIRS with a signature present in `signatures`, or
 * null when a pair has one half only.
 */
function presentPairs(signatures) {
  const present = [];
  for (const pair of SIGNING_PAIRS) {
    const halves = pair.filter(({ name }) => signatures[name] !== undefined);
    if (halves.length === 0) continue;
    if (halves.length !== pair.length) return null;
    present.push(pair);
  }
  return present;
}

/**
 * The shape check of spec 13.4.2 (1): `signatures` is an object whose
 * fields are strings under the eight role names, at least two of the three
 * pairs present and both halves of every present pair.
 */
export function hasAccountSignatureShape(signatures) {
  if (!isObject(signatures)) return false;
  for (const [role, value] of Object.entries(signatures)) {
    if (!SIGNATURE_ROLES.includes(role) || typeof value !== 'string') return false;
  }
  const pairs = presentPairs(signatures);
  return pairs !== null && pairs.length >= MIN_SIGNING_PAIRS;
}

/**
 * The verification of spec 13.4.2 (4): every present pair verifies over the
 * RFC 8785 canonical bytes of `payload` against the matching keys of
 * `publicKeys` (the stored creation's), P-256 over the SHA-256 of the bytes,
 * ML-DSA-87 over the bytes. False when fewer than two pairs are present, a
 * key is missing or does not decode, a signature does not decode or does
 * not verify. Never throws on bad input.
 */
export function verifyAccountSignatures(publicKeys, signatures, payload) {
  if (!isObject(publicKeys) || !isObject(signatures)) return false;
  const pairs = presentPairs(signatures);
  if (pairs === null || pairs.length < MIN_SIGNING_PAIRS) return false;

  let message;
  try {
    message = Buffer.from(canonicalize(payload), 'utf8');
  } catch {
    return false;
  }
  for (const pair of pairs) {
    for (const { name, algorithm } of pair) {
      const publicKey = decodePublicKey(algorithm, publicKeys[name]);
      const signature = decodeSignature(algorithm, signatures[name]);
      if (publicKey === null || signature === null || !verifySignature(algorithm, publicKey, message, signature)) {
        return false;
      }
    }
  }
  return true;
}
