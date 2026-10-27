import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { env } from '../config/env.js';
import { isObject } from '../util/is-object.js';

/**
 * The passkey checks, wrapping @simplewebauthn/server. Both verifications
 * expect the browser's PublicKeyCredential.toJSON() as the phone sends it,
 * the challenge the server issued (raw bytes; the library compares its
 * base64url form with clientDataJSON), RP_ID and the WEB_ORIGIN list from
 * the environment, and user verification. The library throws on every failure,
 * so each wrapper turns that into { ok: false, reason } for the log.
 */

/**
 * Verifies a registration. Returns { ok: true, credentialId, publicKey }
 * with the credential id and the COSE public key as Buffers, or
 * { ok: false, reason }.
 */
export async function verifyRegistration(passkeyJson, challenge) {
  try {
    const result = await verifyRegistrationResponse({
      response: passkeyJson,
      expectedChallenge: challenge.toString('base64url'),
      expectedOrigin: env.webOrigins,
      expectedRPID: env.rpId,
      requireUserVerification: true,
    });
    if (!result.verified) return { ok: false, reason: 'registration not verified' };
    const { credential } = result.registrationInfo;
    return {
      ok: true,
      credentialId: Buffer.from(credential.id, 'base64url'),
      publicKey: Buffer.from(credential.publicKey),
    };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

/**
 * Verifies an assertion against the stored credential id and COSE public
 * key (Buffers). The sign counter is ignored: the stored counter is given
 * as 0, and the library only compares counters when one of them is above
 * 0, so a synced passkey reporting 0 and a hardware key counting up both
 * pass. Returns { ok: true } or { ok: false, reason }.
 */
export async function verifyAuthentication(assertionJson, challenge, credentialId, publicKey) {
  try {
    const result = await verifyAuthenticationResponse({
      response: assertionJson,
      expectedChallenge: challenge.toString('base64url'),
      expectedOrigin: env.webOrigins,
      expectedRPID: env.rpId,
      requireUserVerification: true,
      credential: {
        id: credentialId.toString('base64url'),
        publicKey: new Uint8Array(publicKey),
        counter: 0,
      },
    });
    return result.verified ? { ok: true } : { ok: false, reason: 'assertion not verified' };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

/**
 * True when the WebAuthn JSON carries a PRF output
 * (clientExtensionResults.prf.results). The PRF output is the phone's
 * secret and must never reach the server; both ceremonies refuse it.
 */
export function prfResultsPresent(json) {
  const prf = json?.clientExtensionResults?.prf;
  return isObject(prf) && prf.results !== undefined;
}

/** True when a registration reports clientExtensionResults.prf.enabled === true. */
export function prfEnabled(json) {
  return json?.clientExtensionResults?.prf?.enabled === true;
}

/**
 * Decodes a base64url string as the WebAuthn JSON carries them (rawId,
 * userHandle) to a Buffer; null for anything that is not one. Strict, unlike
 * decodeBytes, because a credential id has no fixed length to tell hex from
 * base64 by.
 */
export function decodeBase64Url(text) {
  if (typeof text !== 'string' || text.length === 0 || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
  return Buffer.from(text, 'base64url');
}
