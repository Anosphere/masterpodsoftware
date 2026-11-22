import { createCipheriv, createECDH, createPrivateKey, hkdfSync, randomBytes, sign } from 'node:crypto';

/**
 * A notification for a phone (Web Push), with Node's own crypto and no
 * package. Two parts:
 *
 *   encryptPush: the body of the request, scrambled for one phone
 *   (RFC 8291, with the content coding aes128gcm of RFC 8188). Only that
 *   phone's browser can open it; the delivery service in between cannot.
 *
 *   vapidAuthorization: the Authorization header that tells the delivery
 *   service which server is sending (RFC 8292): a short token signed with
 *   this server's own P-256 key, and the key's public half.
 *
 * And isP256Point, which says whether a phone's public key is one.
 */

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');

/** The record size written into the body's header: one record holds the whole message. */
const RECORD_SIZE = 4096;

/**
 * Scrambles `plaintext` (a Buffer) for the phone whose subscription holds
 * `p256dh` (its public key, 65 bytes) and `auth` (its secret, 16 bytes).
 * Returns the request body as a Buffer. `salt` (16 bytes) and
 * `localPrivateKey` (32 bytes) are random for every message; they are
 * arguments only so that the RFC's own example can be tried.
 */
export function encryptPush(plaintext, p256dh, auth, salt = randomBytes(16), localPrivateKey = null) {
  const ecdh = createECDH('prime256v1');
  if (localPrivateKey === null) ecdh.generateKeys();
  else ecdh.setPrivateKey(localPrivateKey);
  const localPublicKey = ecdh.getPublicKey();
  const shared = ecdh.computeSecret(p256dh);

  // RFC 8291 section 3.4: the input keying material, from the shared secret,
  // the phone's auth secret and both public keys.
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0', 'ascii'), p256dh, localPublicKey]);
  const ikm = Buffer.from(hkdfSync('sha256', shared, auth, keyInfo, 32));

  // RFC 8188 section 2.2 and 2.3: the content key and the nonce, from the salt.
  const key = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0', 'ascii'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0', 'ascii'), 12));

  // One record: the message, then the byte 2, which marks the last record.
  const cipher = createCipheriv('aes-128-gcm', key, nonce);
  const sealed = Buffer.concat([cipher.update(Buffer.concat([plaintext, Buffer.from([2])])), cipher.final(), cipher.getAuthTag()]);

  // RFC 8188 section 2.1: salt, record size, the length of the key id, the
  // key id (this message's public key), then the sealed record.
  const header = Buffer.alloc(21);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header.writeUInt8(localPublicKey.length, 20);
  return Buffer.concat([header, localPublicKey, sealed]);
}

/**
 * True when `bytes` are a point on the P-256 curve in the long form: 65
 * bytes, the first a 4. A phone's public key has to be one; with anything
 * else encryptPush would throw. Checked when a phone is added.
 */
export function isP256Point(bytes) {
  if (bytes.length !== 65 || bytes[0] !== 4) return false;
  try {
    const ecdh = createECDH('prime256v1');
    ecdh.generateKeys();
    ecdh.computeSecret(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * This server's key for the delivery services, from its private half
 * (32 bytes): { privateKey (a KeyObject), publicKey (65 bytes) }.
 */
export function pushKeyFrom(privateBytes) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(privateBytes);
  const publicKey = ecdh.getPublicKey();
  const privateKey = createPrivateKey({
    key: { kty: 'EC', crv: 'P-256', d: b64url(privateBytes), x: b64url(publicKey.subarray(1, 33)), y: b64url(publicKey.subarray(33, 65)) },
    format: 'jwk',
  });
  return { privateKey, publicKey };
}

/**
 * The Authorization header for one delivery service (RFC 8292): `audience`
 * is the origin of the phone's delivery address, `contact` a web address
 * or a mailto: address of ours, `expires` the token's end as seconds since
 * 1970 (at most 24 hours ahead).
 */
export function vapidAuthorization(pushKey, audience, contact, expires) {
  const head = b64url(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const claims = b64url(JSON.stringify({ aud: audience, exp: expires, sub: contact }));
  const signature = sign('sha256', Buffer.from(`${head}.${claims}`, 'ascii'), { key: pushKey.privateKey, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${head}.${claims}.${b64url(signature)}, k=${b64url(pushKey.publicKey)}`;
}
