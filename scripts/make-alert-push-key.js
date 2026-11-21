import { createECDH } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Makes this server's key for the phones' delivery services (spec 25.8),
 * the key a notification of the security alerts is signed with:
 *
 *   npm run make-alert-push-key -- <file>
 *
 * A fresh P-256 key pair. The private half goes into <file> as ONE line,
 *
 *   ALERT_PUSH_PRIVATE_KEY=<the private half, 32 bytes as base64url>
 *
 * which is the line for the end of .env, the same on every server. The
 * file is made for its owner alone (mode 0600), and a file that exists is
 * never overwritten. What is printed: the file's path and the public half
 * as base64url. Nothing else, and never the private half.
 *
 * The file is the one copy of the key outside the servers: with a new key
 * every phone has to be turned on again. It reads no env variable, opens
 * no database and needs no node_modules. Exits 2 with no <file>, 1 when
 * the file exists already or cannot be written.
 */

const file = process.argv[2];
if (file === undefined || file === '') {
  console.error('usage: npm run make-alert-push-key -- <file>');
  process.exit(2);
}

const ecdh = createECDH('prime256v1');
ecdh.generateKeys();

// The private half as 32 bytes: a number that begins with a zero byte
// comes back shorter, and the setting takes exactly 43 characters.
const short = ecdh.getPrivateKey();
const privateHalf = Buffer.concat([Buffer.alloc(32 - short.length), short]);

const path = resolve(file);
try {
  writeFileSync(path, `ALERT_PUSH_PRIVATE_KEY=${privateHalf.toString('base64url')}\n`, { mode: 0o600, flag: 'wx' });
} catch (err) {
  console.error(err.code === 'EEXIST' ? `${path}: this file exists already, nothing was written` : `${path}: could not be written (${err.code ?? err.message})`);
  process.exit(1);
}

console.log(`written: ${path}`);
console.log(`public key: ${ecdh.getPublicKey().toString('base64url')}`);
