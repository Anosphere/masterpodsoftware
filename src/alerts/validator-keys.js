import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { env } from '../config/env.js';
import { ECDSA_P256, decodePublicKey } from '../crypto/signatures.js';
import { isObject } from '../util/is-object.js';

/**
 * The validators' public keys (spec 25.8), for their reports of waiting
 * transfers (validator-reports.js). The file is network/validators.json, or
 * the one VALIDATOR_KEYS_FILE names: a JSON list of { id, publicKey }, the
 * id and the public key of each entry of the validators' registry
 * (anossoftware/network/testnet.registry.json), and nothing else of it. A
 * validator's key changes only with the registry; when a registry entry is
 * added or its key changes, the file gets the same change and this server
 * is deployed.
 *
 * The file is read once, when this module is imported. Without the file
 * the keys are null and every report is refused. A file that is there and
 * is wrong stops the boot, with the file's path and the entry's place in
 * the error.
 */

/** The repo's root, where a path that does not start with / is taken from. */
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

/**
 * Reads the file at `path`: a Map from a validator's id to its key's 33
 * bytes, or null when there is no such file. Throws on a file that does not
 * parse or is no list, on an entry whose id is not a positive whole number
 * or whose key is not 33 bytes of a P-256 key, and on an id that stands
 * twice.
 */
function readKeys(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error(`${path}: the validators' keys cannot be read (${err.code ?? err.message})`);
  }
  let list;
  try {
    list = JSON.parse(text);
  } catch {
    throw new Error(`${path}: the validators' keys are not JSON`);
  }
  if (!Array.isArray(list)) throw new Error(`${path}: the validators' keys must be a JSON list`);

  const keys = new Map();
  list.forEach((entry, index) => {
    const place = `${path}: entry ${index + 1}`;
    if (!isObject(entry) || !Number.isInteger(entry.id) || entry.id < 1) {
      throw new Error(`${place}: id must be a positive whole number`);
    }
    const key = decodePublicKey(ECDSA_P256, entry.publicKey);
    if (key === null || key.length !== 33) {
      throw new Error(`${place}: publicKey must be the 33 bytes of a P-256 key`);
    }
    if (keys.has(entry.id)) throw new Error(`${place}: id ${entry.id} stands twice`);
    keys.set(entry.id, key);
  });
  return keys;
}

const file = env.alerts.validatorKeysFile;

/**
 * The validators' keys: a Map from id to the key's 33 bytes (a Buffer), or
 * null when the file does not exist.
 */
export const validatorKeys = readKeys(file.startsWith('/') ? file : join(REPO_ROOT, file));
