import { randomInt, timingSafeEqual } from 'node:crypto';
import { lockPod } from '../anos-accounts/anos-accounts.queries.js';
import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { sha256 } from '../crypto/hash.js';
import { withTransaction } from '../db/transaction.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { raiseAlert } from './alert-events.js';
import { kickAlertSender, pushKey } from './alert-sender.js';
import {
  clearEmailRemoval,
  clearPhoneRemoval,
  confirmEmail,
  countEmails,
  countPhones,
  countWrongCode,
  deleteEmail,
  findEmailByAddress,
  findPhoneByEndpoint,
  insertEmail,
  insertMessage,
  insertPhone,
  listEmails,
  listPhones,
  lockEmail,
  lockPhone,
  recentChanges,
  recentCodes,
  setCode,
  setEmailRemoval,
  setPhoneRemoval,
} from './alerts.queries.js';
import { isP256Point } from './push.js';

/**
 * A pod's security alerts (spec section 25): the emails and the phones its
 * alerts go to. Eight routes at level setup, for the pod whose list it is.
 * An email counts once the person typed back the six-digit code that was
 * sent to it. An email or a phone that is taken off still gets every alert
 * for a month (ALERT_REMOVE_MINUTES), and "Keep" undoes the taking off, so
 * that whoever gets into a wallet cannot switch its alerts off. Every
 * confirmed email and every phone on the list is told of each change
 * (raiseAlert, alert-events.js). No route asks for a passkey tap. Each
 * function runs its route's checks in the spec's order (25.3) and returns
 * ok(status, body) or refuse(status, reason).
 *
 * The numbers below are constants and not env variables, as the listing
 * limit is not: the user owns .env.
 */

const BAD_SHAPE = 'bad request shape';

/** How many emails and how many phones a pod's list holds at most, the ones that are coming off too. */
const EMAIL_LIMIT = 3;
const PHONE_LIMIT = 5;

/** How many wrong codes use a code up. */
const CODE_TRIES = 5;

/** How long after a code a new one can be asked for, in seconds, and how many codes a pod is sent in 24 hours. */
const CODE_WAIT_SECONDS = 60;
const CODES_A_DAY = 5;

/** How many changes a pod's list takes in 24 hours. "Keep" is not counted. */
const CHANGES_A_DAY = 20;

/**
 * The delivery services a phone may be on: Apple's, Google's, Mozilla's
 * and Microsoft's. A phone's delivery address has one of these hosts, or
 * a host that ends with a dot and one of them. Without the list a person
 * who is logged in could make this server send requests to any address,
 * also one inside our own network.
 */
const PUSH_HOSTS = ['push.apple.com', 'fcm.googleapis.com', 'push.services.mozilla.com', 'notify.windows.com'];

/** The kinds of device the wallet names a phone by. */
const PHONE_LABELS = ['iphone', 'ipad', 'android', 'computer', 'other'];

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+$/;
const CODE_PATTERN = /^[0-9]{6}$/;
const LANGUAGES = ['en', 'th'];

/**
 * A control character. No email address holds one, and the database takes
 * no zero byte in a text: an address with one is refused before it is
 * looked up.
 */
const CONTROL_PATTERN = /[\x00-\x1f\x7f]/;

/**
 * A delivery address as a browser hands it over: a URL in plain ASCII, with
 * no blank and no control character. Anything else is no address of a
 * delivery service, and letters outside ASCII could make a row too large
 * for the table's unique index.
 */
const ENDPOINT_PATTERN = /^[\x21-\x7e]+$/;

/** Email is on when the two email settings are set; notifications on the phone when the two phone settings are. */
const emailOn = env.alerts.resendApiKey !== null;
const phonesOn = pushKey !== null;

/** The public half of this server's key for the delivery services as base64url, 87 characters, or null when the phones are off. */
const pushPublicKey = pushKey === null ? null : pushKey.publicKey.toString('base64url');

/** A Date as an ISO string; null stays null. */
const iso = (date) => (date === null ? null : date.toISOString());

/**
 * True when `text` has `min` to `max` characters, counted as the database
 * counts them: a character outside the basic plane is one, not two. A text
 * that is too long by any count is told before it is counted.
 */
function hasLength(text, min, max) {
  if (text.length < min || text.length > max * 2) return false;
  const count = Array.from(text).length;
  return count >= min && count <= max;
}

/**
 * POST /list-alert-settings (setup). Body { }. The caller's list: its
 * emails and its phones, each oldest first, and what the page needs to
 * know about this server. A phone is named by the SHA-256 of its delivery
 * address: the address itself is never answered, since whoever knows it
 * can send to the phone. No code is answered either.
 */
export async function listAlertSettings(anopod) {
  const emails = await listEmails(anopod.anopodId);
  const phones = await listPhones(anopod.anopodId);
  return ok(200, {
    emails: emails.map((row) => ({
      emailId: toHex(row.emailId),
      email: row.email,
      language: row.language,
      confirmed: row.verifiedAt !== null,
      createdAt: row.createdAt.toISOString(),
      removesAt: iso(row.removesAt),
    })),
    phones: phones.map((row) => ({
      phoneId: toHex(row.phoneId),
      endpointHash: toHex(sha256(row.endpoint)),
      label: row.label,
      createdAt: row.createdAt.toISOString(),
      removesAt: iso(row.removesAt),
    })),
    emailOn,
    pushPublicKey,
    emailLimit: EMAIL_LIMIT,
    phoneLimit: PHONE_LIMIT,
    removeMinutes: env.alerts.removeMinutes,
  });
}

/**
 * POST /add-alert-email (setup). Body { email, language }. A new address
 * goes on the caller's list, not confirmed, and is sent a six-digit code;
 * an address that is on the list and not confirmed yet is sent a new code.
 * The four checks of spec 25.3, then one transaction with the pod's row
 * locked: the address's row, the limit of 3, the two counts of codes, and
 * the writes.
 */
export async function addAlertEmail(anopod, body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.email !== 'string' || typeof body.language !== 'string') return refuse(400, BAD_SHAPE);

  // 2. Email is on.
  if (!emailOn) return refuse(503, 'email alerts not set up');

  // 3. The address, trimmed: 3 to 254 characters, something on each side of
  //    one @, no blank and no control character.
  const email = body.email.trim();
  if (!hasLength(email, 3, 254) || !EMAIL_PATTERN.test(email) || CONTROL_PATTERN.test(email)) return refuse(400, 'invalid email');

  // 4. The language the wallet shows: every email to this address is written in it.
  const { language } = body;
  if (!LANGUAGES.includes(language)) return refuse(400, 'invalid language');

  const result = await withTransaction(async (client) => {
    await lockPod(client, anopod.anopodId);

    // 5. The pod's row for this address, compared in lower case. A
    //    confirmed one is listed already; one that is not confirmed gets a
    //    new code.
    const existing = await findEmailByAddress(client, anopod.anopodId, email);
    if (existing !== null && existing.verifiedAt !== null) return refuse(409, 'email already listed');

    // 6. No row: the limit, the rows that are coming off and the unconfirmed ones counted too.
    if (existing === null && (await countEmails(client, anopod.anopodId)) >= EMAIL_LIMIT) return refuse(403, 'email limit reached');

    // 7. The codes of the last 24 hours, and the wait after the latest.
    const codes = await recentCodes(client, anopod.anopodId);
    if (codes.count >= CODES_A_DAY) return refuse(429, 'too many codes today');
    if (codes.latest !== null && Date.now() - codes.latest.getTime() < CODE_WAIT_SECONDS * 1000) {
      return refuse(429, 'wait before a new code');
    }

    // 8. The writes: the row for a new address, the code, and the message that carries the code.
    const emailId = existing === null ? randomId() : existing.emailId;
    if (existing === null) await insertEmail(client, { emailId, anopodId: anopod.anopodId, email, language });
    await setCode(client, emailId, String(randomInt(0, 1_000_000)).padStart(6, '0'), language);
    await insertMessage(client, { messageId: randomId(), anopodId: anopod.anopodId, kind: 'emailCode', emailId, phoneId: null, details: {} });
    return ok(existing === null ? 201 : 200, { emailId: toHex(emailId), email: existing === null ? email : existing.email, confirmed: false });
  });

  if (result.ok) kickAlertSender();
  return result;
}

/**
 * POST /confirm-alert-email (setup). Body { emailId, code }. The person
 * types back the code that was sent to the address. One transaction with
 * the email's row locked. A wrong code is counted, and that count is
 * committed; five wrong ones use the code up. The address then counts:
 * confirmed, and told to the rest of the list as emailAdded.
 */
export async function confirmAlertEmail(anopod, body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.emailId !== 'string' || typeof body.code !== 'string') return refuse(400, BAD_SHAPE);

  // 2. The id, 32 bytes, and the code, six digits.
  const emailId = decodeId(body.emailId);
  if (emailId === null) return refuse(400, 'invalid emailId');
  if (!CODE_PATTERN.test(body.code)) return refuse(400, 'invalid code');

  const result = await withTransaction(async (client) => {
    // 3. The row is there and is the caller's.
    const row = await lockEmail(client, emailId);
    if (row === null || !row.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown email');

    // 4. It is not confirmed yet.
    if (row.verifiedAt !== null) return refuse(409, 'email already confirmed');

    // 5. It has a code, and the code's ten minutes are not over.
    if (row.code === null || row.codeExpiresAt === null || row.codeExpiresAt.getTime() <= Date.now()) return refuse(410, 'code expired');

    // 6. The code is not used up.
    if (row.codeTries >= CODE_TRIES) return refuse(410, 'code used up');

    // 7. The code is the row's. A wrong one is counted; the transaction
    //    commits, so the count stays.
    if (!timingSafeEqual(Buffer.from(body.code, 'utf8'), Buffer.from(row.code, 'utf8'))) {
      await countWrongCode(client, emailId);
      return refuse(401, 'wrong code');
    }

    // 8. The changes of the list in the last 24 hours. The code stays good
    //    until its ten minutes are over.
    if ((await recentChanges(client, anopod.anopodId)) >= CHANGES_A_DAY) return refuse(429, 'too many changes today');

    // 9. The writes: the address counts, and the rest of the list is told.
    await confirmEmail(client, emailId);
    await raiseAlert(client, {
      anopodId: anopod.anopodId,
      kind: 'emailAdded',
      details: { emailId: toHex(emailId) },
      reference: anopod.anopodId,
      exceptEmailId: emailId,
    });
    return ok(200, { emailId: toHex(emailId), confirmed: true });
  });

  if (result.ok) kickAlertSender();
  return result;
}

/**
 * POST /remove-alert-email (setup). Body { emailId }. "Take off". An
 * address that was never confirmed got no alert and goes at once; nobody
 * is told. A confirmed one is set to come off a month from now, and the
 * whole list is told, the address itself too. One that is coming off
 * already keeps its day.
 */
export async function removeAlertEmail(anopod, body) {
  // 1. Shape. 2. The id.
  if (!isObject(body) || typeof body.emailId !== 'string') return refuse(400, BAD_SHAPE);
  const emailId = decodeId(body.emailId);
  if (emailId === null) return refuse(400, 'invalid emailId');

  let told = false;
  const result = await withTransaction(async (client) => {
    // 3. The row is there and is the caller's.
    const row = await lockEmail(client, emailId);
    if (row === null || !row.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown email');

    // 4. Not confirmed: it goes at once.
    if (row.verifiedAt === null) {
      await deleteEmail(client, emailId);
      return ok(200, { emailId: toHex(emailId), removed: true, removesAt: null });
    }

    // 5. It is coming off already: nothing is written.
    if (row.removesAt !== null) return ok(200, { emailId: toHex(emailId), removed: false, removesAt: iso(row.removesAt) });

    // 6. The changes of the list in the last 24 hours, then the day it
    //    comes off, told to the whole list.
    if ((await recentChanges(client, anopod.anopodId)) >= CHANGES_A_DAY) return refuse(429, 'too many changes today');
    const removesAt = iso(await setEmailRemoval(client, emailId, env.alerts.removeMinutes));
    await raiseAlert(client, {
      anopodId: anopod.anopodId,
      kind: 'emailRemoving',
      details: { emailId: toHex(emailId), removesAt },
      reference: anopod.anopodId,
    });
    told = true;
    return ok(200, { emailId: toHex(emailId), removed: false, removesAt });
  });

  if (told) kickAlertSender();
  return result;
}

/**
 * POST /keep-alert-email (setup). Body { emailId }. "Keep": an address
 * that was set to come off stays, and the whole list is told. It is not
 * counted against the changes of a day: it can only undo a "Take off", and
 * a person must always be able to save an address.
 */
export async function keepAlertEmail(anopod, body) {
  // 1. Shape. 2. The id.
  if (!isObject(body) || typeof body.emailId !== 'string') return refuse(400, BAD_SHAPE);
  const emailId = decodeId(body.emailId);
  if (emailId === null) return refuse(400, 'invalid emailId');

  let told = false;
  const result = await withTransaction(async (client) => {
    // 3. The row is there and is the caller's.
    const row = await lockEmail(client, emailId);
    if (row === null || !row.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown email');

    // It was set to come off: it stays, and the whole list is told. One
    // that was not is left as it is, and nothing is written.
    if (row.removesAt !== null) {
      await clearEmailRemoval(client, emailId);
      await raiseAlert(client, {
        anopodId: anopod.anopodId,
        kind: 'emailKept',
        details: { emailId: toHex(emailId) },
        reference: anopod.anopodId,
      });
      told = true;
    }
    return ok(200, { emailId: toHex(emailId), removesAt: null });
  });

  if (told) kickAlertSender();
  return result;
}

/**
 * POST /add-alert-phone (setup). Body { endpoint, p256dh, auth, label }:
 * what the browser handed the wallet when the person allowed
 * notifications (the delivery address, the browser's public key and its
 * secret), and the kind of device as the wallet read it. The five checks
 * of spec 25.3, then one transaction with the pod's row locked. A phone
 * that is on the caller's list already is answered as it stands. A new one
 * is told to the rest of the list as phoneAdded, and gets one notification
 * of its own at once, phoneOn, so that the person sees that it works.
 *
 * A refusal for a delivery service that is not on the list carries the
 * address's host, for the handler's log line.
 */
export async function addAlertPhone(anopod, body) {
  // 1. Shape.
  if (!isObject(body) || typeof body.endpoint !== 'string' || typeof body.p256dh !== 'string'
    || typeof body.auth !== 'string' || typeof body.label !== 'string') {
    return refuse(400, BAD_SHAPE);
  }

  // 2. Phone alerts are on.
  if (!phonesOn) return refuse(503, 'phone alerts not set up');

  // 3. The delivery address: 20 to 1024 characters of plain ASCII with no
  //    blank, an https URL with no user name, no password and no port, on
  //    one of the delivery services.
  const { endpoint } = body;
  let url = null;
  if (hasLength(endpoint, 20, 1024) && ENDPOINT_PATTERN.test(endpoint)) {
    try {
      url = new URL(endpoint);
    } catch {
      url = null;
    }
  }
  if (url === null || url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.port !== '') {
    return refuse(400, 'invalid endpoint');
  }
  if (!PUSH_HOSTS.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`))) {
    return { ...refuse(400, 'push service not supported'), host: url.hostname };
  }

  // 4. The browser's public key, 65 bytes that are a point on the curve,
  //    and its secret, 16 bytes.
  const p256dh = decodeBytes(body.p256dh, [65]);
  if (p256dh === null || !isP256Point(p256dh)) return refuse(400, 'invalid p256dh');
  const auth = decodeBytes(body.auth, [16]);
  if (auth === null) return refuse(400, 'invalid auth');

  // 5. The kind of device.
  const { label } = body;
  if (!PHONE_LABELS.includes(label)) return refuse(400, 'invalid label');

  let told = false;
  const result = await withTransaction(async (client) => {
    await lockPod(client, anopod.anopodId);

    // 6. The pod has this delivery address already: nothing is written.
    const existing = await findPhoneByEndpoint(client, anopod.anopodId, endpoint);
    if (existing !== null) return ok(200, { phoneId: toHex(existing.phoneId), removesAt: iso(existing.removesAt) });

    // 7. The limit, the rows that are coming off counted too, and the
    //    changes of the list in the last 24 hours.
    if ((await countPhones(client, anopod.anopodId)) >= PHONE_LIMIT) return refuse(403, 'phone limit reached');
    if ((await recentChanges(client, anopod.anopodId)) >= CHANGES_A_DAY) return refuse(429, 'too many changes today');

    // 8. The writes: the row, the word to the rest of the list, and the
    //    new phone's own first notification.
    const phoneId = randomId();
    await insertPhone(client, { phoneId, anopodId: anopod.anopodId, endpoint, p256dh, auth, label });
    await raiseAlert(client, {
      anopodId: anopod.anopodId,
      kind: 'phoneAdded',
      details: { phoneId: toHex(phoneId), label },
      reference: anopod.anopodId,
      exceptPhoneId: phoneId,
    });
    await insertMessage(client, { messageId: randomId(), anopodId: anopod.anopodId, kind: 'phoneOn', emailId: null, phoneId, details: {} });
    told = true;
    return ok(201, { phoneId: toHex(phoneId), removesAt: null });
  });

  if (told) kickAlertSender();
  return result;
}

/**
 * POST /remove-alert-phone (setup). Body { phoneId }. "Take off": the
 * phone is set to come off a month from now, and the whole list is told,
 * the phone itself too. One that is coming off already keeps its day.
 */
export async function removeAlertPhone(anopod, body) {
  // 1. Shape. 2. The id.
  if (!isObject(body) || typeof body.phoneId !== 'string') return refuse(400, BAD_SHAPE);
  const phoneId = decodeId(body.phoneId);
  if (phoneId === null) return refuse(400, 'invalid phoneId');

  let told = false;
  const result = await withTransaction(async (client) => {
    // 3. The row is there and is the caller's.
    const row = await lockPhone(client, phoneId);
    if (row === null || !row.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown phone');

    // It is coming off already: nothing is written.
    if (row.removesAt !== null) return ok(200, { phoneId: toHex(phoneId), removesAt: iso(row.removesAt) });

    // The changes of the list in the last 24 hours, then the day it comes
    // off, told to the whole list.
    if ((await recentChanges(client, anopod.anopodId)) >= CHANGES_A_DAY) return refuse(429, 'too many changes today');
    const removesAt = iso(await setPhoneRemoval(client, phoneId, env.alerts.removeMinutes));
    await raiseAlert(client, {
      anopodId: anopod.anopodId,
      kind: 'phoneRemoving',
      details: { phoneId: toHex(phoneId), label: row.label, removesAt },
      reference: anopod.anopodId,
    });
    told = true;
    return ok(200, { phoneId: toHex(phoneId), removesAt });
  });

  if (told) kickAlertSender();
  return result;
}

/**
 * POST /keep-alert-phone (setup). Body { phoneId }. "Keep": a phone that
 * was set to come off stays, and the whole list is told. Not counted
 * against the changes of a day, as for an email.
 */
export async function keepAlertPhone(anopod, body) {
  // 1. Shape. 2. The id.
  if (!isObject(body) || typeof body.phoneId !== 'string') return refuse(400, BAD_SHAPE);
  const phoneId = decodeId(body.phoneId);
  if (phoneId === null) return refuse(400, 'invalid phoneId');

  let told = false;
  const result = await withTransaction(async (client) => {
    // 3. The row is there and is the caller's.
    const row = await lockPhone(client, phoneId);
    if (row === null || !row.anopodId.equals(anopod.anopodId)) return refuse(404, 'unknown phone');

    // It was set to come off: it stays, and the whole list is told. One
    // that was not is left as it is, and nothing is written.
    if (row.removesAt !== null) {
      await clearPhoneRemoval(client, phoneId);
      await raiseAlert(client, {
        anopodId: anopod.anopodId,
        kind: 'phoneKept',
        details: { phoneId: toHex(phoneId), label: row.label },
        reference: anopod.anopodId,
      });
      told = true;
    }
    return ok(200, { phoneId: toHex(phoneId), removesAt: null });
  });

  if (told) kickAlertSender();
  return result;
}
