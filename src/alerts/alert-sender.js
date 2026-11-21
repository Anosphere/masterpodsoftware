import { env } from '../config/env.js';
import { withTransaction } from '../db/transaction.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { raiseAlert } from './alert-events.js';
import { emailOf, phoneFactsOf } from './alert-words.js';
import {
  claimDue,
  deletePhonesByEndpoint,
  findEmail,
  findPhone,
  markFailed,
  markGaveUp,
  markSent,
  removeDue,
} from './alerts.queries.js';
import { sendEmail } from './email.js';
import { encryptPush, pushKeyFrom, vapidAuthorization } from './push.js';
import { validatorKeys } from './validator-keys.js';

/**
 * The alert sender (spec 25.6), in the shape of src/dao/dao-clock.js: one
 * run at boot, then every SEND_EVERY_MS, started from src/server.js after
 * listen and stopped in its shutdown. A route that wrote a message calls
 * kickAlertSender() after its transaction has committed, so a message
 * leaves at once after its event and not at the next minute; the minute's
 * run is for the tries after a failure and for what comes off after its
 * month. A run does, in order:
 *
 *   1. What is due to come off, comes off: the emails and the phones that
 *      were taken off a month ago, and the emails that were not confirmed
 *      within a day.
 *   2. The sending, at most ROUNDS rounds. A round is one transaction: up
 *      to ROUND_SIZE messages that are due are taken and held; then the
 *      requests are made, the ones to phones all at once and the ones to
 *      the email company one after another, because it limits the requests
 *      of one second; then each outcome is written. A round that took
 *      fewer than ROUND_SIZE messages and raised no alert is the last.
 *
 * Each message is built and sent on its own. Whatever throws for one
 * message, while its words are made, its body is scrambled or its request
 * is sent, is that message's failure and no other's, so one bad row cannot
 * hold the others back.
 *
 * Three masterpods run the sender at once on prod1, prod2 and prod3: the
 * rows a round holds are skipped by the others (FOR UPDATE SKIP LOCKED),
 * and the deletes of step 1 are idempotent. One run at a time in a
 * process: a run that is asked for while one is under way runs right after
 * it. A run that throws logs the error and the next one runs.
 *
 * No log line holds an email address or a phone's delivery address.
 */

/** How often the sender runs, in milliseconds. */
const SEND_EVERY_MS = 60_000;

/** How many rounds one run makes at most, and how many messages one round takes. */
const ROUNDS = 10;
const ROUND_SIZE = 20;

/** How long a delivery service gets to answer, in milliseconds. */
const TIMEOUT_MS = 10_000;

/** How long a delivery service keeps a notification for a phone that is switched off, in seconds: 7 days. */
const PUSH_TTL_SECONDS = 604_800;

/**
 * The signed token a delivery service is given (push.js, RFC 8292) ends 12
 * hours after it was made. One is kept per audience and used for 6 hours,
 * then made anew: Apple asks that a token is not made more often than once
 * an hour.
 */
const TOKEN_LIFE_SECONDS = 43_200;
const TOKEN_USE_MS = 21_600_000;

/** Email is on when the two email settings are set (src/config/env.js). */
const emailOn = env.alerts.resendApiKey !== null;

/** Notifications on the phone are on when the two phone settings are set. */
const phonesOn = env.alerts.pushPrivateKey !== null;

/**
 * This server's key for the phones' delivery services, { privateKey,
 * publicKey }, or null when the phones are off. 32 bytes that are no
 * private key of the curve stop the boot; the error names the variable and
 * never its value.
 */
function readPushKey() {
  if (!phonesOn) return null;
  try {
    return pushKeyFrom(env.alerts.pushPrivateKey);
  } catch {
    throw new Error('ALERT_PUSH_PRIVATE_KEY is not a private key of the P-256 curve');
  }
}

export const pushKey = readPushKey();

/** The token kept for each audience: a Map from the origin to { header, madeAt }. */
const tokens = new Map();

/** The Authorization header for the delivery service at `audience`, kept for TOKEN_USE_MS. */
function tokenFor(audience) {
  const now = Date.now();
  const kept = tokens.get(audience);
  if (kept !== undefined && now - kept.madeAt < TOKEN_USE_MS) return kept.header;
  for (const [origin, token] of tokens) {
    if (now - token.madeAt >= TOKEN_USE_MS) tokens.delete(origin);
  }
  const header = vapidAuthorization(pushKey, audience, env.alerts.pushContact, Math.floor(now / 1000) + TOKEN_LIFE_SECONDS);
  tokens.set(audience, { header, madeAt: now });
  return header;
}

/** The outcomes of one message: it went out, a send failed, it is given up, or its phone is gone. */
const sent = () => ({ type: 'sent' });
const failed = (error) => ({ type: 'failed', error });
const gaveUp = (error) => ({ type: 'gaveUp', error });
const unreachable = (endpoint) => ({ type: 'unreachable', endpoint });

/** The first 8 hex characters of a pod's id, for a log line. */
const podStart = (anopodId) => toHex(anopodId).slice(0, 8);

/**
 * What a message's words are made of, read on `client`: the message's
 * details, the address of the email that changed (the three email kinds
 * name it by its id; null when that row is gone), and the code of the
 * email the message goes to.
 */
async function factsOf(client, message, destination) {
  const details = isObject(message.details) ? message.details : {};
  let email = null;
  if (typeof details.emailId === 'string') {
    const emailId = decodeId(details.emailId);
    const changed = emailId === null ? null : await findEmail(emailId, client);
    email = changed === null ? null : changed.email;
  }
  return {
    amount: details.amount,
    accountType: details.accountType,
    accountId: details.accountId,
    writesAt: details.writesAt ?? null,
    removesAt: details.removesAt ?? null,
    label: details.label,
    email,
    code: destination === null ? null : destination.code,
  };
}

/**
 * Makes one message ready on `client`: reads where it goes and builds its
 * request. Returns { message, request } with request { email } or
 * { phone }, or { message, outcome } when there is nothing to send: the
 * address or the phone is gone, a code is no longer needed, or the message
 * could not be built.
 */
async function prepare(client, message) {
  if (message.emailId !== null) {
    const to = await findEmail(message.emailId, client);
    if (to === null) return { message, outcome: gaveUp('address gone') };
    if (message.kind === 'emailCode' && to.code === null) return { message, outcome: gaveUp('code no longer needed') };
    const facts = await factsOf(client, message, to);
    try {
      const { subject, text } = emailOf(message.kind, to.language, facts);
      return { message, request: { email: { to: to.email, subject, text } } };
    } catch {
      return { message, outcome: gaveUp('could not be built') };
    }
  }

  const phone = await findPhone(message.phoneId, client);
  if (phone === null) return { message, outcome: gaveUp('phone gone') };
  const facts = await factsOf(client, message, null);
  try {
    const body = encryptPush(Buffer.from(JSON.stringify(phoneFactsOf(message.kind, facts)), 'utf8'), phone.p256dh, phone.auth);
    const authorization = tokenFor(new URL(phone.endpoint).origin);
    return { message, request: { phone: { endpoint: phone.endpoint, body, authorization } } };
  } catch {
    return { message, outcome: gaveUp('could not be built') };
  }
}

/**
 * Hands one notification to the phone's delivery service (RFC 8030): the
 * scrambled body, POSTed to the phone's delivery address. A status from
 * 200 to 299 means taken; 404 or 410 that the phone is gone; anything
 * else, also no answer, is a failure. A redirect is not followed. The
 * failure's words never hold the delivery address.
 */
async function sendPush({ endpoint, body, authorization }) {
  let response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        TTL: String(PUSH_TTL_SECONDS),
        Urgency: 'high',
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        Authorization: authorization,
      },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    return failed(String(err.message).split(endpoint).join('the delivery address').slice(0, 200));
  }
  if (response.status >= 200 && response.status <= 299) return sent();
  if (response.status === 404 || response.status === 410) return unreachable(endpoint);
  return failed(`status ${response.status}`);
}

/** Hands one email to the email company (email.js). */
async function sendMail(message, { to, subject, text }) {
  const error = await sendEmail({ to, subject, text, messageId: message.messageId, tries: message.tries });
  return error === null ? sent() : failed(error);
}

/** Writes one message's outcome on `client`, with its log line. Returns true when an alert was raised. */
async function write(client, { message, outcome }) {
  const told = `${message.kind} ${message.emailId !== null ? 'by email' : 'to a phone'}, pod ${podStart(message.anopodId)}`;
  if (outcome.type === 'sent') {
    await markSent(client, message.messageId);
    console.log(`alert sent: ${told}`);
    return false;
  }
  if (outcome.type === 'failed') {
    await markFailed(client, message.messageId, outcome.error);
    console.log(`alert not sent: ${told}: ${outcome.error}`);
    return false;
  }
  if (outcome.type === 'gaveUp') {
    await markGaveUp(client, message.messageId, outcome.error);
    console.log(`alert not sent: ${told}: ${outcome.error}`);
    return false;
  }

  // The phone is gone: every row with its delivery address comes off,
  // whichever pod's, and each of those pods is told on the rest of its
  // list. The messages that raiseAlert writes are taken by the next round.
  const gone = await deletePhonesByEndpoint(client, outcome.endpoint);
  for (const phone of gone) {
    await raiseAlert(client, { anopodId: phone.anopodId, kind: 'phoneUnreachable', details: { label: phone.label }, reference: phone.anopodId });
    console.log(`alert phone unreachable: pod ${podStart(phone.anopodId)}, ${phone.label}`);
  }
  await markGaveUp(client, message.messageId, 'phone unreachable');
  if (gone.length === 0) console.log(`alert not sent: ${told}: phone unreachable`);
  return gone.length > 0;
}

/**
 * One round, one transaction. Returns { taken, raised }: how many messages
 * it took, and whether it raised an alert whose messages wait for the next
 * round.
 */
function round() {
  return withTransaction(async (client) => {
    const messages = await claimDue(client, ROUND_SIZE, emailOn, phonesOn);

    // Each message made ready, one after another: the reads are the
    // transaction's.
    const jobs = [];
    for (const message of messages) jobs.push(await prepare(client, message));

    // The requests: the phones all at once, the emails one after another.
    const pushes = jobs.filter((job) => job.request?.phone !== undefined);
    const mails = jobs.filter((job) => job.request?.email !== undefined);
    await Promise.all([
      Promise.all(pushes.map(async (job) => {
        job.outcome = await sendPush(job.request.phone).catch((err) => failed(String(err.message).slice(0, 200)));
      })),
      (async () => {
        for (const job of mails) {
          job.outcome = await sendMail(job.message, job.request.email).catch((err) => failed(String(err.message).slice(0, 200)));
        }
      })(),
    ]);

    // Each outcome written, in the order the messages were taken.
    let raised = false;
    for (const job of jobs) {
      if (await write(client, job)) raised = true;
    }
    return { taken: messages.length, raised };
  });
}

/** One run: what is due to come off, then the sending. */
async function run() {
  const went = await removeDue();
  if (went.emails > 0 || went.phones > 0) {
    console.log(`alerts: ${went.emails} emails and ${went.phones} phones came off`);
  }
  if (!emailOn && !phonesOn) return;
  for (let n = 0; n < ROUNDS && !stopped; n += 1) {
    const { taken, raised } = await round();
    if (taken < ROUND_SIZE && !raised) break;
  }
}

let timer = null;
let stopped = false;
let running = null;
let again = false;

/** Runs until no run was asked for meanwhile. An error is logged, not thrown: the next run runs. */
async function runs() {
  do {
    again = false;
    try {
      await run();
    } catch (err) {
      console.error(`alert sender run failed: ${err.message}`);
    }
  } while (again && !stopped);
}

/**
 * A run now. One run at a time in a process: when one is under way, a new
 * one runs right after it. Resolves when the run, and one that was asked
 * for meanwhile, are done; never rejects.
 */
export function runAlertSender() {
  if (running !== null) {
    again = true;
    return running;
  }
  running = runs().finally(() => {
    running = null;
  });
  return running;
}

/**
 * Starts a run now and returns at once: called after the commit of a
 * transaction that wrote a message. Does nothing once the sender is
 * stopped.
 */
export function kickAlertSender() {
  if (stopped) return;
  void runAlertSender();
}

/** Starts the sender: one log line, a run now, then one every SEND_EVERY_MS. Starting it twice does nothing. */
export function startAlertSender() {
  if (timer !== null) return;
  stopped = false;
  const keys = validatorKeys === null ? 'no validator keys' : `${validatorKeys.size} validator keys`;
  console.log(`alerts: email ${emailOn ? 'on' : 'off'}, phones ${phonesOn ? 'on' : 'off'}, ${keys}`);
  timer = setInterval(kickAlertSender, SEND_EVERY_MS);
  timer.unref();
  kickAlertSender();
}

/** Stops the sender: no new round starts; a round already under way finishes on its own. */
export function stopAlertSender() {
  stopped = true;
  if (timer === null) return;
  clearInterval(timer);
  timer = null;
}
