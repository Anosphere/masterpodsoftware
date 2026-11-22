import { env } from '../config/env.js';
import { toHex } from '../util/ids.js';

/**
 * The call to the email company, Resend (spec 25.6): one plain-text email
 * to one address. No package: fetch, Node's own.
 */

/** Where an email is handed over. */
const RESEND_URL = 'https://api.resend.com/emails';

/** How long the email company gets to answer, in milliseconds. */
const TIMEOUT_MS = 10_000;

/**
 * Sends one email: { to, subject, text, messageId, tries }. `to` is the
 * address, `messageId` the alert_messages row's id (a Buffer), `tries` how
 * many sends of the row have failed so far.
 *
 * Returns null when the email company took it (a status from 200 to 299),
 * otherwise a few words for last_error: `status <n>` and the answer's
 * `name` when it has one, or the fetch's own error. Never throws.
 *
 * The email company refuses a request with no User-Agent header. The
 * Idempotency-Key is the message's id and the try's number. So a try whose
 * outcome was never written, because the server stopped between the send
 * and the write, is not sent a second time when its row is taken again;
 * and a try after a failure is a new request. A redirect is not followed.
 */
export async function sendEmail({ to, subject, text, messageId, tries }) {
  let response;
  try {
    response = await fetch(RESEND_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.alerts.resendApiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'masterpodsoftware',
        'Idempotency-Key': `${toHex(messageId)}-${tries}`,
      },
      body: JSON.stringify({ from: env.alerts.emailFrom, to: [to], subject, text }),
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    return err.message;
  }
  if (response.status >= 200 && response.status <= 299) return null;

  // The email company answers a refusal as JSON with a `name`, such as
  // validation_error or rate_limit_exceeded. An answer that is no JSON, or
  // has none, is told by its status alone. The name is cut at 60
  // characters: last_error holds a few words.
  let name = null;
  try {
    const answer = await response.json();
    if (answer !== null && typeof answer === 'object' && typeof answer.name === 'string') name = answer.name.slice(0, 60);
  } catch {
    name = null;
  }
  return name === null ? `status ${response.status}` : `status ${response.status} ${name}`;
}
