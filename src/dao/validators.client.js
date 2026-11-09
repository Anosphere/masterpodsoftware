import { env } from '../config/env.js';
import { isObject } from '../util/is-object.js';

/**
 * The one outbound call this server makes to the validators: POST
 * /list-dao-stakes (anossoftware spec 23; through a doorman, doormansoftware
 * spec 6), every account's DAO stake, public and unsigned. Shaped like
 * anossoftware's src/masterpod/masterpod.client.js: a fetch with a timeout,
 * every failure one outcome. The URLs are env.validatorUrls, tried in
 * order; the first good answer wins, so a doorman or a validator that has
 * not pulled the route (a 404), a joiner (503 not counted yet), a refusal,
 * a timeout or a body of the wrong shape moves to the next URL with one log
 * line. The doormen's certificates are Let's Encrypt, so the fetch verifies
 * them as any other.
 */

/** How long each validator has to answer. */
const TIMEOUT_MS = 5_000;

/** A decimal string of millionths: digits only, zero allowed. */
const DIGITS = /^(0|[1-9][0-9]*)$/;

/** An account id as the validators answer it: 64 lowercase hex characters. */
const ACCOUNT_ID = /^[0-9a-f]{64}$/;

/**
 * True for an answer of the right shape (anossoftware spec 23): asOf a
 * time, total digits, stakes a list of { accountId, daoVoteStake }.
 */
function hasStakesShape(body) {
  return isObject(body)
    && typeof body.asOf === 'string' && !Number.isNaN(Date.parse(body.asOf))
    && typeof body.total === 'string' && DIGITS.test(body.total)
    && Array.isArray(body.stakes)
    && body.stakes.every((stake) => isObject(stake)
      && typeof stake.accountId === 'string' && ACCOUNT_ID.test(stake.accountId)
      && typeof stake.daoVoteStake === 'string' && DIGITS.test(stake.daoVoteStake));
}

/**
 * Asks one validator. Returns { asOf, total, stakes } on a 200 of the right
 * shape, else a string saying what went wrong, for the log line.
 */
async function askOne(url) {
  let response;
  try {
    response = await fetch(`${url}/list-dao-stakes`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    return err.message;
  }
  let body;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (response.status !== 200) {
    return `status ${response.status}${typeof body?.error === 'string' ? ` ${body.error}` : ''}`;
  }
  if (!hasStakesShape(body)) return 'bad shape';
  return { asOf: body.asOf, total: body.total, stakes: body.stakes };
}

/**
 * Every account's DAO stake from the first validator of env.validatorUrls
 * that answers: { asOf, total, stakes: [ { accountId, daoVoteStake } ] },
 * asOf ISO 8601, total and daoVoteStake decimal strings of millionths,
 * accountId 64 lowercase hex. Null when every URL failed.
 */
export async function fetchDaoStakes() {
  for (const url of env.validatorUrls) {
    const outcome = await askOne(url);
    if (typeof outcome !== 'string') return outcome;
    console.log(`dao: ${url}/list-dao-stakes failed: ${outcome}`);
  }
  return null;
}
