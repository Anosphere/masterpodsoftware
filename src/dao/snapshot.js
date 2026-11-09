import { findPodsForAccounts } from '../anos-accounts/anos-accounts.queries.js';
import { fetchDaoStakes } from './validators.client.js';

/**
 * The DAO snapshot (spec 15.6): every account's DAO stake from a validator,
 * boiled down to one weight per pod. One staked anos is one vote: a pod's
 * weight is the millionths of dao_vote_stake summed over its anos accounts
 * (anos_accounts maps each account to its pod), floored to whole anos;
 * pods at 0 are dropped. Stake on an account the masterpod does not know
 * (none today: every account is made through /create-anos-account) counts
 * in the total and in nobody's weight. Taken when a proposal is posted and
 * again when it goes open; stake added after a snapshot counts from the
 * next one.
 */

/** Millionths in one anos. */
const MILLIONTHS = 1_000_000n;

/**
 * Reads the stakes (validators.client.js) and sums them per pod. Returns
 * { asOf, total, weights: [ { anopodId, weight } ] }: asOf the validator's,
 * total and weight BigInts of whole anos, anopodId a 32-byte Buffer; null
 * when no validator could be reached.
 */
export async function takeSnapshot() {
  const answer = await fetchDaoStakes();
  if (answer === null) return null;

  const pods = await findPodsForAccounts(answer.stakes.map((stake) => Buffer.from(stake.accountId, 'hex')));
  const sums = new Map();
  for (const stake of answer.stakes) {
    const anopodId = pods.get(stake.accountId);
    if (anopodId === undefined) continue;
    const key = anopodId.toString('hex');
    const sum = sums.get(key) ?? { anopodId, millionths: 0n };
    sum.millionths += BigInt(stake.daoVoteStake);
    sums.set(key, sum);
  }
  const weights = [];
  for (const { anopodId, millionths } of sums.values()) {
    const weight = millionths / MILLIONTHS;
    if (weight > 0n) weights.push({ anopodId, weight });
  }
  return { asOf: answer.asOf, total: BigInt(answer.total) / MILLIONTHS, weights };
}
