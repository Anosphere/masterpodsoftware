import { countVouches, findById, findByUsername, profileOf, seedStatus, setVouched } from '../anopods/anopods.queries.js';
import { findSelfie } from '../anopods/public-selfies.queries.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import { notify } from '../notifications/notifications.queries.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { insertSeed, isSeed } from './seeds.queries.js';
import { deleteRequest, findRequest, insertRequest, listOpenFor, requestOpen } from './vouch-requests.queries.js';
import { insertVouch } from './vouches.queries.js';

/**
 * The vouching feature: finding a pod by username, asking a seed to vouch,
 * and the seed's inbox with approve and decline. A pod is vouched by one
 * super seed or by two seeds; a super seed's approval also makes the pod a
 * seed. Each function runs its route's checks in the spec's order (section
 * 5) and returns ok(status, body) or refuse(status, reason).
 */

const BAD_SHAPE = 'bad request shape';

/** True when the pod may vouch: it is in seeds or in super_seeds. */
function canVouch(status) {
  return status.isSeed || status.isSuperSeed;
}

/**
 * POST /search-usernames. Body { username }: exact match on the lowercased
 * username, any pod. The profile's isSeed and isSuperSeed say whether the
 * match can vouch, so a requester sees at once that a pod exists but cannot;
 * the same lookup finds a pod to invite to a chat room.
 */
export async function searchUsernames(body) {
  if (!isObject(body) || typeof body.username !== 'string') return refuse(400, BAD_SHAPE);
  const anopod = await findByUsername(body.username.toLowerCase());
  if (anopod === null) return refuse(404, 'username not found');
  const status = await seedStatus(anopod.anopodId);
  const selfie = await findSelfie(anopod.anopodId);
  return ok(200, { ...profileOf(anopod, status), selfie });
}

/** POST /send-vouch-request. Body { anopodIdTo }. */
export async function sendRequest(anopod, body) {
  if (!isObject(body) || typeof body.anopodIdTo !== 'string') return refuse(400, BAD_SHAPE);
  if (anopod.vouched) return refuse(409, 'already vouched');
  const anopodIdTo = decodeId(body.anopodIdTo);
  if (anopodIdTo === null) return refuse(400, 'invalid anopodIdTo');
  if (anopodIdTo.equals(anopod.anopodId)) return refuse(400, 'cannot request yourself');
  if ((await findById(anopodIdTo)) === null) return refuse(404, 'anopod not found');
  if (!canVouch(await seedStatus(anopodIdTo))) return refuse(403, 'user is not seed');
  if (await requestOpen(anopod.anopodId, anopodIdTo)) return refuse(409, 'request already open');

  const vouchIdNumber = randomId();
  try {
    await withTransaction(async (client) => {
      await insertRequest(client, vouchIdNumber, anopod.anopodId, anopodIdTo);
      await notify(client, anopodIdTo, 'vouchRequest', vouchIdNumber);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return refuse(409, 'request already open');
    throw err;
  }
  return ok(201, { vouchIdNumber: toHex(vouchIdNumber) });
}

/** POST /list-vouch-requests. The open requests addressed to the caller; empty for a pod that is no seed. */
export async function listRequests(anopod) {
  if (!canVouch(await seedStatus(anopod.anopodId))) return ok(200, { requests: [] });
  return ok(200, { requests: await listOpenFor(anopod.anopodId) });
}

/**
 * The request named in `body`, checked to exist and to be addressed to the
 * caller: { request } or { result } with the refusal.
 */
async function ownRequest(anopod, body) {
  if (!isObject(body) || typeof body.vouchIdNumber !== 'string') return { result: refuse(400, BAD_SHAPE) };
  const vouchIdNumber = decodeId(body.vouchIdNumber);
  const request = vouchIdNumber === null ? null : await findRequest(vouchIdNumber);
  if (request === null) return { result: refuse(404, 'request not found') };
  if (!request.anopodIdTo.equals(anopod.anopodId)) return { result: refuse(403, 'not your request') };
  return { request };
}

/**
 * POST /approve-vouch-request. Body { vouchIdNumber }. The five writes of
 * the spec in one transaction: the vouch, the request deleted, vouched
 * flipped when a super seed approved or this is the second vouch, the
 * requester made a seed when a super seed approved, the notifications.
 * nowVouched and nowSeed are the requester's state after the call.
 */
export async function approve(anopod, body) {
  const { request, result } = await ownRequest(anopod, body);
  if (result) return result;
  const status = await seedStatus(anopod.anopodId);
  if (!canVouch(status)) return refuse(403, 'user is not seed');
  const requester = request.anopodIdFrom;
  const requesterRow = await findById(requester);

  let outcome;
  try {
    outcome = await withTransaction(async (client) => {
      await insertVouch(client, request.vouchIdNumber, anopod.anopodId, requester);
      await deleteRequest(client, request.vouchIdNumber);

      const count = await countVouches(requester, client);
      const flipped = (status.isSuperSeed || count >= 2) && (await setVouched(client, requester));

      let nowSeed = await isSeed(requester, client);
      if (status.isSuperSeed && !nowSeed) {
        await insertSeed(client, requester, toHex(anopod.anopodId));
        nowSeed = true;
      }

      await notify(client, requester, 'vouchApproved', request.vouchIdNumber);
      if (flipped) await notify(client, requester, 'vouched', requester);

      return { nowVouched: flipped || (requesterRow?.vouched ?? false), nowSeed };
    });
  } catch (err) {
    // The same seed vouched for this requester before, on an earlier
    // request: vouches (by, for) is unique.
    if (isUniqueViolation(err)) return refuse(409, 'vouch already recorded');
    throw err;
  }

  return ok(200, {
    vouchIdNumber: toHex(request.vouchIdNumber),
    vouchedFor: toHex(requester),
    nowVouched: outcome.nowVouched,
    nowSeed: outcome.nowSeed,
  });
}

/** POST /decline-vouch-request. Body { vouchIdNumber }. */
export async function decline(anopod, body) {
  const { request, result } = await ownRequest(anopod, body);
  if (result) return result;

  await withTransaction(async (client) => {
    await deleteRequest(client, request.vouchIdNumber);
    await notify(client, request.anopodIdFrom, 'vouchDeclined', request.vouchIdNumber);
  });
  return ok(200, { vouchIdNumber: toHex(request.vouchIdNumber) });
}
