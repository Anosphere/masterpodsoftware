import { notify } from '../notifications/notifications.queries.js';
import { randomId } from '../util/ids.js';
import { destinations, insertMessage, recentRecoveryAlerts } from './alerts.queries.js';

/**
 * raiseAlert (spec 25.5): what one event of the security alerts writes. It
 * runs on the client of the transaction of the event it reports, like
 * notify, so the alert lands with the event or not at all. The sender
 * (alert-sender.js) takes the messages from the table afterwards; the
 * caller calls kickAlertSender() once its transaction has committed.
 */

/**
 * The bell's kind for each kind of alert: the three events under their own
 * names, and each of the seven changes of a pod's list under
 * alertSettingsChanged.
 */
const BELL_KINDS = Object.freeze({
  transferWaiting: 'transferWaiting',
  recoveryMoveWaiting: 'recoveryMoveWaiting',
  recoveryCaseOpened: 'recoveryCaseOpened',
  emailAdded: 'alertSettingsChanged',
  emailRemoving: 'alertSettingsChanged',
  emailKept: 'alertSettingsChanged',
  phoneAdded: 'alertSettingsChanged',
  phoneRemoving: 'alertSettingsChanged',
  phoneKept: 'alertSettingsChanged',
  phoneUnreachable: 'alertSettingsChanged',
});

/**
 * Writes one alert for `anopodId` on `client`:
 *
 *   1. The bell's row, notify(client, anopodId, <the bell's kind>,
 *      reference). `reference` is 32 bytes: the account's id for the two
 *      transfer kinds, the case's id for recoveryCaseOpened, the pod's own
 *      id for a change of its list.
 *   2. One alert_messages row for each confirmed email and each phone of
 *      the pod, the ones that are coming off too, without `exceptEmailId`
 *      and `exceptPhoneId` (the email or the phone that was just added),
 *      each with a fresh id, the kind and `details`.
 *
 * `details` by kind (ids hex, moments ISO strings): { accountId,
 * accountType, amount, writesAt } for transferWaiting and
 * recoveryMoveWaiting, writesAt null for a transfer that waits for
 * attestors alone; {} for recoveryCaseOpened; { emailId } for emailAdded
 * and emailKept; { emailId, removesAt } for emailRemoving; { phoneId,
 * label } for phoneAdded and phoneKept; { phoneId, label, removesAt } for
 * phoneRemoving; { label } for phoneUnreachable.
 *
 * recoveryCaseOpened is raised at most once in 24 hours for one pod: with
 * one or more of the pod's own in that time nothing is written. Anybody
 * can open a recovery case for a pod whose id they know, as often as they
 * like, and without this count an outsider could make this server write to
 * a pod's whole list without end.
 *
 * Returns the number of messages written.
 */
export async function raiseAlert(client, { anopodId, kind, details, reference, exceptEmailId = null, exceptPhoneId = null }) {
  if (kind === 'recoveryCaseOpened' && (await recentRecoveryAlerts(client, anopodId)) >= 1) return 0;

  await notify(client, anopodId, BELL_KINDS[kind], reference);

  const { emailIds, phoneIds } = await destinations(client, anopodId);
  let written = 0;
  for (const emailId of emailIds) {
    if (exceptEmailId !== null && emailId.equals(exceptEmailId)) continue;
    await insertMessage(client, { messageId: randomId(), anopodId, kind, emailId, phoneId: null, details });
    written += 1;
  }
  for (const phoneId of phoneIds) {
    if (exceptPhoneId !== null && phoneId.equals(exceptPhoneId)) continue;
    await insertMessage(client, { messageId: randomId(), anopodId, kind, emailId: null, phoneId, details });
    written += 1;
  }
  return written;
}
