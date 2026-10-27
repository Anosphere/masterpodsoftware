import { pool } from '../db/pool.js';
import { randomId } from '../util/ids.js';

/**
 * SQL for the recovery_events table (spec 12.3 and 12.5): the audit trail
 * of a case, append-only. The service decides which events a caller sees;
 * this module reads and writes them all.
 */

/** The kinds of spec 12.5, which the column's check also lists. */
export const EVENT_KINDS = [
  'opened', 'scheduled', 'bucketOneViewed', 'bucketTwoViewed',
  'approvalSigned', 'rejectionSigned', 'approved', 'dismissed',
  'shareReceived', 'recovered', 'completed',
];

/** A recovery_events row in camelCase. `details` is the parsed JSON. */
export function eventRow(row) {
  return {
    eventId: row.event_id,
    caseId: row.case_id,
    kind: row.kind,
    anopodId: row.anopod_id,
    details: row.details,
    createdAt: row.created_at,
  };
}

/**
 * Appends an event on `client`: `kind` one of EVENT_KINDS, `anopodId` the
 * acting moderator (a Buffer) or null for the person's, the server's and
 * the keyholders' events, `details` what the kind carries. Returns the
 * minted event id. created_at is the statement's clock, not the
 * transaction's, so two events one transaction writes (a sign-off and the
 * approval it completes) keep their order.
 */
export async function insertEvent(client, caseId, kind, anopodId, details = {}) {
  const eventId = randomId();
  await client.query(
    `INSERT INTO recovery_events (event_id, case_id, kind, anopod_id, details, created_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, clock_timestamp())`,
    [eventId, caseId, kind, anopodId, JSON.stringify(details)],
  );
  return eventId;
}

/** Every event of a case, oldest first. */
export async function listForCase(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT event_id, case_id, kind, anopod_id, details, created_at
     FROM recovery_events WHERE case_id = $1
     ORDER BY created_at, event_id`,
    [caseId],
  );
  return rows.map(eventRow);
}

/**
 * Every event of a case with the acting moderator's username (null when
 * nobody acted or the pod's row is gone), oldest first: what
 * /get-recovery-case shows the moderators.
 */
export async function listForCaseWithUsernames(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT e.event_id, e.case_id, e.kind, e.anopod_id, e.details, e.created_at, a.username
     FROM recovery_events e
     LEFT JOIN anopods a ON a.anopod_id = e.anopod_id
     WHERE e.case_id = $1
     ORDER BY e.created_at, e.event_id`,
    [caseId],
  );
  return rows.map((row) => ({ ...eventRow(row), username: row.username }));
}

/** How many distinct pods signed an approval on the case: the two-approval rule counts these. */
export async function countApprovals(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT count(DISTINCT anopod_id)::int AS approvals FROM recovery_events
     WHERE case_id = $1 AND kind = 'approvalSigned'`,
    [caseId],
  );
  return rows[0].approvals;
}

/** True when this pod already signed an approval or a rejection on the case: one sign-off per pod per case. */
export async function signedOffBy(caseId, anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM recovery_events
                    WHERE case_id = $1 AND anopod_id = $2 AND kind IN ('approvalSigned', 'rejectionSigned')) AS found`,
    [caseId, anopodId],
  );
  return rows[0].found;
}
