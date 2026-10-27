import { pool } from '../db/pool.js';
import { randomId } from '../util/ids.js';

/**
 * SQL for the attestor_events table (spec 13.3 and 13.5): the log of both
 * kinds of case, append-only. The service decides which events a caller
 * sees; this module reads and writes them all.
 */

/** The kinds of spec 13.5, which the column's check also lists. */
export const EVENT_KINDS = [
  'opened', 'lookupIdShared', 'evidenceAdded', 'scheduled',
  'bucketOneViewed', 'bucketTwoViewed', 'caseKeyShared',
  'attestationSigned', 'verdictSigned', 'decided',
  'lookupIdCleared', 'evidenceDeleted', 'sent', 'dismissed',
];

/** The two kinds of sign-off event; one per pod per case, whichever the case's kind takes. */
export const SIGN_OFF_KINDS = ['attestationSigned', 'verdictSigned'];

/** An attestor_events row in camelCase. `details` is the parsed JSON. */
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
 * acting pod (a Buffer), an attestor or a party, or null for the server's
 * own events, `details` what the kind carries. Returns the minted event id.
 * created_at is the statement's clock, not the transaction's, so the events
 * one transaction writes (a sign-off, the decision it completes, the
 * clearing) keep their order.
 */
export async function insertEvent(client, caseId, kind, anopodId, details = {}) {
  const eventId = randomId();
  await client.query(
    `INSERT INTO attestor_events (event_id, case_id, kind, anopod_id, details, created_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, clock_timestamp())`,
    [eventId, caseId, kind, anopodId, JSON.stringify(details)],
  );
  return eventId;
}

/** Every event of a case, oldest first. */
export async function listForCase(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT event_id, case_id, kind, anopod_id, details, created_at
     FROM attestor_events WHERE case_id = $1
     ORDER BY created_at, event_id`,
    [caseId],
  );
  return rows.map(eventRow);
}

/**
 * Every event of a case with the acting pod's username (null when nobody
 * acted or the pod's row is gone), oldest first: what /get-trade-case and
 * /get-dispute-case show the attestors.
 */
export async function listForCaseWithUsernames(caseId, db = pool) {
  const { rows } = await db.query(
    `SELECT e.event_id, e.case_id, e.kind, e.anopod_id, e.details, e.created_at, a.username
     FROM attestor_events e
     LEFT JOIN anopods a ON a.anopod_id = e.anopod_id
     WHERE e.case_id = $1
     ORDER BY e.created_at, e.event_id`,
    [caseId],
  );
  return rows.map((row) => ({ ...eventRow(row), username: row.username }));
}

/** How many distinct pods wrote an event of `kind` on the case: the sign-off counts (attestationSigned, verdictSigned). */
export async function countSignOffs(caseId, kind, db = pool) {
  const { rows } = await db.query(
    'SELECT count(DISTINCT anopod_id)::int AS n FROM attestor_events WHERE case_id = $1 AND kind = $2',
    [caseId, kind],
  );
  return rows[0].n;
}

/** How many distinct pods signed a verdict of this value (success or cancel) on the case: the two-agreeing-verdicts rule counts these. */
export async function countVerdicts(caseId, verdict, db = pool) {
  const { rows } = await db.query(
    `SELECT count(DISTINCT anopod_id)::int AS n FROM attestor_events
     WHERE case_id = $1 AND kind = 'verdictSigned' AND details->>'verdict' = $2`,
    [caseId, verdict],
  );
  return rows[0].n;
}

/** True when this pod already signed an attestation or a verdict on the case: one sign-off per pod per case. */
export async function signedOffBy(caseId, anopodId, db = pool) {
  const { rows } = await db.query(
    `SELECT EXISTS (SELECT 1 FROM attestor_events
                    WHERE case_id = $1 AND anopod_id = $2 AND kind = ANY ($3::text[])) AS found`,
    [caseId, anopodId, SIGN_OFF_KINDS],
  );
  return rows[0].found;
}

/** The details of every event of `kind` on the case, oldest first: the signer ids a decided event lists. */
export async function listDetails(caseId, kind, db = pool) {
  const { rows } = await db.query(
    'SELECT details FROM attestor_events WHERE case_id = $1 AND kind = $2 ORDER BY created_at, event_id',
    [caseId, kind],
  );
  return rows.map((row) => row.details);
}
