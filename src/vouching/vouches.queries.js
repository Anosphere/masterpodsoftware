/** SQL for the vouches table: the record of an approval, written once. */

/**
 * Records on `client` that `anopodIdVouchedBy` vouched for
 * `anopodIdVouchedFor`, under the request's `vouchIdNumber`. A second vouch
 * by the same pod for the same pod throws a unique violation.
 */
export async function insertVouch(client, vouchIdNumber, anopodIdVouchedBy, anopodIdVouchedFor) {
  await client.query(
    `INSERT INTO vouches (vouch_id_number, anopod_id_vouched_by, anopod_id_vouched_for)
     VALUES ($1, $2, $3)`,
    [vouchIdNumber, anopodIdVouchedBy, anopodIdVouchedFor],
  );
}
