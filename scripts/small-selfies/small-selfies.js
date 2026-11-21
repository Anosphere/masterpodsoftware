import { createHash } from 'node:crypto';
import sharp from 'sharp';
import { closePool, pool, query } from '../../src/db/pool.js';
import { imageSize } from '../../src/util/images.js';

/**
 * Makes the stored public selfies small, once (spec section 24). Since
 * 2026-11-21 the wallet sends a new selfie as the middle of the picture, a
 * square of at most 320 pixels. The selfies stored before that are about
 * 1280 pixels on their longer side and weigh hundreds of kilobytes, and
 * every page that draws a face loads one. This job draws each of them
 * again as the middle of its picture, a square of 320 by 320 pixels, as a
 * JPEG, and never makes a picture larger than it is. It is run by hand,
 * once:
 *
 *   npm run small-selfies -- look
 *   npm run small-selfies -- write
 *
 * look reads and draws every selfie and writes nothing. write does the
 * same and then, in one transaction, copies the whole table aside as
 * public_selfies_before_small and replaces the pictures: all or none. A
 * selfie of 320 pixels or less on both sides is left as it is. So is one
 * that cannot be read, and one whose small picture does not match its own
 * original; those two kinds are named under the report. write refuses to
 * start while the copy of an earlier run is still there. Putting every
 * picture back and removing the copy are plain psql lines (spec section
 * 24). The pictures are drawn by sharp, which is named in this folder's
 * own package.json and not in the masterpod's: the running masterpod never
 * loads it. Exits 1 on an error and on a copy that is still there, 2 on
 * anything but look or write. There is no route for this.
 */

const SIDE = 320;
const JPEG_QUALITY = 80;
const MATCH_LIMIT = 4;
const COPY = 'public_selfies_before_small';

sharp.cache(false);
sharp.concurrency(1);

/** The middle square of a stored selfie as a small JPEG; null when it is 320 or less on both sides. */
async function drawSmall(image) {
  const { autoOrient } = await sharp(image, { failOn: 'warning' }).metadata();
  if (autoOrient.width <= SIDE && autoOrient.height <= SIDE) return null;
  const side = Math.min(SIDE, autoOrient.width, autoOrient.height);
  const small = await sharp(image, { failOn: 'warning' })
    .autoOrient()
    .resize(side, side, { fit: 'cover', position: 'centre', fastShrinkOnLoad: false })
    .flatten({ background: '#ffffff' })
    .jpeg({ quality: JPEG_QUALITY, chromaSubsampling: '4:2:0' })
    .toBuffer();
  return { small, side };
}

/** 32 by 32 grey points of the original's middle square, cut out exactly. */
async function marksOfOriginal(image) {
  const { data, info } = await sharp(image, { failOn: 'warning' })
    .autoOrient().flatten({ background: '#ffffff' }).raw().toBuffer({ resolveWithObject: true });
  const square = Math.min(info.width, info.height);
  return sharp(data, { raw: { width: info.width, height: info.height, channels: info.channels } })
    .extract({ left: Math.floor((info.width - square) / 2), top: Math.floor((info.height - square) / 2), width: square, height: square })
    .resize(32, 32, { fit: 'fill' }).greyscale().raw().toBuffer();
}

/** 32 by 32 grey points of the small picture. */
function marksOfSmall(small) {
  return sharp(small, { failOn: 'warning' })
    .resize(32, 32, { fit: 'fill', fastShrinkOnLoad: false }).greyscale().raw().toBuffer();
}

/** The mean difference of two sets of points, 0 to 255. */
function apart(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i += 1) sum += Math.abs(a[i] - b[i]);
  return sum / a.length;
}

/**
 * What becomes of one stored selfie, as { outcome, small, reason }:
 * 'already small' when it is 320 pixels or less on both sides; 'did not
 * match' when the masterpod's own reader, imageSize, does not read the
 * small picture as a JPEG of side by side pixels, or when its points are
 * more than MATCH_LIMIT apart from the original's; 'cannot be read' when
 * sharp throws in any of that, with the first line of its message;
 * otherwise 'to be made small', with the small bytes.
 */
async function drawAndCompare(image) {
  try {
    const drawn = await drawSmall(image);
    if (drawn === null) return { outcome: 'already small' };
    const { small, side } = drawn;
    const size = imageSize('image/jpeg', small);
    if (size === null || size.width !== side || size.height !== side) {
      return { outcome: 'did not match', reason: `the small picture is not ${side} by ${side} pixels` };
    }
    const far = apart(await marksOfOriginal(image), await marksOfSmall(small));
    if (far > MATCH_LIMIT) {
      return { outcome: 'did not match', reason: `${far.toFixed(2)} apart from the original, the limit is ${MATCH_LIMIT}` };
    }
    return { outcome: 'to be made small', small };
  } catch (err) {
    return { outcome: 'cannot be read', reason: String(err.message).split('\n')[0] };
  }
}

/** Whose selfie a row is, as a line names it: the username and the first eight characters of the id in hex. */
const whose = (username, anopodId) => `${username ?? 'no anopod row'} (${anopodId.toString('hex').slice(0, 8)})`;

/**
 * Reads every stored selfie, one at a time, and draws it. Answers the rows
 * to be made small (the id, the username, the SHA-256 of the stored bytes
 * and the small bytes; the stored bytes are let go), the lines for the
 * rows that cannot be read or did not match, and the report's counts and
 * weights. "After" is the small bytes of the rows to be made small plus
 * the stored bytes of the rows left as they are.
 */
async function readAndDraw() {
  const found = { read: 0, toMakeSmall: [], alreadySmall: 0, cannotBeRead: 0, didNotMatch: 0, named: [], weightNow: 0, weightAfter: 0, heaviest: 0 };
  const { rows: ids } = await query('SELECT anopod_id FROM public_selfies ORDER BY anopod_id');
  for (const { anopod_id: anopodId } of ids) {
    const { rows } = await query(
      `SELECT p.username, s.content_type, s.image FROM public_selfies s
       LEFT JOIN anopods p ON p.anopod_id = s.anopod_id WHERE s.anopod_id = $1`,
      [anopodId],
    );
    // A row that is gone by now is skipped.
    if (rows.length === 0) continue;
    const { username, image } = rows[0];
    found.read += 1;
    found.weightNow += image.length;
    const { outcome, small, reason } = await drawAndCompare(image);
    if (outcome === 'to be made small') {
      found.toMakeSmall.push({ anopodId, username, sha256: createHash('sha256').update(image).digest(), small });
      found.weightAfter += small.length;
      found.heaviest = Math.max(found.heaviest, small.length);
      continue;
    }
    found.weightAfter += image.length;
    if (outcome === 'already small') {
      found.alreadySmall += 1;
      continue;
    }
    if (outcome === 'cannot be read') found.cannotBeRead += 1;
    else found.didNotMatch += 1;
    found.named.push(`${whose(username, anopodId)}: ${outcome}: ${reason}`);
  }
  return found;
}

/** A number of bytes with its thousands marked: 1,781,286. */
const marked = (bytes) => bytes.toLocaleString('en-US');

/** A weight as the report prints it: the bytes, and the MB (1,048,576 bytes) with one decimal. */
const weight = (bytes) => `${marked(bytes)} bytes (${(bytes / 1_048_576).toFixed(1)} MB)`;

/** The report, the same in both runs but for its first line. */
function report(run, found) {
  console.log(run === 'look' ? 'small selfies: look (nothing is written)' : 'small selfies: write');
  console.log(`selfies read: ${found.read}`);
  console.log(`  to be made small: ${found.toMakeSmall.length}`);
  console.log(`  left as they are, already ${SIDE} pixels or less: ${found.alreadySmall}`);
  console.log(`  left as they are, cannot be read: ${found.cannotBeRead}`);
  console.log(`  left as they are, the small picture did not match: ${found.didNotMatch}`);
  console.log(`weight now: ${weight(found.weightNow)}, after: ${weight(found.weightAfter)}`);
  console.log(`the heaviest small picture: ${marked(found.heaviest)} bytes`);
  for (const line of found.named) console.log(line);
}

/**
 * The write, in one transaction on one client: the copy of the whole
 * table, then one UPDATE per row to be made small, which changes the row
 * only while it still holds the bytes that were read, then the count of
 * the rows that differ from the copy. All or none. Answers the exit code.
 */
async function copyAndReplace(toMakeSmall) {
  const client = await pool.connect();
  // When the connection is lost, the query that is running fails, and the catch below says so. The client
  // also emits an 'error' event of its own then; with no listener, Node would end the process before the catch.
  client.on('error', () => {});
  try {
    await client.query('BEGIN');
    const copy = await client.query(`CREATE TABLE ${COPY} AS SELECT * FROM public_selfies`);
    for (const { anopodId, username, sha256, small } of toMakeSmall) {
      const updated = await client.query(
        `UPDATE public_selfies SET content_type = 'image/jpeg', image = $1 WHERE anopod_id = $2 AND sha256(image) = $3`,
        [small, anopodId, sha256],
      );
      if (updated.rowCount !== 1) {
        throw new Error(`${whose(username, anopodId)}: the stored selfie is no longer the one that was read`);
      }
    }
    const { rows } = await client.query(
      `SELECT count(*)::int AS changed FROM public_selfies s JOIN ${COPY} b USING (anopod_id) WHERE s.image <> b.image`,
    );
    if (rows[0].changed !== toMakeSmall.length) {
      throw new Error(`${rows[0].changed} selfies differ from the copy, where ${toMakeSmall.length} were to be made small`);
    }
    await client.query('COMMIT');
    console.log(`copy kept as ${COPY}: ${copy.rowCount} rows`);
    console.log(`made small: ${rows[0].changed}`);
    console.log('committed');
    return 0;
  } catch (err) {
    // When the connection is lost the ROLLBACK fails too, and PostgreSQL ends the open transaction itself.
    await client.query('ROLLBACK').catch(() => {});
    console.error(err.message);
    console.error('Nothing was kept.');
    return 1;
  } finally {
    client.release();
  }
}

/** Whether the copy of an earlier write run is still there. */
async function copyIsThere() {
  const { rows } = await query(`SELECT to_regclass('public.${COPY}') AS copy`);
  return rows[0].copy !== null;
}

const run = process.argv[2];
if (run !== 'look' && run !== 'write') {
  console.error('usage: npm run small-selfies -- <look|write>');
  process.exit(2);
}

let exitCode = 0;
try {
  if (run === 'write' && (await copyIsThere())) {
    console.error(`The copy ${COPY} of an earlier run is still there. Put it back or remove it first.`);
    exitCode = 1;
  } else {
    const found = await readAndDraw();
    report(run, found);
    if (run === 'look') console.log('Nothing was written.');
    else if (found.toMakeSmall.length === 0) console.log('Nothing to make small.');
    else exitCode = await copyAndReplace(found.toMakeSmall);
  }
} catch (err) {
  // An error outside the write's transaction: the database could not be reached or read.
  console.error(err.message);
  console.error('Nothing was written.');
  exitCode = 1;
} finally {
  await closePool();
}
process.exit(exitCode);
