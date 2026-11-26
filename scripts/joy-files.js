import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { closePool, pool } from '../src/db/pool.js';
import { FILE_MAX_BYTES, FILE_NAMES } from '../src/joy/joy.files.js';
import { listStoredFiles, upsertFile } from '../src/joy/joy.queries.js';

/**
 * Puts Joy's files into the database (spec section 35): the texts that
 * Joy reads with her tool read_file. The files come as a folder, the
 * folder joy of the wallet's repository: wallet.md and anosphere.md. It
 * is run by hand, on a masterpod server:
 *
 *   npm run joy-files -- look <folder>
 *   npm run joy-files -- write <folder>
 *
 * look reads the folder and the database. For each file it says whether
 * the file is new, changed or the same as the stored one, with its
 * bytes, and it names every fault. It writes nothing. write does the
 * same and then writes, in one transaction: all of it or nothing. A
 * fault stops the run before anything is written. A file that is not in
 * the folder is left as it is, and anything else in the folder is passed
 * over. The script never takes a row out. A written file is what Joy's
 * next call of read_file gets, on every server: the server keeps no
 * copy, so there is nothing to restart. Exits 1 on a fault and on an
 * error, 2 on anything but look or write with one folder. There is no
 * route for this.
 */

// ---------------------------------------------------------------------------
// The folder
// ---------------------------------------------------------------------------

/** A number with its thousands marked: 59,781. */
const marked = (n) => n.toLocaleString('en-US');

/** The system's words for a file or a folder that could not be opened, by its error code. */
const NOT_OPENED = {
  ENOENT: 'is not there',
  EACCES: 'may not be read by this user',
  EISDIR: 'is a folder, not a file',
  ENOTDIR: 'is not a folder',
};

/** What went wrong with a file or a folder, for a fault's line. */
const why = (err) => NOT_OPENED[err.code] ?? `cannot be read (${err.code ?? err.message})`;

/** A file as it is named in the folder: wallet.md for the file wallet. */
const inFolder = (name) => `${name}.md`;

/** Reads bytes as UTF-8 text and throws at a byte that is none. A byte order mark stays in the text: the stored text is the file, byte for byte. */
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Reads the folder. Answers the files of FILE_NAMES that it holds, in
 * that order, each as { name, text, bytes }: the file's text and how
 * many bytes it has. A name whose file is not in the folder is not in
 * the answer. A file is read as bytes and has to be text: valid UTF-8
 * with no zero byte in it, more than white space, and at most
 * FILE_MAX_BYTES bytes. Every fault goes into `faults`.
 */
async function readFolder(folder, faults) {
  try {
    await readdir(folder);
  } catch (err) {
    faults.push(`the folder ${why(err)}`);
    return [];
  }
  const files = [];
  let met = 0; // how many of the names the folder has something for
  for (const name of FILE_NAMES) {
    const where = inFolder(name);
    let bytes;
    try {
      bytes = await readFile(path.join(folder, where));
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      met += 1;
      faults.push(`${where} ${why(err)}`);
      continue;
    }
    met += 1;
    if (bytes.length > FILE_MAX_BYTES) {
      faults.push(`${where}: ${marked(bytes.length)} bytes, the limit is ${marked(FILE_MAX_BYTES)}`);
      continue;
    }
    let text;
    try {
      text = utf8.decode(bytes);
    } catch {
      faults.push(`${where}: not a text file: its bytes are not UTF-8`);
      continue;
    }
    if (bytes.includes(0)) {
      faults.push(`${where}: not a text file: it holds a zero byte`);
      continue;
    }
    if (text.trim() === '') {
      faults.push(`${where}: the file is empty`);
      continue;
    }
    files.push({ name, text, bytes: bytes.length });
  }
  if (met === 0) faults.push(`the folder holds none of Joy's files: ${FILE_NAMES.map(inFolder).join(', ')}`);
  return files;
}

// ---------------------------------------------------------------------------
// The database
// ---------------------------------------------------------------------------

/**
 * Compares the files read from the folder with what the database holds,
 * on `db`. Answers one entry for each name of FILE_NAMES, in that order:
 * { name, state, text, bytes, storedBytes }. `state` is 'new' for a file
 * that the database does not hold, 'changed' for one whose stored text
 * differs, 'same' for one whose stored text is the file's, and 'absent'
 * for a name whose file is not in the folder. `storedBytes` is how many
 * bytes the stored text has, null when the database holds none.
 */
async function compare(db, files) {
  const stored = new Map((await listStoredFiles([...FILE_NAMES], db)).map((row) => [row.name, row.content]));
  return FILE_NAMES.map((name) => {
    const file = files.find((one) => one.name === name) ?? null;
    const was = stored.get(name) ?? null;
    const storedBytes = was === null ? null : Buffer.byteLength(was, 'utf8');
    if (file === null) return { name, state: 'absent', text: null, bytes: null, storedBytes };
    const state = was === null ? 'new' : was === file.text ? 'same' : 'changed';
    return { name, state, text: file.text, bytes: file.bytes, storedBytes };
  });
}

/** The entries that a write would write. */
const toWrite = (found) => found.filter((file) => file.state === 'new' || file.state === 'changed');

/** "1 new file (5,515 bytes)", "2 changed files (65,296 bytes)"; an empty list when there is none of that state. */
function inWords(found, state, one, many) {
  const those = found.filter((file) => file.state === state);
  if (those.length === 0) return [];
  const bytes = those.reduce((sum, file) => sum + file.bytes, 0);
  return [`${those.length} ${those.length === 1 ? one : many} (${marked(bytes)} bytes)`];
}

/** The report of a run without a fault: one line for each file, and the sum. */
function report(found) {
  for (const file of found) {
    const where = inFolder(file.name);
    if (file.state === 'absent') {
      const stored = file.storedBytes === null ? 'and the database holds none' : `the stored one is left as it is (${marked(file.storedBytes)} bytes)`;
      console.log(`  ${where}: not in the folder, ${stored}`);
    } else {
      const state = { new: 'new', changed: `changed: the stored one has ${marked(file.storedBytes ?? 0)} bytes`, same: 'the same as the stored one' }[file.state];
      console.log(`  ${where}: ${marked(file.bytes)} bytes, ${state}`);
    }
  }
  const words = [...inWords(found, 'new', 'new file', 'new files'), ...inWords(found, 'changed', 'changed file', 'changed files')];
  console.log(`to write: ${words.length === 0 ? 'nothing' : words.join(', ')}`);
}

/** The faults, each on a line of its own, and the closing line. */
function sayFaults(faults) {
  console.error(`faults: ${faults.length}`);
  for (const fault of faults) console.error(`  ${fault}`);
  console.error('Nothing was written.');
}

/**
 * The write run, in one transaction on one client: the comparison, the
 * writes, and the comparison once more, which must find nothing left to
 * write. All or none. Answers the exit code.
 */
async function write(files) {
  const client = await pool.connect();
  // When the connection is lost, the query that is running fails, and the catch below says so. The client
  // also emits an 'error' event of its own then; with no listener, Node would end the process before the catch.
  client.on('error', () => {});
  try {
    await client.query('BEGIN');
    const found = await compare(client, files);
    report(found);
    if (toWrite(found).length === 0) {
      await client.query('ROLLBACK');
      console.log('Nothing to write.');
      return 0;
    }
    for (const file of toWrite(found)) await upsertFile(client, file.name, file.text);
    const left = await compare(client, files);
    if (toWrite(left).length > 0) throw new Error('After the write the database does not hold what the folder says.');
    await client.query('COMMIT');
    console.log('committed');
    return 0;
  } catch (err) {
    // When the connection is lost the ROLLBACK fails too, and PostgreSQL ends the open transaction itself.
    await client.query('ROLLBACK').catch(() => {});
    console.error(err.message);
    console.error('Nothing was written.');
    return 1;
  } finally {
    client.release();
  }
}

/** The look run: the comparison and the report. Writes nothing. Answers the exit code. */
async function look(files) {
  report(await compare(pool, files));
  console.log('Nothing was written.');
  return 0;
}

const run = process.argv[2];
if ((run !== 'look' && run !== 'write') || process.argv.length !== 4) {
  console.error('usage: npm run joy-files -- <look|write> <folder>');
  process.exit(2);
}
const folder = path.resolve(process.argv[3]);

let exitCode = 0;
try {
  console.log(run === 'look' ? 'joy-files: look (nothing is written)' : 'joy-files: write');
  console.log(`folder: ${folder}`);
  const faults = [];
  const files = await readFolder(folder, faults);
  if (faults.length > 0) {
    // A fault of the folder stops the run before the database is asked.
    sayFaults(faults);
    exitCode = 1;
  } else {
    exitCode = await (run === 'look' ? look : write)(files);
  }
} catch (err) {
  // An error outside the write's transaction: the folder or the database could not be read.
  console.error(err.message);
  console.error('Nothing was written.');
  exitCode = 1;
} finally {
  await closePool();
}
process.exit(exitCode);
