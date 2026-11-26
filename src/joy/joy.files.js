import { isObject } from '../util/is-object.js';
import { findFile } from './joy.queries.js';

/**
 * Joy's files (spec section 35). How the wallet and the anoSphere work is
 * told in two files of text. They live in this server's database
 * (joy_files) and come in by scripts/joy-files.js. Joy reads one with her
 * tool read_file, by its name, when a question needs it. This file holds
 * the files' names, the tool, the few words Joy is told when a call
 * brings no file, and the read.
 *
 * This server keeps no copy of a file in its memory. Each call reads the
 * file's row at that moment. So a file that the script has changed is
 * what Joy's next call gets, on every server, with no restart.
 */

/**
 * The names of Joy's files, in the one place that has them: the tool's
 * list, the read and scripts/joy-files.js take them from here. In the
 * folder that the script reads, a file is its name with .md after it.
 * A new name also changes the words below and joy/shared-memory.md,
 * which tell Joy what each file holds.
 */
export const FILE_NAMES = Object.freeze(['wallet', 'anosphere']);

/** The largest file, in bytes of UTF-8. The check of joy_files.content in db/schema.sql says the same. */
export const FILE_MAX_BYTES = 100_000;

/**
 * Joy's tool for her files, as Anthropic's API takes it. Its input is
 * checked here, in readJoyFile.
 */
export const READ_FILE_TOOL = Object.freeze({
  name: 'read_file',
  description:
    'Read one of your two files. wallet: how the anoPod wallet works, every part of it, with the names of its pages and buttons in English and in Thai and a list of known troubles. anosphere: what the anoSphere is, what it is for, how it is built and what is planned. Call it before you answer a question about the wallet or about the anoSphere, each time anew: nothing of a file stays in the chat. The whole text of the file comes back. Do not call it for anything else.',
  input_schema: {
    type: 'object',
    properties: {
      name: { type: 'string', enum: [...FILE_NAMES], description: 'The file to read: wallet or anosphere.' },
    },
    required: ['name'],
  },
});

/** What read_file answers Joy when it brings no file. Both are handed over as a refusal. */
const OUTCOMES = Object.freeze({
  noSuchFile: 'there is no such file: the two files are wallet and anosphere',
  notRead:
    'the file could not be read right now: tell the member that you cannot look this up right now and that they can ask again later, and do not answer from what you remember',
});

/** A file that could not be read: one line in the log, the file's name and what went wrong, and the few words for Joy, as a refusal. */
function notRead(name, why) {
  console.log('joy file not read:', name, why);
  return { result: OUTCOMES.notRead, isError: true };
}

/**
 * Carries out one call of read_file: one read of the file's row, by its
 * name, at this moment.
 *
 *   input   the call's input, as the model wrote it
 *
 * Returns { result, isError }: the file's text, whole and alone, with
 * nothing in front of it and nothing after it; or a few words for Joy,
 * as a refusal. A name that is none of FILE_NAMES, and an input with no
 * name, is answered that there is no such file, without a read. A row
 * that is not there and a read that fails are both answered that the
 * file could not be read right now, and each writes one line into the
 * log. Never throws.
 */
export async function readJoyFile(input) {
  const name = isObject(input) ? input.name : undefined;
  if (typeof name !== 'string' || !FILE_NAMES.includes(name)) return { result: OUTCOMES.noSuchFile, isError: true };

  let text;
  try {
    text = await findFile(name);
  } catch (err) {
    // PostgreSQL's own words for it, and its code for the error where
    // the words do not hold it: 42P01 for a table that is not there.
    const words = String(err.message).slice(0, 100);
    const code = typeof err.code === 'string' && !words.includes(err.code) ? ` (${err.code})` : '';
    return notRead(name, `${words}${code}`);
  }
  if (text === null) return notRead(name, 'no row in joy_files');
  return { result: text, isError: false };
}
