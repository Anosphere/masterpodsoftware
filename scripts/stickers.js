import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { closePool, pool } from '../src/db/pool.js';
import {
  STICKER_MAX_BYTES,
  STICKER_MAX_HEIGHT,
  STICKER_MAX_WIDTH,
  TAG_MAX_CHARS,
  isSetName,
  isStickerNumber,
} from '../src/stickers/sticker-rules.js';
import {
  deleteStickerTags,
  insertSticker,
  insertStickerSet,
  insertStickerTags,
  listSetPlaces,
  listStoredStickers,
  updateStickerPlace,
} from '../src/stickers/stickers.queries.js';
import { imageSize } from '../src/util/images.js';

/**
 * Puts the stickers of the wallet's chat into the database (spec section
 * 28). The stickers come as a folder: all-sets.ts, one .ts file for each
 * set, and one folder of pictures for each set, named after the set, with
 * 01.webp, 02.webp and so on. It is run by hand, on a masterpod server:
 *
 *   npm run stickers -- look <folder>
 *   npm run stickers -- write <folder>
 *
 * look reads the folder and the database, says what it would write and
 * names every fault. It writes nothing. write does the same and then
 * writes, in one transaction: all of it or nothing. A set that is not in
 * the database is added behind the last set of the row, in the order of
 * all-sets.ts. For a set that is in the database, new stickers are added,
 * and the tags and the order of its stickers are brought in line with the
 * set's file. A fault stops the run before anything is written. The
 * script never deletes a sticker or a set, never moves a set in the row
 * and never changes a stored picture: those are plain psql lines (spec
 * section 28). The .ts files are read as text and never run as code.
 * Exits 1 on a fault and on an error, 2 on anything but look or write
 * with one folder. There is no route for this.
 */

// ---------------------------------------------------------------------------
// A .ts file, read as text
// ---------------------------------------------------------------------------

/** A place in a .ts file that cannot be read: its message is the line and what is wrong there. */
class Unreadable extends Error {}

const unreadable = (line, what) => new Unreadable(`line ${line}: ${what}`);

const WORD = /[A-Za-z_$][A-Za-z0-9_$]*/y;
const MARKS = '{}[]:,;=';

/** A part as a message names it. */
const shown = (part) => (part.kind === 'string' ? `'${part.value}'` : (part.value ?? part.kind));

/**
 * Cuts the text of a .ts file into its parts, each with its line: a word,
 * a string in quote marks, or one of the marks { } [ ] : , ; =. Comments
 * are left out. Throws Unreadable at anything else.
 */
function partsOf(text) {
  const parts = [];
  let line = 1;
  let at = 0;
  while (at < text.length) {
    const char = text[at];
    if (char === '\n') {
      line += 1;
      at += 1;
    } else if (/\s/.test(char)) {
      at += 1;
    } else if (text.startsWith('//', at)) {
      const end = text.indexOf('\n', at);
      at = end === -1 ? text.length : end;
    } else if (text.startsWith('/*', at)) {
      const end = text.indexOf('*/', at + 2);
      if (end === -1) throw unreadable(line, 'a comment that does not end');
      line += text.slice(at, end).split('\n').length - 1;
      at = end + 2;
    } else if (char === "'" || char === '"') {
      let value = '';
      let next = at + 1;
      while (text[next] !== char) {
        if (next >= text.length || text[next] === '\n') throw unreadable(line, 'a quote mark that is not closed');
        if (text[next] === '\\') {
          next += 1;
          if (text[next] !== '\\' && text[next] !== "'" && text[next] !== '"') {
            throw unreadable(line, 'a backslash that stands in front of something other than a quote mark or a backslash');
          }
        }
        value += text[next];
        next += 1;
      }
      parts.push({ kind: 'string', value, line });
      at = next + 1;
    } else if (MARKS.includes(char)) {
      parts.push({ kind: char, line });
      at += 1;
    } else {
      WORD.lastIndex = at;
      const word = WORD.exec(text);
      if (word === null) throw unreadable(line, `${char} is not expected here`);
      parts.push({ kind: 'word', value: word[0], line });
      at += word[0].length;
    }
  }
  return parts;
}

/** A reader that goes through the parts of one file, front to back. */
function readerOf(parts) {
  let at = 0;
  const lastLine = parts.length === 0 ? 1 : parts.at(-1).line;
  return {
    lastLine,
    /** The next part, or undefined at the end of the file. */
    next: () => parts[at],
    /** Takes the next part, which must be of `kind` and, when `value` is given, say `value`. */
    take(kind, value) {
      const part = parts[at];
      const wanted = value ?? (kind === 'word' ? 'a name' : kind === 'string' ? 'a text in quote marks' : kind);
      if (part === undefined) throw unreadable(lastLine, `the file ends where ${wanted} is expected`);
      if (part.kind !== kind || (value !== undefined && part.value !== value)) {
        throw unreadable(part.line, `${wanted} is expected, not ${shown(part)}`);
      }
      at += 1;
      return part;
    },
    /** Takes the next part when it is of `kind`, and says whether it did. */
    takeIf(kind) {
      if (parts[at]?.kind !== kind) return false;
      at += 1;
      return true;
    },
  };
}

/**
 * Reads one value: a string in quote marks, a bare word, a list in [ ]
 * or an object in { }, the last two with or without a comma after their
 * last entry. Answers { kind: 'string' | 'word', value, line }, { kind:
 * 'list', items, line } or { kind: 'object', fields, line }, `fields` a
 * Map of the keys to their values.
 */
function readValue(reader) {
  const part = reader.next();
  if (part === undefined) throw unreadable(reader.lastLine, 'the file ends where a value is expected');
  if (part.kind === 'string' || part.kind === 'word') return reader.take(part.kind);
  if (part.kind === '[') {
    reader.take('[');
    const items = [];
    while (!reader.takeIf(']')) {
      items.push(readValue(reader));
      if (!reader.takeIf(',')) {
        reader.take(']');
        break;
      }
    }
    return { kind: 'list', items, line: part.line };
  }
  if (part.kind === '{') {
    reader.take('{');
    const fields = new Map();
    while (!reader.takeIf('}')) {
      const key = reader.take(reader.next()?.kind === 'string' ? 'string' : 'word');
      reader.take(':');
      if (fields.has(key.value)) throw unreadable(key.line, `${key.value} stands twice`);
      fields.set(key.value, readValue(reader));
      if (!reader.takeIf(',')) {
        reader.take('}');
        break;
      }
    }
    return { kind: 'object', fields, line: part.line };
  }
  throw unreadable(part.line, `${shown(part)} is not expected here`);
}

/** The value of `name` in an object, which must be a string in quote marks or a list, as `kind` says. */
function field(object, name, kind) {
  if (object.kind !== 'object') throw unreadable(object.line, `{ is expected, not ${shown(object)}`);
  const value = object.fields.get(name);
  if (value === undefined) throw unreadable(object.line, `${name} is missing`);
  if (value.kind !== kind) {
    throw unreadable(value.line, `${name} must be ${kind === 'string' ? 'a text in quote marks' : 'a list in square brackets'}`);
  }
  return value;
}

/**
 * Reads all-sets.ts: lines of the form
 *   import { SET as <NICKNAME> } from './<set>';
 * and one list of the nicknames,
 *   export const ALL_SETS = [ <NICKNAME>, ... ];
 * Answers the names of the sets in the order of the list. A set stands
 * in both places, once.
 */
function readAllSets(text) {
  const reader = readerOf(partsOf(text));
  const imported = new Map();
  let list = null;
  while (reader.next() !== undefined) {
    const first = reader.take('word');
    if (first.value === 'import') {
      reader.take('{');
      reader.take('word', 'SET');
      reader.take('word', 'as');
      const nickname = reader.take('word');
      reader.take('}');
      reader.take('word', 'from');
      const from = reader.take('string');
      reader.takeIf(';');
      if (imported.has(nickname.value)) throw unreadable(nickname.line, `${nickname.value} stands in two import lines`);
      imported.set(nickname.value, { name: from.value.replace(/^\.\//, '').replace(/\.ts$/, ''), line: nickname.line });
    } else if (first.value === 'export') {
      reader.take('word', 'const');
      reader.take('word');
      reader.take('=');
      const value = readValue(reader);
      reader.takeIf(';');
      if (list !== null) throw unreadable(first.line, 'a second list of the sets');
      if (value.kind !== 'list') throw unreadable(value.line, 'the list of the sets in square brackets is expected here');
      list = value;
    } else {
      throw unreadable(first.line, `${first.value} is not expected here`);
    }
  }
  if (list === null) throw unreadable(reader.lastLine, 'the list of the sets is missing');
  const names = [];
  const listed = new Set();
  for (const item of list.items) {
    if (item.kind !== 'word') throw unreadable(item.line, 'the list holds the nicknames of the import lines');
    if (!imported.has(item.value)) throw unreadable(item.line, `${item.value} stands in the list and has no import line`);
    if (listed.has(item.value)) throw unreadable(item.line, `${item.value} stands twice in the list`);
    listed.add(item.value);
    const { name } = imported.get(item.value);
    if (names.includes(name)) throw unreadable(item.line, `the set ${name} stands twice`);
    names.push(name);
  }
  for (const [nickname, { line }] of imported) {
    if (!listed.has(nickname)) throw unreadable(line, `${nickname} has an import line and is not in the list`);
  }
  return names;
}

/**
 * Reads a set's file:
 *   export const SET = { id: '<set>', stickers: [ { id: '<number>', tags: [ '<tag>', ... ] }, ... ] };
 * Answers { id, lines: [ { number, tags, line } ] } as written, the
 * lines in the file's order. Another key in an object is passed over.
 */
function readSetFile(text) {
  const reader = readerOf(partsOf(text));
  reader.take('word', 'export');
  reader.take('word', 'const');
  reader.take('word');
  reader.take('=');
  const set = readValue(reader);
  reader.takeIf(';');
  const more = reader.next();
  if (more !== undefined) throw unreadable(more.line, `${shown(more)} is not expected after the set`);
  const id = field(set, 'id', 'string');
  const lines = field(set, 'stickers', 'list').items.map((item) => {
    const number = field(item, 'id', 'string');
    const tags = field(item, 'tags', 'list');
    for (const tag of tags.items) {
      if (tag.kind !== 'string') throw unreadable(tag.line, `a tag is a text in quote marks, not ${shown(tag)}`);
    }
    return { number: number.value, tags: tags.items.map((tag) => tag.value), line: item.line };
  });
  return { id: id.value, lines };
}

// ---------------------------------------------------------------------------
// The folder
// ---------------------------------------------------------------------------

/** A number with its thousands marked: 150,000. */
const marked = (n) => n.toLocaleString('en-US');

/** The system's words for a file or a folder that could not be opened, by its error code. */
const NOT_OPENED = {
  ENOENT: 'is not there',
  EACCES: 'may not be read by this user',
  EISDIR: 'is a folder, not a file',
  ENOTDIR: 'is not a folder',
};

/** What went wrong with a file, for a fault's line: the line and the reason of an Unreadable, the system's words otherwise. */
const why = (err) => (err instanceof Unreadable ? err.message : (NOT_OPENED[err.code] ?? `cannot be read (${err.code ?? err.message})`));

/** A sticker's tags as they are stored: each without the spaces around it and in small letters, an empty one and a repeat left out. */
function tagsOf(tags) {
  return [...new Set(tags.map((tag) => tag.trim().toLowerCase()).filter((tag) => tag !== ''))];
}

/**
 * Reads one picture and checks it: a WebP of at most STICKER_MAX_BYTES
 * bytes, at most STICKER_MAX_WIDTH pixels wide and STICKER_MAX_HEIGHT
 * high. Answers { image, hash }, the bytes and their SHA-256, or null
 * with the fault named.
 */
async function readPicture(file, where, faults) {
  let image;
  try {
    image = await readFile(file);
  } catch (err) {
    faults.push(`${where}: ${why(err)}`);
    return null;
  }
  const pixels = imageSize('image/webp', image);
  if (pixels === null) {
    faults.push(`${where}: not a WebP picture`);
    return null;
  }
  const tooHeavy = image.length > STICKER_MAX_BYTES;
  const tooLarge = pixels.width > STICKER_MAX_WIDTH || pixels.height > STICKER_MAX_HEIGHT;
  if (tooHeavy) faults.push(`${where}: ${marked(image.length)} bytes, the limit is ${marked(STICKER_MAX_BYTES)}`);
  if (tooLarge) {
    faults.push(`${where}: ${pixels.width} by ${pixels.height} pixels, the limit is ${STICKER_MAX_WIDTH} by ${STICKER_MAX_HEIGHT}`);
  }
  return tooHeavy || tooLarge ? null : { image, hash: createHash('sha256').update(image).digest() };
}

/**
 * Reads one set from the folder: its folder of pictures and its file.
 * Answers { name, stickers: [ { number, tags, image, hash } ] } in the
 * order of the file's lines, or null when the name is no set's name or
 * the file cannot be read. `image` and `hash` are null for a sticker
 * whose picture is missing or has a fault. Every fault goes into
 * `faults`.
 */
async function readSet(folder, name, faults) {
  if (!isSetName(name)) {
    faults.push(`all-sets.ts: ${name} is not a set's name: small letters, digits and hyphens, at most 32 characters`);
    return null;
  }
  const pictures = new Map();
  let entries = [];
  let folderRead = true;
  try {
    entries = await readdir(path.join(folder, name), { withFileTypes: true });
  } catch (err) {
    faults.push(`${name}: the folder of pictures ${why(err)}`);
    folderRead = false;
  }
  entries = entries.filter((entry) => !entry.name.startsWith('.')).sort((a, b) => (a.name < b.name ? -1 : 1));
  for (const entry of entries) {
    const where = `${name}/${entry.name}`;
    const number = /^([0-9]{2})\.webp$/.exec(entry.name)?.[1];
    if (!isStickerNumber(number) || !entry.isFile()) {
      faults.push(`${where}: not a picture named by its number, like 01.webp`);
    } else {
      pictures.set(number, await readPicture(path.join(folder, name, entry.name), where, faults));
    }
  }

  let read;
  try {
    read = readSetFile(await readFile(path.join(folder, `${name}.ts`), 'utf8'));
  } catch (err) {
    faults.push(`${name}.ts ${why(err)}`);
    return null;
  }
  if (read.id !== name) faults.push(`${name}.ts: the name inside is ${read.id}, and the file's own name says ${name}`);
  const stickers = [];
  const numbers = new Set();
  for (const { number, tags, line } of read.lines) {
    if (!isStickerNumber(number)) {
      faults.push(`${name}.ts line ${line}: ${number} is not a sticker's number: two digits, 01 to 99`);
    } else if (numbers.has(number)) {
      faults.push(`${name}.ts line ${line}: the number ${number} stands twice`);
    } else {
      numbers.add(number);
      // With no folder of pictures, the one line about the folder says it for every sticker.
      if (folderRead && !pictures.has(number)) {
        faults.push(`${name}.ts line ${line}: sticker ${number} has no picture ${name}/${number}.webp`);
      }
      const words = tagsOf(tags);
      if (words.some((tag) => [...tag].length > TAG_MAX_CHARS)) {
        faults.push(`${name}.ts line ${line}: a tag of more than ${TAG_MAX_CHARS} characters`);
      }
      const picture = pictures.get(number) ?? null;
      stickers.push({ number, tags: words, image: picture?.image ?? null, hash: picture?.hash ?? null });
    }
  }
  for (const number of pictures.keys()) {
    if (!numbers.has(number)) faults.push(`${name}/${number}.webp: the picture has no line in ${name}.ts`);
  }
  return { name, stickers };
}

/**
 * Reads the whole folder. Answers { named, sets }: how many sets
 * all-sets.ts names, and the sets that could be read, in its order.
 */
async function readFolder(folder, faults) {
  try {
    await readdir(folder);
  } catch (err) {
    faults.push(`the folder ${why(err)}`);
    return { named: 0, sets: [] };
  }
  let names;
  try {
    names = readAllSets(await readFile(path.join(folder, 'all-sets.ts'), 'utf8'));
  } catch (err) {
    faults.push(`all-sets.ts ${why(err)}`);
    return { named: 0, sets: [] };
  }
  const sets = [];
  for (const name of names) {
    const set = await readSet(folder, name, faults);
    if (set !== null) sets.push(set);
  }
  return { named: names.length, sets };
}

// ---------------------------------------------------------------------------
// The database
// ---------------------------------------------------------------------------

/**
 * Compares the sets read from the folder with what the database holds,
 * on `db`. Answers what a write would do, one entry for each set:
 * { name, place, stored, add, move, tagsOn, tagsOff }. `place` is the
 * place in the row a new set gets, null for a set that is in the row;
 * `stored` is how many of its stickers the database holds; `add` is the
 * new stickers, [ { number, place, image, tags } ]; `move` the stored
 * stickers that get another place in the set, [ { number, place } ];
 * `tagsOn` and `tagsOff` the tags that a stored sticker gains and loses,
 * [ { number, tags } ]. A stored sticker with no line in the set's file
 * and a picture that differs from the stored one go into `faults`.
 */
async function compare(db, sets, faults) {
  const row = await listSetPlaces(db);
  let last = row.reduce((highest, set) => Math.max(highest, set.place), 0);
  const changes = [];
  for (const set of sets) {
    const stored = new Map((await listStoredStickers(set.name, db)).map((sticker) => [sticker.number, sticker]));
    const change = { name: set.name, place: null, stored: stored.size, add: [], move: [], tagsOn: [], tagsOff: [] };
    if (!row.some((inRow) => inRow.name === set.name)) {
      last += 1;
      change.place = last;
    }
    const lines = new Set(set.stickers.map((sticker) => sticker.number));
    for (const number of stored.keys()) {
      if (!lines.has(number)) faults.push(`${set.name}.ts: sticker ${number} is in the database and has no line in the file`);
    }
    set.stickers.forEach(({ number, tags, image, hash }, index) => {
      const place = index + 1;
      const was = stored.get(number);
      if (was === undefined) {
        change.add.push({ number, place, image, tags });
        return;
      }
      if (hash !== null && !hash.equals(was.imageHash)) {
        faults.push(`${set.name}/${number}.webp: differs from the picture stored under this number`);
      }
      if (was.place !== place) change.move.push({ number, place });
      const on = tags.filter((tag) => !was.tags.includes(tag));
      const off = was.tags.filter((tag) => !tags.includes(tag));
      if (on.length > 0) change.tagsOn.push({ number, tags: on });
      if (off.length > 0) change.tagsOff.push({ number, tags: off });
    });
    changes.push(change);
  }
  return changes;
}

/** How many tags a list of { tags } holds in all. */
const tagCount = (list) => list.reduce((sum, { tags }) => sum + tags.length, 0);

/** The counts of what a write would do, for one set or for all of them. */
function countsOf(changes) {
  const counts = { sets: 0, stickers: 0, bytes: 0, tagsOn: 0, tagsOff: 0, moved: 0 };
  for (const change of changes) {
    if (change.place !== null) counts.sets += 1;
    counts.stickers += change.add.length;
    counts.bytes += change.add.reduce((sum, { image }) => sum + image.length, 0);
    counts.tagsOn += tagCount(change.add) + tagCount(change.tagsOn);
    counts.tagsOff += tagCount(change.tagsOff);
    counts.moved += change.move.length;
  }
  return counts;
}

/** "1 new sticker", "25 new stickers". */
const some = (n, one, many) => `${marked(n)} ${n === 1 ? one : many}`;

/** The counts as a list of words, without the new sets: [ "25 new stickers (612,345 bytes)", "14 tags added" ]. */
function inWords(counts) {
  const words = [];
  if (counts.stickers > 0) words.push(`${some(counts.stickers, 'new sticker', 'new stickers')} (${marked(counts.bytes)} bytes)`);
  if (counts.tagsOn > 0) words.push(`${some(counts.tagsOn, 'tag', 'tags')} added`);
  if (counts.tagsOff > 0) words.push(`${some(counts.tagsOff, 'tag', 'tags')} taken off`);
  if (counts.moved > 0) words.push(`${some(counts.moved, 'sticker', 'stickers')} moved in the set`);
  return words;
}

/** True when a write would change anything. */
function somethingToWrite(changes) {
  const counts = countsOf(changes);
  return counts.sets + counts.stickers + counts.tagsOn + counts.tagsOff + counts.moved > 0;
}

/** The report of a run without a fault: one line for each set, and the sum. */
function report(named, changes) {
  console.log(`sets in all-sets.ts: ${named}`);
  for (const change of changes) {
    const words = inWords(countsOf([change]));
    if (change.place === null) {
      const stored = `in the database with ${some(change.stored, 'sticker', 'stickers')}`;
      console.log(`  ${change.name}: ${stored}: ${words.length === 0 ? 'nothing to change' : words.join(', ')}`);
    } else {
      console.log(`  ${change.name}: ${['a new set', `place ${change.place} in the row`, ...words].join(', ')}`);
    }
  }
  const counts = countsOf(changes);
  const sets = counts.sets > 0 ? [some(counts.sets, 'new set', 'new sets')] : [];
  console.log(`to write: ${somethingToWrite(changes) ? [...sets, ...inWords(counts)].join(', ') : 'nothing'}`);
}

/** The faults, each on a line of its own, and the closing line. */
function sayFaults(faults) {
  console.error(`faults: ${faults.length}`);
  for (const fault of faults) console.error(`  ${fault}`);
  console.error('Nothing was written.');
}

/** Writes what compare() found, on `client`. */
async function writeChanges(client, changes) {
  for (const { name, place, add, move, tagsOn, tagsOff } of changes) {
    if (place !== null) await insertStickerSet(client, name, place);
    for (const sticker of add) {
      await insertSticker(client, name, sticker.number, sticker.place, sticker.image);
      if (sticker.tags.length > 0) await insertStickerTags(client, name, sticker.number, sticker.tags);
    }
    for (const sticker of move) await updateStickerPlace(client, name, sticker.number, sticker.place);
    for (const sticker of tagsOff) await deleteStickerTags(client, name, sticker.number, sticker.tags);
    for (const sticker of tagsOn) await insertStickerTags(client, name, sticker.number, sticker.tags);
  }
}

/**
 * The write run, in one transaction on one client: the comparison, the
 * writes, and the comparison once more, which must find nothing left to
 * write and no fault. All or none. Answers the exit code.
 */
async function write(named, sets, faults) {
  const client = await pool.connect();
  // When the connection is lost, the query that is running fails, and the catch below says so. The client
  // also emits an 'error' event of its own then; with no listener, Node would end the process before the catch.
  client.on('error', () => {});
  try {
    await client.query('BEGIN');
    const changes = await compare(client, sets, faults);
    if (faults.length > 0) {
      await client.query('ROLLBACK');
      sayFaults(faults);
      return 1;
    }
    report(named, changes);
    if (!somethingToWrite(changes)) {
      await client.query('ROLLBACK');
      console.log('Nothing to write.');
      return 0;
    }
    await writeChanges(client, changes);
    const faultsAfter = [];
    const left = await compare(client, sets, faultsAfter);
    if (faultsAfter.length > 0 || somethingToWrite(left)) {
      throw new Error('After the write the database does not hold what the folder says.');
    }
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
async function look(named, sets, faults) {
  const changes = await compare(pool, sets, faults);
  if (faults.length > 0) {
    sayFaults(faults);
    return 1;
  }
  report(named, changes);
  console.log('Nothing was written.');
  return 0;
}

const run = process.argv[2];
if ((run !== 'look' && run !== 'write') || process.argv.length !== 4) {
  console.error('usage: npm run stickers -- <look|write> <folder>');
  process.exit(2);
}
const folder = path.resolve(process.argv[3]);

let exitCode = 0;
try {
  console.log(run === 'look' ? 'stickers: look (nothing is written)' : 'stickers: write');
  console.log(`folder: ${folder}`);
  const faults = [];
  const { named, sets } = await readFolder(folder, faults);
  exitCode = await (run === 'look' ? look : write)(named, sets, faults);
} catch (err) {
  // An error outside the write's transaction: the folder or the database could not be read.
  console.error(err.message);
  console.error('Nothing was written.');
  exitCode = 1;
} finally {
  await closePool();
}
process.exit(exitCode);
