import { isObject } from '../util/is-object.js';

/**
 * A member's memory file for Joy, as text, and the two tools Joy changes it
 * with (spec section 30). The file is plain text. Joy's own lines begin
 * with "- "; the member may write anything into it in the wallet.
 *
 * This server never stores the text. The wallet sends the file with every
 * message, Joy's changes are made on that copy here, and the changed file
 * goes back to the wallet in the answer's last line.
 */

/** The largest memory file, in bytes of UTF-8. */
export const MEMORY_MAX_BYTES = 10_240;

/** The longest line Joy may write, in characters. */
const LINE_MAX_CHARS = 500;

/**
 * Joy's two tools, as Anthropic's API takes them. Their inputs are checked
 * here, in applyMemoryTool: with eager_input_streaming Anthropic hands an
 * input over as the model wrote it.
 */
export const MEMORY_TOOLS = Object.freeze([
  {
    name: 'remember',
    description:
      "Add one line to this member's memory file. Call it when the member tells you a lasting fact about themselves that will help in later chats: their name, where they live, their work, their family, the language they want, how they like to be answered, a plan or a project they keep coming back to. Also call it when the member asks you to remember something. One fact for each call, as one short line about the member in the third person. Do not save passing details of the chat at hand. Never save passwords, keys, recovery details or other secrets.",
    eager_input_streaming: true,
    input_schema: {
      type: 'object',
      properties: {
        line: { type: 'string', description: 'The fact, as one short line. For example: Sells coffee in Chiang Mai.' },
      },
      required: ['line'],
    },
  },
  {
    name: 'update_memory',
    description:
      "Change or take out one line of this member's memory file. Call it when a line is no longer true, or when the member asks you to forget something. To make room in a full file, take out the line that matters least.",
    eager_input_streaming: true,
    input_schema: {
      type: 'object',
      properties: {
        old_line: { type: 'string', description: 'The line as it stands in the memory file, copied exactly.' },
        new_line: { type: 'string', description: 'The line that takes its place. An empty string takes the line out.' },
      },
      required: ['old_line', 'new_line'],
    },
  },
]);

/** A line as it is compared: without the "- " in front and the spaces around it. */
function bare(line) {
  return line.trim().replace(/^-\s*/, '').trim();
}

/** `value` as one line: line breaks become spaces, and the spaces around it go. */
function oneLine(value) {
  return value.replace(/\s*[\r\n]+\s*/g, ' ').trim();
}

/** What Joy is told when an input is not the object its tool asks for: the input itself, so she can send it again (Anthropic's form for it). */
function invalidInput(text, input) {
  return { text, result: JSON.stringify({ INVALID_JSON: JSON.stringify(input ?? null) }), isError: true };
}

/**
 * Carries out one call of a memory tool on the file's text. Returns
 * { text, result, isError }: the file after the call (unchanged when the
 * call is refused), the few words Joy is told, and whether they are a
 * refusal. Never throws.
 */
export function applyMemoryTool(text, name, input) {
  if (name === 'remember') {
    if (!isObject(input) || typeof input.line !== 'string') return invalidInput(text, input);
    const line = bare(oneLine(input.line));
    if (line === '') return { text, result: 'the line is empty', isError: true };
    if (line.length > LINE_MAX_CHARS) return { text, result: `a line is at most ${LINE_MAX_CHARS} characters`, isError: true };
    if (text.split('\n').some((existing) => bare(existing) === line)) {
      return { text, result: 'that line is already in the memory file', isError: false };
    }
    const next = `${text.trimEnd()}${text.trim() === '' ? '' : '\n'}- ${line}`;
    if (Buffer.byteLength(next, 'utf8') > MEMORY_MAX_BYTES) {
      return { text, result: 'the memory file is full: take out or shorten a line with update_memory first', isError: true };
    }
    return { text: next, result: 'saved', isError: false };
  }

  if (name === 'update_memory') {
    if (!isObject(input) || typeof input.old_line !== 'string' || typeof input.new_line !== 'string') {
      return invalidInput(text, input);
    }
    const oldLine = bare(oneLine(input.old_line));
    const newLine = bare(oneLine(input.new_line));
    if (oldLine === '') return { text, result: 'old_line is empty', isError: true };
    if (newLine.length > LINE_MAX_CHARS) return { text, result: `a line is at most ${LINE_MAX_CHARS} characters`, isError: true };
    const lines = text.split('\n');
    const at = lines.findIndex((existing) => bare(existing) === oldLine);
    if (at === -1) return { text, result: 'that line is not in the memory file', isError: true };
    if (newLine === '') lines.splice(at, 1);
    else lines[at] = `- ${newLine}`;
    const next = lines.join('\n');
    if (Buffer.byteLength(next, 'utf8') > MEMORY_MAX_BYTES) {
      return { text, result: 'the memory file would be too long: write a shorter line', isError: true };
    }
    return { text: next, result: newLine === '' ? 'taken out' : 'changed', isError: false };
  }

  return { text, result: `there is no tool named ${String(name).slice(0, 60)}`, isError: true };
}
