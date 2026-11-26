import { env } from '../config/env.js';
import { askAnthropic, describeFailure as describeAnthropic, failureOf as failureOfAnthropic, joyIsOn as anthropicIsOn } from './joy.anthropic.js';
import { askOpenAI, describeFailure as describeOpenAI, failureOf as failureOfOpenAI, joyIsOn as openaiIsOn } from './joy.openai.js';

/**
 * Who answers Joy (spec section 36). Two companies' models can write her
 * answers: Anthropic's, through joy.anthropic.js, and OpenAI's, through
 * joy.openai.js. This file is the one place that picks. The route's
 * handler and its checks ask here and name no company.
 *
 * The setting JOY_PROVIDER picks: anthropic or openai. It is read once,
 * when this server starts, and anthropic is what it is when the setting
 * is not there. One company answers every message. A split by the kind
 * of message would be a change in this file alone. It is not built.
 *
 * Each company has its own key, model, level of thinking and most
 * tokens (src/config/env.js). Joy's pictures do not ask here: they are
 * made by OpenAI's image model whoever answers (joy.pictures.js).
 */

/** The two companies, each with its four functions, its model and the name of the setting that holds its key. */
const COMPANIES = Object.freeze({
  anthropic: Object.freeze({ ask: askAnthropic, isOn: anthropicIsOn, failureOf: failureOfAnthropic, describeFailure: describeAnthropic, model: env.joy.model, key: 'ANTHROPIC_API_KEY' }),
  openai: Object.freeze({ ask: askOpenAI, isOn: openaiIsOn, failureOf: failureOfOpenAI, describeFailure: describeOpenAI, model: env.joy.openaiModel, key: 'OPENAI_API_KEY' }),
});

/** The company that answers, picked once. */
const company = COMPANIES[env.joy.provider];

/**
 * Sends one message to Joy and reads her answer, through the company
 * that answers. What goes in, what comes back and the calls back are
 * told at askAnthropic() in joy.anthropic.js, and are the same for
 * askOpenAI() in joy.openai.js.
 */
export function askJoy(message) {
  return company.ask(message);
}

/** True when this server holds a key for the company that answers. */
export function joyIsOn() {
  return company.isOn();
}

/** The reason a failed call is answered with, or null when there is nobody to tell: the wallet went away. By the rules of the company that answers. */
export function failureOf(err) {
  return company.failureOf(err);
}

/** A failed call in a few words for the log. Never the key, never a member's text. */
export function describeFailure(err) {
  return company.describeFailure(err);
}

/** One line for the log when this server starts: who answers Joy and with which model, or that Joy is off and which key is not there. */
export function whoAnswersJoy() {
  if (!joyIsOn()) return `Joy is off: JOY_PROVIDER picks ${env.joy.provider}, and ${company.key} is not set`;
  return `Joy is answered by ${env.joy.provider}, model ${company.model}`;
}
