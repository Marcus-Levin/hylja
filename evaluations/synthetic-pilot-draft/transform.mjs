/**
 * PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY.
 * Pure public synthetic schema experiment, not accepted treatment/CREATE/DISPLAY.
 * No authentication, custody, lookup, restoration, keys, I/O, clocks or randomness.
 * See docs/specs/synthetic-pilot-draft.md for the complete frozen contract.
 */
import { createHash } from 'node:crypto';

const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'PILOT_TRANSFORM_REFUSED' });
const DOMAIN = 'hylja.public-synthetic-pilot-draft.reference.v1';
// Absolute end assertions: not even a terminal line break is part of this namespace.
const ASSET = /^SYNTHETIC-ASSET-[A-Z0-9]{1,64}(?![\s\S])/u;
const SCOPE = /^SYNTHETIC-SCOPE-[A-Z0-9]{1,32}(?![\s\S])/u;
const SESSION = /^SYNTHETIC-SESSION-[A-Z0-9]{1,32}(?![\s\S])/u;
const CONTEXT = /^SYNTHETIC-CONTEXT-[A-Z0-9]{1,32}(?![\s\S])/u;

function boundedJson(text, cap) {
  // No caller-object reads or coercion; size/ASCII guards precede JSON.parse.
  if (typeof text !== 'string' || text.length < 1 || text.length > cap || /[^\x20-\x7e]/u.test(text)) return null;
  return JSON.parse(text);
}

function closed(value, keys) {
  // Only JSON-created records ever reach this function, never caller objects.
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function validContext(value) {
  return closed(value, ['version', 'scope', 'session', 'context']) && value.version === 1 &&
    typeof value.scope === 'string' && SCOPE.test(value.scope) &&
    typeof value.session === 'string' && SESSION.test(value.session) &&
    typeof value.context === 'string' && CONTEXT.test(value.context);
}

function validAsset(value) {
  return typeof value === 'string' && value.length >= 17 && value.length <= 80 && ASSET.test(value);
}

function validMessage(value) {
  return closed(value, ['version', 'task', 'assets']) && value.version === 1 &&
    (value.task === 'ERROR_COUNTS' || value.task === 'FIRST_ERRORS') && Array.isArray(value.assets) &&
    value.assets.length >= 1 && value.assets.length <= 8 && value.assets.every(validAsset) &&
    new Set(value.assets).size === value.assets.length;
}

function validLog(value) {
  return closed(value, ['version', 'events']) && value.version === 1 && Array.isArray(value.events) &&
    value.events.length >= 1 && value.events.length <= 128 && value.events.every((event) =>
      closed(event, ['asset', 'tick', 'level', 'code']) && validAsset(event.asset) &&
      Number.isSafeInteger(event.tick) && event.tick >= 0 && event.tick <= 1000000 &&
      (event.level === 'INFO' || event.level === 'ERROR') &&
      (event.code === 'START' || event.code === 'STOP' || event.code === 'FAILURE'));
}

function reference(context, asset) {
  // ASCII admission makes lengths exact UTF-8 byte lengths. Each component,
  // including the distinct public domain, is length-framed without ambiguity.
  // Unkeyed public digests remain forgeable/dictionary-recomputable, NOT authority.
  const framed = [DOMAIN, context.scope, context.session, context.context, asset]
    .map((value) => String(value.length) + ':' + value).join('');
  return 'DRAFT-PILOT-REF-' + createHash('sha256').update(framed).digest('hex');
}

export function derivePilotReference(contextJson, asset) {
  try {
    const context = boundedJson(contextJson, 512);
    if (!validContext(context) || !validAsset(asset) || JSON.stringify(context) !== contextJson) return REFUSAL;
    return Object.freeze({ status: 'DERIVED', mode: 'PUBLIC_DRAFT_ONLY', reference: reference(context, asset) });
  } catch {
    return REFUSAL;
  }
}

export function transformPilot(contextJson, messageJson, logJson) {
  try {
    const context = boundedJson(contextJson, 512);
    const message = boundedJson(messageJson, 1024);
    const log = boundedJson(logJson, 16384);
    if (!validContext(context) || !validMessage(message) || !validLog(log)) return REFUSAL;
    // Schema validation bounds all traversed parsed fields. Exact canonical
    // round-trip rejects duplicates, escape variants, whitespace and numbers.
    if (JSON.stringify(context) !== contextJson || JSON.stringify(message) !== messageJson ||
      JSON.stringify(log) !== logJson) return REFUSAL;
    const declared = new Set(message.assets);
    const observed = new Set(log.events.map((event) => event.asset));
    if (declared.size !== observed.size || [...observed].some((asset) => !declared.has(asset))) return REFUSAL;

    // Only after complete validation: ephemeral per-call equality map, never
    // returned. No inspected prefix, original or context label leaves either API.
    const refs = new Map(message.assets.map((asset) => [asset, reference(context, asset)]));
    const cloakedJson = JSON.stringify({
      version: 1,
      mode: 'PUBLIC_DRAFT_ONLY',
      message: { version: 1, task: message.task, assets: [...refs.values()] },
      log: { version: 1, events: log.events.map((event) => ({
        asset: refs.get(event.asset), tick: event.tick, level: event.level, code: event.code,
      })) },
    });
    if (cloakedJson.length > 32768) return REFUSAL;
    return Object.freeze({
      status: 'TRANSFORMED', mode: 'PUBLIC_DRAFT_ONLY', cloakedJson,
      references: Object.freeze([...refs.values()]),
    });
  } catch {
    // Fixed non-echoing atomic refusal, including parse/hash/allocation errors.
    // Dropping local strings is not caller/runtime/heap/swap erasure proof.
    return REFUSAL;
  }
}
