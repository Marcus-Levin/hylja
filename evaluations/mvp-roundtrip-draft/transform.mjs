/**
 * PROPOSED / PUBLIC_DRAFT_ONLY / NON-ENFORCING. Pure synthetic schema experiment.
 * No accepted classification, decidePolicy treatment, CREATE, custody, authentication,
 * restoration, storage, file/socket/child/provider IO, randomness or key generation.
 * See docs/specs/mvp-synthetic-roundtrip-draft.md for the complete frozen schema.
 * Primitive ASCII JSON strings only: do not supply real values or arbitrary log text.
 */
import { createHash } from 'node:crypto';

const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'TRANSFORM_REFUSED' });
const ASSET = /^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$/u;
const SCOPE = /^SYNTHETIC-SCOPE-[A-Z0-9]{1,32}$/u;
const SESSION = /^SYNTHETIC-SESSION-[A-Z0-9]{1,32}$/u;
const CONTEXT = /^SYNTHETIC-CONTEXT-[A-Z0-9]{1,32}$/u;
const DOMAIN = 'hylja.public-synthetic-roundtrip-draft.reference.v1';

// All input values are primitives. Bounds run before JSON parsing, with no coercion.
// Printable ASCII makes string length exactly the UTF-8 byte count; escaped/noncanonical
// alternatives are refused later, not decoded into a broader accepted namespace.
function boundedJson(text, max) {
  if (typeof text !== 'string' || text.length < 1 || text.length > max || !/^[\x20-\x7e]+$/u.test(text)) return null;
  return JSON.parse(text);
}

// These records are produced only by JSON.parse, never by caller object reflection.
// Reject unknown/missing members before inspecting any variable field.
function closed(record, members) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) return false;
  const keys = Object.keys(record);
  return keys.length === members.length && members.every((member) => Object.hasOwn(record, member));
}

function validContext(value) {
  return closed(value, ['version', 'scope', 'session', 'context']) && value.version === 1 &&
    typeof value.scope === 'string' && SCOPE.test(value.scope) &&
    typeof value.session === 'string' && SESSION.test(value.session) &&
    typeof value.context === 'string' && CONTEXT.test(value.context);
}

function validAsset(value) {
  return typeof value === 'string' && ASSET.test(value);
}

function validMessage(value) {
  return closed(value, ['version', 'task', 'asset']) && value.version === 1 &&
    value.task === 'SUMMARIZE_FAILURES' && validAsset(value.asset);
}

function validLog(value) {
  if (!closed(value, ['version', 'events']) || value.version !== 1 || !Array.isArray(value.events) ||
    value.events.length < 1 || value.events.length > 128) return false;
  return value.events.every((event) => closed(event, ['asset', 'tick', 'level', 'code']) &&
    validAsset(event.asset) && Number.isSafeInteger(event.tick) && event.tick >= 0 && event.tick <= 1000000 &&
    (event.level === 'INFO' || event.level === 'ERROR') &&
    (event.code === 'START' || event.code === 'STOP' || event.code === 'FAILURE'));
}

/**
 * Unkeyed digest over public fixture values ONLY; not a credential, anonymization,
 * private reference primitive or proof of unlinkability. Context label freshness is
 * a fixture-caller obligation. Array framing/domain/version bind every component.
 * No scope/asset lookup or restoration function is exported.
 */
function reference(context, asset) {
  return 'DRAFT-REF-' + createHash('sha256').update(JSON.stringify([
    DOMAIN, context.scope, context.session, context.context, asset,
  ]), 'utf8').digest('hex');
}

/**
 * transformDraft(contextJson, messageJson, logJson)
 * Success contains one complete cloaked JSON image and unique opaque references;
 * refusal contains only one fixed code. No original mapping or partial output escapes.
 */
export function transformDraft(contextJson, messageJson, logJson) {
  try {
    const context = boundedJson(contextJson, 512);
    const message = boundedJson(messageJson, 512);
    const log = boundedJson(logJson, 16384);
    if (!validContext(context) || !validMessage(message) || !validLog(log)) return REFUSAL;
    // Validate the complete schema first: stringify traverses only the small known
    // records now. Exact compact round-trip rejects duplicates, whitespace, escape
    // variants, negative zero and noncanonical numbers. Key order may vary at input.
    if (JSON.stringify(context) !== contextJson || JSON.stringify(message) !== messageJson ||
      JSON.stringify(log) !== logJson) return REFUSAL;

    // Mapping is ephemeral, local to this call, and never returned or retained.
    const refs = new Map();
    const tokenFor = (asset) => {
      if (!refs.has(asset)) refs.set(asset, reference(context, asset));
      return refs.get(asset);
    };
    const cloakedMessage = { version: 1, task: message.task, asset: tokenFor(message.asset) };
    const cloakedLog = { version: 1, events: log.events.map((event) => ({
      asset: tokenFor(event.asset), tick: event.tick, level: event.level, code: event.code,
    })) };
    const cloakedJson = JSON.stringify({ version: 1, mode: 'PUBLIC_DRAFT_ONLY', message: cloakedMessage, log: cloakedLog });
    if (cloakedJson.length > 32768) return REFUSAL;
    return Object.freeze({ status: 'TRANSFORMED', cloakedJson, references: Object.freeze([...refs.values()]) });
  } catch {
    // Parse/hash/allocation failures never echo a source or exception, and do not
    // return a previously transformed prefix. Runtime string/heap erasure unclaimed.
    return REFUSAL;
  }
}
