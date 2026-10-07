/**
 * PROPOSED / PUBLIC_DRAFT_ONLY / NON-ENFORCING. Public synthetic integration only.
 * Fixed regular-file reader and actual ASCII byte boundary to an in-process
 * deterministic responder, NOT a provider/model, protected-egress/auth boundary,
 * accepted CREATE/DISPLAY, custody, policy, private-data or secure-erasure service.
 */
import { constants, openSync, fstatSync, readSync, closeSync } from 'node:fs';
import { transformDraft } from './transform.mjs';
import { createDraftOwner } from './owner.mjs';

const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'INTEGRATION_REFUSED' });
const ASSET = 'SYNTHETIC-ASSET-A1';
const CONTEXT = Object.freeze({ version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' });
const MESSAGE = JSON.stringify({ version: 1, task: 'SUMMARIZE_FAILURES', asset: ASSET });
const CONFIG = JSON.stringify({ version: 1, purpose: 'SYNTHETIC-LOG-SUMMARY', operation: 'DISPLAY', destination: 'SYNTHETIC-DISPLAY-A', adminDestination: 'SYNTHETIC-ADMIN-A', createdAt: 10, expiresAt: 100, revision: 1 });
const REQUEST = Object.freeze({ ...CONTEXT, purpose: 'SYNTHETIC-LOG-SUMMARY', operation: 'DISPLAY', destination: 'SYNTHETIC-DISPLAY-A', revision: 1 });
const ADMIN = JSON.stringify({ ...CONTEXT, administrativePurpose: 'SYNTHETIC-OWNER-LIFECYCLE', operation: 'REVOKE', destination: 'SYNTHETIC-ADMIN-A', revision: 1 });
const REFERENCE = /^DRAFT-REF-[a-f0-9]{64}$/u;
const SCENARIOS = new Set(['VALID', 'WRONG_PURPOSE', 'WRONG_DESTINATION', 'USE', 'EXPORT', 'FOREIGN_SCOPE', 'FOREIGN_SESSION', 'FOREIGN_CONTEXT', 'STALE_REVISION', 'EXPIRED', 'REVOKED', 'ROLLBACK', 'FOREIGN_REFERENCE', 'UNKNOWN_REFERENCE', 'MALFORMED_RESPONSE', 'COUNT_DISAGREEMENT', 'SUMMARY_DISAGREEMENT', 'AUTHORITY_SMUGGLING', 'OVERSIZE_RESPONSE', 'DUPLICATE_RESPONSE', 'ESCAPED_RESPONSE', 'NON_ASCII_RESPONSE', 'WRONG_RESPONSE_TYPE', 'NEGATIVE_COUNT', 'OVER_COUNT', 'TRAILING_RESPONSE', 'MALFORMED_REFERENCE']);
const admittedScenario = (value) => typeof value === 'string' && value.length <= 32 && SCENARIOS.has(value);

function closed(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function asciiBytes(text, max) {
  if (typeof text !== 'string' || text.length < 1 || text.length > max || !/^[\x20-\x7e]+$/u.test(text)) return null;
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i);
  return bytes;
}
// Internal owned numeric byte arrays only; no caller object/byte-buffer interface.
function asciiText(bytes, max) {
  if (bytes.length < 1 || bytes.length > max) return null;
  let text = '';
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 32 || byte > 126) return null;
    text += String.fromCharCode(byte);
  }
  return text;
}
function parse(text, max, keys) {
  if (typeof text !== 'string' || text.length < 1 || text.length > max || !/^[\x20-\x7e]+$/u.test(text)) return null;
  const value = JSON.parse(text);
  return closed(value, keys) && JSON.stringify(value) === text ? value : null;
}

// Fixed URL only, numeric POSIX flags required. No unbounded readFileSync allocation.
// Trusted stable local directory/file required. Flags do NOT prove ancestor/mount
// confinement, hard-link exclusion, finite native blocking or concurrent-file atomicity.
function readFixedAttachment() {
  let fd = null;
  let text = null;
  const bytes = new Uint8Array(16385); // cap + one overflow byte, never resized
  try {
    if (![constants.O_RDONLY, constants.O_NOFOLLOW, constants.O_NONBLOCK].every((flag) => Number.isInteger(flag) && flag >= 0)) return null;
    fd = openSync(new URL('./fixed-synthetic-log.json', import.meta.url), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stats = fstatSync(fd);
    if (!stats.isFile() || !Number.isSafeInteger(stats.size) || stats.size < 1 || stats.size > 16384) return null;
    let used = 0;
    let eof = false;
    // Positive progress limits calls to at most 16385; zero is EOF, not retry.
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (!Number.isInteger(count) || count < 0 || count > bytes.length - used) return null;
      if (count === 0) { eof = true; break; }
      used += count;
    }
    if (!eof || used > 16384 || used !== stats.size) return null;
    text = asciiText(bytes.subarray(0, used), 16384);
  } catch {
    text = null; // Never expose exception/path/raw diagnostics.
  } finally {
    if (fd !== null) {
      try { closeSync(fd); } catch { text = null; }
    }
    bytes.fill(0); // Owned byte array only; runtime/string/caller erasure unclaimed.
  }
  return text;
}

function inspectedCloak(text) {
  const image = parse(text, 32768, ['version', 'mode', 'message', 'log']);
  if (image === null || image.version !== 1 || image.mode !== 'PUBLIC_DRAFT_ONLY' ||
    !closed(image.message, ['version', 'task', 'asset']) || image.message.version !== 1 ||
    image.message.task !== 'SUMMARIZE_FAILURES' || typeof image.message.asset !== 'string' || !REFERENCE.test(image.message.asset) ||
    !closed(image.log, ['version', 'events']) || image.log.version !== 1 || !Array.isArray(image.log.events) ||
    image.log.events.length < 1 || image.log.events.length > 128) return null;
  if (!image.log.events.every((entry) => closed(entry, ['asset', 'tick', 'level', 'code']) && entry.asset === image.message.asset &&
    Number.isSafeInteger(entry.tick) && entry.tick >= 0 && entry.tick <= 1000000 &&
    (entry.level === 'INFO' || entry.level === 'ERROR') && ['START', 'STOP', 'FAILURE'].includes(entry.code))) return null;
  return image;
}
const errorCount = (image) => image.log.events.filter((entry) => entry.asset === image.message.asset && entry.level === 'ERROR').length;

// Capture at actual consumption, then parse that very snapshot. No callback/native
// transport or reconstructed-object-as-traffic substitute. Literal test scenarios only.
function respond(inputBytes, scenario) {
  const consumedBytes = Object.freeze(Array.from(inputBytes));
  const text = asciiText(consumedBytes, 32768);
  const image = inspectedCloak(text);
  if (image === null) return null;
  const count = errorCount(image);
  const reply = { version: 1, summary: count === 0 ? 'NO_FAILURES' : 'FAILURES_FOUND', reference: image.message.asset, errorCount: count };
  if (scenario === 'FOREIGN_REFERENCE') {
    const foreign = transformDraft(JSON.stringify({ ...CONTEXT, scope: 'SYNTHETIC-SCOPE-B' }), MESSAGE,
      JSON.stringify({ version: 1, events: [{ asset: ASSET, tick: 0, level: 'INFO', code: 'START' }] }));
    if (foreign.status !== 'TRANSFORMED') return null;
    reply.reference = foreign.references[0];
  }
  if (scenario === 'UNKNOWN_REFERENCE') reply.reference = 'DRAFT-REF-' + '0'.repeat(64);
  if (scenario === 'MALFORMED_REFERENCE') reply.reference = 'DRAFT-REF-x';
  if (scenario === 'COUNT_DISAGREEMENT') reply.errorCount = count === 128 ? 127 : count + 1;
  if (scenario === 'SUMMARY_DISAGREEMENT') reply.summary = count === 0 ? 'FAILURES_FOUND' : 'NO_FAILURES';
  if (scenario === 'AUTHORITY_SMUGGLING') reply.purpose = 'SYNTHETIC-LOG-SUMMARY';
  if (scenario === 'WRONG_RESPONSE_TYPE') reply.errorCount = String(count);
  if (scenario === 'NEGATIVE_COUNT') reply.errorCount = -1;
  if (scenario === 'OVER_COUNT') reply.errorCount = 129;
  let returnedText = JSON.stringify(reply);
  if (scenario === 'MALFORMED_RESPONSE') returnedText = '{';
  if (scenario === 'OVERSIZE_RESPONSE') returnedText = 'x'.repeat(1025);
  if (scenario === 'DUPLICATE_RESPONSE') returnedText = returnedText.replace('"version":1', '"version":2,"version":1');
  if (scenario === 'ESCAPED_RESPONSE') returnedText = returnedText.replace('DRAFT', '\\u0044RAFT');
  if (scenario === 'TRAILING_RESPONSE') returnedText += '{}';
  // Fault bytes intentionally come from finite synthetic scenarios, not raw diagnostics.
  const returnedBytes = scenario === 'NON_ASCII_RESPONSE' ? new Uint8Array([255]) : asciiBytes(returnedText, 1025);
  if (returnedBytes === null) return null;
  return { consumedBytes, returnedBytes };
}

function complete(logJson, scenario, attachmentKind) {
  try {
    const attachmentBytes = asciiBytes(logJson, 16384);
    if (attachmentBytes === null) return REFUSAL;
    const transformed = transformDraft(JSON.stringify(CONTEXT), MESSAGE, logJson);
    if (transformed.status !== 'TRANSFORMED' || transformed.references.length !== 1) return REFUSAL;
    const image = inspectedCloak(transformed.cloakedJson);
    if (image === null || transformed.references[0] !== image.message.asset) return REFUSAL;
    // Independent fixed original must be the only admitted value, not merely one
    // of several synthetic markers. S1 has already inspected the complete schema.
    const attachment = JSON.parse(logJson);
    if (!attachment.events.every((entry) => entry.asset === ASSET)) return REFUSAL;
    const outboundBytes = asciiBytes(transformed.cloakedJson, 32768);
    if (outboundBytes === null) return REFUSAL;
    const exchange = respond(outboundBytes, scenario);
    if (exchange === null) return REFUSAL;
    // These are the actual returned bytes, not a reserialization of reply fields.
    const returnedBytes = Object.freeze(Array.from(exchange.returnedBytes));
    const reply = parse(asciiText(returnedBytes, 1024), 1024, ['version', 'summary', 'reference', 'errorCount']);
    const count = errorCount(image);
    if (reply === null || reply.version !== 1 || typeof reply.reference !== 'string' || !REFERENCE.test(reply.reference) ||
      reply.reference !== image.message.asset || !Number.isSafeInteger(reply.errorCount) || reply.errorCount < 0 || reply.errorCount > 128 ||
      reply.errorCount !== count || reply.summary !== (count === 0 ? 'NO_FAILURES' : 'FAILURES_FOUND')) return REFUSAL;
    // Responder supplies NO request authority, clock, config, destination or grant.
    const owned = createDraftOwner(CONFIG, JSON.stringify(CONTEXT), ASSET);
    if (owned.status !== 'OWNED') return REFUSAL;
    const request = { ...REQUEST };
    if (scenario === 'WRONG_PURPOSE') request.purpose = 'OTHER';
    if (scenario === 'WRONG_DESTINATION') request.destination = 'SYNTHETIC-DISPLAY-B';
    if (scenario === 'USE' || scenario === 'EXPORT') request.operation = scenario;
    if (scenario === 'FOREIGN_SCOPE') request.scope = 'SYNTHETIC-SCOPE-B';
    if (scenario === 'FOREIGN_SESSION') request.session = 'SYNTHETIC-SESSION-B';
    if (scenario === 'FOREIGN_CONTEXT') request.context = 'SYNTHETIC-CONTEXT-B';
    if (scenario === 'STALE_REVISION') request.revision = 0;
    if (scenario === 'REVOKED' && owned.owner.revoke(ADMIN, 20).status !== 'REVOKED') return REFUSAL;
    if (scenario === 'ROLLBACK') owned.owner.displayOne('unknown', JSON.stringify(REQUEST), 30);
    const now = scenario === 'EXPIRED' ? 100 : 20;
    const requestJson = JSON.stringify(request);
    const displayed = owned.owner.displayOne(reply.reference, requestJson, now);
    if (displayed.status !== 'DISPLAYED' || displayed.value !== ASSET) return REFUSAL;
    const answer = `Synthetic log summary for ${displayed.value}: ${reply.errorCount} ERROR events.`;
    if (answer.length > 256) return REFUSAL;
    return Object.freeze({ status: 'DISPLAYED', mode: 'PUBLIC_DRAFT_ONLY', answer, errorCount: reply.errorCount,
      trace: Object.freeze({ attachmentKind, attachmentBytes: Object.freeze(Array.from(attachmentBytes)),
        consumedBytes: exchange.consumedBytes, returnedBytes, displayRequestJson: requestJson, displayNow: now }) });
  } catch {
    return REFUSAL;
  }
}

// No arbitrary attachment path/config/clock/response/callback API. Each run creates
// a new public fixture owner: not shared durable lifecycle or accepted CREATE.
export function runFixedDraft(scenario = 'VALID') {
  if (!admittedScenario(scenario)) return REFUSAL;
  const log = readFixedAttachment();
  return log === null ? REFUSAL : complete(log, scenario, 'FIXED_FILE');
}
// Injected primitive-text cases are explicitly NOT physical file-failure evidence.
export function runInjectedDraft(logJson, scenario = 'VALID') {
  if (!admittedScenario(scenario)) return REFUSAL;
  return complete(logJson, scenario, 'INJECTED_TEXT');
}
