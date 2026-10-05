/**
 * Narrow, fixture-only observation of the REAL fixed sentinel worker children (#250).
 *
 * Why this exists. The accepted receiver ([openai-keep-receiver.ts](../../src/openai-keep-receiver.ts))
 * deliberately collapses EVERY non-`ALLOW` worker outcome into one fixed `SENTINEL_BLOCKED` refusal: a
 * genuine block over a registered original, a crashed child, a malformed reply and a missing reply are
 * indistinguishable from the outside. That runtime contract is correct and nothing here changes it. It
 * does mean an operator demonstration cannot tell "the real worker really blocked this reply" from "the
 * real worker died", so this module observes the children themselves and records what really happened,
 * as counts and booleans only.
 *
 * What it does. It captures the native `spawn` BEFORE the module graph that binds it is linked, forwards
 * every call to it with its own arguments, and returns the ACTUAL `ChildProcess` the native call
 * produced: untouched, unwrapped, unproxied, with the same streams and the same stdio. The observation is
 * purely additive - the only thing added to the real process is this module's own read-only listeners
 * on that child's own `stdout` and `close` events, and the real runner keeps receiving all of them.
 *
 * What it records. Per worker child, in spawn order: that it reported `close`, whether it exited with
 * code zero, whether a signal closed it, whether its whole stdout was exactly one complete RESPONSE
 * decision frame of the fixed protocol, the fixed decision enum inside that frame, and whether the
 * frame carried the known-original reason code and named the ref THIS fixture registered. Nothing else
 * is read: no payload byte, no original, no key, no reason text and no rule text is retained, decoded
 * into a string, logged or printed. Reason and rule fields are compared against this parent's own fixed
 * literals and then dropped, and the accumulated reply bytes are dropped at `close`. A child that prints
 * anything this reader cannot parse is recorded as "not one complete decision frame", never as a
 * decision, and an exit code of zero alone admits nothing.
 *
 * What it is NOT. It is not an enforcement boundary, a second worker, a control or a policy authority.
 * It sends no byte, decides nothing, changes no result and can release nothing: it observes the real
 * children the real runner spawns, over obviously synthetic, non-routable fixtures. The fault hook at
 * the bottom is TEST/DEMO-ONLY and is reachable from fixture code only; the operator command has no
 * argument, environment variable or file that can arm it.
 */
import { createRequire } from 'node:module';

/**
 * The native module object, obtained WITHOUT importing `node:child_process` as an ES module. ESM links a
 * module graph before any body in it runs, and a builtin named import is a VALUE SNAPSHOT taken when the
 * facade is created at that link step, so patching this object only reaches a `spawn` binding that has not
 * been linked yet. An entry point therefore calls `installWorkerObservation()` first and imports the
 * accepted runtime AFTER it: `scripts/synthetic-conversation-demo.mjs` and the test-only fault driver do
 * exactly that, and the case module refuses to load when the capture was not installed in time.
 */
const nativeModule = createRequire(import.meta.url)('node:child_process');
const NATIVE_SPAWN = nativeModule.spawn;
if (typeof NATIVE_SPAWN !== 'function') throw new Error('the native child-process spawn is unavailable');
let installed = false;

/* ---------- The fixed RESPONSE frame, read only as far as the decision ---------- */

const encoder = new TextEncoder();
/** The fixed worker this repository ships next to the runner. No other child is observed. */
const WORKER_SUFFIX = 'egress-sentinel-process-worker.js';
const MAGIC = Uint8Array.from([0x48, 0x53, 0x50, 0x50]); // "HSPP"
const KIND_RESPONSE = 0x02;
const NEWLINE = 0x0a;
const HEADER_BYTES = 9;
const FIELD_HEADER_BYTES = 5;
const DECISION_ALLOW = 0x01;
const DECISION_BLOCK = 0x02;
/** The protocol's own reply bounds, restated so an oversize reply is never accumulated. */
const MAX_REPLY_BYTES = 1 << 20;
const MAX_REASONS = 32;
const MAX_LABEL_BYTES = 256;
/** The fixed sentinel reason code for a match against a registered original, compared as bytes. */
const KNOWN_ORIGINAL_REASON = encoder.encode('KNOWN_ORIGINAL_DETECTED');
/** Response tags in their fixed wire order: eight echoed bindings, then decision, then count. */
const BINDING_TAGS = Object.freeze([30, 31, 32, 33, 34, 35, 36, 37]);
const TAG_DECISION = 38;
const TAG_REASON_COUNT = 39;
const TAG_REASON = 40;
const TAG_RULE = 50;

const DONE = Object.freeze({ kind: 'done' });
const BAD = Object.freeze({ kind: 'bad' });

function sameBytes(bytes, expected) {
  if (bytes.byteLength !== expected.byteLength) return false;
  for (let index = 0; index < expected.byteLength; index += 1) {
    if (bytes[index] !== expected[index]) return false;
  }
  return true;
}

/**
 * Read one whole RESPONSE frame. Magic, kind, the declared body length, the trailing newline and the
 * exact field order must all hold, so truncation, a second reply, an unknown field and a reordered
 * field are all "not one complete decision frame" rather than a decision. Label fields are SKIPPED, the
 * decision is read as a single fixed byte, and each reason and rule is compared against this parent's
 * own literal and then forgotten: no field text becomes a string or leaves this function.
 */
function readResponse(bytes) {
  const seen = { complete: false, decision: 'NONE', knownOriginalReason: false, registeredRefNamed: false };
  if (bytes.byteLength <= HEADER_BYTES || bytes.byteLength > MAX_REPLY_BYTES) return seen;
  for (let index = 0; index < MAGIC.byteLength; index += 1) if (bytes[index] !== MAGIC[index]) return seen;
  if (bytes[4] !== KIND_RESPONSE) return seen;
  const whole = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (whole.getUint32(5, false) + HEADER_BYTES + 1 !== bytes.byteLength) return seen;
  if (bytes[bytes.byteLength - 1] !== NEWLINE) return seen;
  const body = bytes.subarray(HEADER_BYTES, bytes.byteLength - 1);
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let at = 0;
  const step = () => {
    if (at === body.byteLength) return DONE;
    if (body.byteLength - at < FIELD_HEADER_BYTES) return BAD;
    const tag = body[at];
    const length = view.getUint32(at + 1, false);
    if (body.byteLength - at - FIELD_HEADER_BYTES < length) return BAD;
    const start = at + FIELD_HEADER_BYTES;
    at = start + length;
    return { tag, bytes: body.subarray(start, at) };
  };
  const field = (tag) => {
    const stepped = step();
    if (stepped === DONE || stepped === BAD || stepped.tag !== tag) return null;
    return stepped.bytes;
  };
  for (const tag of BINDING_TAGS) if (field(tag) === null) return seen;
  const decision = field(TAG_DECISION);
  if (decision === null || decision.byteLength !== 1) return seen;
  const code = decision[0];
  if (code !== DECISION_ALLOW && code !== DECISION_BLOCK) return seen;
  const count = field(TAG_REASON_COUNT);
  if (count === null || count.byteLength !== 4) return seen;
  const reasons = new DataView(count.buffer, count.byteOffset, count.byteLength).getUint32(0, false);
  if (reasons > MAX_REASONS) return seen;
  for (let index = 0; index < reasons; index += 1) {
    const reason = field(TAG_REASON);
    if (reason === null || reason.byteLength === 0 || reason.byteLength > MAX_LABEL_BYTES) return seen;
    if (sameBytes(reason, KNOWN_ORIGINAL_REASON)) seen.knownOriginalReason = true;
  }
  let rules = 0;
  let everyRuleNamed = registeredRef !== null;
  for (;;) {
    const stepped = step();
    if (stepped === DONE) break;
    if (stepped === BAD || stepped.tag !== TAG_RULE) return seen;
    const rule = stepped.bytes;
    if (rule.byteLength === 0 || rule.byteLength > MAX_LABEL_BYTES) return seen;
    rules += 1;
    if (registeredRef === null || !sameBytes(rule, registeredRef)) everyRuleNamed = false;
  }
  // The protocol's own consistency rule, re-checked here: an ALLOW carries no reason and no ref, and a
  // BLOCK carries at least one of them. Anything else is not a coherent decision frame.
  if ((code === DECISION_ALLOW) !== (reasons === 0 && rules === 0)) return seen;
  seen.complete = true;
  seen.decision = code === DECISION_ALLOW ? 'ALLOW' : 'BLOCK';
  seen.registeredRefNamed = everyRuleNamed && rules > 0;
  return seen;
}

/* ---------- The private observation state ---------- */

/** One record per observed fixed worker child, in spawn order. Nothing here is caller reachable. */
const records = [];
/** The privacy-safe ref this fixture registered, so a child naming a rule can be compared to it. */
let registeredRef = null;
/** An armed TEST-ONLY termination, or `null`. Never set by the operator command. */
let injected = null;

export const MAX_FAULT_ORDINAL = 8;

/**
 * Declare the privacy-safe ref THIS fixture registered, so that a `BLOCK` frame naming a rule can be
 * compared against the parent's own registration without the child's text being retained or printed.
 * Declaring it after a child has already been observed only affects later children.
 */
export function noteRegisteredOriginal(ref) {
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 128) throw new TypeError('registered original ref');
  registeredRef = encoder.encode(ref);
}

/**
 * TEST/DEMO-ONLY fault: terminate the `ordinal`-th fixed worker child this process spawns, immediately
 * after the native spawn returns and before it can finish, so the real runner observes a real crash and
 * the receiver's real collapse into `SENTINEL_BLOCKED` is what the demonstration has to survive. Fixture
 * code calls this; no operator argument, environment variable or file can reach it. Re-arming the same
 * ordinal is a no-op, and an ordinal outside `1..MAX_FAULT_ORDINAL` is refused.
 */
export function injectWorkerTermination(ordinal) {
  if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > MAX_FAULT_ORDINAL) {
    throw new TypeError('worker termination ordinal');
  }
  if (injected !== null && injected.ordinal === ordinal) return;
  injected = { ordinal };
}

/** One worker's private record. */
function observe(args, child) {
  const record = {
    closed: false, exitedZero: false, closedBySignal: false,
    complete: false, decision: 'NONE', knownOriginalReason: false, registeredRefNamed: false,
  };
  records.push(record);
  const chunks = [];
  let captured = 0;
  let textual = false;
  const stdout = child === null ? null : child.stdout;
  if (stdout !== null && stdout !== undefined) {
    stdout.on('data', (chunk) => {
      if (!(chunk instanceof Uint8Array)) { textual = true; chunks.length = 0; return; }
      captured += chunk.byteLength;
      if (captured > MAX_REPLY_BYTES) { chunks.length = 0; captured = MAX_REPLY_BYTES + 1; return; }
      chunks.push(chunk);
    });
  }
  child.on('close', (code, signal) => {
    record.closed = true;
    record.exitedZero = code === 0;
    record.closedBySignal = typeof signal === 'string';
    if (!textual && captured > 0 && captured <= MAX_REPLY_BYTES) {
      const joined = new Uint8Array(captured);
      let at = 0;
      for (const chunk of chunks) { joined.set(chunk, at); at += chunk.byteLength; }
      const seen = readResponse(joined);
      record.complete = seen.complete;
      record.decision = seen.decision;
      record.knownOriginalReason = seen.knownOriginalReason;
      record.registeredRefNamed = seen.registeredRefNamed;
    }
    // The reply bytes existed only to read the fixed decision out of them. Nothing is retained.
    chunks.length = 0;
  });
  if (injected !== null && records.length === injected.ordinal) {
    // The actual child is still forwarded untouched; the fixture only asks the OS to stop it.
    try { child.kill('SIGKILL'); } catch { /* already gone: the runner observes the real close */ }
  }
  return record;
}

/**
 * Only the fixed compiled worker of this repository is observed, and only in the one argument shape the
 * accepted runner uses: the node executable plus exactly one worker module. Any other spawn is forwarded
 * untouched and observed by nothing.
 */
const isFixedWorker = (args) => Array.isArray(args) && args.length === 3 && Array.isArray(args[1]) &&
  args[1].length === 1 && typeof args[1][0] === 'string' && args[1][0].endsWith(WORKER_SUFFIX);

/**
 * Install the one capture, and only once. Every call still goes to the native spawn with its own
 * arguments and the caller's own receiver, and the actual `ChildProcess` it returns is handed back as it
 * is: the fixed worker keeps its own streams, its own stdio and its own lifecycle, and nothing below can
 * change a result. Calling this again is a no-op, so an entry point may install defensively.
 */
export function installWorkerObservation() {
  if (installed) return;
  installed = true;
  nativeModule.spawn = function observedSpawn(...args) {
    const child = Reflect.apply(NATIVE_SPAWN, this, args);
    if (isFixedWorker(args) && child !== null && typeof child === 'object' && 'on' in child) observe(args, child);
    return child;
  };
}

/** Whether the capture is in place. The case module checks this at import, so a wrong order fails loudly. */
export const workerObservationInstalled = () => installed;

/**
 * What the real children did, as fixed counters. Read after cleanup; a second read of the same run
 * reports the same numbers, because every child has already reported `close` by then.
 */
export function workerObservation() {
  let exitedZero = 0;
  let closedBySignal = 0;
  let reportedClose = 0;
  let complete = 0;
  let allow = 0;
  let block = 0;
  let named = 0;
  for (const record of records) {
    if (record.closed) reportedClose += 1;
    if (record.exitedZero) exitedZero += 1;
    if (record.closedBySignal) closedBySignal += 1;
    if (!record.complete) continue;
    complete += 1;
    if (record.decision === 'ALLOW') allow += 1;
    if (record.decision === 'BLOCK') {
      block += 1;
      if (record.knownOriginalReason && record.registeredRefNamed) named += 1;
    }
  }
  return Object.freeze({
    spawned: records.length,
    exitedZero,
    closedBySignal,
    neverReportedClose: records.length - reportedClose,
    completeFrames: complete,
    allow,
    block,
    namedKnownOriginal: named,
  });
}