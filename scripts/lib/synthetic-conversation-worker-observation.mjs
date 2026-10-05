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
 * produced: untouched, unwrapped, unproxied, with the same streams and the same stdio. On top of that it
 * installs TWO read-only taps, each a pass-through that keeps its own receiver, its own arguments, its
 * own callbacks and its own return value:
 *
 * 1. the outgoing request frame, on the actual `write` and `end` methods of the child's own `stdin`, so
 *    the binding a reply will be checked against comes from the frame the REAL runner really wrote;
 * 2. the incoming reply bytes, on the child's own `stdout` event delivery, so the reply can be validated
 *    instead of partially interpreted.
 *
 * What it validates, and with what. Both directions are decided by the SAME authoritative protocol the
 * accepted runner uses ([egress-sentinel-process-protocol.ts](../../src/egress-sentinel-process-protocol.ts)):
 * `decodeRequestFrame` on the outgoing frame, `projectSentinelReplyBinding` on the decoded request, then
 * `classifyReplyFraming` and `decodeResponseFrame` on the child's whole stdout. This module keeps NO
 * decoder of its own. A child is counted as a complete frame ONLY when the request frame decoded, the
 * binding exists, the framing is exactly one complete response frame and the authoritative decoder
 * accepted it - which is also what decides the known-original reason and whether every reported ref is
 * one this parent's own request frame registered. An unknown reason code, a foreign binding, a ref this
 * parent never registered, more rules than the protocol bounds allow, a truncated, duplicated or trailing
 * reply, a missing binding, a child that did not exit zero, a child that never reported `close` and a
 * child that reported a diagnostic overflow are therefore all "no decision", never a block.
 *
 * Privacy. No payload byte, no key, no original and no child reply text is retained, logged or printed.
 * Reason codes are compared against this parent's own fixed literals and dropped; refs are compared
 * against the label this fixture registered and dropped. The temporary copies the decoder allocates for
 * the payload and the registration key are overwritten with zeroes here and the reference is dropped, and
 * the accumulated reply bytes are dropped at `close`. That is a bounded reference drop and a typed-array
 * overwrite: this module creates no string of a protected value itself, and it claims no string erasure
 * and no heap or RSS erasure - the authoritative decoder materialises registration values as strings
 * inside its own temporary snapshot, which this module then drops.
 *
 * What it is NOT. It is not an enforcement boundary, a second worker, a control or a policy authority.
 * It sends no byte, decides nothing, changes no result and can release nothing: it observes the real
 * children the real runner spawns, over obviously synthetic, non-routable fixtures. The fault hooks at the
 * bottom are TEST/DEMO-ONLY and are reachable from fixture code only; the operator command has no
 * argument, environment variable or file that can arm them.
 */
import { createRequire } from 'node:module';
import {
  EGRESS_SENTINEL_PROCESS_LIMITS, classifyReplyFraming, decodeRequestFrame, decodeResponseFrame,
  encodeResponseFrame, projectSentinelReplyBinding,
} from '../../dist/egress-sentinel-process-protocol.js';

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

/** The fixed worker this repository ships next to the runner. No other child is observed. */
const WORKER_SUFFIX = 'egress-sentinel-process-worker.js';
/** The protocol's own reply bound: an oversize reply is never accumulated in the first place. */
const MAX_REPLY_BYTES = EGRESS_SENTINEL_PROCESS_LIMITS.maxStdoutBytes;
/** The fixed sentinel reason code for a match against a registered original, compared as a string. */
const KNOWN_ORIGINAL_REASON = 'KNOWN_ORIGINAL_DETECTED';

/* ---------- The request binding, taken from the frame the runner really wrote ---------- */

/**
 * Decode one outgoing request frame into the binding a reply is checked against, and drop everything
 * else about it immediately.
 *
 * The frame is the runner's own buffer: it is read here and never written to. `decodeRequestFrame`
 * recomputes the payload digest from the frame bytes rather than trusting any parent-side value, and
 * rejects a frame it cannot rebuild. The projection it returns holds only labels and that digest, so the
 * payload copy and the registration key copy the decoder just allocated are zeroed and dropped with the
 * temporary snapshot. That is a bounded overwrite of this module's own copies; it is not heap erasure.
 */
function bindingFromFrame(record, chunk) {
  if (record.binding !== null || record.frameRefused) return;
  if (!(chunk instanceof Uint8Array)) { record.frameRefused = true; return; }
  const decoded = decodeRequestFrame(chunk);
  if (!decoded.ok) { record.frameRefused = true; return; }
  record.binding = projectSentinelReplyBinding(decoded.value);
  decoded.value.payload.fill(0);
  decoded.value.known?.key.fill(0);
}

/**
 * Pass-through taps on the child's OWN `stdin.write` and `stdin.end`, which are the two methods the
 * accepted runner actually calls with its request frame. Each tap forwards the call unchanged - same
 * receiver, same argument list including any callback, same return value - and reads the byte argument
 * only when there is one, because `end()` is called here with no data at all.
 */
function tapOutgoingRequest(child, record) {
  const stdin = child.stdin;
  if (stdin === null || stdin === undefined) return;
  const nativeWrite = stdin.write;
  const nativeEnd = stdin.end;
  if (typeof nativeWrite !== 'function' || typeof nativeEnd !== 'function') return;
  stdin.write = function observedWrite(...args) {
    if (args.length > 0) bindingFromFrame(record, args[0]);
    return Reflect.apply(nativeWrite, this, args);
  };
  stdin.end = function observedEnd(...args) {
    if (args.length > 0) bindingFromFrame(record, args[0]);
    return Reflect.apply(nativeEnd, this, args);
  };
}

/* ---------- The reply, decided by the authoritative protocol decoder ---------- */

/**
 * Record one child's whole stdout, or nothing. The binding must exist, the bytes must be exactly one
 * complete RESPONSE frame, and the authoritative decoder must accept it against that binding; anything
 * else leaves `complete` false, so a malformed, foreign, oversized or duplicated reply is never counted
 * as a decision. The decoded reason codes and refs are compared to this parent's own literals here and
 * are not stored.
 */
function recordReply(record, bytes) {
  if (record.binding === null) return;
  const framing = classifyReplyFraming(bytes);
  if (framing !== 'OK') return;
  const decoded = decodeResponseFrame(bytes, record.binding);
  if (!decoded.ok) return;
  record.complete = true;
  record.decision = decoded.value.decision;
  record.knownOriginalReason = decoded.value.reasonCodes.includes(KNOWN_ORIGINAL_REASON);
  // The decoder already restricted every reported ref to the refs this parent's own request frame
  // registered, so this only decides whether they are the fixture's declared known-original label.
  record.registeredRefNamed = decoded.value.rules.length > 0
    && declaredRef !== null
    && decoded.value.rules.every((rule) => rule === declaredRef);
}

/* ---------- TEST/DEMO-ONLY faults, reachable from fixture code only ---------- */

/** The fixed reply faults a fixture may inject, each a real refusal the real runner must reach. */
export const REPLY_FAULTS = Object.freeze({
  UNKNOWN_REASON: 'unknown-reason',
  FOREIGN_BINDING: 'foreign-binding',
  TOO_MANY_RULES: 'too-many-rules',
});
const KNOWN_FAULTS = new Set(Object.values(REPLY_FAULTS));

/**
 * Build the frame this fixture substitutes for one child's real reply. It is built from the request
 * binding that child really received, through the protocol's own encoder, so it is a well-formed frame
 * that differs from the truth in exactly one documented way. This is deliberately NOT a decode of the
 * child's own reply: the fault is "this child answered differently", and the whole point is that the
 * runner has to reject it.
 */
function corruptedReply(record) {
  const binding = record.binding;
  if (binding === null || declaredRef === null) return null;
  const echoed = {
    requestId: binding.requestId,
    tenantRef: binding.scope.tenantRef,
    projectRef: binding.scope.projectRef,
    observedId: binding.observed.id,
    observedProfileDigest: binding.observed.profileDigest,
    authorizedId: binding.authorized.id,
    authorizedProfileDigest: binding.authorized.profileDigest,
    payloadDigest: binding.payloadDigest,
  };
  if (record.fault === REPLY_FAULTS.FOREIGN_BINDING) {
    // A digest this parent never computed for this payload: a binding mismatch, not a decision.
    return encodeResponseFrame({
      ...echoed,
      payloadDigest: 'f'.repeat(64),
      response: { decision: 'BLOCK', reasonCodes: [KNOWN_ORIGINAL_REASON], rules: [declaredRef] },
    });
  }
  if (record.fault === REPLY_FAULTS.UNKNOWN_REASON) {
    // The genuine known-original block plus one reason code this sentinel version cannot produce.
    return encodeResponseFrame({
      ...echoed,
      response: {
        decision: 'BLOCK',
        reasonCodes: [KNOWN_ORIGINAL_REASON, 'FIXTURE_REASON_THIS_SENTINEL_CANNOT_PRODUCE'],
        rules: [declaredRef],
      },
    });
  }
  // One ref over the protocol's own rule bound, every one of them a ref this parent registered.
  return encodeResponseFrame({
    ...echoed,
    response: {
      decision: 'BLOCK',
      reasonCodes: [KNOWN_ORIGINAL_REASON],
      rules: Array.from(
        { length: EGRESS_SENTINEL_PROCESS_LIMITS.maxRules + 1 },
        () => declaredRef,
      ),
    },
  });
}

/**
 * Substitute the faulted frame for the FIRST reply this child writes, through the child's own `stdout`
 * delivery, so the real runner receives a real `data` event carrying it. Every other event and every
 * later chunk of this child is forwarded untouched.
 */
function tapOutgoingReplyFault(record) {
  const stdout = record.stdout;
  if (record.fault === null || stdout === null || stdout === undefined) return;
  const nativeEmit = stdout.emit;
  if (typeof nativeEmit !== 'function') return;
  let substituted = false;
  stdout.emit = function observedEmit(event, ...args) {
    if (!substituted && event === 'data' && args.length === 1 && args[0] instanceof Uint8Array) {
      const corrupted = corruptedReply(record);
      if (corrupted !== null) {
        substituted = true;
        return Reflect.apply(nativeEmit, this, ['data', corrupted]);
      }
    }
    return Reflect.apply(nativeEmit, this, [event, ...args]);
  };
}

/* ---------- The private observation state ---------- */

/** One record per observed fixed worker child, in spawn order. Nothing here is caller reachable. */
const records = [];
/** The privacy-safe ref this fixture registered, so a child naming a rule can be compared to it. */
let declaredRef = null;
/** An armed TEST-ONLY termination or reply fault, or `null`. Never set by the operator command. */
let injected = null;

export const MAX_FAULT_ORDINAL = 8;

/**
 * Declare the privacy-safe ref THIS fixture registered, so that a `BLOCK` frame naming a rule can be
 * compared against the parent's own registration without the child's text being retained or printed.
 * Declaring it after a child has already been observed only affects later children.
 */
export function noteRegisteredOriginal(ref) {
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 128) throw new TypeError('registered original ref');
  declaredRef = ref;
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
  injected = { ordinal, fault: null };
}

/**
 * TEST/DEMO-ONLY fault: the `ordinal`-th fixed worker child answers with a frame that differs from the
 * truth in one documented way, so the real runner's real refusal and the receiver's real collapse into
 * `SENTINEL_BLOCKED` are what the demonstration has to survive. The child's own reply is replaced; the
 * child itself, the runner and the receiver are untouched. Reachable from fixture code only.
 */
export function injectReplyFrameFault(ordinal, fault) {
  if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > MAX_FAULT_ORDINAL) {
    throw new TypeError('reply fault ordinal');
  }
  if (!KNOWN_FAULTS.has(fault)) throw new TypeError('reply fault kind');
  if (injected !== null && injected.ordinal === ordinal && injected.fault === fault) return;
  injected = { ordinal, fault };
}

/** One worker's private record. */
function observe(args, child) {
  const record = {
    closed: false, exitedZero: false, closedBySignal: false,
    complete: false, decision: 'NONE', knownOriginalReason: false, registeredRefNamed: false,
    binding: null, frameRefused: false,
    // A fault belongs to ONE ordinal: the request-side child is never faulted, so it still really runs
    // and really answers, which is what makes a faulted run comparable to a working one.
    fault: injected !== null && records.length + 1 === injected.ordinal ? injected.fault : null,
    stdout: child === null ? null : child.stdout,
  };
  records.push(record);
  tapOutgoingRequest(child, record);
  const chunks = [];
  let captured = 0;
  let textual = false;
  if (record.stdout !== null && record.stdout !== undefined) {
    record.stdout.on('data', (chunk) => {
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
      recordReply(record, joined);
    }
    // The reply bytes and the binding existed only to decide one boolean. Nothing is retained.
    chunks.length = 0;
    record.binding = null;
    record.stdout = null;
  });
  tapOutgoingReplyFault(record);
  if (injected !== null && record.fault === null && records.length === injected.ordinal) {
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
