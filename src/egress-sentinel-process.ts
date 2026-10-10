/**
 * Optional one-check local child-process wrapper around `checkEgress` (#147). Local lifecycle isolation
 * only: it lets a caller withhold release, stay responsive while a check runs and terminate a stalled
 * check, because `checkEgress` and its zlib work are synchronous and a same-thread promise or timer
 * cannot interrupt them. It is NOT a model gateway, an authenticated effect boundary, an OS sandbox, a
 * memory or RSS cap, or a policy decision. It never sends a byte and it never decides to release: an
 * `ALLOW` here is the sentinel's own result plus a private copy of the bytes the parent snapshotted.
 * Normative expansion: docs/contracts/egress-sentinel-process.md - the contract owns the normative order, codes and
 * limits; this header is the working summary.
 *
 * The premise of this design is narrow on purpose. Cancellation is runner-owned (`runner.cancel()`),
 * never a caller-supplied `AbortSignal`, option bag, callback or worker hook: the accepted request
 * shape is exactly five keys and an unknown one is refused before a process exists, without invoking
 * its value. Nothing here walks Node-private symbols, WeakMap internals or caller listener closures.
 *
 * Lifecycle rules that make the bound real:
 *
 * - The absolute deadline starts at spawn and is never reset by output. Trickled output cannot buy time.
 * - The first observed stop wins. A cancel, deadline, crash or framing failure that arrives first is the
 *   outcome; no later reply overrides it, and an `ALLOW` is returned only after a complete, correctly
 *   bound frame AND an actual observed zero exit.
 * - `SIGKILL` is not termination. The runner reports `CLEANUP_UNCONFIRMED` and quarantines itself when
 *   the child's `close` event does not arrive within the grace window, because an untracked child is a
 *   child this runner can no longer stop.
 * - Nothing from the child reaches an ordinary result. stdout is parsed into fixed codes, stderr is
 *   counted and dropped, and both are discarded with the closure. The release bytes are a fresh private
 *   copy of the parent's own snapshot, never a buffer the caller or the worker can still mutate.
 *
 * One runner owns at most one active child: there is no pool, no retry, no restart, no fallback to an
 * in-thread check, and no configurable worker path. The worker is this module's fixed sibling.
 */
import { spawn } from 'node:child_process';
import { clearTimeout, setTimeout } from 'node:timers';
import type { WorkerTimer } from 'node:timers';
import { fileURLToPath } from 'node:url';
import {
  EGRESS_SENTINEL_PROCESS_LIMITS,
  classifyReplyFraming,
  decodeResponseFrame,
  encodeRequestFrame,
  newSentinelRequestId,
  snapshotSentinelRequest,
} from './egress-sentinel-process-protocol.js';
import type { SentinelReplyFailure, SentinelProcessSnapshot } from './egress-sentinel-process-protocol.js';

/** The fixed compiled worker, resolved next to this module. There is no runtime-selectable worker. */
export const EGRESS_SENTINEL_PROCESS_WORKER =
  fileURLToPath(new URL('./egress-sentinel-process-worker.js', import.meta.url));

/**
 * The whole environment is replaced, so nothing is inherited: no proxy settings, no `NODE_OPTIONS`, no
 * locale surprise and no credential-bearing variable ever reaches the child. Each spawn gets its own
 * mutable private copy: the stdlib spawn writes into the object it is handed (`NODE_V8_COVERAGE` under
 * `--experimental-test-coverage`), so a frozen object would throw before any child exists.
 */
const WORKER_ENV: Readonly<Record<string, string>> = Object.freeze({
  PATH: '/usr/bin:/bin',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NODE_NO_WARNINGS: '1',
});

export type SentinelProcessState = 'IDLE' | 'BUSY' | 'QUARANTINED';

export type SentinelProcessBlockCode =
  | SentinelReplyFailure
  | 'INVALID_REQUEST'
  | 'RUNNER_BUSY'
  | 'RUNNER_QUARANTINED'
  | 'CANCELLED'
  | 'DEADLINE_EXCEEDED'
  | 'SPAWN_FAILED'
  | 'CHILD_CRASHED'
  | 'REPLY_MISSING'
  | 'DIAGNOSTIC_OVERFLOW'
  | 'CLEANUP_UNCONFIRMED'
  | 'SENTINEL_BLOCK';

export type SentinelProcessOutcome =
  | Readonly<{ status: 'ALLOW'; release: Uint8Array }>
  | Readonly<{
    status: 'BLOCK';
    code: SentinelProcessBlockCode;
    /** Fixed sentinel reason codes on `SENTINEL_BLOCK`; empty for every transport failure. */
    reasonCodes: readonly string[];
    /** Refs this runner itself registered; empty for every transport failure. */
    rules: readonly string[];
  }>;

export interface SentinelProcessScope { readonly tenantRef: string; readonly projectRef: string }
export interface SentinelProcessDestination { readonly id: string; readonly profileDigest: string }
export interface SentinelProcessKnownEntry {
  readonly kind: 'ORIGINAL' | 'CANARY';
  /** Privacy-safe label chosen by this caller. It is the only label a child may report back. */
  readonly ref: string;
  readonly value: string;
}
/**
 * The ONLY accepted way to protect known originals. It carries its own scope, which must equal the
 * check scope, and a dedicated key of at least 32 bytes. A process-local `KnownOriginalsHandle` is not
 * accepted here: it cannot cross a process boundary and encoding it would silently weaken the check.
 */
export interface SentinelProcessKnownRegistration {
  readonly scope: SentinelProcessScope;
  readonly key: Uint8Array;
  readonly entries: readonly SentinelProcessKnownEntry[];
}

export interface SentinelProcessRequest {
  readonly bytes: Uint8Array;
  readonly scope: SentinelProcessScope;
  /** Destination and profile observed at the send point. */
  readonly destination: SentinelProcessDestination;
  /** Destination and profile the policy decision authorized. */
  readonly authorized: SentinelProcessDestination;
  /** Explicit registration, or an explicit `null` for egress that has no known originals. */
  readonly known: SentinelProcessKnownRegistration | null;
}

export interface SentinelProcessRunnerConfig {
  /** Host-owned absolute deadline measured from spawn. Never extended by output. */
  readonly deadlineMs: number;
  /** Time after a stop signal in which `close` must confirm the child is gone. */
  readonly cleanupGraceMs?: number;
}

/**
 * The exact own DATA properties a runner configuration may carry. An unknown key - a caller-owned
 * `signal`, a `worker` path, an `options` bag, a `shell` flag - is refused before any child exists,
 * and a refused configuration accessor is never invoked to find out what it would have returned.
 */
const RUNNER_CONFIG_KEYS: ReadonlySet<string> = new Set(['deadlineMs', 'cleanupGraceMs']);

export interface SentinelProcessRunner {
  /** One check per call; a second concurrent call is refused rather than queued or pooled. */
  check(request: SentinelProcessRequest): Promise<SentinelProcessOutcome>;
  /** Runner-owned cancellation of the sole active request. A no-op when nothing is in flight. */
  cancel(): void;
  readonly state: SentinelProcessState;
}

const NO_REASONS: readonly string[] = Object.freeze([]);

function block(code: SentinelProcessBlockCode): SentinelProcessOutcome {
  return Object.freeze({ status: 'BLOCK' as const, code, reasonCodes: NO_REASONS, rules: NO_REASONS });
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.byteLength; }
  return out;
}

function boundedInteger(value: unknown, low: number, high: number): number | null {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < low || value > high) return null;
  return value;
}

/**
 * Read the runner configuration from own data descriptors only. Returns `null` for anything the exact
 * shape does not allow; the constructor then builds a runner whose every check is restrictive instead
 * of echoing a thrown caller value back at the caller.
 */
function snapshotRunnerConfig(
  config: unknown,
): Readonly<{ deadlineMs: unknown; cleanupGraceMs: unknown }> | null {
  if (typeof config !== 'object' || config === null) return null;
  let names: string[];
  let symbols: symbol[];
  try {
    names = Object.getOwnPropertyNames(config);
    symbols = Object.getOwnPropertySymbols(config);
  } catch { return null; }
  if (symbols.length !== 0 || names.length < 1 || names.length > RUNNER_CONFIG_KEYS.size) return null;
  let deadlineMs: unknown = undefined;
  let cleanupGraceMs: unknown = undefined;
  for (const name of names) {
    if (!RUNNER_CONFIG_KEYS.has(name)) return null;
    let descriptor: PropertyDescriptor | undefined;
    try { descriptor = Object.getOwnPropertyDescriptor(config, name); } catch { return null; }
    if (descriptor === undefined || !('value' in descriptor)) return null;
    if (name === 'deadlineMs') deadlineMs = descriptor.value;
    else cleanupGraceMs = descriptor.value;
  }
  return Object.freeze({ deadlineMs, cleanupGraceMs });
}

/** Private per-check stop state. Nothing about it is reachable from a caller-supplied object. */
interface StopState {
  reason: SentinelProcessBlockCode | null;
  kill: (() => void) | null;
  cancel: () => void;
}

export function createSentinelProcessRunner(config: SentinelProcessRunnerConfig): SentinelProcessRunner {
  const limits = EGRESS_SENTINEL_PROCESS_LIMITS;
  // An unsupported or malformed configuration yields a restrictive runner, not a thrown echo of a
  // caller value and not a runner that silently ignores the key it did not understand.
  const read = snapshotRunnerConfig(config);
  const deadlineMs = read === null
    ? null
    : boundedInteger(read.deadlineMs, limits.minDeadlineMs, limits.maxDeadlineMs);
  const graceMs = read === null
    ? null
    : boundedInteger(read.cleanupGraceMs ?? limits.defaultCleanupGraceMs, 0, limits.maxCleanupGraceMs);
  let quarantined = false;
  let busy = false;
  let active: StopState | null = null;

  const check = (request: SentinelProcessRequest): Promise<SentinelProcessOutcome> => {
    // Every refusal below happens before a child exists, and none of them reads a value it refused.
    if (quarantined) return Promise.resolve(block('RUNNER_QUARANTINED'));
    if (busy) return Promise.resolve(block('RUNNER_BUSY'));
    // Admission is claimed BEFORE any caller-observable inspection below. A caller getter that
    // re-enters `check()` therefore sees a busy runner and cannot start a second child; an invalid
    // snapshot releases the claim immediately and leaves the runner idle.
    busy = true;
    if (deadlineMs === null || graceMs === null) {
      busy = false;
      return Promise.resolve(block('INVALID_REQUEST'));
    }
    let prepared: Readonly<{ snapshot: SentinelProcessSnapshot; frame: Uint8Array }> | null = null;
    try {
      const random = new Uint32Array(2);
      globalThis.crypto.getRandomValues(random);
      const taken = snapshotSentinelRequest(request, newSentinelRequestId(random));
      if (taken.ok) {
        const frame = encodeRequestFrame(taken.value);
        if (frame === null) { taken.value.payload.fill(0); taken.value.known?.key.fill(0); }
        else prepared = { snapshot: taken.value, frame };
      }
    } catch { prepared = null; }
    if (prepared === null) {
      busy = false;
      return Promise.resolve(block('INVALID_REQUEST'));
    }
    const snapshot = prepared.snapshot;
    const frame = prepared.frame;

    const stop: StopState = { reason: null, kill: null, cancel: () => { /* installed below */ } };
    active = stop;
    return new Promise<SentinelProcessOutcome>((resolve) => {
      let settled = false;
      let deadline: WorkerTimer | null = null;
      let grace: WorkerTimer | null = null;
      const stdout: Uint8Array[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;

      const clearTimers = (): void => {
        if (deadline !== null) { clearTimeout(deadline); deadline = null; }
        if (grace !== null) { clearTimeout(grace); grace = null; }
      };
      /** Drop every captured byte and the private snapshot, then resolve exactly once. */
      const finish = (outcome: SentinelProcessOutcome, quarantine = false): void => {
        if (settled) return;
        settled = true;
        clearTimers();
        stdout.length = 0;
        stdoutBytes = 0;
        stderrBytes = 0;
        stop.kill = null;
        busy = false;
        active = null;
        if (quarantine) quarantined = true;
        // The release copy is already private; these erases drop the parent's remaining copies.
        snapshot.payload.fill(0);
        snapshot.known?.key.fill(0);
        resolve(outcome);
      };
      /** The first observed stop wins. Nothing observed later can override it. */
      const halt = (reason: SentinelProcessBlockCode): void => {
        if (settled || stop.reason !== null) return;
        stop.reason = reason;
        if (stop.kill === null) { finish(block(reason)); return; }
        stop.kill();
        // `SIGKILL` is a request, not a termination: without `close` this runner cannot know the child
        // is gone, so the grace window decides between a confirmed stop and a quarantine.
        grace = setTimeout(() => finish(block('CLEANUP_UNCONFIRMED'), true), graceMs);
        grace.unref();
      };
      stop.cancel = () => halt('CANCELLED');

      deadline = setTimeout(() => halt('DEADLINE_EXCEEDED'), deadlineMs);
      deadline.unref();

      let child;
      try {
        child = spawn(process.execPath, [EGRESS_SENTINEL_PROCESS_WORKER], {
          stdio: ['pipe', 'pipe', 'pipe'], env: { ...WORKER_ENV }, windowsHide: true,
        });
      } catch {
        finish(block('SPAWN_FAILED'));
        return;
      }
      stop.kill = () => { try { child.kill('SIGKILL'); } catch { /* released by close or the grace timer */ } };

      child.stdout?.on('data', (chunk: Uint8Array) => {
        if (settled || stop.reason !== null) return;
        stdoutBytes += chunk.byteLength;
        if (stdoutBytes > limits.maxStdoutBytes) { stdout.length = 0; halt('REPLY_TOO_LARGE'); return; }
        stdout.push(chunk);
      });
      child.stderr?.on('data', (chunk: Uint8Array) => {
        // Counted and dropped. A stack trace can carry planted text and host paths, so stderr is never
        // materialised, reported or attached to an error.
        if (settled || stop.reason !== null) return;
        stderrBytes += chunk.byteLength;
        if (stderrBytes > limits.maxStderrBytes) halt('DIAGNOSTIC_OVERFLOW');
      });
      child.on('error', () => halt('SPAWN_FAILED'));
      child.stdin?.on('error', () => halt('SPAWN_FAILED'));
      child.on('close', (first: Error | number | null) => {
        const code = typeof first === 'number' ? first : null;
        if (settled) return;
        if (stop.reason !== null) { finish(block(stop.reason)); return; }
        if (code !== 0) { finish(block('CHILD_CRASHED')); return; }
        if (stdoutBytes === 0) { finish(block('REPLY_MISSING')); return; }
        const framing = classifyReplyFraming(concat(stdout, stdoutBytes));
        if (framing !== 'OK') { finish(block(framing)); return; }
        const decoded = decodeResponseFrame(concat(stdout, stdoutBytes), snapshot);
        if (!decoded.ok) { finish(block(decoded.code)); return; }
        if (decoded.value.decision === 'ALLOW') {
          // A private copy of the bytes this parent snapshotted and that the child reported checking.
          // Never the caller's buffer, never a buffer the worker selected.
          finish(Object.freeze({ status: 'ALLOW' as const, release: snapshot.payload.slice() }));
          return;
        }
        finish(Object.freeze({
          status: 'BLOCK' as const,
          code: 'SENTINEL_BLOCK' as const,
          reasonCodes: decoded.value.reasonCodes,
          rules: decoded.value.rules,
        }));
      });

      try {
        child.stdin?.write(frame);
        child.stdin?.end();
      } catch { halt('SPAWN_FAILED'); }
    });
  };

  return Object.freeze({
    check,
    cancel(): void { active?.cancel(); },
    get state(): SentinelProcessState {
      if (quarantined) return 'QUARANTINED';
      return busy ? 'BUSY' : 'IDLE';
    },
  });
}