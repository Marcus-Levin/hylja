/**
 * #113 bounded local worker transport. Evaluation-only, NON-ENFORCING and synthetic-only.
 *
 * One analysis is one child process: a single request line on stdin, a single reply line on stdout.
 * Nothing is shared between analyses, so a reply cannot be replayed into a later request, and a crash
 * or a wedged interpreter cannot survive into the next case.
 *
 * Every byte the child produces is untrusted protected traffic. stdout is captured only up to the
 * caller's ceiling and is handed to the pure reply validator, never to a report. **stderr is counted
 * and dropped**: a Python traceback embeds source text, file paths and values, so this module never
 * materialises it, never reports it and never lets it reach an error message. The same applies to
 * spawn errors, which carry a `path` argument — every failure below is a fixed code.
 *
 * The environment is a fixed minimum: no inherited variables, no proxy settings, no user site, no
 * bytecode writes. This does not by itself remove network access; the real trial additionally runs
 * inside a network-unshared sandbox. The transport never installs, imports or updates anything, and it
 * has no restart, retry or fallback path — an unavailable runtime is an explicit failure, never a
 * successful zero-findings result.
 */
import { spawn } from 'node:child_process';
import { clearTimeout, setTimeout } from 'node:timers';
import type { WorkerTimer } from 'node:timers';
import { PRESIDIO_MAX_REPLY_BYTES } from './presidio-candidate-source.js';

export type PresidioRunReason =
  | 'WORKER_SPAWN_FAILED'
  | 'WORKER_STARTUP_TIMEOUT'
  | 'WORKER_EXECUTION_TIMEOUT'
  | 'WORKER_OUTPUT_LIMIT'
  | 'WORKER_STDERR_LIMIT'
  | 'WORKER_REPLY_MISSING'
  | 'WORKER_REPLY_INCOMPLETE'
  | 'WORKER_CRASHED';

export type PresidioRunOutcome =
  | Readonly<{ status: 'REPLY'; line: string; exitCode: number | null }>
  | Readonly<{ status: 'FAILURE'; reason: PresidioRunReason; killedNotReaped?: true }>;

/** Trusted configuration. Nothing here is derived from analysed content or from a worker reply. */
export interface PresidioWorkerCommand {
  /** Interpreter executable. A path, never a shell word list: `spawn` takes an argv array. */
  readonly pythonPath: string;
  /** Worker script. Must be a regular file inside the disposable evaluation directory. */
  readonly workerScript: string;
  /** Extra argv for the worker (for example a fake-worker's control file). Bounded and pinned. */
  readonly args?: readonly string[];
  /** Time from spawn to the worker's first stdout byte. Bounds import/load time. */
  readonly startupTimeoutMs: number;
  /** Time from the first stdout byte to process exit. Bounds analysis time. */
  readonly executionTimeoutMs: number;
  readonly maxStdoutBytes?: number;
  readonly maxStderrBytes?: number;
  readonly cwd?: string;
}

export const PRESIDIO_WORKER_LIMITS = Object.freeze({
  startupTimeoutMs: 120_000,
  executionTimeoutMs: 60_000,
  maxStdoutBytes: PRESIDIO_MAX_REPLY_BYTES,
  maxStderrBytes: 64 * 1024,
  maxArgs: 8,
  maxArgLength: 1024,
});
const REAP_GRACE_MS = 2_000;
const decoder = new TextDecoder('utf-8', { fatal: true });
/** Join the captured chunks without depending on a `Buffer` global this project does not declare. */
function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.byteLength; }
  return out;
}

function safeString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function invalidConfiguration(): PresidioRunOutcome {
  return Object.freeze({ status: 'FAILURE', reason: 'WORKER_SPAWN_FAILED' });
}

/** The fixed, minimal environment. Anything the interpreter might inherit is simply absent. */
function workerEnv(cwd: string | undefined): Record<string, string> {
  return {
    PATH: '/usr/bin:/bin',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PYTHONHASHSEED: '0',
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONNOUSERSITE: '1',
    PYTHONUNBUFFERED: '1',
    ...(cwd === undefined ? {} : { TMPDIR: cwd, HOME: cwd }),
  };
}

/**
 * Run one bounded analysis. Resolves exactly once, always with a fixed code or the single reply line.
 * The child is killed and reaped on every failure path; nothing is retried.
 */
/**
 * The two remaining catch blocks are an outer defensive net, not reachable behaviour: `spawn` throws
 * synchronously only for a non-string command or invalid options, and `stdin.write` throws only for a
 * stream that was never opened, both of which the configuration validation above already excludes.
 * They are kept so a future platform change cannot raise a path or a message out of this function.
 */
export function runPresidioWorker(line: string, command: PresidioWorkerCommand): Promise<PresidioRunOutcome> {
  const startup = command?.startupTimeoutMs;
  const execution = command?.executionTimeoutMs;
  const stdoutLimit = command?.maxStdoutBytes ?? PRESIDIO_WORKER_LIMITS.maxStdoutBytes;
  const stderrLimit = command?.maxStderrBytes ?? PRESIDIO_WORKER_LIMITS.maxStderrBytes;
  const args = command?.args ?? [];
  // The request is exactly one newline-terminated line: the body carries no other control byte, so
  // an embedded newline cannot smuggle a second framed message to the worker.
  const body = typeof line === 'string' && line.endsWith('\n') ? line.slice(0, -1) : null;
  if (!safeString(command?.pythonPath, 4096) || !safeString(command?.workerScript, 4096) ||
    body === null || !safeString(body, PRESIDIO_MAX_REPLY_BYTES * 8) ||
    !Number.isSafeInteger(startup) || (startup as number) < 1 || (startup as number) > 600_000 ||
    !Number.isSafeInteger(execution) || (execution as number) < 1 || (execution as number) > 600_000 ||
    !Number.isSafeInteger(stdoutLimit) || (stdoutLimit as number) < 64 || (stdoutLimit as number) > PRESIDIO_MAX_REPLY_BYTES ||
    !Number.isSafeInteger(stderrLimit) || (stderrLimit as number) < 0 || (stderrLimit as number) > (1 << 20) ||
    !Array.isArray(args) || args.length > PRESIDIO_WORKER_LIMITS.maxArgs ||
    !args.every((item) => safeString(item, PRESIDIO_WORKER_LIMITS.maxArgLength))) {
    return Promise.resolve(invalidConfiguration());
  }
  return new Promise<PresidioRunOutcome>((resolve) => {
    let settled = false;
    let stopReason: PresidioRunReason | null = null;
    let killTimer: WorkerTimer | null = null;
    let startupTimer: WorkerTimer | null = null;
    let executionTimer: WorkerTimer | null = null;
    const stdout: Uint8Array[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const finish = (outcome: PresidioRunOutcome): void => {
      if (settled) return;
      settled = true;
      if (startupTimer) clearTimeout(startupTimer);
      if (executionTimer) clearTimeout(executionTimer);
      if (killTimer) clearTimeout(killTimer);
      // Drop the captured bytes with the closure; nothing is left readable on the result.
      stdout.length = 0;
      stdoutBytes = 0;
      stderrBytes = 0;
      resolve(outcome);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command.pythonPath, [command.workerScript, ...args], {
        stdio: ['pipe', 'pipe', 'pipe'], env: workerEnv(command.cwd), windowsHide: true,
        ...(command.cwd === undefined ? {} : { cwd: command.cwd }),
      });
    } catch { finish(invalidConfiguration()); return; }
    const stop = (reason: PresidioRunReason): void => {
      if (settled || stopReason) return;
      stopReason = reason;
      try { child.kill('SIGKILL'); } catch { /* the handle is released by 'close' or by the grace timer */ }
      // A child that exits but is never reaped still leaves a process this module can no longer track.
      // The reason the kill happened is preserved; the unconfirmed reap is recorded alongside it,
      // so a reader is never told a timed-out worker was cleanly cleaned up.
      killTimer = setTimeout(() => finish(Object.freeze({ status: 'FAILURE' as const,
        reason: stopReason ?? 'WORKER_CRASHED', killedNotReaped: true as const })), REAP_GRACE_MS);
      killTimer.unref();
    };
    startupTimer = setTimeout(() => stop('WORKER_STARTUP_TIMEOUT'), startup as number);
    startupTimer.unref();
    child.stdout?.on('data', (chunk: Uint8Array) => {
      if (settled || stopReason) return;
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > (stdoutLimit as number)) { stop('WORKER_OUTPUT_LIMIT'); return; }
      stdout.push(chunk);
      if (startupTimer) { clearTimeout(startupTimer); startupTimer = null; }
      if (executionTimer) clearTimeout(executionTimer);
      executionTimer = setTimeout(() => stop('WORKER_EXECUTION_TIMEOUT'), execution as number);
      executionTimer.unref();
    });
    child.stderr?.on('data', (chunk: Uint8Array) => {
      // Counted and dropped. A Python traceback can carry planted text and host paths.
      if (settled || stopReason) return;
      stderrBytes += chunk.byteLength;
      if (stderrBytes > (stderrLimit as number)) stop('WORKER_STDERR_LIMIT');
    });
    child.on('error', () => { if (!stopReason) finish(invalidConfiguration()); });
    // A child that exits before the request is fully written makes the write fail asynchronously.
    // Without this listener the socket's error would be an uncaught exception in this process.
    child.stdin?.on('error', () => { if (!stopReason && stdoutBytes === 0) finish(invalidConfiguration()); });
    child.on('close', (first: Error | number | null) => {
      const code = typeof first === 'number' ? first : null;
      if (stopReason) { finish(Object.freeze({ status: 'FAILURE', reason: stopReason })); return; }
      if (settled) return;
      if (stdoutBytes === 0) {
        finish(Object.freeze({ status: 'FAILURE',
          reason: code === 0 ? 'WORKER_REPLY_MISSING' : 'WORKER_CRASHED' }));
        return;
      }
      if (code !== 0) { finish(Object.freeze({ status: 'FAILURE', reason: 'WORKER_CRASHED' })); return; }
      let text: string;
      try { text = decoder.decode(concat(stdout, stdoutBytes)); } catch { text = ''; }
      if (!text.endsWith('\n') || text.slice(0, -1).indexOf('\n') >= 0) {
        finish(Object.freeze({ status: 'FAILURE', reason: 'WORKER_REPLY_INCOMPLETE' }));
        return;
      }
      finish(Object.freeze({ status: 'REPLY', line: text, exitCode: code }));
    });
    try {
      child.stdin?.write(line);
      child.stdin?.end();
    } catch { stop('WORKER_SPAWN_FAILED'); }  });
}
