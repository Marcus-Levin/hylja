#!/usr/bin/env node
/**
 * #137 bounded developer handoff helper.
 *
 *   npm run --silent agent:handoff -- <command> [options]
 *   node scripts/development/agent-handoff.mjs <command> [options]
 *   node scripts/development/agent-handoff.mjs --help
 *
 * Use `--silent` or the direct `node` command when stdout is consumed as one JSON document: npm adds its own
 * banner and lifecycle output around the script, and that output is outside the cap below.
 *
 * This is developer tooling in the repository's Node ESM `scripts/` convention. It is not Hylja runtime
 * core: `src/` imports nothing from here, `src/index.ts` exports none of it, it adds no dependency, it
 * selects no model or harness and it stores no orchestration policy. It authenticates nothing, sends no
 * model traffic and is not a security boundary.
 *
 * Commands
 * - `capabilities`   One bounded report of which optional commands this environment has, so a task stops
 *                    guessing. Availability is a PATH lookup: nothing is installed, authenticated or read
 *                    from an account, credential or authentication file. Environment entries report whether
 *                    a name is defined; no environment value is read.
 * - `project-github` Read one GitHub JSON response and print a bounded projection of whitelisted metadata
 *                    fields on the first read. The raw response is never printed and never reaches a
 *                    tracked path; `--capture` may store it in a private directory outside any repository.
 * - `compare`        Compare two documents by Git/blob identity, or by one bounded linear line scan when
 *                    the identities differ. Proofs are line numbers with per-line digests.
 * - `session-handoff` Validate an explicit safe session inventory and print a bounded handoff that keeps
 *                    user chats and workers apart with ids, opaque primary-log locators, fork/resume
 *                    relationships and explicit inaccessible sessions.
 *
 * Options (each configurable bound has a fixed range; leaving it is a refusal, never a silent clamp)
 * - `--max-output-bytes N`  emitted UTF-8 cap, default 4096, range 256..262144.
 * - `--timeout-ms N`        active budget for every spawned child and for the line scan, default 5000,
 *                          range 1..120000.
 * - `--max-raw-bytes N`     cap on one bounded stdin or file read, default 8 MiB, range 1024..32 MiB.
 * - `--input <path|->`     `project-github`, `session-handoff`; `-` (the default) reads stdin.
 * - `--capture <dir>`      `project-github`; store the raw response in an existing private directory.
 * - `--kind <kind>`        `project-github`; auto (default), issue, pull, list, comment.
 *
 * Fixed bounds not exposed as options: 500 records per inventory, 500 records per GitHub response, 64
 * labels and 20 differing-line proofs per record, 16 MiB scanned per operand, 120 characters per printed
 * scalar and 400 per printed path. The full table is `LIMITS`, exported for tests.
 *
 * Output contract
 * - stdout is one compact JSON document with no trailing newline, and its UTF-8 byte length never exceeds
 *   `--max-output-bytes`. Reduction order is fixed: every record at the richest field tier that fits, then
 *   every record at each lower tier, and only then the record count at the identity tier. Any loss the
 *   budget forced sets `output.truncated`; `output.tier`, `output.fieldsWithheld`, `recordsOmitted` and
 *   `omitted.*` separate what happened to every supplied key in the records that were actually projected:
 *   emitted, derived into another field, grouped, refused by validation, withheld by the tier, or never
 *   read. `--help` is the one unbounded text output. A cap too small for the mandatory envelope is the
 *   refusal `output-cap-unrepresentable` rather than an unlabelled result.
 * - every projected value is a bounded printable-ASCII scalar, a safe integer or a boolean from a fixed
 *   vocabulary. A value outside that shape is dropped, never truncated into something that looks valid.
 *
 * Refusals
 * - one fixed code on stderr, no input-derived value, and no partial result:
 *   `agent handoff: refused; <code>` (exit 1) or `agent handoff: budget; <code>` (exit 3).
 *   Codes: usage-invalid, option-out-of-range, command-unavailable, input-unreadable, input-malformed,
 *   input-above-raw-bound, input-not-a-regular-path, input-shape-mismatch, session-record-invalid,
 *   records-above-bound, capture-directory-unusable, capture-verification-unavailable,
 *   capture-inside-work-tree, capture-inside-repository, capture-exists, operand-unresolvable,
 *   operand-not-a-regular-path, operand-above-scan-bound, output-cap-unrepresentable,
 *   command-budget-exceeded, scan-budget-exceeded.
 *
 * Privacy and bounds
 * - the only command ever spawned is `git`, with an argv array, no shell and the configured timeout, and
 *   only when the PATH lookup found it. `capabilities` runs one bounded `rev-parse --show-toplevel`;
 *   `compare` may additionally run `rev-parse`, `cat-file` and `hash-object`. The work-tree probe runs with
 *   the per-call `gitProbeEnvironment()`; a `compare` operand lookup runs with the caller's own
 *   environment, which changes what a caller reads and never decides whether anything is written.
 *   Nothing else is executed.
 * - no raw response body, title, comment, patch, author login, session transcript, hidden reasoning,
 *   credential, protected value or authentication database is read into the output, exported or committed.
 * - `project-github` is a whitelist: only the fields named in `GITHUB_FIELDS` are read, and only their
 *   values. Every other key is counted by class and never read, and each supplied key of a projected record
 *   is reported by what actually happened to it, so the categories sum to `omitted.inputKeys`.
 * - `--capture` refuses a missing, symlinked or group/world-writable directory, a directory that is Git
 *   metadata storage or that physically sits inside a work tree at any depth, any containment it cannot
 *   establish, and any existing destination. Containment is established by walking the real path without Git
 *   and without any environment override; the bounded Git probe is a sanitized cross-check, not the decision.
 *   The capture is written `0600` and named by the SHA-256 of its own content, so a rerun cannot overwrite one.
 * - `compare` uses Git blob identity when git is available and one bounded linear pass otherwise. Both
 *   operands are bounded by refusal, so a reported scan is complete over both of them. There is no
 *   character-level quadratic diff, no unbounded child process, and no source text in output.
 *
 * Not enforced
 * - a capability report, a projection, a comparison or a handoff produced here is developer evidence. It
 *   is not an authoritative classification, policy decision, evaluation label or adoption record.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { accessSync, closeSync, constants, lstatSync, openSync, readSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve as resolvePath, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const TOOL = 'agent-handoff';
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;
const GIT_BLOB_SPEC = /^[A-Za-z0-9][A-Za-z0-9_.^~@{}/-]*:[^\s:][^\n]*$/;
const OBJECT_ID = /^[0-9a-f]{40,64}$/;
const ASSOCIATIONS = ['COLLABORATOR', 'CONTRIBUTOR', 'FIRST_TIMER', 'FIRST_TIME_CONTRIBUTOR', 'MANNEQUIN', 'MEMBER', 'NONE', 'OWNER'];
const MERGEABLE_STATES = ['behind', 'blocked', 'clean', 'dirty', 'draft', 'has_hooks', 'unknown', 'unstable'];
const SUBJECT_TYPES = ['commit', 'discussion', 'issue', 'pull_request'];
const KINDS = ['auto', 'issue', 'pull', 'list', 'comment'];
const SESSION_KINDS = ['user-chat', 'worker'];
const ACCESS_STATES = ['accessible', 'inaccessible', 'unknown'];
const CONTENT_KEY = /(?:transcript|message|body|content|text|raw|prompt|completion|reasoning|thought|diff|patch|hunk|comment|title|subject)/i;
const CREDENTIAL_KEY = /(?:token|secret|password|passwd|credential|cookie|auth|apikey|api_key|session[_-]?key)/i;
/** The entries Git itself keeps in a metadata directory, checked at every ancestor, recognised without Git. */
const GIT_METADATA_MARKERS = Object.freeze(['HEAD', 'config', 'objects', 'refs']);

export const LIMITS = Object.freeze({
  outputBytes: Object.freeze({ default: 4096, min: 256, max: 262144 }),
  timeoutMs: Object.freeze({ default: 5000, min: 1, max: 120000 }),
  rawBytes: Object.freeze({ default: 8 << 20, min: 1024, max: 32 << 20 }),
  scanBytes: 16 << 20,
  maxItems: 500,
  maxSessions: 500,
  maxLabels: 64,
  proofs: 20,
  scalarLength: 120,
  pathLength: 400,
  commands: Object.freeze(['gh', 'git', 'rg', 'jq', 'node', 'npm', 'python3', 'flock', 'curl', 'timeout']),
  environmentNames: Object.freeze(['GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_ENTERPRISE_TOKEN', 'GITHUB_HOST', 'GIT_ASKPASS']),
});

const HELP = `agent handoff: usage
  node scripts/development/agent-handoff.mjs <command> [options]

capabilities    Report which optional commands exist on PATH without running them.
project-github  Project a GitHub JSON response to bounded, whitelisted metadata.
compare         Compare two documents by Git/blob identity or a bounded line scan.
session-handoff Turn an explicit safe session inventory into a bounded handoff.

Options
  --max-output-bytes N  emitted UTF-8 cap (${LIMITS.outputBytes.min}..${LIMITS.outputBytes.max}, default ${LIMITS.outputBytes.default})
  --timeout-ms N        active budget per child process and per scan (${LIMITS.timeoutMs.min}..${LIMITS.timeoutMs.max}, default ${LIMITS.timeoutMs.default})
  --max-raw-bytes N     bounded stdin/file read cap (${LIMITS.rawBytes.min}..${LIMITS.rawBytes.max}, default ${LIMITS.rawBytes.default})
  --input <path|->      input path, or - for stdin (default)
  --capture <dir>       private directory outside a work tree for the raw response
  --kind <kind>         ${KINDS.join(', ')} (default auto)

The bounds this tool does not take as options: ${LIMITS.maxSessions} inventory records, ${LIMITS.maxItems}
GitHub records, ${LIMITS.maxLabels} labels, ${LIMITS.proofs} line proofs, ${LIMITS.scanBytes} scanned bytes
per operand, ${LIMITS.scalarLength} characters per scalar and ${LIMITS.pathLength} per path. They are
exported as LIMITS. Exceeding a configured range is the refusal option-out-of-range, never a clamp.`;

const CAPABILITY_NOTES = Object.freeze([
  'Availability is a PATH lookup only. Nothing is installed, authenticated, or read from an account, credential or authentication file.',
  'A command reported unavailable was not executed. Re-run this report instead of retrying the command.',
  'Environment entries report whether a name is defined. No environment value is read, and presence says nothing about validity or authentication.',
]);
const GITHUB_NOTES = Object.freeze([
  'Only the whitelisted metadata fields are read. A raw body, title, comment, patch or author login is never projected or printed.',
  'omitted.* counts supplied keys of projected records; a class-counted value is never read.',
]);
const COMPARE_NOTES = Object.freeze([
  'Identity is the Git blob object id when git is available, otherwise a SHA-256 prefix computed in process.',
  'The scan is one linear pass under an active deadline over both operands in full, not a character-level diff.',
  'A proof is a line number with per-line digests. No source text is printed.',
]);
const SESSION_NOTES = Object.freeze([
  'Session logs, transcripts and hidden reasoning are never opened, read, summarised or exported; a primary-log locator is carried through as an opaque string.',
  'A record is metadata a human curated. An unlisted kind or access state is reported as unknown rather than guessed.',
]);

class HandoffError extends Error {
  constructor(code, detail) {
    super(code);
    this.code = code;
    this.detail = detail;
  }
}

class Refused extends HandoffError {}

class Budget extends Refused {
  constructor(code) {
    super(code);
    this.budget = true;
  }
}

function refuse(code, detail) {
  throw new Refused(code, detail);
}

function budget(code) {
  throw new Budget(code);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** A printable ASCII string inside a length bound, or undefined. Nothing else reaches the output. */
function boundedScalar(value, maxLength) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return undefined;
  return PRINTABLE_ASCII.test(value) ? value : undefined;
}

function safeInteger(value) {
  return Number.isSafeInteger(value) ? value : undefined;
}

function booleanValue(value) {
  return typeof value === 'boolean' ? value : undefined;
}

function enumValue(value, allowed) {
  return typeof value === 'string' && allowed.includes(value) ? value : undefined;
}

function scalarList(value, maxItems, maxLength) {
  if (!Array.isArray(value)) return undefined;
  const kept = [];
  for (const entry of value.slice(0, maxItems)) {
    const scalar = boundedScalar(entry, maxLength);
    if (scalar !== undefined) kept.push(scalar);
  }
  return kept;
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

/** The first PATH entry holding an executable with this name, or null. Never runs the candidate. */
function lookupOnPath(name) {
  const names = process.platform === 'win32' ? [name, `${name}.exe`, `${name}.cmd`] : [name];
  for (const directory of (process.env.PATH ?? '').split(delimiter)) {
    if (directory === '') continue;
    for (const candidate of names) {
      const path = join(directory, candidate);
      try {
        if (!statSync(path).isFile()) continue;
        accessSync(path, constants.X_OK);
        return path;
      } catch {
        continue;
      }
    }
  }
  return null;
}

/** Runs git with an argv array, no shell and the active budget. null is a non-zero exit, not a failure. */
function runGit(args, timeoutMs, maxBuffer) {
  const result = spawnSync('git', args, { encoding: 'buffer', maxBuffer, windowsHide: true, timeout: timeoutMs });
  if (result.signal !== null && result.signal !== undefined) budget('command-budget-exceeded');
  if (result.error !== undefined && result.error !== null) {
    if (result.error.code === 'ETIMEDOUT' || result.error.code === 'ENOBUFS') budget('command-budget-exceeded');
    return null;
  }
  if (result.status !== 0) return null;
  return result.stdout;
}

/**
 * The environment a Git discovery probe runs with: a `PATH` and, on Windows, the two variables the process
 * launcher itself needs. No `GIT_*` variable and no `HOME` is carried, so an inherited discovery override
 * cannot answer for the probe and no account or credential configuration is reachable from it.
 *
 * It is a fresh mutable object per call, deliberately. Node's `child_process` assigns
 * `NODE_V8_COVERAGE` onto the object it is handed whenever that variable is set in the caller's
 * environment — that is how `node --test --experimental-test-coverage` collects coverage from a program
 * that spawns with a white-listed environment — so a shared frozen object would make that assignment throw
 * and turn a coverage run into a refusal. Per-call objects keep that legitimate propagation intact and
 * confined to a throwaway copy.
 */
export function gitProbeEnvironment() {
  return {
    PATH: process.env.PATH ?? '',
    ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? '', PATHEXT: process.env.PATHEXT ?? '' } : {}),
  };
}

/**
 * The work tree containing `directory`. A string is its root, null means git ran and this is not a work
 * tree, and undefined means git itself could not run, which is not the same answer and never passes for one.
 *
 * The probe runs with the sanitized environment above, so an inherited `GIT_DIR`, `GIT_WORK_TREE`,
 * `GIT_COMMON_DIR`, `GIT_OBJECT_DIRECTORY`, `GIT_INDEX_FILE`, `GIT_CEILING_DIRECTORIES` or `HOME` cannot
 * decide the answer for a caller.
 */
function gitWorkTree(directory, timeoutMs) {
  const result = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'buffer', maxBuffer: 4096, windowsHide: true, timeout: timeoutMs, cwd: directory, env: gitProbeEnvironment(),
  });
  if (result.signal !== null && result.signal !== undefined) budget('command-budget-exceeded');
  if (result.error !== undefined && result.error !== null) {
    if (result.error.code === 'ETIMEDOUT') budget('command-budget-exceeded');
    return undefined;
  }
  if (result.status !== 0) return null;
  const text = result.stdout.toString('utf8').trim();
  return text === '' ? null : text;
}

/**
 * Reads a handle in bounded chunks. The size is checked again while reading, so a file that grows under
 * the reader cannot cross the bound, and the bytes come from one open handle rather than a second stat.
 */
function readHandle(handle, maxBytes, oversized) {
  const chunks = [];
  let total = 0;
  let stalls = 0;
  const buffer = Buffer.allocUnsafe(65536);
  for (;;) {
    let read;
    try {
      read = readSync(handle, buffer, 0, buffer.length, null);
    } catch (error) {
      // A non-blocking descriptor that keeps returning EAGAIN is a stalled reader, not an endless wait.
      if (error?.code === 'EAGAIN' && stalls < 1000) {
        stalls += 1;
        continue;
      }
      refuse('input-unreadable');
    }
    stalls = 0;
    if (read === 0) break;
    total += read;
    if (total > maxBytes) refuse(oversized);
    chunks.push(Buffer.from(buffer.subarray(0, read)));
  }
  return Buffer.concat(chunks);
}

/** One bounded read from stdin or from a regular file. A symbolic link or an oversized input is refused. */
function readBounded(path, maxBytes) {
  if (path === '-') return readHandle(0, maxBytes, 'input-above-raw-bound');
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    refuse('input-unreadable');
  }
  if (stats.isSymbolicLink() || !stats.isFile()) refuse('input-not-a-regular-path');
  if (stats.size > maxBytes) refuse('input-above-raw-bound');
  let handle;
  try {
    handle = openSync(path, 'r');
  } catch {
    refuse('input-unreadable');
  }
  try {
    return readHandle(handle, maxBytes, 'input-above-raw-bound');
  } finally {
    closeSync(handle);
  }
}

/** The same bounded read for a comparison operand, which reports its own bound instead of the input bound. */
function readFileBytes(path, maxBytes) {
  const stats = lstatSync(path);
  if (stats.isSymbolicLink() || !stats.isFile()) refuse('operand-not-a-regular-path');
  if (stats.size > maxBytes) refuse('operand-above-scan-bound');
  const handle = openSync(path, 'r');
  try {
    return readHandle(handle, maxBytes, 'operand-above-scan-bound');
  } finally {
    closeSync(handle);
  }
}

function parseJson(text, code = 'input-malformed') {
  try {
    return JSON.parse(text);
  } catch {
    refuse(code);
  }
}

/**
 * Keeps the largest projection that fits the cap, in a fixed priority order that never trades a task
 * identity away while a field is still available:
 *   1. every record at the richest tier that fits;
 *   2. every record at each lower tier, richest first;
 *   3. only then the record count, at the identity tier, largest first.
 * A cap too small for the mandatory envelope is a refusal, never a silently unlabelled result.
 */
function fitRecords(capBytes, total, tiers, build) {
  for (const tier of tiers) {
    const text = JSON.stringify(build(total, tier));
    if (Buffer.byteLength(text, 'utf8') <= capBytes) return text;
  }
  const identityTier = tiers[tiers.length - 1];
  let low = 0;
  let high = total;
  let best = null;
  while (low <= high) {
    const kept = Math.floor((low + high) / 2);
    const text = JSON.stringify(build(kept, identityTier));
    if (Buffer.byteLength(text, 'utf8') <= capBytes) {
      best = text;
      low = kept + 1;
    } else {
      high = kept - 1;
    }
  }
  if (best !== null) return best;
  refuse('output-cap-unrepresentable');
}

function fitCandidates(capBytes, candidates) {
  for (const candidate of candidates) {
    const text = JSON.stringify(candidate);
    if (Buffer.byteLength(text, 'utf8') <= capBytes) return text;
  }
  refuse('output-cap-unrepresentable');
}

const GITHUB_FIELDS = Object.freeze([
  { name: 'id', tier: 0, read: (record) => safeInteger(record.id) },
  { name: 'number', tier: 0, read: (record) => safeInteger(record.number) },
  { name: 'state', tier: 0, read: (record) => enumValue(record.state, ['open', 'closed']) },
  { name: 'stateReason', tier: 1, key: 'state_reason', read: (record) => enumValue(record.state_reason, ['completed', 'not_planned', 'reopened']) },
  { name: 'draft', tier: 1, read: (record) => booleanValue(record.draft) },
  { name: 'locked', tier: 1, read: (record) => booleanValue(record.locked) },
  { name: 'commentCount', tier: 1, key: 'comments', read: (record) => safeInteger(record.comments) },
  { name: 'authorAssociation', tier: 1, key: 'author_association', read: (record) => enumValue(record.author_association, ASSOCIATIONS) },
  { name: 'subjectType', tier: 1, key: 'subject_type', read: (record) => enumValue(record.subject_type, SUBJECT_TYPES) },
  { name: 'mergeableState', tier: 1, key: 'mergeable_state', read: (record) => enumValue(record.mergeable_state, MERGEABLE_STATES) },
  { name: 'mergeCommitSha', tier: 1, key: 'merge_commit_sha', read: (record) => boundedScalar(record.merge_commit_sha, 64) },
  { name: 'createdAt', tier: 2, key: 'created_at', read: (record) => boundedScalar(record.created_at, 40) },
  { name: 'updatedAt', tier: 2, key: 'updated_at', read: (record) => boundedScalar(record.updated_at, 40) },
  { name: 'closedAt', tier: 2, key: 'closed_at', read: (record) => boundedScalar(record.closed_at, 40) },
  { name: 'mergedAt', tier: 2, key: 'merged_at', read: (record) => boundedScalar(record.merged_at, 40) },
  { name: 'headRef', tier: 2, key: 'head', read: (record) => (isPlainObject(record.head) ? boundedScalar(record.head.ref, LIMITS.scalarLength) : undefined) },
  { name: 'baseRef', tier: 2, key: 'base', read: (record) => (isPlainObject(record.base) ? boundedScalar(record.base.ref, LIMITS.scalarLength) : undefined) },
  {
    name: 'labelNames',
    tier: 2,
    key: 'labels',
    read: (record) => (Array.isArray(record.labels)
      ? scalarList(record.labels.map((label) => (isPlainObject(label) ? label.name : undefined)), LIMITS.maxLabels, 64)
      : undefined),
  },
]);

/**
 * The whitelist applied to one record. It reads only the named fields and their values, and records what
 * actually happened to each supplied key: emitted as its own field, excluded by the output tier, or
 * inspected and refused. A key the record does not have produces no occurrence at all.
 */
function projectGitHubRecord(record, tier) {
  const item = {};
  const outcomes = new Map();
  for (const field of GITHUB_FIELDS) {
    const key = field.key ?? field.name;
    if (!Object.hasOwn(record, key)) continue;
    if (field.tier > tier) {
      outcomes.set(key, 'withheldKeys');
      continue;
    }
    const value = field.read(record);
    if (value === undefined) {
      outcomes.set(key, 'rejectedKeys');
      continue;
    }
    item[field.name] = value;
    outcomes.set(key, 'projectedKeys');
  }
  return { item, outcomes };
}

function projectedGitHubFields(tier) {
  return GITHUB_FIELDS.filter((field) => field.tier <= tier).map((field) => field.name);
}

const RICHEST_TIER = 2;

/**
 * Accounting over the records that were actually projected. Every supplied key occurrence in those records
 * lands in exactly one category: `projectedKeys` (emitted as its own output field), `derivedKeys` (emitted
 * inside another field, a session relationship edge), `groupedKeys` (consulted for the emitted session
 * group), `rejectedKeys` (inspected and refused by validation or by a rule), `withheldKeys` (a whitelisted
 * key the output tier dropped), and the three never-read classes. Records dropped by the output budget are
 * not in this scope at all; they are reported by `recordsOmitted` and `sessionsOmitted`. Values behind a
 * class-counted occurrence are never read, so counting them cannot mean reading them.
 */
function accountKeys(projected, outcomes) {
  const totals = {
    inputKeys: 0,
    projectedKeys: 0,
    derivedKeys: 0,
    groupedKeys: 0,
    rejectedKeys: 0,
    withheldKeys: 0,
    contentKeys: 0,
    credentialKeys: 0,
    otherKeys: 0,
  };
  for (const [index, record] of projected.entries()) {
    const outcome = outcomes[index];
    for (const key of Object.keys(record)) {
      totals.inputKeys += 1;
      const category = outcome.get(key);
      if (category !== undefined) totals[category] += 1;
      else if (CONTENT_KEY.test(key)) totals.contentKeys += 1;
      else if (CREDENTIAL_KEY.test(key)) totals.credentialKeys += 1;
      else totals.otherKeys += 1;
    }
  }
  return { ...totals, valuesReadFromOmittedKeys: false };
}

function detectKind(payload) {
  if (Array.isArray(payload)) return 'list';
  if (isPlainObject(payload) && Array.isArray(payload.items)) return 'list';
  return 'issue';
}

function selectRecords(payload, kind) {
  if (kind === 'list') {
    if (Array.isArray(payload)) return payload;
    if (isPlainObject(payload) && Array.isArray(payload.items)) return payload.items;
    refuse('input-shape-mismatch');
  }
  if (Array.isArray(payload)) refuse('input-shape-mismatch');
  if (!isPlainObject(payload)) refuse('input-shape-mismatch');
  return [payload];
}

/** An entry that may legitimately be absent (false) or that we may not establish (a refusal). */
function entryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return false;
    refuse('capture-verification-unavailable');
  }
}

/**
 * Establishes that `directory` is physically outside every Git work tree and every Git metadata
 * directory, without running Git and without consulting any environment override. The destination and
 * every ancestor are checked twice: for Git's own metadata entries, which is what a bare repository has and
 * a work tree has not, and for a `.git` entry, which is a directory in a normal repository and a pointer
 * file in a linked worktree or a submodule. Any ancestor that cannot be examined fails closed.
 */
function assertPhysicallyOutsideGit(directory) {
  let current = directory;
  for (;;) {
    let stats;
    try {
      stats = lstatSync(current);
    } catch {
      refuse('capture-verification-unavailable');
    }
    if (stats.isSymbolicLink()) refuse('capture-verification-unavailable');
    if (GIT_METADATA_MARKERS.every((marker) => entryExists(join(current, marker)))) refuse('capture-inside-repository');
    if (entryExists(join(current, '.git'))) refuse('capture-inside-work-tree');
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

/** Stores the raw response outside model context: private directory, outside every repository, never a rerun overwrite. */
function captureRaw(raw, directory, timeoutMs) {
  let given;
  try {
    given = lstatSync(directory);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') refuse('capture-directory-unusable');
    refuse('capture-verification-unavailable');
  }
  if (given.isSymbolicLink() || !given.isDirectory()) refuse('capture-directory-unusable');
  let real;
  try {
    real = realpathSync(directory);
  } catch {
    refuse('capture-verification-unavailable');
  }
  if ((given.mode & 0o022) !== 0) refuse('capture-directory-unusable');
  assertPhysicallyOutsideGit(real);
  // Cross-check with Git only after the physical walk has established containment. Git cannot override it;
  // a Git answer that disagrees is a refusal, not a correction.
  if (lookupOnPath('git') !== null) {
    const top = gitWorkTree(real, timeoutMs);
    if (top === undefined) refuse('capture-verification-unavailable');
    if (top !== null) {
      const root = resolvePath(top);
      if (real === root || real.startsWith(`${root}${sep}`)) refuse('capture-inside-work-tree');
    }
  }
  const target = join(real, `github-response-${sha256(raw).slice(0, 16)}.json`);
  try {
    writeFileSync(target, raw, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    refuse(error?.code === 'EEXIST' ? 'capture-exists' : 'capture-directory-unusable');
  }
  return target;
}

function projectGitHub(raw, options) {
  const capturePath = options.capture === undefined ? null : captureRaw(raw, options.capture, options.timeoutMs);
  const text = raw.toString('utf8');
  const payload = parseJson(text);
  const kind = options.kind === 'auto' ? detectKind(payload) : options.kind;
  const selected = selectRecords(payload, kind);
  // A hard bound: an oversized response is refused, never sliced down to the bound with a completeness claim.
  if (selected.length > LIMITS.maxItems) refuse('records-above-bound');
  const objects = selected.filter(isPlainObject);
  const build = (kept, tier) => {
    const items = [];
    const outcomes = [];
    for (const record of objects.slice(0, kept)) {
      const projected = projectGitHubRecord(record, tier);
      items.push(projected.item);
      outcomes.push(projected.outcomes);
    }
    // This projection derives and groups nothing, so those two categories are structurally absent rather
    // than reported as zero. Every category present describes real input/output behaviour.
    const counted = accountKeys(objects.slice(0, kept), outcomes);
    const omitted = {
      inputKeys: counted.inputKeys,
      projectedKeys: counted.projectedKeys,
      rejectedKeys: counted.rejectedKeys,
      withheldKeys: counted.withheldKeys,
      contentKeys: counted.contentKeys,
      credentialKeys: counted.credentialKeys,
      otherKeys: counted.otherKeys,
      valuesReadFromOmittedKeys: false,
    };
    return {
      tool: TOOL,
      command: 'project-github',
      limits: { outputBytes: options.outputBytes, rawBytes: options.rawBytes, timeoutMs: options.timeoutMs },
      output: {
        capBytes: options.outputBytes,
        // Any loss the output budget forced is a truncation: a withheld field or a dropped record.
        truncated: tier < RICHEST_TIER || kept < objects.length,
        tier,
        fieldsProjected: projectedGitHubFields(tier),
        fieldsWithheld: GITHUB_FIELDS.length - projectedGitHubFields(tier).length,
        recordsRead: objects.length,
        recordsProjected: kept,
        recordsOmitted: objects.length - kept,
        recordsIgnored: selected.length - objects.length,
      },
      kind,
      items,
      omitted,
      raw: { printed: false, captured: capturePath !== null, capturePath },
      notes: GITHUB_NOTES,
    };
  };
  return fitRecords(options.outputBytes, objects.length, [RICHEST_TIER, 1, 0], build);
}

const SESSION_FIELDS = Object.freeze([
  { name: 'id', tier: 0, read: (record) => boundedScalar(record.id, 80) },
  { name: 'access', tier: 0, read: (record) => enumValue(record.access, ACCESS_STATES) ?? 'unknown' },
  { name: 'label', tier: 1, read: (record) => boundedScalar(record.label, 80) },
  { name: 'startedAt', tier: 2, read: (record) => boundedScalar(record.startedAt, 40) },
  { name: 'primaryLogLocator', tier: 2, key: 'primaryLog', read: (record) => boundedScalar(record.primaryLog, LIMITS.scalarLength) },
]);

const SESSION_DERIVED_FROM = Object.freeze(['kind', 'forkedFrom', 'resumedFrom']);

function projectedSessionFields(tier) {
  return [...SESSION_FIELDS.filter((field) => field.tier <= tier).map((field) => field.name), 'relationships'];
}

/**
 * Fork and resume edges between inventory ids, recording whether each supplied edge was emitted or refused.
 * An edge to an id outside the inventory stays unresolved; a self reference or an unsafe value is refused,
 * and neither can be called derived.
 */
function relationships(record, known, outcomes) {
  const edges = [];
  for (const [key, kind] of [['forkedFrom', 'fork'], ['resumedFrom', 'resume']]) {
    if (!Object.hasOwn(record, key)) continue;
    const from = boundedScalar(record[key], 80);
    if (from === undefined || from === record.id) {
      outcomes.set(key, 'rejectedKeys');
      continue;
    }
    outcomes.set(key, 'derivedKeys');
    edges.push({ kind, from, resolved: known.has(from) });
  }
  return edges;
}

function parseInventory(text) {
  const trimmed = text.trim();
  if (trimmed === '') refuse('input-malformed');
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    const rows = [];
    for (const line of trimmed.split('\n')) {
      if (line.trim() === '') continue;
      rows.push(parseJson(line));
    }
    if (rows.length === 0) refuse('input-malformed');
    return rows;
  }
  if (Array.isArray(parsed)) return parsed;
  if (isPlainObject(parsed) && Array.isArray(parsed.sessions)) return parsed.sessions;
  // One record is valid JSON and one valid JSONL row. It is a one-row inventory, not a shape mismatch.
  if (isPlainObject(parsed) && typeof parsed.id === 'string') return [parsed];
  refuse('input-shape-mismatch');
}

/** Drops the surplus from the largest group first, so a truncated handoff keeps the spread of its groups. */
function keepFirst(groups, kept) {
  const counts = groups.map((group) => group.items.length);
  let excess = counts.reduce((sum, count) => sum + count, 0) - kept;
  while (excess > 0) {
    let target = -1;
    for (let index = 0; index < counts.length; index += 1) {
      if (counts[index] === 0) continue;
      if (target === -1 || counts[index] > counts[target]) target = index;
    }
    if (target === -1) break;
    counts[target] -= 1;
    excess -= 1;
  }
  return groups.map((group, index) => group.items.slice(0, counts[index]));
}

function sessionHandoff(raw, options) {
  const records = parseInventory(raw.toString('utf8'));
  if (records.length > LIMITS.maxSessions) refuse('records-above-bound');
  const known = new Set();
  const entries = [];
  let duplicateIds = 0;
  for (const [index, record] of records.entries()) {
    if (!isPlainObject(record)) refuse('session-record-invalid', ` (index ${index})`);
    const id = boundedScalar(record.id, 80);
    if (id === undefined) refuse('session-record-invalid', ` (index ${index})`);
    if (known.has(id)) {
      duplicateIds += 1;
      continue;
    }
    known.add(id);
    entries.push({ record, id, group: SESSION_KINDS.includes(record.kind) ? record.kind : 'unclassified' });
  }
  const groups = [
    { name: 'userChats', items: entries.filter((entry) => entry.group === 'user-chat') },
    { name: 'workers', items: entries.filter((entry) => entry.group === 'worker') },
    { name: 'unclassified', items: entries.filter((entry) => entry.group === 'unclassified') },
  ];
  const projectSession = (item, tier) => {
    const record = item.record;
    const entry = {};
    const outcomes = new Map();
    entry.id = item.id;
    outcomes.set('id', 'projectedKeys');
    const access = enumValue(record.access, ACCESS_STATES);
    if (Object.hasOwn(record, 'access')) outcomes.set('access', access === undefined ? 'rejectedKeys' : 'projectedKeys');
    entry.access = access ?? 'unknown';
    // `kind` never becomes an output field: it places the session in an emitted group, or is refused.
    if (Object.hasOwn(record, 'kind')) outcomes.set('kind', SESSION_KINDS.includes(record.kind) ? 'groupedKeys' : 'rejectedKeys');
    for (const field of SESSION_FIELDS) {
      if (field.name === 'id' || field.name === 'access') continue;
      const key = field.key ?? field.name;
      if (!Object.hasOwn(record, key)) continue;
      if (field.tier > tier) {
        outcomes.set(key, 'withheldKeys');
        continue;
      }
      const value = field.read(record);
      if (value === undefined) {
        outcomes.set(key, 'rejectedKeys');
        continue;
      }
      entry[field.name] = value;
      outcomes.set(key, 'projectedKeys');
    }
    entry.relationships = relationships(record, known, outcomes);
    return { entry, outcomes };
  };
  const build = (kept, tier) => {
    const taken = keepFirst(groups, kept);
    const projected = {};
    const projectedRecords = [];
    const outcomes = [];
    const inaccessible = [];
    for (const [index, group] of groups.entries()) {
      projected[group.name] = taken[index].map((item) => {
        const result = projectSession(item, tier);
        projectedRecords.push(item.record);
        outcomes.push(result.outcomes);
        if (enumValue(item.record.access, ACCESS_STATES) === 'inaccessible') inaccessible.push(item.id);
        return result.entry;
      });
    }
    const totals = {
      records: entries.length,
      userChats: projected.userChats.length,
      workers: projected.workers.length,
      unclassified: projected.unclassified.length,
      inaccessible: inaccessible.length,
    };
    const omitted = { ...accountKeys(projectedRecords, outcomes), duplicateIds };
    return {
      tool: TOOL,
      command: 'session-handoff',
      limits: { outputBytes: options.outputBytes, rawBytes: options.rawBytes, timeoutMs: options.timeoutMs },
      output: {
        capBytes: options.outputBytes,
        truncated: tier < RICHEST_TIER || kept < entries.length,
        tier,
        fieldsProjected: projectedSessionFields(tier),
        fieldsWithheld: SESSION_FIELDS.length + 1 - projectedSessionFields(tier).length,
        derivedFrom: SESSION_DERIVED_FROM,
        sessionsRead: records.length,
        sessionsProjected: kept,
        sessionsOmitted: entries.length - kept,
        sessionsDuplicate: duplicateIds,
      },
      totals,
      userChats: projected.userChats,
      workers: projected.workers,
      unclassified: projected.unclassified,
      inaccessible: inaccessible,
      omitted,
      notes: SESSION_NOTES,
    };
  };
  return fitRecords(options.outputBytes, entries.length, [RICHEST_TIER, 1, 0], build);
}

/** Line spans of the buffer. A trailing newline closes the last line rather than opening an empty one. */
function lineSpans(buffer, end) {
  const spans = [];
  let start = 0;
  for (let index = 0; index < end; index += 1) {
    if (buffer[index] === 0x0a) {
      spans.push([start, index]);
      start = index + 1;
    }
  }
  if (start < end) spans.push([start, end]);
  return spans;
}

function lineDigest(buffer, span) {
  return `sha256:${sha256(buffer.subarray(span[0], span[1])).slice(0, 12)}`;
}

/**
 * One linear pass over both operands, which are bounded by refusal before they are read, so every byte is
 * compared. Proofs are line numbers with per-line digests,
 * never text. `now` is injectable so the deadline is a testable invariant rather than a timing accident.
 */
export function scanLines(left, right, { maxProofs = LIMITS.proofs, deadlineMs = LIMITS.timeoutMs.default, now = Date.now } = {}) {
  const deadline = now() + deadlineMs;
  const leftLines = lineSpans(left, left.length);
  const rightLines = lineSpans(right, right.length);
  const proofs = [];
  let differingLines = 0;
  let comparedLines = 0;
  for (let index = 0; ; index += 1) {
    if (index % 1024 === 0 && now() > deadline) budget('scan-budget-exceeded');
    const leftSpan = leftLines[index];
    const rightSpan = rightLines[index];
    if (leftSpan === undefined && rightSpan === undefined) break;
    const same = leftSpan !== undefined && rightSpan !== undefined
      && left.compare(right, rightSpan[0], rightSpan[1], leftSpan[0], leftSpan[1]) === 0;
    if (!same) {
      differingLines += 1;
      if (proofs.length < maxProofs) {
        proofs.push({
          line: index + 1,
          left: leftSpan === undefined ? null : lineDigest(left, leftSpan),
          right: rightSpan === undefined ? null : lineDigest(right, rightSpan),
        });
      }
    }
    comparedLines += 1;
  }
  return { identical: differingLines === 0, comparedLines, linesLeft: leftLines.length, linesRight: rightLines.length, differingLines, proofs };
}

/** Resolves one operand to an identity. A Git blob spec needs git; a file is hashed by git or in process. */
function resolveOperand(operand, options) {
  const spec = boundedScalar(operand, LIMITS.pathLength);
  if (spec === undefined) refuse('usage-invalid');
  const gitAvailable = lookupOnPath('git') !== null;
  if (GIT_BLOB_SPEC.test(spec)) {
    if (!gitAvailable) refuse('command-unavailable');
    const output = runGit(['rev-parse', '--verify', spec], options.timeoutMs, 4096);
    const identity = output === null ? '' : output.toString('utf8').trim();
    if (!OBJECT_ID.test(identity)) refuse('operand-unresolvable');
    const size = runGit(['cat-file', '-s', identity], options.timeoutMs, 4096);
    const bytes = size === null ? null : Number.parseInt(size.toString('utf8').trim(), 10);
    if (bytes !== null && bytes > LIMITS.scanBytes) refuse('operand-above-scan-bound');
    return {
      spec,
      kind: 'git-blob',
      identity,
      bytes,
      load: () => {
        const blob = runGit(['cat-file', 'blob', identity], options.timeoutMs, LIMITS.scanBytes + 1);
        if (blob === null) refuse('operand-unresolvable');
        if (blob.length > LIMITS.scanBytes) refuse('operand-above-scan-bound');
        return blob;
      },
    };
  }
  const absolute = resolvePath(process.cwd(), spec);
  let stats;
  try {
    stats = lstatSync(absolute);
  } catch {
    refuse('operand-unresolvable');
  }
  if (stats.isSymbolicLink() || !stats.isFile()) refuse('operand-not-a-regular-path');
  if (stats.size > LIMITS.scanBytes) refuse('operand-above-scan-bound');
  let cached;
  const load = () => {
    if (cached === undefined) cached = readFileBytes(absolute, LIMITS.scanBytes);
    return cached;
  };
  if (gitAvailable) {
    const output = runGit(['hash-object', '--no-filters', '--', absolute], options.timeoutMs, 4096);
    const identity = output === null ? '' : output.toString('utf8').trim();
    if (OBJECT_ID.test(identity)) return { spec, kind: 'file', identity, bytes: stats.size, load };
  }
  return { spec, kind: 'file', identity: `sha256:${sha256(load()).slice(0, 16)}`, bytes: stats.size, load };
}

function compareOperands(request) {
  const { options } = request;
  const left = resolveOperand(request.positionals[0], options);
  const right = resolveOperand(request.positionals[1], options);
  const identical = left.identity === right.identity;
  const side = (operand) => ({ spec: operand.spec, kind: operand.kind, identity: operand.identity, bytes: operand.bytes });
  let scan = null;
  let proofs = [];
  let differingLines = null;
  if (!identical) {
    const leftBytes = left.load();
    const rightBytes = right.load();
    const result = scanLines(leftBytes, rightBytes, { maxProofs: LIMITS.proofs, deadlineMs: options.timeoutMs });
    // Each operand is bounded at load time, so a reported scan covers both operands in full. A difference in
    // length is a difference in content, not incomplete inspection, and is left to `left.bytes`/`right.bytes`.
    scan = {
      bytes: Math.min(leftBytes.length, rightBytes.length),
      comparedLines: result.comparedLines,
      linesLeft: result.linesLeft,
      linesRight: result.linesRight,
      complete: true,
    };
    differingLines = result.differingLines;
    proofs = result.proofs;
  }
  const envelope = (shown) => ({
    tool: TOOL,
    command: 'compare',
    limits: { outputBytes: options.outputBytes, timeoutMs: options.timeoutMs, scanBytes: LIMITS.scanBytes },
    output: { capBytes: options.outputBytes, truncated: shown < proofs.length },
    left: side(left),
    right: side(right),
    identical,
    identityOnly: identical,
    scan,
    differingLines,
    proofs: shown === 0 ? [] : proofs.slice(0, shown),
    notes: COMPARE_NOTES,
  });
  return fitCandidates(options.outputBytes, [
    envelope(LIMITS.proofs),
    envelope(8),
    envelope(3),
    envelope(0),
    {
      tool: TOOL,
      command: 'compare',
      limits: { outputBytes: options.outputBytes, timeoutMs: options.timeoutMs, scanBytes: LIMITS.scanBytes },
      output: { capBytes: options.outputBytes, truncated: true },
      identical,
      identityOnly: identical,
      differingLines,
      notes: COMPARE_NOTES,
    },
  ]);
}

const OPTION_BOUNDS = Object.freeze({
  '--max-output-bytes': 'outputBytes',
  '--timeout-ms': 'timeoutMs',
  '--max-raw-bytes': 'rawBytes',
});

const COMMAND_OPTIONS = Object.freeze({
  capabilities: Object.freeze(['--max-output-bytes', '--timeout-ms']),
  'project-github': Object.freeze(['--max-output-bytes', '--timeout-ms', '--max-raw-bytes', '--input', '--capture', '--kind']),
  compare: Object.freeze(['--max-output-bytes', '--timeout-ms']),
  'session-handoff': Object.freeze(['--max-output-bytes', '--timeout-ms', '--max-raw-bytes', '--input']),
});
const COMMANDS = Object.freeze(Object.keys(COMMAND_OPTIONS));

function parseBound(name, raw) {
  const bound = LIMITS[OPTION_BOUNDS[name]];
  if (!/^\d+$/.test(raw)) refuse('option-out-of-range');
  const value = Number.parseInt(raw, 10);
  if (value < bound.min || value > bound.max) refuse('option-out-of-range');
  return value;
}

/** Resolves the argv into one command and bounded options. Anything unexpected is usage-invalid. */
export function parseArgs(argv) {
  const args = [...argv];
  if (args.length === 0) {
    process.stdout.write(`${HELP}\n`);
    refuse('usage-invalid');
  }
  if (args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    process.stdout.write(`${HELP}\n`);
    return null;
  }
  const command = args.shift();
  if (!COMMANDS.includes(command)) refuse('usage-invalid');
  const allowed = COMMAND_OPTIONS[command];
  const positionals = [];
  const options = {
    outputBytes: LIMITS.outputBytes.default,
    timeoutMs: LIMITS.timeoutMs.default,
    rawBytes: LIMITS.rawBytes.default,
    input: '-',
    capture: undefined,
    kind: 'auto',
  };
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith('--')) {
      if (command !== 'compare' || positionals.length >= 2) refuse('usage-invalid');
      positionals.push(token);
      continue;
    }
    const equals = token.indexOf('=');
    const name = equals === -1 ? token : token.slice(0, equals);
    if (!allowed.includes(name)) refuse('usage-invalid');
    const inline = equals === -1 ? null : token.slice(equals + 1);
    const value = () => {
      if (inline !== null) return inline;
      index += 1;
      if (index >= args.length) refuse('usage-invalid');
      return args[index];
    };
    if (OPTION_BOUNDS[name] !== undefined) options[OPTION_BOUNDS[name]] = parseBound(name, value());
    else if (name === '--input') options.input = value();
    else if (name === '--capture') options.capture = value();
    else {
      const kind = value();
      if (!KINDS.includes(kind)) refuse('usage-invalid');
      options.kind = kind;
    }
  }
  if (command === 'compare' && positionals.length !== 2) refuse('usage-invalid');
  return { command, positionals, options };
}

function capabilitiesReport(options) {
  const commands = {};
  for (const name of LIMITS.commands) {
    const path = lookupOnPath(name);
    commands[name] = { available: path !== null, path: path === null ? null : (boundedScalar(path, LIMITS.pathLength) ?? null) };
  }
  const namesOnly = Object.fromEntries(Object.entries(commands).map(([name, entry]) => [name, { available: entry.available, path: null }]));
  const environment = {};
  for (const name of LIMITS.environmentNames) {
    // Name presence only. The value is never read, inspected, tested for emptiness or emitted, so this says
    // nothing about whether a credential exists, is valid or is accepted.
    environment[name] = { present: Object.hasOwn(process.env, name), value: null };
  }
  const top = commands.git.available ? gitWorkTree(process.cwd(), options.timeoutMs) : null;
  const runtime = {
    node: boundedScalar(process.version, 40),
    platform: boundedScalar(process.platform, 40),
    gitWorkTree: top !== null,
    repositoryRoot: top === null ? null : (boundedScalar(top, LIMITS.pathLength) ?? null),
  };
  const report = (notes, listed, present, truncated) => ({
    tool: TOOL,
    command: 'capabilities',
    limits: { outputBytes: options.outputBytes, timeoutMs: options.timeoutMs },
    output: { capBytes: options.outputBytes, truncated },
    runtime,
    commands: listed,
    environment: present,
    notes,
  });
  return fitCandidates(options.outputBytes, [
    report(CAPABILITY_NOTES, commands, environment, false),
    report([], commands, environment, true),
    report([], namesOnly, environment, true),
    {
      tool: TOOL,
      command: 'capabilities',
      limits: { outputBytes: options.outputBytes, timeoutMs: options.timeoutMs },
      output: { capBytes: options.outputBytes, truncated: true },
      commands: namesOnly,
    },
    {
      tool: TOOL,
      command: 'capabilities',
      output: { capBytes: options.outputBytes, truncated: true },
      probedCommands: LIMITS.commands.length,
    },
  ]);
}

function runCommand(request) {
  const { command, options } = request;
  if (command === 'capabilities') return capabilitiesReport(options);
  if (command === 'compare') return compareOperands(request);
  const raw = readBounded(options.input, options.rawBytes);
  return command === 'project-github' ? projectGitHub(raw, options) : sessionHandoff(raw, options);
}

export function main(argv) {
  try {
    const request = parseArgs(argv);
    if (request === null) return 0;
    process.stdout.write(runCommand(request));
    return 0;
  } catch (error) {
    if (error instanceof Budget) process.stderr.write(`agent handoff: budget; ${error.code}\n`);
    else if (error instanceof Refused) process.stderr.write(`agent handoff: refused; ${error.code}${error.detail ?? ''}\n`);
    else process.stderr.write('agent handoff: unusable; the command could not complete\n');
    return error instanceof Budget ? 3 : 1;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
