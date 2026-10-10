/**
 * Hylja development workflow guard: pure decision helper for Pi bash tool calls.
 *
 * Developer tooling, not runtime core and not a security boundary. It authenticates nothing, sends no
 * bytes, executes no command and writes no log. It exists because one observed pipeline run burned
 * eight minutes on `find / -name hylja-implementer.md` while the exact path had already been supplied.
 *
 * Two decisions, both pure and total:
 * 1. Block a `find` whose search root is a machine-wide absolute root. Scoped and relative roots, the
 *    caller's home directory and the current worktree stay allowed.
 * 2. Preserve explicit finite positive `timeout` values without clamping; omission or null selects
 *    no tool cap. Malformed values are refused. A declared finite command window still requires
 *    a finite cap that fits its stop and finish reserve.
 *
 * Neither decision parses shell. The command string is split on control separators and whitespace,
 * quotes are stripped, and only the leading tokens of each segment are inspected: environment
 * assignments, wrapper names and wrapper flags are skipped to find the command. Dynamic expansion
 * (`$(...)`, backticks, variables), `eval`, aliases, a wrapper that takes a value argument
 * (`sudo -u other find /`), `find` invoked indirectly, and any other API that reaches a shell are
 * outside this guard by construction. Treat a pass here as a workflow speed bump, never as proof that a
 * command is safe, bounded or correct. The timeout decision applies only to calls that reach this
 * guard's builtin `bash` handling; it adds no bound to other tools or APIs.
 *
 * Optional command-window helpers snapshot a declared stop and reserve, then check supplied UTC;
 * they do not observe a native deadline or prove final backend execution timing.
 * No input text reaches the caller: refusals use fixed reasons.
 */

import { homedir } from 'node:os';

/** Fixed, non-echoing setup refusal; approval is trusted coordinator configuration, not authentication. */
export const INVALID_VALIDATION_APPROVAL = 'Invalid Hylja validation approval';
export const INVALID_COMMAND_WINDOW = 'Invalid Hylja command window';

/** Trusted run configuration, snapshotted once without invoking accessors. No deadline renewal. */
export function snapshotCommandWindow(record) {
	if (record === undefined) return undefined;
	try {
		if (record === null || typeof record !== 'object' || Object.getPrototypeOf(record) !== Object.prototype) throw new Error();
		const fields = Object.getOwnPropertyDescriptors(record);
		if (Reflect.ownKeys(fields).length !== 2 || !fields.hardStopMs || !fields.reserveSeconds ||
			!Object.hasOwn(fields.hardStopMs, 'value') || !Object.hasOwn(fields.reserveSeconds, 'value')) throw new Error();
		const hardStopMs = fields.hardStopMs.value;
		const reserveSeconds = fields.reserveSeconds.value;
		if (!Number.isSafeInteger(hardStopMs) || hardStopMs <= 0 ||
			!Number.isSafeInteger(reserveSeconds) || reserveSeconds < 0 || reserveSeconds > 86400) throw new Error();
		return Object.freeze({ hardStopMs, reserveSeconds });
	} catch {
		throw new Error(INVALID_COMMAND_WINDOW);
	}
}

/** Pure admission at supplied UTC: cap plus fixed finish reserve must fit, rounded up to milliseconds. */
export function commandFitsWindow(window, now, seconds) {
	if (!Number.isSafeInteger(now) || now < 0 || typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0) return false;
	const requiredMs = Math.ceil(seconds * 1000) + window.reserveSeconds * 1000;
	return Number.isSafeInteger(requiredMs) && requiredMs <= window.hardStopMs - now;
}

/** Snapshot the compact approval once; malformed records never grant a partial approval. */
export function snapshotValidationApproval(record) {
	if (record === undefined) return undefined;
	try {
		if (record === null || typeof record !== 'object' || Object.getPrototypeOf(record) !== Object.prototype) throw new Error();
		const fields = Object.getOwnPropertyDescriptors(record);
		if (Reflect.ownKeys(fields).length !== 2 || !fields.cwd || !fields.commands ||
			!Object.hasOwn(fields.cwd, 'value') || !Object.hasOwn(fields.commands, 'value')) throw new Error();
		const cwd = fields.cwd.value;
		const commands = fields.commands.value;
		if (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.length > 4096 || /[\x00-\x1f\x7f]/.test(cwd) ||
			!Array.isArray(commands) || Object.getPrototypeOf(commands) !== Array.prototype) throw new Error();
		const length = Object.getOwnPropertyDescriptor(commands, 'length')?.value;
		if (!Number.isInteger(length) || length < 1 || length > 2) throw new Error();
		const entries = Object.getOwnPropertyDescriptors(commands);
		if (Reflect.ownKeys(entries).length !== length + 1) throw new Error();
		const copy = [];
		for (let index = 0; index < length; index += 1) {
			const entry = entries[index];
			if (!entry || !Object.hasOwn(entry, 'value')) throw new Error();
			const command = entry.value;
			if (typeof command !== 'string' || command.trim().length === 0 || command.length > 16384 || command.includes('\0') ||
				copy.includes(command)) throw new Error();
			copy.push(command);
		}
		return Object.freeze({ cwd, commands: Object.freeze(copy) });
	} catch {
		throw new Error(INVALID_VALIDATION_APPROVAL);
	}
}

/**
 * Top-level absolute roots that mean "the whole machine", matched on the first path segment. `/tmp`,
 * `/var/tmp` and unlisted absolute roots are deliberately absent: this project keeps scratch work in
 * a temp file. Allowed roots do not imply a bounded or safe scan.
 */
export const MACHINE_WIDE_ROOT_SEGMENTS = new Set([
	'Applications', 'Library', 'System', 'Users', 'Volumes',
	'bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib32', 'lib64',
	'mnt', 'media', 'nix', 'opt', 'private', 'proc', 'root', 'run',
	'sbin', 'snap', 'srv', 'sys', 'usr', 'var',
]);

/** Leading words that may precede the real command; skipped when locating it. */
const COMMAND_WRAPPERS = new Set(['command', 'env', 'ionice', 'nice', 'nohup', 'stdbuf', 'sudo', 'time', 'xargs']);

/** Shells whose `-c` string is tokenized here, so `sh -c "find / ..."` is still inspected. */
const SHELL_WRAPPERS = new Set(['bash', 'dash', 'ksh', 'rbash', 'sh', 'zsh']);

/** Shell control operators that end one segment. Splitting is textual, not a grammar. */
const SEGMENT_SEPARATORS = /[;&|\n\r]+/;

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

export const BLOCK_REASON_MACHINE_WIDE_SEARCH =
	'Hylja workflow guard refused this call: a machine-wide filesystem search is not allowed in this project. '
	+ 'Use the exact file path the task already provides, or search a named root such as the repository worktree, '
	+ 'your home directory, or a directory named in the brief. The guard logs no command, argument or output.';

export const BLOCK_REASON_INVALID_TIMEOUT =
	'Hylja workflow guard refused this call: the bash timeout must be a finite number of seconds greater than zero. '
	+ 'Omit it or pass null for no tool cap, or pass a positive number of seconds. '
	+ 'The guard logs no command, argument or output.';

/** Strips surrounding quote characters from a token, including an unterminated one. */
function unquote(token) {
	let value = token.trim();
	while (value.length > 0 && (value.startsWith('"') || value.startsWith("'"))) value = value.slice(1);
	while (value.length > 0 && (value.endsWith('"') || value.endsWith("'"))) value = value.slice(0, -1);
	return value;
}

/** Index of the first token that could be the command itself. */
function commandStartIndex(tokens) {
	let index = 0;
	let afterWrapper = false;
	while (index < tokens.length) {
		const token = unquote(tokens[index]);
		if (ASSIGNMENT.test(token) || COMMAND_WRAPPERS.has(token) || SHELL_WRAPPERS.has(token)) {
			afterWrapper = true;
			index += 1;
			continue;
		}
		// A wrapper flag (`-c`, `-lc`, `-x`) belongs to the wrapper, not to the command.
		if (afterWrapper && token.startsWith('-')) {
			index += 1;
			continue;
		}
		break;
	}
	return index;
}

/** The search root of a `find` invocation, or `undefined` when the segment is not a `find`. */
function findSearchRoot(segment) {
	const tokens = segment.trim().split(/\s+/).filter((token) => token.length > 0);
	let index = commandStartIndex(tokens);
	const executable = index < tokens.length ? unquote(tokens[index]) : '';
	if (executable.split('/').pop() !== 'find') return undefined;
	index += 1;
	while (index < tokens.length) {
		const token = unquote(tokens[index]);
		if (token.startsWith('-')) {
			index += 1;
			continue;
		}
		return token;
	}
	return undefined;
}

/** Collapses repeated separators and a trailing slash, so `//usr/` and `/usr` compare equal. */
function normalizeAbsoluteRoot(root) {
	const collapsed = root.replace(/\/{2,}/g, '/');
	return collapsed.length > 1 && collapsed.endsWith('/') ? collapsed.slice(0, -1) : collapsed;
}

/** Named roots that always stay allowed: the caller's home directory and the current working directory. */
function namedRoots(options) {
	const roots = new Set();
	const home = options.home ?? homedir();
	const cwd = options.cwd ?? process.cwd();
	if (typeof home === 'string' && home.startsWith('/')) roots.add(normalizeAbsoluteRoot(home));
	if (typeof cwd === 'string' && cwd.startsWith('/')) roots.add(normalizeAbsoluteRoot(cwd));
	for (const extra of options.namedRoots ?? []) {
		if (typeof extra === 'string' && extra.startsWith('/')) roots.add(normalizeAbsoluteRoot(extra));
	}
	return [...roots];
}

/** True when the root is an absolute path outside every named root whose first segment is machine-wide. */
export function isMachineWideFindRoot(rawRoot, options = {}) {
	const root = normalizeAbsoluteRoot(unquote(rawRoot));
	if (!root.startsWith('/')) return false;
	if (root === '/') return true;
	const roots = namedRoots(options);
	if (roots.some((named) => root === named || root.startsWith(`${named}/`))) return false;
	const first = root.split('/')[1] ?? '';
	return MACHINE_WIDE_ROOT_SEGMENTS.has(first);
}

/** Preserve a finite positive request; omission/null selects no cap, never a timing baseline. */
export function resolveCommandTimeout(value) {
	if (value === undefined || value === null) return { allowed: true, seconds: undefined };
	if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return { allowed: false, seconds: undefined };
	return { allowed: true, seconds: value };
}

/**
 * The one entry point the Pi adapter calls.
 *
 * @param input - the bash tool input, mutated by the caller with the returned timeout.
 * @param options - named roots plus an installation-snapshotted validation approval; defaults to
 * the real home and working directory. Exact approval scope is retained as receipt metadata;
 * approval no longer changes the requested timeout or bypasses any refusal.
 * @returns `{ allowed: false, reason }` to block, or `{ allowed: true, timeout, validationApproved }`.
 * An undefined timeout must be omitted before calling Pi's optional-number Bash API.
 */
export function evaluateBashToolInput(input, options = {}) {
	const command = input !== null && typeof input === 'object' && typeof input.command === 'string' ? input.command : '';
	for (const segment of command.split(SEGMENT_SEPARATORS)) {
		const root = findSearchRoot(segment);
		if (root !== undefined && isMachineWideFindRoot(root, options)) {
			return { allowed: false, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH };
		}
	}
	// Exact whole-string comparison only; this does not verify shell safety or coordinator authority.
	const approved = options.validationApproval !== undefined && options.cwd === options.validationApproval.cwd &&
		options.validationApproval.commands.includes(command);
	const timeout = resolveCommandTimeout(input !== null && typeof input === 'object' ? input.timeout : undefined);
	if (!timeout.allowed) return { allowed: false, reason: BLOCK_REASON_INVALID_TIMEOUT };
	return { allowed: true, timeout: timeout.seconds, validationApproved: approved };
}
