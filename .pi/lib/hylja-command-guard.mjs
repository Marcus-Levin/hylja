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
 * 2. Guarantee a finite positive `timeout` for every bash call that reaches this guard: a default when
 *    the caller omits it, a tighter explicit value preserved, an excessive value clamped, and a
 *    malformed value refused.
 *
 * Neither decision parses shell. The command string is split on control separators and whitespace,
 * quotes are stripped, and only the leading tokens of each segment are inspected: environment
 * assignments, wrapper names and wrapper flags are skipped to find the command. Dynamic expansion
 * (`$(...)`, backticks, variables), `eval`, aliases, a wrapper that takes a value argument
 * (`sudo -u other find /`), `find` invoked indirectly, and any other API that reaches a shell are
 * outside this guard by construction. Treat a pass here as a workflow speed bump, never as proof that a
 * command is safe, bounded or correct. The timeout decision bounds only calls that reach this guard's
 * builtin `bash` handling; other tools and other APIs receive no bound from here.
 *
 * No input text reaches the caller: a refusal is one of two fixed reasons below.
 */

import { homedir } from 'node:os';

/** Applied when the model omits `timeout`; Pi's builtin bash has no default of its own. */
export const DEFAULT_COMMAND_TIMEOUT_SECONDS = 120;

/** Ceiling for an explicit request; a larger value is clamped, never granted. */
export const MAX_COMMAND_TIMEOUT_SECONDS = 300;

/**
 * Top-level absolute roots that mean "the whole machine", matched on the first path segment. `/tmp`,
 * `/var/tmp` and unlisted absolute roots are deliberately absent: this project keeps scratch work in
 * a temp file, and the timeout default already bounds any scan.
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
	+ `Omit it to accept the ${DEFAULT_COMMAND_TIMEOUT_SECONDS}s guard default, or pass a positive number of seconds. `
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

/**
 * Decides the timeout for one bash call: default when absent, explicit tighter value preserved,
 * excessive value clamped, malformed value refused.
 */
export function resolveCommandTimeout(value) {
	if (value === undefined) return { allowed: true, seconds: DEFAULT_COMMAND_TIMEOUT_SECONDS };
	if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return { allowed: false, seconds: undefined };
	return { allowed: true, seconds: Math.min(value, MAX_COMMAND_TIMEOUT_SECONDS) };
}

/**
 * The one entry point the Pi adapter calls.
 *
 * @param input - the bash tool input, mutated by the caller with the returned timeout.
 * @param options - named roots for the decision; defaults to the real home and working directory.
 * @returns `{ allowed: false, reason }` to block, or `{ allowed: true, timeout }` to apply.
 */
export function evaluateBashToolInput(input, options = {}) {
	const command = input !== null && typeof input === 'object' && typeof input.command === 'string' ? input.command : '';
	for (const segment of command.split(SEGMENT_SEPARATORS)) {
		const root = findSearchRoot(segment);
		if (root !== undefined && isMachineWideFindRoot(root, options)) {
			return { allowed: false, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH };
		}
	}
	const timeout = resolveCommandTimeout(input !== null && typeof input === 'object' ? input.timeout : undefined);
	if (!timeout.allowed) return { allowed: false, reason: BLOCK_REASON_INVALID_TIMEOUT };
	return { allowed: true, timeout: timeout.seconds };
}
