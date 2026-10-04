#!/usr/bin/env node
/**
 * Hylja native foreground lane CLI.
 *
 * Root-owned developer tooling, not runtime core and not a security boundary, not a shell sandbox. It
 * reads one bounded root-owned lane config, launches Pi once with exactly three extensions (the
 * installed `pi-subagents` entry, the project workflow guard and the opt-in controller) and the one
 * fixed input the controller answers, then verifies the public evidence that leaf left behind. There
 * is no coordinator model in this process, no model override, no role fallback, no background mode
 * and no nesting: one lane, one child, one receipt.
 *
 * Every evidence path must be fresh, so a previous run's receipt, dispatch tuple, progress file or
 * verification record can never be reused as this run's evidence. The dispatch tuple the controller
 * persisted before emitting its request is mandatory: a receipt from a different attempt, a nonzero
 * native exit, a fired terminal deadline, an unbound verdict, an unresolved launch contract or a
 * metadata record that does not match the guard identity and bound digest the preflight declared is a
 * setup failure, never a completed lane.
 *
 * Exit codes: 0 verified completed lane, 2 setup or evidence failure (INCOMPLETE), 3 the native leaf
 * finished in a non-completed state.
 */

import { spawn } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, readdirSync, readSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
	FIXED_LANE_INPUT,
	LANE_CONFIG_ENV,
	LANE_ROLES,
	LANE_SUBAGENTS_ENV,
	LANE_VERDICTS,
	MAX_PROGRESS_BYTES,
	MAX_PROGRESS_RECORDS,
	admitRequiredReferences,
	checkRequiredReferenceList,
	probeReferenceMetadata,
	resolveInstalledModules,
} from '../../.pi/lib/hylja-native-lane.ts';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ARTIFACT_SUFFIXES = ['_meta.json', '_output.md'];
const MAX_CONFIG_BYTES = 65_536;
const MAX_TASK_CHARS = 1_048_576;
/** Extra wall clock over the native request timeout before the watchdog stops the owned child. */
export const WATCHDOG_GRACE_MS = 60_000;
/** Grace between SIGTERM and SIGKILL for the owned child. */
export const KILL_GRACE_MS = 10_000;
/** Final finite wait for `close` after SIGKILL. Never an indefinite wait. */
export const CLOSE_WAIT_MS = 10_000;
/**
 * Hard ceiling on one positional read of the default platform, whatever a caller asks for. It is the
 * writer's own byte window, not a second number beside it: a read clamped below the window the
 * progress parser must cover would silently hide the records the writer retained.
 */
export const MAX_RANGE_READ_BYTES = MAX_PROGRESS_BYTES;

export const SETUP_FAILURES = {
	argv: 'SETUP_FAILED_ARGUMENTS',
	config: 'SETUP_FAILED_LANE_CONFIG',
	references: 'SETUP_FAILED_REQUIRED_REFERENCE',
	install: 'SETUP_FAILED_INSTALL_CHECK',
	spawn: 'SETUP_FAILED_SPAWN',
	stale: 'SETUP_FAILED_STALE_EVIDENCE',
	tuple: 'SETUP_FAILED_TUPLE_MISMATCH',
	nativeExit: 'SETUP_FAILED_NATIVE_EXIT',
	receipt: 'SETUP_FAILED_MISSING_RECEIPT',
	malformed: 'SETUP_FAILED_MALFORMED_RECEIPT',
	artifacts: 'SETUP_FAILED_MISSING_ARTIFACTS',
	model: 'SETUP_FAILED_MODEL_MISMATCH',
	role: 'SETUP_FAILED_ROLE_MISMATCH',
	guard: 'SETUP_FAILED_GUARD_NOT_EFFECTIVE',
	contract: 'SETUP_FAILED_LAUNCH_CONTRACT',
	acceptance: 'SETUP_FAILED_RUNTIME_ACCEPTANCE',
	status: 'SETUP_FAILED_NON_COMPLETED_STATUS',
	cleanup: 'SETUP_FAILED_CLEANUP_UNCERTAIN',
};

/**
 * The acceptance states the installed extension actually reports. A direct-API writer or reviewer run
 * through this controller resolves `not-required` because the role profile disables the native gate
 * with the deprecated false shorthand; a writer whose gate did run reports `checked`. Anything else,
 * including an actual acceptance failure, is refused. This is not a whitelist of intent: it is the
 * two observed forms, and it never implies the writer gate passed.
 */
const ACCEPTED_RUNTIME_ACCEPTANCE = ['not-required', 'checked'];

const TUPLE_FIELDS = ['requestId', 'ownerRunId', 'nodeId'];
const USAGE_FIELDS = ['input', 'output', 'cacheRead', 'cacheWrite', 'cost', 'turns', 'toolCalls', 'durationMs'];
/** The launch-resolved extension record the installed extension actually writes, per the retained smoke. */
const RESOLVED_EXTENSION_VERSION = 1;
const RESOLVED_EXTENSION_SOURCE = 'launch-resolved';
const RESOLVED_EXTENSION_LISTS = ['runtime', 'configured', 'required', 'effective'];

const fail = (code, detail) => ({ ok: false, verdict: 'INCOMPLETE', reason: code, ...(detail ? { detail } : {}) });

const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const isText = (value) => typeof value === 'string' && value.length > 0 && value.length <= 1_048_576;
const isCount = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const isDigestList = (value) => Array.isArray(value) && value.every((entry) => typeof entry === 'string' && entry.length > 0);

/** Reads the role profile this repository already owns: model and deadline are its frontmatter. */
export function readRoleProfile(agent, fs = defaultFs) {
	const text = fs.readFile(join(repoRoot, '.pi', 'agents', `${agent}.md`), 'utf8');
	const field = (name) => new RegExp(`^${name}:\\s*(\\S+)$`, 'm').exec(text)?.[1];
	const model = field('model');
	const timeoutMs = Number(field('timeoutMs'));
	if (model === undefined || !Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new Error(SETUP_FAILURES.install);
	return { model, timeoutMs };
}

const defaultFs = {
	readFile: (path) => readFileSync(path, 'utf8'),
	exists: existsSync,
	// Bounded metadata over one declared reference path: stat plus one open that reads nothing and is
	// closed immediately. Absent, broken and denied paths answer null and are never admitted.
	file: probeReferenceMetadata,
	size: (path) => statSync(path).size,
	read: (path, offset, length) => {
		// A bounded positional read of exactly the requested window, never a whole-file read: the
		// caller sizes the tail, this clamps it, and the descriptor is closed in every path.
		if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length)) throw new Error(SETUP_FAILURES.malformed);
		const want = Math.min(length, MAX_RANGE_READ_BYTES);
		if (want <= 0) return Buffer.alloc(0);
		const handle = openSync(path, 'r');
		try {
			const buffer = Buffer.allocUnsafe(want);
			return buffer.subarray(0, readSync(handle, buffer, 0, want, offset));
		} finally {
			closeSync(handle);
		}
	},
	readdir: (path) => readdirSync(path),
	writeFile: (path, data) => writeFileSync(path, data, { mode: 0o600 }),
};

/** Validates the bounded root-owned lane config. Fixed failure codes, never a planted value. */
export function validateLaneConfig(value, profile) {
	if (!isObject(value)) return fail(SETUP_FAILURES.config);
	if (!LANE_ROLES.includes(value.agent)) return fail(SETUP_FAILURES.config);
	if (typeof value.task !== 'string' || value.task.length === 0 || value.task.length > MAX_TASK_CHARS) {
		return fail(SETUP_FAILURES.config);
	}
	if (typeof value.key !== 'string' || value.key.length === 0) return fail(SETUP_FAILURES.config);
	// One optional bounded structured list of simple labels and absolute paths. Absent and an empty list
	// are the same assertion of no references; any other shape is the fixed reference refusal rather
	// than a repaired value, and no declared label or path is echoed into the record.
	const declared = checkRequiredReferenceList(value.requiredReferences);
	if (declared.ok !== true) return fail(SETUP_FAILURES.references);
	const requiredReferences = declared.references ?? [];
	if (!Number.isInteger(value.timeoutMs) || value.timeoutMs <= 0 || value.timeoutMs > profile.timeoutMs) {
		return fail(SETUP_FAILURES.config);
	}
	// Optional soft budget: a positive integer strictly below the finite hard timeout. Absent keeps
	// the lane's previous behaviour; present but invalid is a refusal, never a repaired value. It
	// arms one warning timer in the child and grants the child no authority, so root still owns the
	// hard clock, the watchdog and every verdict.
	let softBudgetMs;
	if ('softBudgetMs' in value) {
		if (!Number.isInteger(value.softBudgetMs) || value.softBudgetMs <= 0 || value.softBudgetMs >= value.timeoutMs) {
			return fail(SETUP_FAILURES.config);
		}
		softBudgetMs = value.softBudgetMs;
	}
	const paths = ['cwd', 'sessionDir', 'receipt', 'verification', 'progress', 'dispatch', 'pi', 'subagents', 'guard', 'controller'];
	for (const field of paths) {
		if (typeof value[field] !== 'string' || !value[field].startsWith('/')) return fail(SETUP_FAILURES.config);
	}
	if ('model' in value) return fail(SETUP_FAILURES.config); // No model override exists, so refuse one.
	return {
		ok: true,
		config: {
			key: value.key,
			agent: value.agent,
			task: value.task,
			cwd: value.cwd,
			timeoutMs: value.timeoutMs,
			...(softBudgetMs === undefined ? {} : { softBudgetMs }),
			...(requiredReferences.length === 0 ? {} : { requiredReferences }),
			sessionDir: value.sessionDir,
			receipt: value.receipt,
			verification: value.verification,
			progress: value.progress,
			dispatch: value.dispatch,
			pi: value.pi,
			subagents: value.subagents,
			guard: value.guard,
			controller: value.controller,
		},
	};
}

/**
 * Admits every declared reference by metadata alone, before Pi is spawned: each path must be an
 * existing regular file this host can open for reading. Nothing is read from the file, no path is
 * searched for or substituted, and admission is not approval nor a guarantee about later
 * availability. Omission runs no probe at all, so the previous behaviour is unchanged.
 */
export function checkRequiredReferences(config, fs) {
	const references = config.requiredReferences ?? [];
	if (references.length === 0) return { ok: true };
	// The host's own filesystem view is the seam; a host that cannot answer admits nothing.
	const probe = typeof fs.file === 'function' ? (path) => fs.file(path) : () => null;
	try {
		admitRequiredReferences(references, probe);
	} catch {
		return fail(SETUP_FAILURES.references);
	}
	return { ok: true };
}

/** The exact argv. No discovery, no ambient extension discovery, no skills, one fixed message. */
export function buildArgv(config) {
	return [
		'--print', '--no-extensions', '--no-skills', '--no-prompt-templates',
		'--approve', '--session-dir', config.sessionDir,
		'--extension', config.subagents,
		'--extension', config.guard,
		'--extension', config.controller,
		'--', FIXED_LANE_INPUT,
	];
}

/**
 * One bundled finite setup pass: role profile, declared entrypoints, the installed package's own
 * export map, and the proof that this evidence has not been written before.
 */
export function checkInstall(config, profile, fs, resolveModules = resolveInstalledModules) {
	for (const path of [config.pi, config.subagents, config.guard, config.controller, config.cwd, config.sessionDir]) {
		if (!fs.exists(path)) return fail(SETUP_FAILURES.install);
	}
	for (const path of [config.receipt, config.verification, config.progress, config.dispatch]) {
		if (fs.exists(path)) return fail(SETUP_FAILURES.stale); // Fresh evidence paths only, never a reused run.
	}
	if (!profile.model.endsWith(':max')) return fail(SETUP_FAILURES.install);
	try {
		resolveModules(config.subagents);
	} catch {
		return fail(SETUP_FAILURES.install);
	}
	return { ok: true };
}

/**
 * Discovers the public evidence for this runId and agent with exactly one listing of the supplied
 * session directory, and requires exactly one metadata file and one public output file. Filenames are
 * never rebuilt from a pattern, and anything not `*_meta.json` or `*_output.md` is never opened.
 */
export function discoverPublicArtifacts(config, runId, agent, fs) {
	const dir = join(config.sessionDir, 'subagent-artifacts');
	if (!fs.exists(dir)) return fail(SETUP_FAILURES.artifacts);
	let names;
	try {
		names = fs.readdir(dir).filter((name) => name.startsWith(`${runId}_${agent}`) && ARTIFACT_SUFFIXES.some((s) => name.endsWith(s)));
	} catch {
		return fail(SETUP_FAILURES.artifacts);
	}
	const metas = names.filter((name) => name.endsWith('_meta.json'));
	const outputs = names.filter((name) => name.endsWith('_output.md'));
	if (metas.length !== 1 || outputs.length !== 1) return fail(SETUP_FAILURES.artifacts);
	// One pair means one attempt: the metadata and the public output must be the same artifact, so
	// `_0_meta.json` beside `_1_output.md` is two runs' files, never one lane's evidence.
	const stem = (name, suffix) => name.slice(0, -suffix.length);
	if (stem(metas[0], '_meta.json') !== stem(outputs[0], '_output.md')) return fail(SETUP_FAILURES.artifacts);
	return { ok: true, artifacts: { meta: join(dir, metas[0]), output: join(dir, outputs[0]) } };
}

/** The dispatch tuple the controller persisted before it emitted its request. */
function readDispatchTuple(value) {
	if (!isObject(value) || !isObject(value.expected)) return null;
	for (const field of TUPLE_FIELDS) {
		if (!isText(value[field]) || !isText(value.expected.launchContractDigest)) return null;
	}
	if (typeof value.agent !== 'string' || !isText(value.expected.guardExtension)) return null;
	if (!isDigestList(value.expected.configuredExtensions)) return null;
	if (value.expected.disableAmbientExtensions !== true) return null;
	if (value.expected.context !== 'fresh') return null;
	return value;
}

/**
 * Binds the receipt's verdict field to the literal first line of its result text, exactly the way the
 * controller derived it: a declared verdict line must equal the field, and a result carrying no
 * declared verdict line may only resolve to the `INCOMPLETE` fallback the controller assigns it. Empty
 * text, an unbound field and a contradiction are refused, so no result can carry an approval its own
 * text never declared.
 */
function verdictAgreesWithResult(verdict, text) {
	const first = text.split('\n', 1)[0].trim();
	return LANE_VERDICTS.includes(first) ? first === verdict : verdict === 'INCOMPLETE';
}

/** The first non-empty line of a public artifact, compared literally and never by containment. */
function leadingLine(text) {
	return text.split('\n').map((line) => line.trim()).find((line) => line.length > 0) ?? '';
}

/**
 * Schema check for the public receipt, run before anything is compared: a mistyped verdict, a
 * non-numeric usage field, a missing tuple field, an unbound verdict or a nonzero exit is malformed
 * evidence, never a partially valid lane.
 */
export function isValidReceipt(value) {
	if (!isObject(value) || !LANE_VERDICTS.includes(value.verdict)) return false;
	if (!isText(value.status) || !isText(value.runId) || typeof value.agent !== 'string') return false;
	if (!isObject(value.result) || value.result.kind !== 'text' || !isText(value.result.text)) return false;
	if (!isObject(value.usage)) return false;
	for (const field of USAGE_FIELDS) {
		if (!isCount(value.usage[field])) return false;
	}
	for (const field of TUPLE_FIELDS) {
		if (typeof value[field] !== 'string' || value[field].length === 0) return false;
	}
	if (value.exitCode !== 0) return false;
	if (!verdictAgreesWithResult(value.verdict, value.result.text)) return false;
	return isText(value.model) && isText(value.thinking) && isText(value.launchContractDigest);
}

/** Schema check for the public receipt. Anything absent, mistyped or non-numeric is refused. */
function readReceipt(value) {
	return isValidReceipt(value) ? value : null;
}

/**
 * Checks the runtime record against the contract this dispatch was launched with. Nothing is inferred
 * from the leaf's text, and the public output file must carry the literal terminal result.
 */
export function verifyArtifacts(config, profile, dispatch, receipt, artifacts, fs) {
	if (!isObject(dispatch)) return fail(SETUP_FAILURES.tuple);
	if (!isObject(receipt)) return fail(SETUP_FAILURES.malformed);
	if (!isValidReceipt(receipt)) return fail(SETUP_FAILURES.malformed);
	if (TUPLE_FIELDS.some((field) => receipt[field] !== dispatch[field]) || receipt.agent !== dispatch.agent) {
		return fail(SETUP_FAILURES.tuple);
	}
	if (receipt.status !== 'completed') return fail(SETUP_FAILURES.status, receipt.status);
	const expected = dispatch.expected;
	if (receipt.launchContractDigest !== expected.launchContractDigest) return fail(SETUP_FAILURES.contract);
	if (receipt.agent !== config.agent || dispatch.agent !== config.agent) return fail(SETUP_FAILURES.role);
	// The effective model is the role profile model at :max, and the resolved thinking must match.
	if (receipt.model !== expected.model || receipt.model !== profile.model || !receipt.model.endsWith(':max')) {
		return fail(SETUP_FAILURES.model);
	}
	if (expected.thinking !== null && receipt.thinking !== expected.thinking) return fail(SETUP_FAILURES.model);
	let meta;
	try {
		meta = JSON.parse(fs.readFile(artifacts.meta));
	} catch {
		return fail(SETUP_FAILURES.malformed);
	}
	if (!isObject(meta)) return fail(SETUP_FAILURES.malformed);
	if (meta.runId !== receipt.runId || meta.agent !== config.agent) return fail(SETUP_FAILURES.role);
	if (meta.model !== expected.model) return fail(SETUP_FAILURES.model);
	if (!isText(meta.launchContractDigest) || meta.launchContractDigest !== expected.launchContractDigest) {
		return fail(SETUP_FAILURES.contract);
	}
	// Guard identity: the declared guard extension must be in the resolved configured set, ambient
	// extensions must be off, and nothing may be omitted from the effective set.
	const resolved = isObject(meta.launchResolvedExtensions) ? meta.launchResolvedExtensions : null;
	// One shared boundary rule for all four lists: each must be present and be an array of non-empty
	// digest strings, validated together before any of them is extracted. No list is defaulted to `[]`,
	// because an absent or mistyped list is missing evidence, not an assertion that nothing was
	// required at runtime. An explicitly empty list is a real assertion and stays valid.
	const resolvedLists = RESOLVED_EXTENSION_LISTS.every((name) => isDigestList(resolved?.[name]));
	const configured = resolvedLists ? resolved.configured : null;
	const runtime = resolvedLists ? resolved.runtime : null;
	const required = resolvedLists ? resolved.required : null;
	const effective = resolvedLists ? resolved.effective : null;
	const omitted = isObject(resolved?.omitted) ? resolved.omitted : null;
	if (
		// Only the launch-resolved schema the installed extension actually writes is evidence here:
		// another version or another source is refused, never read as a weaker field it happens to hold.
		resolved?.version !== RESOLVED_EXTENSION_VERSION
		|| resolved?.source !== RESOLVED_EXTENSION_SOURCE
		|| !resolvedLists
		|| resolved?.disableAmbientExtensions !== true
		|| expected.disableAmbientExtensions !== true
		|| expected.guardExtension !== config.guard
		// The metadata reports opaque extension digests while preflight reports paths, so identity is
		// bound by the declared guard path above and by the launch digest equality checked earlier;
		// here the resolved set must be the declared number of configured extensions, ambient-off,
		// with nothing omitted from the effective set, and every configured, runtime and required
		// digest must occur in the effective set.
		|| configured.length !== expected.configuredExtensions.length
		|| omitted === null
		|| Object.values(omitted).some((count) => count !== 0)
		|| RESOLVED_EXTENSION_LISTS.some((name) => omitted[name] !== 0)
		|| !configured.every((digest) => effective.includes(digest))
		|| !runtime.every((digest) => effective.includes(digest))
		|| !required.every((digest) => effective.includes(digest))
	) {
		return fail(SETUP_FAILURES.guard);
	}
	const acceptance = isObject(meta.acceptance) ? meta.acceptance : null;
	if (acceptance === null || !ACCEPTED_RUNTIME_ACCEPTANCE.includes(acceptance.status)) return fail(SETUP_FAILURES.acceptance);
	let output;
	try {
		output = fs.readFile(artifacts.output);
	} catch {
		return fail(SETUP_FAILURES.artifacts);
	}
	if (!output.includes(Buffer.from(receipt.result.text, 'utf8'))) return fail(SETUP_FAILURES.artifacts);
	// The public artifact must lead with the literal line the receipt binds. Finding the terminal text
	// somewhere inside the output is not on its own proof that the leaf declared that verdict.
	if (leadingLine(output) !== receipt.result.text.split('\n', 1)[0].trim()) return fail(SETUP_FAILURES.artifacts);
	return {
		ok: true,
		verdict: receipt.verdict,
		model: meta.model,
		runId: meta.runId,
		toolCount: isCount(meta.toolCount) ? meta.toolCount : undefined,
		durationMs: isCount(meta.durationMs) ? meta.durationMs : undefined,
		acceptance: acceptance.status,
		// Reported honestly: the installed native writer gate did not run, so this lane carries no
		// native writer acceptance evidence. Root admits a writer lane separately, by verifying clean
		// committed scoped paths and its evidence, before any approval.
		writerAcceptanceGate: meta.agent === 'hylja-implementer' ? acceptance.status : 'not-required',
		acceptanceProvesApproval: false,
	};
}

/** One native child, one wall clock, bounded termination and no timer or listener left behind. */
function launch(config, deps) {
	return new Promise((resolveLaunch) => {
		const timers = new Set();
		const arm = (fn, ms) => {
			const timer = deps.setTimeout(fn, ms);
			timers.add(timer);
			return timer;
		};
		const disarm = (timer) => {
			timers.delete(timer);
			deps.clearTimeout(timer);
		};
		let settled = false;
		let stopped = false;
		let deadline = false;
		let stderrBytes = 0;
		let killTimer = null;
		let closeTimer = null;
		let signoffs = [];
		const finish = (outcome) => {
			if (settled) return;
			settled = true;
			for (const timer of [...timers]) disarm(timer);
			for (const off of signoffs.splice(0)) off();
			resolveLaunch(outcome);
		};
		const child = deps.spawn(config.pi, buildArgv(config), {
			cwd: config.cwd,
			stdio: ['ignore', 'ignore', 'pipe'],
			env: { ...process.env, [LANE_CONFIG_ENV]: deps.configPath, [LANE_SUBAGENTS_ENV]: config.subagents },
		});
		// Shutdown reaches exactly this owned child: SIGTERM, then SIGKILL, then a finite close wait.
		// Idempotent, so a second SIGINT, a SIGTERM and the watchdog cannot stack kill ladders.
		const stop = () => {
			if (settled || stopped) return;
			stopped = true;
			child.kill('SIGTERM');
			killTimer = arm(() => {
				killTimer = null;
				child.kill('SIGKILL');
				closeTimer = arm(() => {
					closeTimer = null;
					finish({ started: true, exitCode: null, deadline, stderrBytes, cleanup: SETUP_FAILURES.cleanup });
				}, CLOSE_WAIT_MS);
			}, KILL_GRACE_MS);
		};
		// Each registration returns one unsubscribe function, exactly as the shipped adapter contract
		// declares. They are collected, never spread: a function is not an iterable of signoffs.
		signoffs = [
			deps.addSignalListener('SIGINT', stop),
			deps.addSignalListener('SIGTERM', stop),
		];
		arm(() => {
			// The deadline is latched before the stop, never after: evidence that arrives after expiry
			// cannot present itself as a lane that finished inside the budget it was launched with.
			deadline = true;
			stop();
		}, config.timeoutMs + WATCHDOG_GRACE_MS);
		child.stderr.on('data', (chunk) => {
			// Only a bounded byte count is retained; a child message is never echoed into the receipt.
			stderrBytes = Math.min(stderrBytes + chunk.length, 65_536);
		});
		child.on('error', () => finish({ started: false, reason: SETUP_FAILURES.spawn }));
		child.on('close', (code) => finish({ started: true, exitCode: code, deadline, stderrBytes }));
	});
}

/**
 * Reads the bounded numeric progress snapshots from the tail of the file the controller persisted. The
 * window is the writer's own: this reader parses exactly the bytes the writer bounded itself to, so a
 * record the writer retained is one this read can still reach.
 */
export function readProgress(path, fs) {
	if (!fs.exists(path)) return [];
	let size;
	try {
		size = fs.size(path);
	} catch {
		return [];
	}
	const cap = MAX_PROGRESS_BYTES;
	const offset = Math.max(0, size - cap);
	let text;
	try {
		text = fs.read(path, offset, size - offset).toString('utf8');
	} catch {
		return [];
	}
	const snapshots = [];
	for (const line of text.split('\n').filter((entry) => entry.length > 0).slice(-MAX_PROGRESS_RECORDS)) {
		let value;
		try {
			value = JSON.parse(line);
		} catch {
			value = null;
		}
		// A parsed record that is not a plain object is bounded malformed evidence. No field of it is
		// read, so a `null` or primitive line cannot escape as a thrown property access.
		if (!isObject(value)) {
			snapshots.push({ event: 'malformed' });
			continue;
		}
		snapshots.push({
			event: typeof value.event === 'string' ? value.event : 'unknown',
			model: typeof value.model === 'string' ? value.model : undefined,
			runId: typeof value.runId === 'string' ? value.runId : undefined,
			toolCount: isCount(value.toolCount) ? value.toolCount : undefined,
			elapsedMs: isCount(value.elapsedMs) ? value.elapsedMs : undefined,
		});
	}
	return snapshots;
}

/** The real default hook: this process owns the listener it adds, and removing it is idempotent. */
const defaultSignalOffs = (name, handler) => {
	process.on(name, handler);
	let removed = false;
	return () => {
		if (removed) return;
		removed = true;
		process.removeListener(name, handler);
	};
};

/** The whole lane. Returns a public verification record; it never returns leaf text. */
export async function runNativeLane(argv, deps = {}) {
	const context = {
		fs: defaultFs,
		spawn,
		setTimeout,
		clearTimeout,
		addSignalListener: defaultSignalOffs,
		configPath: '',
		log: () => {},
		...deps,
	};
	const configArg = argv[argv.indexOf('--config') + 1];
	if (argv[0] !== '--config' || typeof configArg !== 'string' || !configArg.startsWith('/')) return fail(SETUP_FAILURES.argv);
	context.configPath = configArg;
	if (context.fs.exists(configArg) === false) return fail(SETUP_FAILURES.install);
	if (context.fs.readFile(configArg).length > MAX_CONFIG_BYTES) return fail(SETUP_FAILURES.config);
	let raw;
	try {
		raw = JSON.parse(context.fs.readFile(configArg));
	} catch {
		return fail(SETUP_FAILURES.config);
	}
	let profile;
	try {
		profile = readRoleProfile(LANE_ROLES.includes(raw?.agent) ? raw.agent : '', context.fs);
	} catch {
		return fail(SETUP_FAILURES.install);
	}
	const validated = validateLaneConfig(raw, profile);
	if (validated.ok !== true) return validated;
	const config = validated.config;
	// Declared references are admitted before anything is spawned: a fixed refusal, zero children.
	const references = checkRequiredReferences(config, context.fs);
	if (references.ok !== true) return references;
	const install = checkInstall(config, profile, context.fs, context.resolveModules);
	if (install.ok !== true) return install;

	const child = await launch(config, context);
	if (child.started !== true) return fail(child.reason);

	let receipt = null;
	try {
		receipt = readReceipt(JSON.parse(context.fs.readFile(config.receipt)));
	} catch {
		receipt = null;
	}
	let dispatch = null;
	try {
		dispatch = readDispatchTuple(JSON.parse(context.fs.readFile(config.dispatch)));
	} catch {
		dispatch = null;
	}
	const progress = readProgress(config.progress, context.fs);
	let verified = fail(SETUP_FAILURES.receipt);
	if (child.cleanup !== undefined) verified = fail(child.cleanup);
	else if (child.deadline) verified = fail(SETUP_FAILURES.status, 'deadline');
	else if (child.exitCode !== 0) verified = fail(SETUP_FAILURES.nativeExit);
	else if (receipt === null) verified = fail(SETUP_FAILURES.receipt);
	else if (dispatch === null) verified = fail(SETUP_FAILURES.tuple);
	else {
		const discovered = discoverPublicArtifacts(config, receipt.runId, config.agent, context.fs);
		verified = discovered.ok !== true ? discovered : verifyArtifacts(config, profile, dispatch, receipt, discovered.artifacts, context.fs);
	}
	const record = {
		key: config.key,
		agent: config.agent,
		verdict: verified.verdict,
		reason: verified.reason,
		detail: verified.detail,
		status: isObject(receipt) ? receipt.status : null,
		runId: isObject(receipt) ? receipt.runId : null,
		model: verified.model ?? (isObject(receipt) ? receipt.model : null),
		thinking: isObject(receipt) ? receipt.thinking : null,
		usage: isObject(receipt) ? receipt.usage : null,
		exitCode: isObject(receipt) ? receipt.exitCode : null,
		nativeExitCode: child.exitCode,
		deadlineExceeded: child.deadline === true,
		expectedLaunchContractDigest: isObject(dispatch) ? dispatch.expected.launchContractDigest : null,
		guardExtension: isObject(dispatch) ? dispatch.expected.guardExtension : null,
		...(isObject(receipt) ? { tuple: { requestId: receipt.requestId, ownerRunId: receipt.ownerRunId, nodeId: receipt.nodeId } } : {}),
		progress,
		...(verified.outputPath === undefined ? {} : { outputPath: verified.outputPath }),
		...(verified.toolCount === undefined ? {}
			: { toolCount: verified.toolCount, durationMs: verified.durationMs, acceptance: verified.acceptance,
				writerAcceptanceGate: verified.writerAcceptanceGate, acceptanceProvesApproval: verified.acceptanceProvesApproval }),
	};
	context.log(record);
	try {
		context.fs.writeFile(config.verification, `${JSON.stringify(record, null, 2)}\n`);
	} catch {
		return fail(SETUP_FAILURES.receipt);
	}
	return { ...verified, record };
}

const invokedDirectly = process.argv[1] !== undefined
	&& resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) {
	const result = await runNativeLane(process.argv.slice(2), { log: (record) => console.log(JSON.stringify(record)) });
	process.exitCode = result.ok === true ? 0 : result.reason === SETUP_FAILURES.status ? 3 : 2;
}