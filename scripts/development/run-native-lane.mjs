#!/usr/bin/env node
/**
 * Hylja native foreground lane CLI.
 *
 * Root-owned developer tooling, not runtime core and not a security boundary. It reads one bounded,
 * root-owned lane config, launches Pi once with exactly three extensions (the installed
 * `pi-subagents` entry, the project workflow guard and the opt-in controller) and the one fixed input
 * the controller answers, then verifies the public evidence that leaf left behind. There is no
 * coordinator model in this process, no model override, no role fallback, no background mode and no
 * nesting: one lane, one child, one receipt.
 *
 * Every path it touches comes from that config or from this repository's own role profile. It never
 * searches a machine, never opens a raw session transcript or provider reasoning, never creates a
 * branch, modifies source, pushes, merges or closes an issue.
 *
 * Exit codes: 0 verified completed lane, 2 setup or evidence failure (INCOMPLETE), 3 the native leaf
 * finished in a non-completed state.
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FIXED_LANE_INPUT, LANE_CONFIG_ENV, LANE_ROLES, LANE_SUBAGENTS_ENV } from '../../.pi/lib/hylja-native-lane.ts';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ARTIFACT_SUFFIXES = ['_meta.json', '_output.md'];
const MAX_CONFIG_BYTES = 65_536;
const MAX_TASK_CHARS = 1_048_576;
/** Extra wall clock over the native request timeout before the watchdog stops the owned child. */
export const WATCHDOG_GRACE_MS = 60_000;

export const SETUP_FAILURES = {
	argv: 'SETUP_FAILED_ARGUMENTS',
	config: 'SETUP_FAILED_LANE_CONFIG',
	install: 'SETUP_FAILED_INSTALL_CHECK',
	spawn: 'SETUP_FAILED_SPAWN',
	receipt: 'SETUP_FAILED_MISSING_RECEIPT',
	malformed: 'SETUP_FAILED_MALFORMED_RECEIPT',
	artifacts: 'SETUP_FAILED_MISSING_ARTIFACTS',
	model: 'SETUP_FAILED_MODEL_MISMATCH',
	role: 'SETUP_FAILED_ROLE_MISMATCH',
	guard: 'SETUP_FAILED_GUARD_NOT_EFFECTIVE',
	contract: 'SETUP_FAILED_LAUNCH_CONTRACT',
	acceptance: 'SETUP_FAILED_RUNTIME_ACCEPTANCE',
	status: 'SETUP_FAILED_NON_COMPLETED_STATUS',
};

/** Acceptance states a writer role may reach. Anything absent, unknown or negative is refused. */
const WRITER_ACCEPTED = ['accepted', 'complete', 'completed', 'met', 'passed', 'satisfied'];
const READER_ACCEPTED = [...WRITER_ACCEPTED, 'not-required'];

const fail = (code, detail) => ({ ok: false, verdict: 'INCOMPLETE', reason: code, ...(detail ? { detail } : {}) });

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
	readdir: (path) => readdirSync(path),
	writeFile: (path, data) => writeFileSync(path, data, { mode: 0o600 }),
};

/** Validates the bounded root-owned lane config. Fixed failure codes, never a planted value. */
export function validateLaneConfig(value, profile) {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) return fail(SETUP_FAILURES.config);
	if (!LANE_ROLES.includes(value.agent)) return fail(SETUP_FAILURES.config);
	if (typeof value.task !== 'string' || value.task.length === 0 || value.task.length > MAX_TASK_CHARS) {
		return fail(SETUP_FAILURES.config);
	}
	if (typeof value.key !== 'string' || value.key.length === 0) return fail(SETUP_FAILURES.config);
	if (!Number.isInteger(value.timeoutMs) || value.timeoutMs <= 0 || value.timeoutMs > profile.timeoutMs) {
		return fail(SETUP_FAILURES.config);
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

/** One bundled finite setup pass: role profile, installed entrypoints, project guard, controller. */
export function checkInstall(config, profile, fs) {
	for (const path of [config.pi, config.subagents, config.guard, config.controller, config.cwd, config.sessionDir]) {
		if (!fs.exists(path)) return fail(SETUP_FAILURES.install);
	}
	if (!profile.model.endsWith(':max')) return fail(SETUP_FAILURES.install);
	return { ok: true };
}

/**
 * Discovers the public evidence for this runId and agent with exactly one listing of the supplied
 * session directory. Filenames are never rebuilt from a pattern; anything not `*_meta.json` or
 * `*_output.md` is never opened.
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
	const found = { meta: null, output: null };
	for (const name of names) {
		if (name.endsWith('_meta.json')) found.meta = join(dir, name);
		else found.output = join(dir, name);
	}
	return found.meta === null ? fail(SETUP_FAILURES.artifacts) : { ok: true, artifacts: found };
}

/** Checks the runtime record. Nothing is inferred from the leaf's text. */
export function verifyArtifacts(config, profile, receipt, artifacts, fs) {
	if (receipt.status !== 'completed') return fail(SETUP_FAILURES.status, receipt.status);
	if (typeof receipt.runId !== 'string' || receipt.runId.length === 0) return fail(SETUP_FAILURES.malformed);
	if (receipt.result?.kind !== 'text' || typeof receipt.result.text !== 'string') return fail(SETUP_FAILURES.malformed);
	let meta;
	try {
		meta = JSON.parse(fs.readFile(artifacts.meta));
	} catch {
		return fail(SETUP_FAILURES.malformed);
	}
	if (meta.runId !== receipt.runId || meta.agent !== config.agent || receipt.agent !== config.agent) {
		return fail(SETUP_FAILURES.role);
	}
	// The effective model must be the profile model at :max. `requestedModel` and frontmatter alone
	// are a request and an intent, so neither is accepted here.
	if (meta.model !== profile.model || !meta.model.endsWith(':max')) return fail(SETUP_FAILURES.model);
	if (typeof meta.launchContractDigest !== 'string' || meta.launchContractDigest !== receipt.launchContractDigest) {
		return fail(SETUP_FAILURES.contract);
	}
	const resolved = meta.launchResolvedExtensions;
	const configured = Array.isArray(resolved?.configured) ? resolved.configured : [];
	const effective = Array.isArray(resolved?.effective) ? resolved.effective : [];
	if (resolved?.disableAmbientExtensions !== true || configured.length === 0) return fail(SETUP_FAILURES.guard);
	if (!configured.some((digest) => effective.includes(digest))) return fail(SETUP_FAILURES.guard);
	const acceptance = meta.acceptance;
	const accepted = config.agent === 'hylja-reviewer' ? READER_ACCEPTED : WRITER_ACCEPTED;
	if (acceptance?.explicit !== true || !accepted.includes(acceptance.status)) return fail(SETUP_FAILURES.acceptance);
	return {
		ok: true,
		verdict: receipt.verdict,
		model: meta.model,
		runId: meta.runId,
		toolCount: meta.toolCount,
		durationMs: meta.durationMs,
		acceptance: acceptance.status,
		outputPath: artifacts.output,
	};
}

/** One native child, one wall clock, no timers left behind after settle. */
function launch(config, deps) {
	return new Promise((resolve) => {
		const child = deps.spawn(config.pi, buildArgv(config), {
			cwd: config.cwd,
			stdio: ['ignore', 'ignore', 'pipe'],
			env: {
				...process.env,
				[LANE_CONFIG_ENV]: deps.configPath,
				[LANE_SUBAGENTS_ENV]: join(config.subagents, '..', 'src', 'api', 'delegation.js'),
			},
		});
		const timer = deps.setTimeout(() => {
			deadline = true;
			child.kill('SIGTERM');
		}, config.timeoutMs + WATCHDOG_GRACE_MS);
		let deadline = false;
		let stderrBytes = 0;
		child.stderr.on('data', (chunk) => {
			// Only a bounded byte count is retained; a child message is never echoed into the receipt.
			stderrBytes = Math.min(stderrBytes + chunk.length, 65_536);
		});
		child.on('error', () => {
			deps.clearTimeout(timer);
			resolve({ started: false, reason: SETUP_FAILURES.spawn });
		});
		child.on('close', (code) => {
			deps.clearTimeout(timer);
			resolve({ started: true, exitCode: code, deadline, stderrBytes });
		});
	});
}

/** Reads the numeric progress snapshots this lane produced. Text fields are dropped on read. */
export function readProgress(path, fs) {
	if (!fs.exists(path)) return [];
	const lines = fs.readFile(path).split('\n').filter((line) => line.length > 0).slice(-256);
	const snapshots = [];
	for (const line of lines) {
		try {
			const value = JSON.parse(line);
			snapshots.push({
				event: value.event,
				model: typeof value.model === 'string' ? value.model : undefined,
				toolCount: Number.isFinite(value.toolCount) ? value.toolCount : undefined,
				elapsedMs: Number.isFinite(value.elapsedMs) ? value.elapsedMs : undefined,
			});
		} catch {
			snapshots.push({ event: 'malformed' });
		}
	}
	return snapshots;
}

/** The whole lane. Returns a public verification record; it never returns leaf text. */
export async function runNativeLane(argv, deps = {}) {
	const context = {
		fs: defaultFs,
		spawn,
		setTimeout,
		clearTimeout,
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
	const install = checkInstall(config, profile, context.fs);
	if (install.ok !== true) return install;

	const child = await launch(config, context);
	if (child.started !== true) return fail(child.reason);

	let receipt;
	try {
		receipt = JSON.parse(context.fs.readFile(config.receipt));
	} catch {
		return fail(child.deadline ? SETUP_FAILURES.status : SETUP_FAILURES.receipt, child.deadline ? 'deadline' : undefined);
	}
	const progress = readProgress(config.progress, context.fs);
	let tuple = null;
	try {
		tuple = JSON.parse(context.fs.readFile(config.dispatch));
	} catch {
		tuple = null;
	}
	let verified = fail(SETUP_FAILURES.receipt);
	if (child.deadline === false) {
		if (receipt.status !== 'completed') verified = fail(SETUP_FAILURES.status, receipt.status);
		else {
			const discovered = discoverPublicArtifacts(config, receipt.runId, config.agent, context.fs);
			if (discovered.ok !== true) verified = discovered;
			else verified = verifyArtifacts(config, profile, receipt, discovered.artifacts, context.fs);
		}
	}
	const record = {
		key: config.key,
		agent: config.agent,
		verdict: verified.verdict,
		reason: verified.reason,
		detail: verified.detail,
		status: receipt.status,
		runId: receipt.runId,
		model: verified.model ?? receipt.model,
		thinking: receipt.thinking,
		usage: receipt.usage,
		exitCode: receipt.exitCode,
		nativeExitCode: child.exitCode,
		deadlineExceeded: child.deadline,
		tuple,
		progress,
		...(verified.outputPath === undefined ? {} : { outputPath: verified.outputPath }),
		...(verified.toolCount === undefined ? {} : { toolCount: verified.toolCount, durationMs: verified.durationMs, acceptance: verified.acceptance }),
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
