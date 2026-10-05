// Hylja native foreground lane: controller and CLI behaviour.
//
// Every case drives the real controller exports with a fake Pi event API, a fake preflight module and
// a fake native process transport over a synthetic temporary session directory. No case requires a
// local Pi installation, calls a provider, reaches the network, or reads a session transcript: the
// planted strings below are synthetic values that never leave this process unless a case asserts they
// did not leak.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import nodeFs from 'node:fs';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';

import {
	FIXED_LANE_INPUT,
	LANE_CONFIG_ENV,
	LANE_ROLES,
	LANE_SUBAGENTS_ENV,
	MAX_PROGRESS_BYTES,
	MAX_PROGRESS_RECORDS,
	SETUP_FAILURES as LANE_SETUP_FAILURES,
	createLaneController,
	probeReferenceMetadata,
	readExplicitVerdict,
	readLaneConfig,
	resolveInstalledModules,
	writeTerminalReceipt,
	hyljaNativeLane,
} from '../.pi/lib/hylja-native-lane.ts';
import {
	buildArgv,
	checkInstall,
	discoverPublicArtifacts,
	readProgress,
	readRoleProfile,
	runNativeLane,
	MAX_CONFIG_BYTES,
	MAX_RANGE_READ_BYTES,
	SETUP_FAILURES,
	validateLaneConfig,
	verifyArtifacts,
	WATCHDOG_GRACE_MS,
} from '../scripts/development/run-native-lane.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const PLANTED_REASONING = 'synthetic-planted-reasoning.invalid';
const PLANTED_TOOL_ARGS = '--synthetic-planted-argument.invalid';
const PLANTED_RECENT = 'synthetic-planted-recent-output.invalid';
const RUN_ID = 'ddfad7ad-07e1-4ad2-9af3-55fe1e38876b';
const OWNER = 'bad5596d-f94f-43c8-a17c-155fae12ca1b';
const REQUEST_ID = '39e040c4-3535-4971-bca8-76a61b08850d';
const EXPECTED_DIGEST = '5a35ac671887105f555bd11745e682ad7a3ef4410dd12802558cdef74edda96';
const REVIEWER_MODEL = 'openai-codex/gpt-6.1-sol:max';
const WRITER_MODEL = 'opencode-go/space-bunny-free:max';
/**
 * The dedicated writer fallback: a third role root dispatches explicitly after an actual default
 * writer provider failure. It is one named profile at one exact model, never a general failover.
 */
const FALLBACK_ROLE = 'hylja-implementer-sol61';
const FALLBACK_MODEL = 'openai-codex/gpt-6.1-sol:medium';
/** The exact acceptance record the installed extension wrote for a direct-API writer and reviewer. */
const NATIVE_ACCEPTANCE_NOT_REQUIRED = {
	status: 'not-required',
	evidenceStatus: 'not-required',
	explicit: true,
	effectiveAcceptance: {
		level: 'none',
		explicit: true,
		inferredReason: ['declared writer acceptance role'],
		criteria: [],
		evidence: [],
		verify: [],
		stopRules: [],
		reason: 'disabled by deprecated false shorthand',
	},
	inferredReason: ['declared writer acceptance role'],
	criteria: [],
	runtimeChecks: [],
	verifyRuns: [],
};

/** The documented event names, as the installed module declares them. */
const delegation = {
	SUBAGENT_DELEGATION_REQUEST_EVENT: 'prompt-template:subagent:request',
	SUBAGENT_DELEGATION_STARTED_EVENT: 'prompt-template:subagent:started',
	SUBAGENT_DELEGATION_UPDATE_EVENT: 'prompt-template:subagent:update',
	SUBAGENT_DELEGATION_RESPONSE_EVENT: 'prompt-template:subagent:response',
	SUBAGENT_DELEGATION_CANCEL_EVENT: 'prompt-template:subagent:cancel',
};

/** A fake launch preflight: same exported shape, no installed package required. */
function fakePreflight({ digest = EXPECTED_DIGEST, model = REVIEWER_MODEL, thinking = 'max', guard = '' } = {}) {
	const calls = [];
	return {
		calls,
		resolveSubagentLaunchContract: async (input) => {
			calls.push(input);
			return {
				ok: true,
				contract: {
					version: 3,
					context: input.context,
					roots: { cwd: input.cwd },
					model,
					thinking,
					intercomBridge: { active: false, mode: input.intercomBridge?.mode ?? 'off' },
					tools: {
						configuredExtensions: [guard],
						runtimeExtensions: [],
						disableAmbientExtensions: true,
					},
					launchContractDigest: digest,
					digest: `${digest}:contract`,
					diagnostics: [],
				},
			};
		},
	};
}

/** A fake Pi host: the event bus the delegation module publishes on, and the input handler. */
function fakePi() {
	const handlers = new Map();
	const emitted = [];
	const pi = {
		events: {
			on(event, handler) {
				const list = handlers.get(event) ?? [];
				list.push(handler);
				handlers.set(event, list);
				return () => handlers.set(event, (handlers.get(event) ?? []).filter((h) => h !== handler));
			},
			emit(event, payload) {
				emitted.push({ event, payload });
				for (const handler of [...(handlers.get(event) ?? [])]) handler(payload);
			},
		},
		on(event, handler) {
			handlers.set(`pi:${event}`, [handler]);
		},
		live: (event) => (handlers.get(event) ?? []).length,
	};
	return { pi, emitted, handlers, input: () => handlers.get('pi:input')?.[0] };
}

/** A disposable synthetic platform: temporary entrypoints, never a local Pi installation. */
function tempPlatform(overrides = {}) {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-native-platform-'));
	const pkgDir = join(dir, 'node_modules', 'pi-subagents');
	mkdirSync(pkgDir, { recursive: true });
	writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({
		name: 'pi-subagents',
		version: '0.0.0-synthetic',
		type: 'module',
		exports: { '.': './index.js', './delegation': './src/api/delegation.js', './preflight': './src/api/preflight.js' },
	}));
	mkdirSync(join(pkgDir, 'src', 'api'), { recursive: true });
	writeFileSync(join(pkgDir, 'index.js'), 'export default {};\n');
	writeFileSync(join(pkgDir, 'src', 'api', 'delegation.js'), 'export const SUBAGENT_DELEGATION_REQUEST_EVENT = "prompt-template:subagent:request";\n');
	writeFileSync(join(pkgDir, 'src', 'api', 'preflight.js'), 'export const resolveSubagentLaunchContract = async () => ({ ok: false, code: "missing_agent", message: "synthetic", diagnostics: [] });\n');
	const piBin = join(dir, 'bin', 'pi');
	const guard = join(dir, 'guard.ts');
	const controller = join(repoRoot, '.pi', 'lib', 'hylja-native-lane.ts');
	mkdirSync(join(dir, 'bin'), { recursive: true });
	writeFileSync(piBin, '#!/bin/sh\nexit 0\n');
	writeFileSync(guard, 'export default function syntheticGuard() {}\n');
	return { dir, config: { pi: piBin, subagents: pkgDir, guard, controller }, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function tempConfig(overrides = {}) {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-native-lane-'));
	const platform = tempPlatform();
	const config = {
		key: 'mapping-review-round2',
		agent: 'hylja-reviewer',
		task: 'Review the supplied evidence.',
		cwd: repoRoot,
		timeoutMs: 600_000,
		sessionDir: join(dir, 'pi-sessions', 'mapping-review-round2'),
		receipt: join(dir, 'receipt.json'),
		verification: join(dir, 'verification.json'),
		progress: join(dir, 'progress.ndjson'),
		dispatch: join(dir, 'dispatch.json'),
		...platform.config,
		...overrides,
	};
	mkdirSync(config.sessionDir, { recursive: true });
	const configPath = join(dir, 'lane.json');
	writeFileSync(configPath, JSON.stringify(config, null, 2));
	return { dir, config, configPath, platform, cleanup: () => { rmSync(dir, { recursive: true, force: true }); platform.cleanup(); } };
}

/** Native-shaped metadata, using the installed extension's real acceptance and extension record. */
const meta = (overrides = {}) => ({
	runId: RUN_ID,
	agent: 'hylja-reviewer',
	task: '[prompt redacted]',
	exitCode: 0,
	usage: { input: 39_721, output: 2_836, cacheRead: 73_344, cacheWrite: 0, cost: 0.115, turns: 6 },
	model: REVIEWER_MODEL,
	requestedModel: REVIEWER_MODEL,
	durationMs: 107_881,
	toolCount: 19,
	launchContractDigest: EXPECTED_DIGEST,
	launchResolvedExtensions: {
		version: 1,
		source: 'launch-resolved',
		disableAmbientExtensions: true,
		runtime: ['sha256:09f3249c7287ea1a'],
		configured: ['sha256:44e85c6c574d8360'],
		required: [],
		effective: ['sha256:09f3249c7287ea1a', 'sha256:44e85c6c574d8360'],
		omitted: { runtime: 0, configured: 0, required: 0, effective: 0 },
	},
	acceptance: NATIVE_ACCEPTANCE_NOT_REQUIRED,
	...overrides,
});

const receipt = (overrides = {}) => ({
	requestId: REQUEST_ID,
	ownerRunId: OWNER,
	nodeId: 'mapping-review-round2',
	status: 'completed',
	runId: RUN_ID,
	agent: 'hylja-reviewer',
	model: REVIEWER_MODEL,
	thinking: 'max',
	exitCode: 0,
	launchContractDigest: EXPECTED_DIGEST,
	verdict: 'CHANGES REQUESTED',
	result: { kind: 'text', text: 'CHANGES REQUESTED\n\nBody.' },
	usage: { input: 124_991, output: 7_220, cacheRead: 0, cacheWrite: 0, cost: 0, turns: 6, toolCalls: 53, durationMs: 296_680 },
	...overrides,
});

/** The dispatch record the controller persists before it emits the request. */
const dispatchRecord = (config, overrides = {}) => ({
	requestId: REQUEST_ID,
	ownerRunId: OWNER,
	nodeId: config.key,
	agent: config.agent,
	pid: 4242,
	timeoutMs: config.timeoutMs,
	expected: {
		launchContractDigest: EXPECTED_DIGEST,
		guardExtension: config.guard,
		configuredExtensions: [config.guard],
		runtimeExtensions: [],
		disableAmbientExtensions: true,
		context: 'fresh',
		cwd: config.cwd,
		model: REVIEWER_MODEL,
		thinking: 'max',
	},
	...overrides,
});

/** A fake native transport: one child, argv recorded, evidence written before close. */
function fakeSpawn({ onLaunch, record = [], exitCode = 0, hang = false } = {}) {
	return (command, args, options) => {
		record.push({ command, args, options });
		const child = new EventEmitter();
		child.stderr = new EventEmitter();
		child.signals = [];
		child.kill = (signal) => { child.signals.push(signal); return true; };
		child.pid = 4242;
		queueMicrotask(() => {
			try {
				onLaunch?.(options, child);
			} finally {
				if (!hang) {
					child.stderr.emit('data', Buffer.from('synthetic child stderr noise'));
					child.emit('close', exitCode);
				}
			}
		});
		return child;
	};
}

/**
 * One fake clock for the controller's injected `now` and `arm`: every armed timer is recorded with
 * its delay, and the closure it handed back is what cancels it. A case can therefore fire or drain a
 * soft budget deterministically, without waiting out wall-clock minutes and without a timer type cast.
 */
function fakeClock() {
	const timers = [];
	let current = 0;
	return {
		timers,
		now: () => current,
		arm(handler, delayMs) {
			const timer = { handler, delayMs, due: current + delayMs, cancelled: false, fired: false };
			timers.push(timer);
			return () => {
				timer.cancelled = true;
			};
		},
		fire(delayMs) {
			const timer = timers.find((entry) => entry.delayMs === delayMs && !entry.fired);
			if (timer === undefined) throw new Error(`synthetic: no armed timer at ${delayMs}`);
			timer.fired = true;
			current = timer.due;
			timer.handler();
		},
	};
}

/** The soft-budget warnings the controller has actually persisted, parsed from its own progress file. */
const softWarnings = (path) => readFileSync(path, 'utf8').split('\n')
	.filter((line) => line.length > 0)
	.map((line) => JSON.parse(line))
	.filter((entry) => entry.event === 'soft_budget_reached');

/** Shutdown wiring is not what these cases exercise, so no case here touches the real process. */
const noSignals = () => () => {};

/** A terminal completed response for exactly this controller's own tuple. */
const completeLeaf = (pi, controller, text = 'APPROVED\n\nBody.') => {
	pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT,
		{ ...receipt(), ...controller.tuple, result: { kind: 'text', text } });
};

test('unexpected input is handled by this controller and never reaches a parent model', async () => {
	const { dir, configPath, cleanup } = tempConfig();
	try {
		const { pi, input } = fakePi();
		hyljaNativeLane(pi);
		assert.equal(typeof input(), 'function');
		for (const text of ['what is the weather', '', undefined, { toString: () => FIXED_LANE_INPUT }]) {
			const answer = await input()({ text });
			assert.equal(answer.action, 'handled', JSON.stringify(text));
			assert.notEqual(answer.action, 'continue', 'a parent-model turn must be unreachable');
		}
		// A handler that throws on the setup path still cannot fall through to a parent model.
		const throwing = fakePi();
		throwing.pi.events.on = () => { throw new Error('synthetic setup failure'); };
		hyljaNativeLane(throwing.pi);
		const refused = await throwing.input()({ text: FIXED_LANE_INPUT });
		assert.equal(refused.action, 'handled');
		assert.equal(existsSync(configPath), true);
	} finally {
		cleanup();
	}
});

test('the controller resolves the exported preflight and delegation modules from the exact package directory', async () => {
	const { config } = tempConfig();
	try {
		const modules = resolveInstalledModules(config.subagents);
		assert.equal(modules.delegationUrl.startsWith('file:'), true, modules.delegationUrl);
		assert.equal(modules.preflightUrl.startsWith('file:'), true, modules.preflightUrl);
		// The resolved entrypoints are inside the supplied package, not a sibling path guess.
		for (const url of [modules.delegationUrl, modules.preflightUrl]) {
			assert.equal(fileURLToPath(url).startsWith(join(config.subagents, 'src', 'api')), true, url);
		}
		assert.throws(() => resolveInstalledModules('/synthetic/absent-package'), /SETUP_FAILED/);
	} finally {
		rmSync(join(config.subagents, '..'), { recursive: true, force: true });
	}
});

test('the controller dispatches the exact role, context and task deadline after a bound preflight', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi, emitted } = fakePi();
		const preflight = fakePreflight({ guard: config.guard });
		const controller = await createLaneController(pi, loaded, { delegation, preflight });
		const requests = emitted.filter((e) => e.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT);
		assert.equal(requests.length, 1);
		const request = requests[0].payload;
		assert.equal(request.agent, 'hylja-reviewer');
		assert.equal(request.context, 'fresh');
		assert.equal(request.cwd, repoRoot);
		assert.equal(request.timeoutMs, 600_000);
		assert.equal(request.task, 'Review the supplied evidence.');
		assert.equal('model' in request, false);
		// The bridge input is one value, given to both the preflight and the launch it compares against.
		assert.deepEqual(preflight.calls[0].intercomBridge, request.intercomBridge);
		assert.equal(preflight.calls[0].context, 'fresh');
		assert.equal(preflight.calls[0].task, loaded.task);
		assert.equal(preflight.calls[0].cwd, loaded.cwd);
		assert.equal(preflight.calls[0].agent, 'hylja-reviewer');

		// The exact dispatch tuple is persisted before the request is emitted.
		const persisted = JSON.parse(readFileSync(config.dispatch, 'utf8'));
		assert.equal(persisted.requestId, request.requestId);
		assert.equal(persisted.expected.launchContractDigest, EXPECTED_DIGEST);
		assert.equal(persisted.expected.guardExtension, config.guard);

		// A terminal response for a different owner is not this controller's leaf.
		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT,
			{ ...receipt(), ownerRunId: 'synthetic-other-owner', requestId: request.requestId });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, { ...receipt(), requestId: 'synthetic-other-attempt' });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, { ...receipt(), nodeId: 'synthetic-other-node' });
		let settledEarly = false;
		void controller.settle().then(() => { settledEarly = true; });
		await new Promise((r) => setImmediate(r));
		assert.equal(settledEarly, false, 'a mismatched tuple must not settle this attempt');

		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT,
			{ ...receipt(), requestId: request.requestId, ownerRunId: request.ownerRunId, nodeId: request.nodeId });
		const value = await controller.settle();
		assert.equal(value.status, 'completed');
	} finally {
		cleanup();
	}
});

test('an unresolved launch contract never emits a request', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi, emitted } = fakePi();
		const preflight = fakePreflight({ guard: config.guard });
		preflight.resolveSubagentLaunchContract = async () => ({ ok: false, code: 'restricted_agent', message: 'synthetic', diagnostics: [] });
		const controller = await createLaneController(pi, loaded, { delegation, preflight });
		assert.equal(controller.setupFailure, LANE_SETUP_FAILURES.contract);
		assert.equal(emitted.some((e) => e.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT), false);
		assert.equal(existsSync(config.dispatch), false, 'no dispatch is persisted without a contract');
		assert.equal(readFileSync(config.progress, 'utf8').includes('setup_failure'), true);
	} finally {
		cleanup();
	}
});

test('progress stays numeric and bounded: no recent output, tool arguments or reasoning', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi } = fakePi();
		const controller = await createLaneController(pi, loaded, { delegation, preflight: fakePreflight({ guard: config.guard }) });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_STARTED_EVENT, { ...controller.tuple, model: REVIEWER_MODEL });
		// A non-numeric or negative counter is dropped, never persisted as a number.
		pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT, { ...controller.tuple, toolCount: '53', durationMs: -1 });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT, {
			...controller.tuple,
			runId: RUN_ID,
			model: REVIEWER_MODEL,
			toolCount: 53,
			durationMs: 296_680,
			currentTool: 'read',
			currentToolArgs: PLANTED_TOOL_ARGS,
			recentOutput: PLANTED_RECENT,
			recentTools: [{ tool: 'read', args: PLANTED_TOOL_ARGS }],
			reasoning: PLANTED_REASONING,
		});
		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, {
			...receipt(), ...controller.tuple, result: { kind: 'text', text: 'APPROVED\n' },
		});
		await controller.settle();
		const progress = readFileSync(config.progress, 'utf8');
		const written = writeTerminalReceipt(readLaneConfig(configPath), receipt({ result: { kind: 'text', text: 'APPROVED' } }));
		const publicText = `${progress}\n${JSON.stringify(written)}`;
		for (const planted of [PLANTED_TOOL_ARGS, PLANTED_RECENT, PLANTED_REASONING]) {
			assert.equal(publicText.includes(planted), false, planted);
		}
		const records = progress.split('\n').filter((l) => l.length > 0).map((l) => JSON.parse(l));
		assert.equal(records.length <= MAX_PROGRESS_RECORDS, true);
		for (const record of records) {
			for (const [field, value] of Object.entries(record)) {
				assert.equal(['event', 'key', 'model', 'runId', 'toolCount', 'elapsedMs'].includes(field), true, field);
				assert.equal(['string', 'number'].includes(typeof value), true, `${field} ${typeof value}`);
				if (typeof value === 'number') assert.equal(Number.isFinite(value) && value >= 0, true, field);
			}
		}
		assert.equal(records.at(-1).runId, RUN_ID, 'the actual runId is kept');
		assert.equal(records.at(-1).toolCount, 53);
		// A long lane cannot grow the file without bound.
		for (let i = 0; i < MAX_PROGRESS_RECORDS * 2; i += 1) {
			pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT, { ...controller.tuple, toolCount: i, durationMs: i });
		}
		const grown = readFileSync(config.progress, 'utf8').split('\n').filter((l) => l.length > 0);
		assert.equal(grown.length <= MAX_PROGRESS_RECORDS, true, `${grown.length} records`);
	} finally {
		cleanup();
	}
});

test('the controller cancels only its own tuple, wires shutdown, and drains its listeners', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi, emitted } = fakePi();
		const signals = [];
		const controller = await createLaneController(pi, loaded, { delegation, preflight: fakePreflight({ guard: config.guard }) },
			{ addSignalListener: (name, handler) => { signals.push({ name, handler }); return () => {}; } });
		assert.deepEqual(signals.map((s) => s.name), ['SIGINT', 'SIGTERM']);
		const cancels = () => emitted
			.filter((e) => e.event === delegation.SUBAGENT_DELEGATION_CANCEL_EVENT && e.payload.requestId === controller.tuple.requestId)
			.map((e) => e.payload);
		// A cancel aimed at another attempt is observed, never acted on and never echoed.
		pi.events.emit(delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, { ...controller.tuple, requestId: 'synthetic-other-attempt' });
		assert.equal(cancels().length, 0);

		assert.equal(signals[0].handler(), true, 'shutdown cancels exactly this owned tuple');
		assert.equal(cancels().length, 1);
		assert.deepEqual(cancels()[0], controller.tuple);
		assert.equal(controller.cancel(), false, 'a settled or already-cancelled attempt is not cancelled twice');
		assert.equal(cancels().length, 1, 'one owned cancellation, never two');

		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, { ...receipt(), ...controller.tuple });
		await controller.settle();
		for (const event of [delegation.SUBAGENT_DELEGATION_STARTED_EVENT, delegation.SUBAGENT_DELEGATION_UPDATE_EVENT,
			delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT]) {
			assert.equal(pi.live(event), 0, `${event} listener drained`);
		}
		assert.equal(existsSync(config.dispatch), true);
	} finally {
		cleanup();
	}
});

test('completed is not approved: only a literal declared verdict is read', () => {
	assert.equal(readExplicitVerdict('APPROVED\n\nbody'), 'APPROVED');
	assert.equal(readExplicitVerdict('CHANGES REQUESTED\nbody'), 'CHANGES REQUESTED');
	assert.equal(readExplicitVerdict('INCOMPLETE\nbody'), 'INCOMPLETE');
	for (const text of ['approved\nbody', 'Looks good to me.\nbody', 'APPROVED and done', '', undefined]) {
		assert.equal(readExplicitVerdict(text), 'INCOMPLETE', String(text));
	}
	const { dir, configPath, cleanup } = tempConfig();
	try {
		const written = writeTerminalReceipt(readLaneConfig(configPath), receipt({ status: 'completed', result: { kind: 'text', text: 'All good.\n' } }));
		assert.equal(written.status, 'completed');
		assert.equal(written.verdict, 'INCOMPLETE');
	} finally {
		cleanup();
	}
});

test('a lane config outside the contract is refused before any process is launched', () => {
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const { config, cleanup } = tempConfig();
	try {
		const base = { ...config };
		assert.equal(validateLaneConfig(base, profile).ok, true);
		// No model override option exists, so a supplied one is a refusal, not a preference.
		assert.equal(validateLaneConfig({ ...base, model: 'anthropic/claude' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, agent: 'hylja-coordinator' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, timeoutMs: 900_001 }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, timeoutMs: 0 }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, cwd: 'relative/path' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, task: '' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, subagents: '/synthetic/absent-package' }, profile).ok, true);
		assert.equal(validateLaneConfig(null, profile).reason, SETUP_FAILURES.config);
		const implementer = readRoleProfile('hylja-implementer');
		assert.equal(validateLaneConfig({ ...base, agent: 'hylja-implementer', timeoutMs: 1_200_001 }, implementer).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, agent: 'hylja-implementer', timeoutMs: 1_200_000 }, implementer).ok, true);
	} finally {
		cleanup();
	}
});

test('an optional soft budget is validated, and an invalid one is refused before any dispatch', async () => {
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const { dir, config, configPath, cleanup } = tempConfig();
	let variant = 0;
	const variantPath = (overrides) => {
		const path = join(dir, `lane-variant-${variant += 1}.json`);
		writeFileSync(path, JSON.stringify({ ...config, ...overrides }, null, 2));
		return path;
	};
	try {
		// Absent stays absent: the lane keeps its old behaviour and arms no warning timer at all.
		assert.equal(readLaneConfig(configPath).softBudgetMs, undefined);
		assert.equal(readLaneConfig(variantPath({ softBudgetMs: 360_000 })).softBudgetMs, 360_000);
		// Positive, integral and strictly below the finite hard timeout. Anything else is the fixed
		// config refusal in both readers, never a value that is silently repaired.
		for (const softBudgetMs of [0, -1, 600_000, 600_001, 360_000.5, '360000', null, true]) {
			assert.throws(() => readLaneConfig(variantPath({ softBudgetMs })), /SETUP_FAILED_LANE_CONFIG/, JSON.stringify(softBudgetMs));
			assert.equal(validateLaneConfig({ ...config, softBudgetMs }, profile).reason, SETUP_FAILURES.config, JSON.stringify(softBudgetMs));
		}
		for (const softBudgetMs of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
			assert.equal(validateLaneConfig({ ...config, softBudgetMs }, profile).reason, SETUP_FAILURES.config, String(softBudgetMs));
		}
		assert.equal(validateLaneConfig({ ...config, softBudgetMs: 360_000 }, profile).ok, true);
		assert.equal(validateLaneConfig({ ...config, softBudgetMs: 599_999 }, profile).ok, true);
		// A 6-minute soft budget under the writer's own unchanged 20-minute ceiling.
		const writer = readRoleProfile('hylja-implementer');
		assert.equal(validateLaneConfig({ ...config, agent: 'hylja-implementer', timeoutMs: 1_200_000, softBudgetMs: 360_000 }, writer).ok, true);
		assert.equal(validateLaneConfig({ ...config, agent: 'hylja-implementer', timeoutMs: 1_200_001, softBudgetMs: 360_000 }, writer).reason, SETUP_FAILURES.config);
		// The same refusal end to end: an invalid soft budget launches no child at all, and a valid
		// one is an ordinary lane whose only missing part here is the leaf's own evidence.
		const transport = { spawn: fakeSpawn(), addSignalListener: () => () => {} };
		assert.equal((await runNativeLane(['--config', variantPath({ softBudgetMs: 0 })], transport)).reason, SETUP_FAILURES.config);
		assert.equal((await runNativeLane(['--config', variantPath({ softBudgetMs: 360_000 })], transport)).reason, SETUP_FAILURES.receipt);
	} finally {
		cleanup();
	}
});

test('one role-aware numeric soft and hard guide is bound to both the preflight and the native request', async () => {
	const reviewerCase = tempConfig();
	try {
		const loaded = readLaneConfig(reviewerCase.configPath);
		const reviewer = { ...loaded, softBudgetMs: 360_000 };
		const { pi, emitted } = fakePi();
		const preflight = fakePreflight({ guard: reviewerCase.config.guard, model: REVIEWER_MODEL });
		const controller = await createLaneController(pi, reviewer, { delegation, preflight }, { addSignalListener: noSignals });
		const request = controller.request;
		const guide = String(request.task).slice(reviewer.task.length);
		assert.equal(String(request.task).startsWith(reviewer.task), true, 'the raw task is kept verbatim');
		assert.equal(String(request.task).length <= 1_048_576, true, 'the effective task stays inside the raw cap');
		assert.equal(String(request.task).length, reviewer.task.length + guide.length, 'nothing is truncated off the guide');
		// One effective task, not two constructions of it: the bound contract and the dispatched task
		// are the same string, so the launch digest covers exactly what the child was given.
		assert.equal(preflight.calls[0].task, request.task);
		assert.equal(String(preflight.calls[0].task).length, reviewer.task.length + guide.length);
		// Numeric, role-aware, and it grants no authority the role body does not already carry.
		assert.equal(guide.includes('360000'), true, 'the soft budget travels as a number');
		assert.equal(guide.includes('600000'), true, 'the hard deadline travels as a number');
		assert.equal(/\bverdict\b/i.test(guide), true, 'the reviewer guide asks for the verdict');
		assert.equal(/read-only/i.test(guide), true);
		assert.equal(/commit/i.test(guide), false, 'the reviewer guide hands over no writer work');
		assert.equal(/grant/i.test(guide), true, 'the guide states that it grants no authority');
		assert.equal(guide.trim().split('\n').length, 1, 'one concise paragraph, not a rulesprawl');
		assert.equal(guide.length < 600, true, `${guide.length}`);
		// The lane is still the foreground structured public call: no async mode, no steer surface,
		// and the one declared bridge value is the same for the preflight and the request.
		assert.equal('async' in request, false);
		assert.equal('steer' in request, false);
		assert.deepEqual(preflight.calls[0].intercomBridge, request.intercomBridge);
		completeLeaf(pi, controller);
		await controller.settle();

		// Without a configured soft budget the task is byte-identical to the raw one: no guide, no
		// warning timer, the pre-change behaviour exactly.
		const clock = fakeClock();
		const plain = fakePi();
		const plainPreflight = fakePreflight({ guard: reviewerCase.config.guard, model: REVIEWER_MODEL });
		const unconfigured = await createLaneController(plain.pi, loaded, { delegation, preflight: plainPreflight },
			{ now: clock.now, arm: clock.arm, addSignalListener: noSignals });
		assert.equal(unconfigured.request.task, loaded.task);
		assert.equal(plainPreflight.calls[0].task, loaded.task);
		assert.deepEqual(clock.timers, [], 'no warning timer exists when no soft budget is configured');
		completeLeaf(plain.pi, unconfigured);
		await unconfigured.settle();
		assert.equal(emitted.some((e) => e.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT), true);
	} finally {
		reviewerCase.cleanup();
	}

	const writerCase = tempConfig();
	try {
		const writer = { ...readLaneConfig(writerCase.configPath), agent: 'hylja-implementer', timeoutMs: 1_200_000, softBudgetMs: 360_000 };
		const { pi } = fakePi();
		const preflight = fakePreflight({ guard: writerCase.config.guard, model: WRITER_MODEL });
		const controller = await createLaneController(pi, writer, { delegation, preflight }, { addSignalListener: noSignals });
		const guide = String(controller.request.task).slice(writer.task.length);
		assert.equal(preflight.calls[0].task, controller.request.task);
		assert.equal(guide.includes('360000'), true, 'soft 6 minutes');
		assert.equal(guide.includes('1200000'), true, 'hard 20 minutes');
		assert.equal(/commit/i.test(guide), true, 'the writer guide asks for checks, then the commit');
		assert.equal(/report/i.test(guide), true);
		assert.equal(/\bverdict\b/i.test(guide), false, 'the writer guide does not issue review authority');
		completeLeaf(pi, controller, 'Implemented the correction.\n');
		await controller.settle();
	} finally {
		writerCase.cleanup();
	}
});

test('the soft budget warns root exactly once and cancels nothing before the hard deadline', async () => {
	const { config, configPath, cleanup } = tempConfig();
	const clock = fakeClock();
	try {
		const loaded = { ...readLaneConfig(configPath), softBudgetMs: 360_000 };
		const { pi, emitted } = fakePi();
		const controller = await createLaneController(pi, loaded,
			{ delegation, preflight: fakePreflight({ guard: config.guard, model: REVIEWER_MODEL }) },
			{ now: clock.now, arm: clock.arm, addSignalListener: noSignals });
		assert.deepEqual(clock.timers.map((timer) => timer.delayMs), [360_000], 'exactly one armed timer');
		assert.equal(clock.timers[0].cancelled, false);

		clock.fire(360_000);
		const warned = softWarnings(config.progress);
		assert.equal(warned.length, 1, 'one bounded numeric warning');
		assert.equal(warned[0].elapsedMs, 360_000);
		assert.deepEqual(Object.keys(warned[0]).sort(), ['elapsedMs', 'event', 'key']);
		// A repeated callback cannot manufacture a second warning.
		clock.timers[0].handler();
		assert.equal(softWarnings(config.progress).length, 1);
		// The soft deadline is a warning for the reader and nothing else: no cancellation, no kill,
		// no deletion, no reset, no approval, and the dispatch this lane owns is still intact.
		assert.equal(emitted.filter((e) => e.event === delegation.SUBAGENT_DELEGATION_CANCEL_EVENT).length, 0,
			'the soft deadline emitted no cancellation at all');
		assert.equal(existsSync(config.dispatch), true);

		// The hard deadline has not arrived, so a completed leaf is still the accepted outcome.
		completeLeaf(pi, controller);
		const value = await controller.settle();
		const written = writeTerminalReceipt(loaded, value);
		assert.equal(written.status, 'completed');
		assert.equal(written.verdict, 'APPROVED');
		assert.equal(softWarnings(config.progress).length, 1, 'the warning is not rewritten at settlement');
		assert.equal(clock.timers[0].cancelled, true, 'the owner timer is drained on settlement');
		for (const event of [delegation.SUBAGENT_DELEGATION_STARTED_EVENT, delegation.SUBAGENT_DELEGATION_UPDATE_EVENT,
			delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT]) {
			assert.equal(pi.live(event), 0, `${event} listener drained`);
		}
	} finally {
		cleanup();
	}
});

test('the one soft warning survives the capped progress tail the CLI reads after the child exits', async () => {
	// Root reads the tail of this file only after the leaf is gone, so a warning a busy child's own
	// updates push out of the cap is a warning nobody ever sees. More owned updates than the file
	// keeps, all fired after the warning, and the warning must still be exactly one numeric snapshot.
	const { config, configPath, cleanup } = tempConfig();
	const clock = fakeClock();
	const updates = MAX_PROGRESS_RECORDS + 8;
	try {
		const loaded = { ...readLaneConfig(configPath), softBudgetMs: 360_000 };
		const { pi, emitted } = fakePi();
		const controller = await createLaneController(pi, loaded,
			{ delegation, preflight: fakePreflight({ guard: config.guard, model: REVIEWER_MODEL }) },
			{ now: clock.now, arm: clock.arm, addSignalListener: noSignals });
		clock.fire(360_000);
		assert.equal(softWarnings(config.progress).length, 1, 'the warning fired once before the updates');

		for (let toolCount = 0; toolCount < updates; toolCount += 1) {
			pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT,
				{ ...controller.tuple, model: REVIEWER_MODEL, runId: RUN_ID, toolCount, durationMs: 360_000 + toolCount });
		}
		completeLeaf(pi, controller);
		await controller.settle();
		assert.equal(controller.setupFailure, null);
		assert.equal(clock.timers[0].cancelled, true, 'the armed warning timer is drained on settlement');
		assert.equal(emitted.filter((entry) => entry.event === delegation.SUBAGENT_DELEGATION_CANCEL_EVENT).length, 0,
			'no retained record cancelled anything');

		// The shipped CLI reader, over the file the real controller actually wrote.
		const fs = { exists: existsSync, size: (p) => statSync(p).size, read: (p, offset, length) => readFileSync(p).subarray(offset, offset + length) };
		const snapshots = readProgress(config.progress, fs);
		assert.equal(snapshots.length <= MAX_PROGRESS_RECORDS, true, `the cap is unchanged: ${snapshots.length}`);
		const warned = snapshots.filter((entry) => entry.event === 'soft_budget_reached');
		assert.equal(warned.length, 1, 'exactly one warning survives the cap');
		assert.deepEqual(Object.keys(warned[0]).sort(), ['elapsedMs', 'event', 'model', 'runId', 'toolCount'],
			'still one bounded numeric snapshot with no field the reader does not bound');
		assert.equal(Number.isFinite(warned[0].elapsedMs) && warned[0].elapsedMs >= 0, true, 'a finite elapsed count');
		assert.equal(warned[0].elapsedMs, 360_000);
		// Chronological order is kept: the warning stays where it fired, ahead of every update that
		// followed it, and the newest updates are the ones the cap keeps.
		assert.equal(snapshots[0].event, 'soft_budget_reached');
		const counts = snapshots.filter((entry) => entry.event === 'progress').map((entry) => entry.toolCount);
		assert.deepEqual(counts, [...counts].sort((a, b) => a - b), 'retained updates keep chronological order');
		assert.equal(snapshots.at(-1).toolCount, updates - 1, 'the newest update is retained');
	} finally {
		cleanup();
	}
});

test('the one soft warning survives the reader byte window that maximum-length metadata produces', async () => {
	// The record cap and the reader's byte cap are one contract, not two. A record the writer keeps
	// because it fits the record cap can still sit far outside the byte-bounded tail root reads after
	// the leaf exits, and then the warning exists in the file but never reaches the reader. Long
	// accepted metadata is the case that splits the two caps, so it is the case that must be proven.
	const { config, configPath, cleanup } = tempConfig();
	const clock = fakeClock();
	const updates = MAX_PROGRESS_RECORDS + 8;
	// The longest string the controller accepts for each bounded field, so every record here is as
	// large as the accepted contract allows it to be.
	const longModel = 'm'.repeat(4096);
	const longRunId = 'r'.repeat(4096);
	try {
		const loaded = { ...readLaneConfig(configPath), softBudgetMs: 360_000 };
		const { pi, emitted } = fakePi();
		const controller = await createLaneController(pi, loaded,
			{ delegation, preflight: fakePreflight({ guard: config.guard, model: REVIEWER_MODEL }) },
			{ now: clock.now, arm: clock.arm, addSignalListener: noSignals });
		clock.fire(360_000);
		assert.equal(softWarnings(config.progress).length, 1, 'the warning fired once before the updates');

		for (let toolCount = 0; toolCount < updates; toolCount += 1) {
			pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT,
				{ ...controller.tuple, model: longModel, runId: longRunId, toolCount, durationMs: 360_000 + toolCount });
		}
		completeLeaf(pi, controller);
		await controller.settle();
		assert.equal(controller.setupFailure, null);
		assert.equal(clock.timers[0].cancelled, true, 'the armed warning timer is drained on settlement');
		// Retaining the warning costs root nothing: no cancel, no kill, no deletion, no reset and no
		// approval timing changes, and the dispatch this lane owns is untouched.
		assert.equal(emitted.filter((entry) => entry.event === delegation.SUBAGENT_DELEGATION_CANCEL_EVENT).length, 0,
			'no retained record cancelled anything');
		assert.equal(existsSync(config.dispatch), true, 'the lane keeps its own dispatch');
		assert.equal(writeTerminalReceipt(loaded, receipt()).verdict, 'CHANGES REQUESTED',
			'the warning is not an approval and never rewrites the receipt verdict');

		// The persisted file is inside both halves of the one window the reader parses.
		const bytes = statSync(config.progress).size;
		assert.equal(bytes <= MAX_PROGRESS_BYTES, true, `${bytes} bytes exceeds the ${MAX_PROGRESS_BYTES} byte window`);
		const persisted = readFileSync(config.progress, 'utf8').split('\n').filter((line) => line.length > 0);
		assert.equal(persisted.length <= MAX_PROGRESS_RECORDS, true, `${persisted.length} records`);
		assert.equal(Buffer.byteLength(readFileSync(config.progress, 'utf8'), 'utf8'), bytes,
			'the cap is measured in the serialized UTF-8 bytes the reader reads');

		// The shipped CLI reader, over the file the real controller actually wrote.
		const fs = { exists: existsSync, size: (p) => statSync(p).size, read: (p, offset, length) => readFileSync(p).subarray(offset, offset + length) };
		const snapshots = readProgress(config.progress, fs);
		assert.equal(snapshots.length <= MAX_PROGRESS_RECORDS, true, `the record cap is unchanged: ${snapshots.length}`);
		const warned = snapshots.filter((entry) => entry.event === 'soft_budget_reached');
		assert.equal(warned.length, 1, 'exactly one warning reaches the reader');
		assert.deepEqual(Object.keys(warned[0]).sort(), ['elapsedMs', 'event', 'model', 'runId', 'toolCount'],
			'still one bounded snapshot with no field the reader does not bound');
		assert.equal(Number.isFinite(warned[0].elapsedMs) && warned[0].elapsedMs >= 0, true, 'a finite elapsed count');
		assert.equal(warned[0].elapsedMs, 360_000);
		// Chronological order survives, and the newest update is one the reader actually has.
		const counts = snapshots.filter((entry) => entry.event === 'progress').map((entry) => entry.toolCount);
		assert.deepEqual(counts, [...counts].sort((a, b) => a - b), 'retained updates keep chronological order');
		assert.equal(snapshots.at(-1).toolCount, updates - 1, 'the newest update is retained');
		assert.equal(snapshots.at(-1).model, longModel, 'the retained update is the one that was written');
		assert.equal(snapshots.at(-1).runId, longRunId);
	} finally {
		cleanup();
	}
});

test('the byte window counts serialized UTF-8 bytes of multibyte and escaped metadata, not characters', async () => {
	// A window measured in characters is not the window the reader reads: a JSON escape and a
	// multibyte character each turn one accepted character into several serialized bytes, so a
	// character-counted budget silently persists far more than the reader can ever see. Both halves
	// of the one window come from one shared constant, and neither is raised to compensate.
	const { config, configPath, cleanup } = tempConfig();
	const clock = fakeClock();
	const updates = MAX_PROGRESS_RECORDS + 8;
	// One character of each accepted field is inflated on the way to bytes: a control character is
	// escaped to six, a three-byte character costs three, and neither is one byte per character.
	const escapedModel = '\u0001'.repeat(4096);
	const multibyteRunId = '一'.repeat(4096);
	const updateLine = JSON.stringify({
		event: 'progress', key: config.key, model: escapedModel, runId: multibyteRunId, toolCount: 1, elapsedMs: 1,
	});
	assert.equal(MAX_PROGRESS_BYTES / updateLine.length >= 4, true,
		`a character-counted budget would admit four of these records (${updateLine.length} characters each)`);
	assert.equal(4 * Buffer.byteLength(updateLine, 'utf8') > MAX_PROGRESS_BYTES, true,
		`four of them are ${4 * Buffer.byteLength(updateLine, 'utf8')} serialized bytes, past the byte window`);
	assert.equal(Buffer.byteLength(updateLine, 'utf8') > updateLine.length, true,
		'the serialized UTF-8 size exceeds the accepted character count');
	try {
		const loaded = { ...readLaneConfig(configPath), softBudgetMs: 360_000 };
		const { pi } = fakePi();
		const controller = await createLaneController(pi, loaded,
			{ delegation, preflight: fakePreflight({ guard: config.guard, model: REVIEWER_MODEL }) },
			{ now: clock.now, arm: clock.arm, addSignalListener: noSignals });
		clock.fire(360_000);
		for (let toolCount = 0; toolCount < updates; toolCount += 1) {
			pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT,
				{ ...controller.tuple, model: escapedModel, runId: multibyteRunId, toolCount, durationMs: 360_000 + toolCount });
		}
		completeLeaf(pi, controller);
		await controller.settle();
		assert.equal(controller.setupFailure, null);

		const bytes = statSync(config.progress).size;
		assert.equal(bytes <= MAX_PROGRESS_BYTES, true, `${bytes} bytes exceeds the ${MAX_PROGRESS_BYTES} byte window`);
		const persisted = readFileSync(config.progress, 'utf8').split('\n').filter((line) => line.length > 0);
		assert.equal(persisted.length <= MAX_PROGRESS_RECORDS, true, `${persisted.length} records`);

		const fs = { exists: existsSync, size: (p) => statSync(p).size, read: (p, offset, length) => readFileSync(p).subarray(offset, offset + length) };
		const snapshots = readProgress(config.progress, fs);
		assert.equal(snapshots.filter((entry) => entry.event === 'soft_budget_reached').length, 1,
			'exactly one warning reaches the reader through a byte-counted window');
		assert.equal(snapshots.at(-1).toolCount, updates - 1, 'the newest update is retained');
		assert.equal(snapshots.at(-1).model, escapedModel, 'escaped metadata round-trips through the bounded read');
		assert.equal(snapshots.at(-1).runId, multibyteRunId, 'multibyte metadata round-trips through the bounded read');

		// One window, not two coincidentally equal numbers: the reader clamps its positional read to
		// the same constant the writer persists inside, and neither bound was raised.
		assert.equal(MAX_PROGRESS_BYTES, MAX_PROGRESS_RECORDS * 512, 'the byte window is the existing one');
		assert.equal(MAX_RANGE_READ_BYTES, MAX_PROGRESS_BYTES, 'the reader and the writer share one window');
	} finally {
		cleanup();
	}
});

test('settling, failing or overflowing before the soft budget leaves no timer behind', async () => {
	const settledCase = tempConfig();
	const clock = fakeClock();
	try {
		const loaded = { ...readLaneConfig(settledCase.configPath), softBudgetMs: 360_000 };
		const { pi } = fakePi();
		const controller = await createLaneController(pi, loaded,
			{ delegation, preflight: fakePreflight({ guard: settledCase.config.guard, model: REVIEWER_MODEL }) },
			{ now: clock.now, arm: clock.arm, addSignalListener: noSignals });
		completeLeaf(pi, controller);
		await controller.settle();
		assert.equal(clock.timers.length, 1);
		assert.equal(clock.timers[0].cancelled, true, 'settlement drains the armed warning');
		clock.fire(360_000);
		assert.equal(softWarnings(settledCase.config.progress).length, 0, 'a settled lane warns nothing');
	} finally {
		settledCase.cleanup();
	}

	const failureCase = tempConfig();
	try {
		const failing = fakePreflight({ guard: failureCase.config.guard });
		failing.resolveSubagentLaunchContract = async () => ({ ok: false, code: 'restricted_agent', message: 'synthetic', diagnostics: [] });
		const clock2 = fakeClock();
		const { pi } = fakePi();
		const loaded = { ...readLaneConfig(failureCase.configPath), softBudgetMs: 360_000 };
		const controller = await createLaneController(pi, loaded, { delegation, preflight: failing },
			{ now: clock2.now, arm: clock2.arm, addSignalListener: noSignals });
		await controller.settle();
		assert.equal(controller.setupFailure, LANE_SETUP_FAILURES.contract);
		assert.deepEqual(clock2.timers, [], 'a lane that never dispatched arms no warning timer');
	} finally {
		failureCase.cleanup();
	}

	// An effective task past the raw cap fails restrictively. Truncating the task or dropping the
	// guide would dispatch a leaf with a task nobody bound a digest to.
	const oversizeCase = tempConfig();
	try {
		const clock3 = fakeClock();
		const { pi, emitted } = fakePi();
		const loaded = readLaneConfig(oversizeCase.configPath);
		const controller = await createLaneController(pi, { ...loaded, task: 'x'.repeat(1_048_576), softBudgetMs: 360_000 },
			{ delegation, preflight: fakePreflight({ guard: oversizeCase.config.guard, model: REVIEWER_MODEL }) },
			{ now: clock3.now, arm: clock3.arm, addSignalListener: noSignals });
		await controller.settle();
		assert.equal(controller.setupFailure, LANE_SETUP_FAILURES.config);
		assert.equal(emitted.some((e) => e.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT), false, 'no leaf is launched');
		assert.equal(existsSync(oversizeCase.config.dispatch), false);
		assert.deepEqual(clock3.timers, []);
	} finally {
		oversizeCase.cleanup();
	}
});

test('the shipped default arm really fires the warning once and is drained on settlement', async () => {
	// Only the fake Pi host is injected, so the real timer and the real clock are what run: a fake
	// dependency must not be the only path that can warn.
	const { config, configPath, cleanup } = tempConfig();
	let pi = null;
	let controller = null;
	try {
		const loaded = { ...readLaneConfig(configPath), softBudgetMs: 1 };
		const host = fakePi();
		pi = host.pi;
		controller = await createLaneController(pi, loaded,
			{ delegation, preflight: fakePreflight({ guard: config.guard, model: REVIEWER_MODEL }) });
		await new Promise((done) => setTimeout(done, 20));
		const warned = softWarnings(config.progress);
		assert.equal(warned.length, 1, `${warned.length}`);
		assert.equal(Number.isFinite(warned[0].elapsedMs) && warned[0].elapsedMs >= 0, true, 'the real clock reported a finite elapsed count');
	} finally {
		// A failed assertion must still settle the real signal listeners this case registered.
		if (controller !== null && pi !== null) {
			completeLeaf(pi, controller);
			await controller.settle();
		}
		cleanup();
	}
});

test('the argv loads only the three supplied extensions and sends one fixed input', () => {
	const { config, cleanup } = tempConfig();
	try {
		const argv = buildArgv(config);
		assert.deepEqual(argv.slice(0, 2), ['--print', '--no-extensions']);
		assert.equal(argv.includes('--no-skills'), true);
		assert.equal(argv.at(-1), FIXED_LANE_INPUT);
		assert.equal(argv.filter((a) => a === FIXED_LANE_INPUT).length, 1);
		assert.equal(argv.filter((a) => a === '--extension').length, 3);
		assert.deepEqual(argv.filter((a, i) => argv[i - 1] === '--extension'), [config.subagents, config.guard, config.controller]);
	} finally {
		cleanup();
	}
});

test('public artifacts are found with one listing, need exactly one pair, and open only meta and output', () => {
	const { config, cleanup } = tempConfig();
	try {
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		const mine = `${RUN_ID}_hylja-reviewer_0`;
		writeFileSync(join(artifactsDir, `${mine}_meta.json`), JSON.stringify(meta()));
		writeFileSync(join(artifactsDir, `${mine}_output.md`), 'CHANGES REQUESTED\n\nBody.');
		writeFileSync(join(artifactsDir, `${mine}_transcript.jsonl`), PLANTED_REASONING);
		const opened = [];
		const fs = { exists: existsSync, readdir: (p) => readdirSync(p), readFile: (p) => { opened.push(p); return readFileSync(p, 'utf8'); } };
		const found = discoverPublicArtifacts(config, RUN_ID, 'hylja-reviewer', fs);
		assert.equal(found.ok, true, JSON.stringify(found));
		assert.equal(found.artifacts.meta, join(artifactsDir, `${mine}_meta.json`));
		assert.equal(found.artifacts.output, join(artifactsDir, `${mine}_output.md`));
		assert.equal(discoverPublicArtifacts(config, 'synthetic-absent-run', 'hylja-reviewer', fs).reason, SETUP_FAILURES.artifacts);
		assert.equal(discoverPublicArtifacts(config, RUN_ID, 'hylja-implementer', fs).reason, SETUP_FAILURES.artifacts);
		// A metadata file with no public output is incomplete evidence, not a successful discovery.
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_1_output.md`), 'x');
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_1_meta.json`), '{}');
		assert.equal(discoverPublicArtifacts(config, RUN_ID, 'hylja-reviewer', fs).reason, SETUP_FAILURES.artifacts);
		rmSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_1_meta.json`));
		rmSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_1_output.md`));
		verifyArtifacts(config, { model: REVIEWER_MODEL, timeoutMs: 900_000 }, dispatchRecord(config), receipt(), found.artifacts, fs);
		assert.equal(opened.some((p) => p.endsWith('_transcript.jsonl')), false);
	} finally {
		cleanup();
	}
});

test('discovered artifacts must share one stem, and the resolved extension record must carry supported provenance', () => {
	const { config, cleanup } = tempConfig();
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
	mkdirSync(artifactsDir, { recursive: true });
	const fs = { exists: existsSync, readdir: (p) => readdirSync(p), readFile: (p) => readFileSync(p, 'utf8') };
	const write = (suffix, body) => writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_${suffix}`), body);
	try {
		// Two individually plausible files from two different attempts are not one artifact pair.
		write('0_meta.json', JSON.stringify(meta()));
		write('1_output.md', 'CHANGES REQUESTED\n\nBody.');
		assert.equal(discoverPublicArtifacts(config, RUN_ID, 'hylja-reviewer', fs).reason, SETUP_FAILURES.artifacts);
		rmSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_1_output.md`));
		write('0_output.md', 'CHANGES REQUESTED\n\nBody.');
		const found = discoverPublicArtifacts(config, RUN_ID, 'hylja-reviewer', fs);
		assert.equal(found.ok, true, JSON.stringify(found));
		assert.equal(found.artifacts.meta.endsWith(`${RUN_ID}_hylja-reviewer_0_meta.json`), true, found.artifacts.meta);
		assert.equal(found.artifacts.output.endsWith(`${RUN_ID}_hylja-reviewer_0_output.md`), true, found.artifacts.output);

		// The positive record is the installed launch-resolved shape the retained smoke actually wrote.
		const dispatch = dispatchRecord(config);
		const check = (value) => verifyArtifacts(config, profile, dispatch, receipt(), found.artifacts, {
			exists: () => true,
			readdir: () => [],
			readFile: (p) => (p === found.artifacts.meta ? JSON.stringify(value) : 'CHANGES REQUESTED\n\nBody.'),
		});
		assert.equal(check(meta()).ok, true, JSON.stringify(check(meta())));
		const resolved = meta().launchResolvedExtensions;
		// An unsupported schema version, a source that is not the launch-resolved one, an absent key
		// and an incomplete omitted ledger are refused, never read as proven extension provenance.
		for (const launchResolvedExtensions of [
			{ ...resolved, version: 2 },
			{ ...resolved, source: 'declared' },
			{ ...resolved, source: undefined },
			{ ...resolved, version: undefined },
			{ ...resolved, required: 'sha256:synthetic-required' },
			{ ...resolved, omitted: { runtime: 0, configured: 0, required: 0 } },
			{ ...resolved, omitted: { runtime: 0, configured: 0, required: 0, effective: '0' } },
		]) {
			const refused = check(meta({ launchResolvedExtensions }));
			assert.equal(refused.reason, SETUP_FAILURES.guard, JSON.stringify(launchResolvedExtensions));
		}
	} finally {
		cleanup();
	}
});

test('all four resolved extension lists are validated together, and required must be effective', () => {
	const { config, cleanup } = tempConfig();
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const artifacts = { meta: join(config.sessionDir, 'schema-meta.json'), output: join(config.sessionDir, 'schema-output.md') };
	try {
		const check = (launchResolvedExtensions) => verifyArtifacts(config, profile, dispatchRecord(config), receipt(), artifacts, {
			exists: () => true,
			readdir: () => [],
			readFile: (p) => (p === artifacts.meta ? JSON.stringify(meta({ launchResolvedExtensions })) : 'CHANGES REQUESTED\n\nBody.'),
		});
		const base = meta().launchResolvedExtensions;
		// Positive control: the retained smoke's own record verifies, and so does an explicitly empty
		// runtime list, which is a real assertion of no runtime extension and not missing evidence.
		assert.equal(check(base).ok, true, JSON.stringify(check(base)));
		assert.equal(check({ ...base, runtime: [] }).ok, true, JSON.stringify(check({ ...base, runtime: [] })));
		// One matrix over each of the four lists: absent, null, a primitive and a non-string member are
		// each refused, never defaulted to an empty list that would assert the list's contents.
		for (const name of ['runtime', 'configured', 'required', 'effective']) {
			for (const [label, value] of [
				['missing', undefined],
				['null', null],
				['primitive', 'sha256:synthetic-primitive'],
				['non-string element', [...base[name], 42]],
			]) {
				const variant = { ...base, [name]: value };
				if (value === undefined) delete variant[name];
				assert.equal(check(variant).reason, SETUP_FAILURES.guard, `${name}: ${label}`);
			}
		}
		// A required digest the effective set does not contain is refused: list shape alone is not proof
		// that the obligation occurred.
		const absent = 'sha256:00000000000000ff';
		assert.equal(check({ ...base, required: [absent] }).reason, SETUP_FAILURES.guard);
		// A required digest that is effective, alongside a configured one that is not, is still refused.
		assert.equal(check({ ...base, required: [base.effective[0]], effective: [base.effective[0]] }).reason, SETUP_FAILURES.guard);
	} finally {
		cleanup();
	}
});

test('the runtime record is bound to the preflight contract, and mismatched evidence is refused', () => {
	const { config, cleanup } = tempConfig();
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const artifacts = { meta: join(config.sessionDir, 'meta.json'), output: join(config.sessionDir, 'output.md') };
	try {
		const withMeta = (value, output = 'CHANGES REQUESTED\n\nBody.') => ({
			exists: () => true,
			readdir: () => [],
			readFile: (p) => (p === artifacts.meta ? JSON.stringify(value) : output),
		});
		const dispatch = dispatchRecord(config);
		const check = (m, r, d = dispatch, p = profile) => verifyArtifacts(config, p, d, r, artifacts, withMeta(m));

		assert.equal(check(meta(), receipt()).ok, true, JSON.stringify(check(meta(), receipt())));
		// The declared guard identity and the bound digest, not any overlapping extension digest.
		assert.equal(check(meta(), receipt(), { ...dispatch, expected: { ...dispatch.expected, guardExtension: '/synthetic/other-guard.ts' } }).reason,
			SETUP_FAILURES.guard);
		assert.equal(check(meta(), receipt({ launchContractDigest: 'synthetic-other-digest' })).reason, LANE_SETUP_FAILURES.contract);
		assert.equal(check(meta({ launchContractDigest: 'synthetic-other-digest' }), receipt()).reason, LANE_SETUP_FAILURES.contract);
		assert.equal(check(meta(), receipt({ model: 'synthetic/other:max' })).reason, SETUP_FAILURES.model);
		assert.equal(check(meta(), receipt({ thinking: 'high' })).reason, SETUP_FAILURES.model);
		assert.equal(check(meta({ model: 'openai-codex/gpt-6.1-sol:high' }), receipt()).reason, SETUP_FAILURES.model);
		assert.equal(check(meta({ agent: 'hylja-implementer' }), receipt()).reason, SETUP_FAILURES.role);
		assert.equal(check(meta(), receipt(), dispatch, { model: REVIEWER_MODEL.replace(':max', ':high'), timeoutMs: 900_000 }).reason, SETUP_FAILURES.model);
		// Ambient extensions left on, a missing guard, or an omitted extension is refused.
		const ambient = meta().launchResolvedExtensions;
		assert.equal(check(meta({ launchResolvedExtensions: { ...ambient, disableAmbientExtensions: false } }), receipt()).reason, SETUP_FAILURES.guard);
		assert.equal(check(meta({ launchResolvedExtensions: { ...ambient, configured: [], effective: [] } }), receipt()).reason, SETUP_FAILURES.guard);
		assert.equal(check(meta({ launchResolvedExtensions: { ...ambient, omitted: { runtime: 1, configured: 0, required: 0, effective: 0 } } }), receipt()).reason,
			SETUP_FAILURES.guard);
		assert.equal(check(meta({ launchResolvedExtensions: { ...ambient, effective: ['sha256:09f3249c7287ea1a'] } }), receipt()).reason,
			SETUP_FAILURES.guard);
		// Receipt and dispatch must be the same attempt, and the exit code must be zero.
		assert.equal(check(meta(), receipt({ status: 'timed_out' })).reason, SETUP_FAILURES.status);
		assert.equal(check(meta(), receipt({ exitCode: 1 })).reason, SETUP_FAILURES.malformed);
		assert.equal(check(meta(), receipt({ usage: { input: 'synthetic' } })).reason, SETUP_FAILURES.malformed);
		assert.equal(check(meta(), receipt({ verdict: 'approved' })).reason, SETUP_FAILURES.malformed);
		assert.equal(check(meta(), receipt(), { ...dispatch, requestId: 'synthetic-other-attempt' }).reason, SETUP_FAILURES.tuple);
		assert.equal(check(meta(), receipt(), null).reason, SETUP_FAILURES.tuple);
		// The literal public output must contain the literal terminal result.
		assert.equal(check(meta(), receipt(), dispatch, profile).ok, true);
		assert.equal(verifyArtifacts(config, profile, dispatch, receipt(), artifacts, withMeta(meta(), 'unrelated public text')).reason,
			SETUP_FAILURES.artifacts);
	} finally {
		cleanup();
	}
});

test('the receipt verdict is bound to its literal first line, and empty text cannot approve', () => {
	const { config, cleanup } = tempConfig();
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const artifacts = { meta: join(config.sessionDir, 'meta.json'), output: join(config.sessionDir, 'output.md') };
	try {
		const dispatch = dispatchRecord(config);
		const check = (value, output) => verifyArtifacts(config, profile, dispatch, value, artifacts, {
			exists: () => true,
			readdir: () => [],
			readFile: (p) => (p === artifacts.meta ? JSON.stringify(meta()) : output),
		});
		// The two bound shapes the installed controller actually writes: a reviewer verdict and an
		// author's unlabelled result, which the controller resolves to INCOMPLETE and never to approval.
		assert.equal(check(receipt(), 'CHANGES REQUESTED\n\nBody.').verdict, 'CHANGES REQUESTED');
		assert.equal(check(receipt({ verdict: 'APPROVED', result: { kind: 'text', text: 'APPROVED\n\nBody.' } }), 'APPROVED\n\nBody.').verdict, 'APPROVED');
		const author = check(receipt({ verdict: 'INCOMPLETE', result: { kind: 'text', text: 'Implemented the correction.\n' } }),
			'Implemented the correction.\n');
		assert.equal(author.ok, true, JSON.stringify(author));
		assert.equal(author.verdict, 'INCOMPLETE');

		// An unbound field, vacuous text or a contradiction is malformed evidence, never an approval.
		for (const value of [
			receipt({ verdict: 'APPROVED', result: { kind: 'text', text: '' } }),
			receipt({ verdict: 'APPROVED', result: { kind: 'text', text: '   \n' } }),
			receipt({ verdict: 'APPROVED', result: { kind: 'text', text: 'CHANGES REQUESTED\n\nBody.' } }),
			receipt({ verdict: 'APPROVED', result: { kind: 'text', text: 'All good to me.\n' } }),
			receipt({ verdict: 'APPROVED', result: { kind: 'text', text: '\n\nAPPROVED\n' } }),
			receipt({ verdict: 'CHANGES REQUESTED', result: { kind: 'text', text: 'APPROVED\n' } }),
			receipt({ verdict: 'INCOMPLETE', result: { kind: 'text', text: 'APPROVED\n' } }),
			receipt({ verdict: 'INCOMPLETE', result: { kind: 'text', text: '' } }),
		]) {
			const refused = check(value, 'APPROVED\n\nBody.');
			assert.equal(refused.reason, SETUP_FAILURES.malformed, JSON.stringify(value.result));
			assert.notEqual(refused.verdict, 'APPROVED', JSON.stringify(value.result));
		}

		// The public output carrying the literal text is not proof by itself: its leading line must be
		// the same literal line the receipt binds, so a planted match cannot carry a verdict.
		const bound = receipt({ verdict: 'APPROVED', result: { kind: 'text', text: 'APPROVED\n\nBody.' } });
		assert.equal(check(bound, 'APPROVED\n\nBody.').ok, true);
		assert.equal(check(bound, '\n\nAPPROVED\n\nBody.').ok, true);
		assert.equal(check(bound, 'Synthetic run log\n\nAPPROVED\n\nBody.').reason, SETUP_FAILURES.artifacts);
	} finally {
		cleanup();
	}
});

test('a disabled native writer acceptance is reported honestly, never as a passed gate', () => {
	const { config, cleanup } = tempConfig();
	const writer = { ...config, agent: 'hylja-implementer' };
	const writerProfile = { model: WRITER_MODEL, timeoutMs: 1_200_000 };
	const dispatch = dispatchRecord(writer, { expected: { ...dispatchRecord(writer).expected, model: WRITER_MODEL } });
	const writerMeta = meta({ agent: 'hylja-implementer', model: WRITER_MODEL });
	const writerReceipt = receipt({
		agent: 'hylja-implementer',
		model: WRITER_MODEL,
		verdict: 'APPROVED',
		result: { kind: 'text', text: 'APPROVED\n\nBody.' },
	});
	const artifacts = { meta: join(config.sessionDir, 'writer-meta.json'), output: join(config.sessionDir, 'writer-output.md') };
	try {
		const withMeta = (value, output = 'APPROVED\n\nBody.') => ({
			exists: () => true, readdir: () => [],
			readFile: (p) => (p === artifacts.meta ? JSON.stringify(value) : output),
		});
		const checked = verifyArtifacts(writer, writerProfile, dispatch, writerReceipt, artifacts, withMeta(writerMeta));
		assert.equal(checked.ok, true, JSON.stringify(checked));
		assert.equal(checked.acceptance, 'not-required');
		assert.equal(checked.writerAcceptanceGate, 'not-required');
		// Completed is not approval: the writer gate did not run, so root admits it separately.
		assert.equal(checked.verdict, 'APPROVED');
		assert.equal(checked.acceptanceProvesApproval, false);
		assert.equal('acceptancePassed' in checked, false);
		// A successful writer acceptance the installed extension reports is accepted as checked.
		const real = verifyArtifacts(writer, writerProfile, dispatch, writerReceipt, artifacts,
			withMeta({ ...writerMeta, acceptance: { status: 'checked', explicit: false } }));
		assert.equal(real.ok, true, JSON.stringify(real));
		assert.equal(real.acceptance, 'checked');
		// An actual acceptance failure, an absent record and an unknown status are refused.
		for (const acceptance of [{ status: 'failed', explicit: true }, undefined, { explicit: true }, { status: 'synthetic-approved', explicit: true },
			{ status: 42, explicit: true }]) {
			assert.equal(verifyArtifacts(writer, writerProfile, dispatch, writerReceipt, artifacts,
				withMeta({ ...writerMeta, acceptance })).reason, SETUP_FAILURES.acceptance, JSON.stringify(acceptance));
		}
	} finally {
		cleanup();
	}
});

test('a full lane runs the real CLI against a fake transport on a synthetic platform', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_meta.json`), JSON.stringify(meta()));
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_output.md`), 'CHANGES REQUESTED\n\nBody.');
		const record = [];
		const result = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({
				record,
				onLaunch(options, child) {
					assert.equal(options.env[ 'HYLJA_NATIVE_LANE_CONFIG' ], configPath);
					// The installed package directory, never a guessed path outside it.
					assert.equal(options.env.HYLJA_NATIVE_LANE_SUBAGENTS, config.subagents);
					child.stderr.emit('data', Buffer.from(PLANTED_REASONING));
					writeFileSync(config.receipt, JSON.stringify(receipt(), null, 2));
					writeFileSync(config.dispatch, `${JSON.stringify(dispatchRecord(config), null, 2)}\n`);
					writeFileSync(config.progress, `${JSON.stringify({ event: 'progress', key: config.key, runId: RUN_ID, model: REVIEWER_MODEL, toolCount: 53, elapsedMs: 296_680 })}\n`);
				},
			}),
		});
		assert.equal(result.ok, true, JSON.stringify(result));
		assert.equal(record.length, 1);
		assert.equal(record[0].command, config.pi);
		assert.equal(record[0].args.at(-1), FIXED_LANE_INPUT);
		const written = JSON.parse(readFileSync(config.verification, 'utf8'));
		assert.equal(written.verdict, 'CHANGES REQUESTED');
		assert.equal(written.model, REVIEWER_MODEL);
		assert.equal(written.toolCount, 19);
		assert.equal(written.acceptance, 'not-required');
		assert.equal(written.writerAcceptanceGate, 'not-required');
		assert.equal(written.expectedLaunchContractDigest, EXPECTED_DIGEST);
		assert.equal(written.tuple.requestId, REQUEST_ID);
		assert.equal(written.progress.at(-1).toolCount, 53);
		const publicText = readFileSync(config.verification, 'utf8');
		assert.equal(publicText.includes(PLANTED_REASONING), false, 'child stderr is never echoed into the record');
		assert.equal(publicText.includes('result'), false, 'the leaf text stays in its own receipt');
		// A second run over the same evidence paths is refused rather than reusing stale evidence.
		const stale = await runNativeLane(['--config', configPath], { spawn: fakeSpawn() });
		assert.equal(stale.reason, SETUP_FAILURES.stale);
	} finally {
		cleanup();
	}
});

test('a mismatched dispatch tuple, a nonzero native exit and a nonzero verdict are all refused', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	const evidence = () => {
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_meta.json`), JSON.stringify(meta()));
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_output.md`), 'CHANGES REQUESTED\n\nBody.');
	};
	try {
		evidence();
		const mismatched = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({
				onLaunch: () => {
					writeFileSync(config.receipt, JSON.stringify(receipt({ requestId: 'synthetic-other-attempt' })));
					writeFileSync(config.dispatch, JSON.stringify(dispatchRecord(config)));
				},
			}),
		});
		assert.equal(mismatched.reason, SETUP_FAILURES.tuple);

		for (const path of [config.receipt, config.dispatch, config.verification, config.progress]) rmSync(path, { force: true });
		const nonzero = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({
				exitCode: 1,
				onLaunch: () => {
					writeFileSync(config.receipt, JSON.stringify(receipt()));
					writeFileSync(config.dispatch, JSON.stringify(dispatchRecord(config)));
				},
			}),
		});
		assert.equal(nonzero.reason, SETUP_FAILURES.nativeExit);
		assert.equal(JSON.parse(readFileSync(config.verification, 'utf8')).nativeExitCode, 1);
	} finally {
		cleanup();
	}
});

test('a failed, timed-out or malformed receipt is explicit, and no watchdog timer survives', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const missing = await runNativeLane(['--config', configPath], { spawn: fakeSpawn() });
		assert.equal(missing.reason, SETUP_FAILURES.receipt);
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_meta.json`), JSON.stringify(meta()));
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_output.md`), 'CHANGES REQUESTED\n\nBody.');
		for (const path of [config.verification, config.receipt, config.dispatch, config.progress]) rmSync(path, { force: true });
		const failed = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ onLaunch: () => {
				writeFileSync(config.receipt, JSON.stringify(receipt({ status: 'failed' })));
				writeFileSync(config.dispatch, JSON.stringify(dispatchRecord(config)));
			} }),
		});
		assert.equal(failed.reason, SETUP_FAILURES.status);
		assert.equal(JSON.parse(readFileSync(config.verification, 'utf8')).status, 'failed');
		for (const path of [config.verification, config.receipt, config.dispatch, config.progress]) rmSync(path, { force: true });
		const malformed = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ onLaunch: () => writeFileSync(config.receipt, '{ not json') }),
		});
		assert.equal(malformed.reason, SETUP_FAILURES.receipt);
		assert.equal((await runNativeLane([], {}))?.reason, SETUP_FAILURES.argv);
		assert.equal((await runNativeLane(['--config', 'relative.json'], {}))?.reason, SETUP_FAILURES.argv);
	} finally {
		cleanup();
	}
});

test('a fired watchdog is latched before the stop and refuses late zero-exit completed approval evidence', async () => {
	const { config, configPath, cleanup } = tempConfig();
	const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
	mkdirSync(artifactsDir, { recursive: true });
	writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_meta.json`), JSON.stringify(meta()));
	writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_output.md`), 'APPROVED\n\nBody.');
	const approved = receipt({ verdict: 'APPROVED', result: { kind: 'text', text: 'APPROVED\n\nBody.' } });
	// Only the clock is injected, so the watchdog is the real one; it is fired by the recorded timer
	// instead of by waiting out a ten-minute budget.
	const timers = [];
	const clock = () => ({ setTimeout: (fn, ms) => timers.push({ fn, ms }) && timers.length, clearTimeout: () => {}, addSignalListener: () => () => {} });
	const evidence = () => {
		writeFileSync(config.receipt, JSON.stringify(approved));
		writeFileSync(config.dispatch, JSON.stringify(dispatchRecord(config)));
		writeFileSync(config.progress, `${JSON.stringify({ event: 'progress', key: config.key, runId: RUN_ID, model: REVIEWER_MODEL, toolCount: 53, elapsedMs: 296_680 })}\n`);
	};
	try {
		const fired = await runNativeLane(['--config', configPath], {
			...clock(),
			spawn: fakeSpawn({ hang: true, onLaunch: (_options, child) => {
				evidence();
				const watchdog = timers.find((timer) => timer.ms === config.timeoutMs + WATCHDOG_GRACE_MS);
				assert.notEqual(watchdog, undefined, 'the watchdog is armed one grace past the request timeout');
				watchdog.fn();
				assert.deepEqual(child.signals, ['SIGTERM'], 'a fired deadline stops the owned child');
				child.emit('close', 0); // the late zero exit of a child the deadline already stopped
			} }),
		});
		assert.equal(fired.ok, false, 'expiry is not carried away by late completed evidence');
		assert.equal(fired.reason, SETUP_FAILURES.status);
		assert.equal(fired.detail, 'deadline');
		assert.equal(fired.record.deadlineExceeded, true);
		assert.equal(fired.record.verdict, 'INCOMPLETE');
		assert.equal(fired.record.nativeExitCode, 0);
		assert.equal(fired.record.status, 'completed');
		assert.equal(JSON.parse(readFileSync(config.verification, 'utf8')).verdict, 'INCOMPLETE');

		// The control: byte-identical evidence, same platform, no fired deadline, is the verified lane.
		for (const path of [config.receipt, config.dispatch, config.verification, config.progress]) rmSync(path, { force: true });
		const control = await runNativeLane(['--config', configPath], {
			...clock(),
			spawn: fakeSpawn({ onLaunch: () => { evidence(); } }),
		});
		assert.equal(control.ok, true, JSON.stringify(control));
		assert.equal(control.record.verdict, 'APPROVED');
		assert.equal(control.record.deadlineExceeded, false);
	} finally {
		cleanup();
	}
});

test('a hard deadline is INCOMPLETE, keeps the planted evidence and leaves no timer alive', async () => {
	const { config, configPath, cleanup } = tempConfig({ softBudgetMs: 360_000 });
	const timers = [];
	const cleared = [];
	const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
	mkdirSync(artifactsDir, { recursive: true });
	const candidate = join(artifactsDir, 'synthetic-candidate-note.md');
	const candidateBody = `${PLANTED_RECENT}\n`;
	writeFileSync(candidate, candidateBody);
	try {
		const result = await runNativeLane(['--config', configPath], {
			setTimeout: (fn, ms) => {
				const timer = { fn, ms };
				timers.push(timer);
				return timer;
			},
			clearTimeout: (timer) => cleared.push(timer),
			addSignalListener: () => () => {},
			spawn: fakeSpawn({ hang: true, onLaunch: (_options, child) => {
				writeFileSync(config.receipt, JSON.stringify(receipt({
					verdict: 'APPROVED', result: { kind: 'text', text: 'APPROVED\n\nBody.' },
				})));
				writeFileSync(config.dispatch, `${JSON.stringify(dispatchRecord(config), null, 2)}\n`);
				writeFileSync(config.progress, `${JSON.stringify({ event: 'dispatch', key: config.key })}\n`
					+ `${JSON.stringify({ event: 'soft_budget_reached', key: config.key, toolCount: 12, elapsedMs: 360_000 })}\n`);
				const watchdog = timers.find((timer) => timer.ms === config.timeoutMs + WATCHDOG_GRACE_MS);
				assert.notEqual(watchdog, undefined, 'the hard watchdog is armed one grace past the request timeout');
				watchdog.fn();
				child.emit('close', 0);
			} }),
		});
		// A hard timeout is never an approval, and the soft warning that preceded it is not one either.
		assert.equal(result.ok, false, JSON.stringify(result));
		assert.equal(result.reason, SETUP_FAILURES.status);
		assert.equal(result.record.verdict, 'INCOMPLETE');
		assert.equal(result.record.deadlineExceeded, true);
		assert.equal(result.record.status, 'completed');
		// The warning reached root's own record, as a bounded numeric progress snapshot.
		const warned = result.record.progress.filter((entry) => entry.event === 'soft_budget_reached');
		assert.equal(warned.length, 1, JSON.stringify(result.record.progress));
		assert.equal(warned[0].elapsedMs, 360_000);
		assert.equal(warned[0].toolCount, 12);
		// A known hard timeout keeps the worktree evidence: nothing planted or written by the leaf is
		// deleted or rewritten, so root can recover from exactly what the attempt left behind.
		assert.equal(readFileSync(candidate, 'utf8'), candidateBody, 'a planted candidate file survives the timeout');
		assert.equal(JSON.parse(readFileSync(config.receipt, 'utf8')).verdict, 'APPROVED', 'the leaf receipt is left as the leaf wrote it');
		assert.equal(JSON.parse(readFileSync(config.verification, 'utf8')).verdict, 'INCOMPLETE');
		// Nothing survives: every armed timer, including the kill ladder, was cleared.
		assert.equal(timers.length >= 2, true, `${timers.length}`);
		assert.deepEqual([...cleared].sort(), [...timers].sort(), 'every armed timer was disarmed');
	} finally {
		cleanup();
	}
});

test('progress is read from a bounded file, not an unbounded one', () => {
	const { config, cleanup } = tempConfig();
	try {
		const lines = Array.from({ length: MAX_PROGRESS_RECORDS + 400 },
			(_, i) => JSON.stringify({ event: 'progress', key: config.key, toolCount: i, elapsedMs: i })).join('\n');
		writeFileSync(config.progress, `${lines}\n`);
		const fs = { exists: () => true, size: (p) => readFileSync(p).length, read: (p, offset, length) => readFileSync(p).subarray(offset, offset + length) };
		const snapshots = readProgress(config.progress, fs);
		assert.equal(snapshots.length <= MAX_PROGRESS_RECORDS, true, `${snapshots.length}`);
		assert.equal(snapshots.at(-1).toolCount, MAX_PROGRESS_RECORDS + 399);
		assert.equal(readProgress(join(config.sessionDir, 'absent.ndjson'), fs).length, 0);
	} finally {
		cleanup();
	}
});

test('a null or primitive progress record is bounded malformed evidence, never a thrown error', () => {
	const { config, cleanup } = tempConfig();
	try {
		const lines = ['null', '42', 'true', '"synthetic-planted-record.invalid"', '[1,2]',
			JSON.stringify({ event: 'progress', key: config.key, runId: RUN_ID, model: REVIEWER_MODEL, toolCount: 53, elapsedMs: 296_680 })];
		writeFileSync(config.progress, `${lines.join('\n')}\n`);
		const fs = { exists: () => true, size: (p) => readFileSync(p).length, read: (p, offset, length) => readFileSync(p).subarray(offset, offset + length) };
		const snapshots = readProgress(config.progress, fs);
		assert.equal(snapshots.length, lines.length, 'every parsed record yields exactly one bounded snapshot');
		for (const snapshot of snapshots.slice(0, lines.length - 1)) {
			assert.deepEqual(snapshot, { event: 'malformed' }, 'a record that is not an object is malformed evidence');
		}
		assert.equal(snapshots.at(-1).toolCount, 53, 'a well-formed record in the same file still survives');
		// The bounded evidence carries no planted value and no non-scalar field.
		const publicText = JSON.stringify(snapshots);
		assert.equal(publicText.includes('synthetic-planted-record.invalid'), false);
		for (const snapshot of snapshots) {
			for (const [field, value] of Object.entries(snapshot)) {
				assert.equal(['event', 'model', 'runId', 'toolCount', 'elapsedMs'].includes(field), true, field);
				assert.equal(['string', 'number'].includes(typeof value), true, `${field} ${typeof value}`);
			}
		}
	} finally {
		cleanup();
	}
});

test('the controller passes strict TypeScript semantic checking, and the checker really sees diagnostics', () => {
	const { dir, cleanup } = tempConfig();
	const controller = resolve(repoRoot, '.pi', 'lib', 'hylja-native-lane.ts');
	const options = {
		target: ts.ScriptTarget.ES2024,
		module: ts.ModuleKind.NodeNext,
		moduleResolution: ts.ModuleResolutionKind.NodeNext,
		strict: true,
		noUncheckedIndexedAccess: true,
		exactOptionalPropertyTypes: true,
		noImplicitAny: true,
		verbatimModuleSyntax: true,
		noEmit: true,
		skipLibCheck: true,
	};
	// This checkout has no @types/node, so the purely environmental diagnostics are excluded and
	// nothing else: an implicit any, a possibly undefined index or a wrong call still fails.
	const environmental = (d) => {
		const message = ts.flattenDiagnosticMessageText(d.messageText, ' ');
		return message.includes("Cannot find name 'process'") || (d.code === 2307 && message.includes("'node:"));
	};
	const diagnose = (files) => {
		const program = ts.createProgram(files, options);
		return ts.getPreEmitDiagnostics(program).filter((d) => d.file !== undefined
			&& files.some((f) => resolve(d.file.fileName) === resolve(f)) && !environmental(d));
	};
	// The control file carries an implicit any and a possibly undefined index: the mechanical check
	// must see both, so a green controller is a real check and not a stripped-types illusion.
	const control = join(dir, 'control.ts');
	writeFileSync(control, 'export function control(values: string[]) {\n\tconst index = [1];\n\tconst pick = (v) => v;\n\treturn pick(values[index[0]]);\n}\n');
	const controlDiagnostics = diagnose([control]);
	assert.equal(controlDiagnostics.length >= 2, true, `${controlDiagnostics.length} control diagnostics`);
	assert.equal(controlDiagnostics.some((d) => d.code === 7006), true, 'implicit any diagnostic');
	assert.equal(controlDiagnostics.some((d) => d.code === 2538 || d.code === 18048), true,
		`unchecked index diagnostic: ${controlDiagnostics.map((d) => d.code).join(',')}`);

	const controllerDiagnostics = diagnose([controller]);
	assert.deepEqual(controllerDiagnostics.map((d) => `${d.file?.fileName}: ${ts.flattenDiagnosticMessageText(d.messageText, ' ')}`), [],
		'the controller must pass strict semantic checking');
	// A ts-ignore or an unchecked assertion is not a passing check either.
	assert.equal(readFileSync(controller, 'utf8').includes('@ts-ignore'), false);
	assert.equal(/:\s*any\b/.test(readFileSync(controller, 'utf8')), false);
	cleanup();
});

test('the installed Pi executable, role profiles and controller entrypoint are read, never assumed', () => {
	// Read-only validation of this repository's own paths. The operator-supplied Pi executable and
	// package directory are validated at run time by the CLI, not by this suite.
	for (const path of [resolve(repoRoot, '.pi', 'extensions', 'hylja-workflow-guard.ts'),
		resolve(repoRoot, '.pi', 'lib', 'hylja-native-lane.ts'),
		resolve(repoRoot, '.pi', 'agents', 'hylja-implementer.md'),
		resolve(repoRoot, '.pi', 'agents', 'hylja-reviewer.md')]) {
		assert.equal(existsSync(path), true, path);
	}
	assert.equal(readRoleProfile('hylja-implementer').model, WRITER_MODEL);
	assert.equal(readRoleProfile('hylja-reviewer').model, REVIEWER_MODEL);
	assert.equal(readRoleProfile('hylja-implementer').timeoutMs, 1_200_000);
	assert.equal(readRoleProfile('hylja-reviewer').timeoutMs, 900_000);
});

/** Real temporary reference targets: a readable regular file, a directory and an absent path. */
function tempReferences(dir) {
	const file = join(dir, 'required-reference.md');
	writeFileSync(file, 'synthetic required reference body\n');
	const directory = join(dir, 'required-reference-dir');
	mkdirSync(directory);
	return { file, directory, absent: join(dir, 'absent-required-reference.md') };
}

/** One bounded structured list of simple labels and absolute paths, exactly as root supplies it. */
const referenceList = (...entries) => entries.map(([label, path]) => ({ label, path }));

test('a required reference is admitted once, rendered once, and bound to both the preflight and the request', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	try {
		const refs = tempReferences(dir);
		writeFileSync(configPath, JSON.stringify({
			...config,
			requiredReferences: referenceList(['required contract', refs.file], ['candidate note', refs.file]),
		}, null, 2));
		const loaded = readLaneConfig(configPath);
		assert.equal(loaded.requiredReferences.length, 2);
		const { pi, emitted } = fakePi();
		const preflight = fakePreflight({ guard: config.guard });
		const controller = await createLaneController(pi, loaded, { delegation, preflight }, { addSignalListener: noSignals });
		assert.equal(controller.setupFailure, null, String(controller.setupFailure));
		const task = String(controller.request.task);
		// The raw task is kept verbatim and the pointers are appended, never searched for in prose.
		assert.equal(task.startsWith(loaded.task), true);
		const rendered = task.slice(loaded.task.length).split('\n').filter((line) => line.startsWith('- '));
		assert.deepEqual(rendered, [`- required contract: ${refs.file}`, `- candidate note: ${refs.file}`],
			'each label and each exact path is rendered once, in the declared order');
		// Metadata admission is exactly that: not approval, and no guarantee of later availability.
		assert.equal(/metadata/i.test(task), true, 'the task states what admission was');
		assert.equal(/not approval/i.test(task), true, 'admission is not approval');
		assert.equal(/still exists or is still readable/i.test(task), true, 'no later availability is promised');
		// One task for both halves, so the bound digest covers exactly the bytes the child receives.
		assert.equal(preflight.calls[0].task, task);
		assert.equal(task.length <= 1_048_576, true, 'the effective task stays inside the existing raw cap');
		assert.equal(emitted.filter((entry) => entry.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT).length, 1);
		completeLeaf(pi, controller);
		await controller.settle();

		// Omission preserves behaviour exactly: no list, no rendered block, byte-identical task.
		const plain = tempConfig();
		try {
			const plainLoaded = readLaneConfig(plain.configPath);
			assert.equal(plainLoaded.requiredReferences, undefined);
			const plainPi = fakePi();
			const plainPreflight = fakePreflight({ guard: plain.config.guard });
			const unconfigured = await createLaneController(plainPi.pi, plainLoaded,
				{ delegation, preflight: plainPreflight }, { addSignalListener: noSignals });
			assert.equal(unconfigured.setupFailure, null);
			assert.equal(unconfigured.request.task, plainLoaded.task);
			assert.equal(plainPreflight.calls[0].task, plainLoaded.task);
		} finally {
			plain.cleanup();
		}
	} finally {
		cleanup();
	}
});

test('a missing, relative, wrong-shape, directory, unreadable or overbound reference is refused with zero dispatch', async () => {
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const { dir, config, configPath, cleanup } = tempConfig();
	const refs = tempReferences(dir);
	// A planted candidate note is the artifact a refusal must leave untouched.
	const planted = join(dir, 'synthetic-candidate-note.md');
	const plantedBody = `${PLANTED_RECENT}\n`;
	writeFileSync(planted, plantedBody);
	let variant = 0;
	const variantPath = (overrides) => {
		const path = join(dir, `lane-reference-${variant += 1}.json`);
		writeFileSync(path, JSON.stringify({ ...config, ...overrides }, null, 2));
		return path;
	};
	try {
		// Shape is refused by both readers before anything is launched: no repaired value, no truncation,
		// and no label or path echoed back to the caller.
		const refusedShapes = [
			['a bare path string', refs.file],
			['a label-to-path map', { 'required contract': refs.file }],
			['an empty list entry', ['']],
			['a primitive entry', [refs.file]],
			['an unknown entry field', [{ label: 'required contract', path: refs.file, note: 'synthetic' }]],
			['a relative path', referenceList(['required contract', 'relative/reference.md'])],
			['a control character in the label', referenceList(['required\ncontract', refs.file])],
			['an overbound label', referenceList(['l'.repeat(129), refs.file])],
			['an overbound path', referenceList(['required contract', `/${'p'.repeat(4096)}`])],
			['an overbound count', referenceList(...Array.from({ length: 17 }, (unused, index) => [`ref ${index}`, `/${dir}/ref-${index}`]))],
		];
		for (const [name, requiredReferences] of refusedShapes) {
			const path = variantPath({ requiredReferences });
			let message = '';
			try {
				readLaneConfig(path);
			} catch (error) {
				message = String(error.message);
			}
			assert.equal(message, LANE_SETUP_FAILURES.references, `controller: ${name}`);
			assert.equal(validateLaneConfig({ ...config, requiredReferences }, profile).reason, SETUP_FAILURES.references, `CLI: ${name}`);
		}
		assert.equal(validateLaneConfig({ ...config, requiredReferences: [] }, profile).ok, true, 'an empty list asserts no references');

		// Metadata refusals happen in the controller, before preflight and before any dispatch. As root a
		// mode-000 file is genuinely readable, so the unreadable branch is driven through the injected
		// probe instead of a permission bit that would prove nothing about the refusal itself.
		const refusedMetadata = [
			{ name: 'missing', references: referenceList(['required contract', refs.absent]) },
			{ name: 'directory', references: referenceList(['required contract', refs.directory]) },
			{
				name: 'unreadable',
				references: referenceList(['required contract', refs.file]),
				probe: () => ({ isFile: true, isDirectory: false, readable: false }),
			},
			{
				name: 'not a regular file',
				references: referenceList(['required contract', refs.file]),
				probe: () => ({ isFile: false, isDirectory: false, readable: true }),
			},
			{
				name: 'no metadata',
				references: referenceList(['required contract', refs.file]),
				probe: () => null,
			},
		];
		for (const { name, references, probe } of refusedMetadata) {
			const loaded = readLaneConfig(variantPath({ requiredReferences: references }));
			const { pi, emitted } = fakePi();
			const clock = fakeClock();
			const preflight = fakePreflight({ guard: config.guard });
			const controller = await createLaneController(pi, loaded, { delegation, preflight },
				{ now: clock.now, arm: clock.arm, addSignalListener: noSignals, ...(probe === undefined ? {} : { referenceProbe: probe }) });
			await controller.settle();
			assert.equal(controller.setupFailure, LANE_SETUP_FAILURES.references, name);
			assert.equal(preflight.calls.length, 0, `${name}: no launch contract was resolved`);
			assert.equal(emitted.some((entry) => entry.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT), false, `${name}: zero dispatch`);
			assert.equal(existsSync(config.dispatch), false, `${name}: no dispatch was persisted`);
			assert.equal(readFileSync(config.progress, 'utf8').includes('setup_failure'), true, `${name}: reported as a setup failure`);
			assert.deepEqual(clock.timers, [], `${name}: no timer was armed`);
			assert.equal(readFileSync(planted, 'utf8'), plantedBody, `${name}: the planted artifact is preserved`);
			assert.equal(readFileSync(config.progress, 'utf8').includes(refs.file), false, `${name}: no planted path is echoed`);
		}
	} finally {
		cleanup();
	}
});

test('the CLI admits a real required reference before it launches and refuses one it cannot admit', async () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	const refs = tempReferences(dir);
	const planted = join(dir, 'synthetic-candidate-note.md');
	const plantedBody = `${PLANTED_RECENT}\n`;
	writeFileSync(planted, plantedBody);
	let variant = 0;
	const variantPath = (overrides) => {
		const path = join(dir, `lane-cli-reference-${variant += 1}.json`);
		writeFileSync(path, JSON.stringify({ ...config, ...overrides }, null, 2));
		return path;
	};
	const clearEvidence = () => {
		for (const path of [config.receipt, config.dispatch, config.verification, config.progress]) rmSync(path, { force: true });
	};
	try {
		// Positive: the exact generated pointer reaches the native request the child is launched with.
		clearEvidence();
		const record = [];
		const launched = await runNativeLane(['--config', variantPath({ requiredReferences: referenceList(['required contract', refs.file]) })], {
			spawn: fakeSpawn({
				record,
				onLaunch: (options) => {
					const childConfig = JSON.parse(readFileSync(options.env[ 'HYLJA_NATIVE_LANE_CONFIG' ], 'utf8'));
					assert.deepEqual(childConfig.requiredReferences, [{ label: 'required contract', path: refs.file }],
						'the child is launched with the exact path root admitted');
				},
			}),
		});
		assert.equal(record.length, 1, 'an admitted reference launches the lane once');
		assert.equal(record[0].args.at(-1), FIXED_LANE_INPUT);
		assert.equal(launched.reason, SETUP_FAILURES.receipt, 'the fake child leaves no leaf evidence behind');
		assert.equal(readFileSync(planted, 'utf8'), plantedBody, 'the planted artifact survives the launched lane');

		// Negatives: a fixed refusal, zero child processes and every artifact left exactly as it was.
		// The unreadable case is injected through the CLI's own filesystem seam, so it holds as root.
		const refused = [
			{ name: 'missing', references: referenceList(['required contract', refs.absent]) },
			{ name: 'directory', references: referenceList(['required contract', refs.directory]) },
			{ name: 'relative', references: referenceList(['required contract', 'relative/reference.md']) },
			{ name: 'wrong shape', references: { 'required contract': refs.file } },
			{
				name: 'unreadable',
				references: referenceList(['required contract', refs.file]),
				fs: { exists: existsSync, readFile: (path) => readFileSync(path, 'utf8'), file: () => ({ isFile: true, isDirectory: false, readable: false }) },
			},
			{
				name: 'no metadata seam',
				references: referenceList(['required contract', refs.file]),
				fs: { exists: existsSync, readFile: (path) => readFileSync(path, 'utf8') },
			},
		];
		for (const { name, references, fs } of refused) {
			clearEvidence();
			const record2 = [];
			const result = await runNativeLane(['--config', variantPath({ requiredReferences: references })], {
				spawn: fakeSpawn({ record: record2 }),
				...(fs === undefined ? {} : { fs }),
			});
			assert.equal(result.reason, SETUP_FAILURES.references, name);
			assert.equal(record2.length, 0, `${name}: zero dispatch`);
			for (const path of [config.receipt, config.dispatch, config.verification, config.progress]) {
				assert.equal(existsSync(path), false, `${name}: nothing was written to ${path}`);
			}
			assert.equal(readFileSync(planted, 'utf8'), plantedBody, `${name}: the planted artifact is preserved`);
			assert.equal(readFileSync(configPath, 'utf8').includes('synthetic-planted-recent-output'), false, `${name}: no config echo`);
		}
	} finally {
		cleanup();
	}
});

/**
 * An empty label is not a label. This is the structured `{ label: '', path }` shape with a real,
 * readable file behind it, not the primitive `['']` entry: only the label can be refused here, and
 * both readers refuse it before either seam can dispatch anything.
 */
test('an empty label over a readable file is refused by both readers with zero dispatch', async () => {
	const profile = { model: REVIEWER_MODEL, timeoutMs: 900_000 };
	const { dir, config, configPath, cleanup } = tempConfig();
	const refs = tempReferences(dir);
	const emptyLabel = [{ label: '', path: refs.file }];
	try {
		// Both readers refuse the same declared shape, with the same fixed code and no echo.
		writeFileSync(configPath, JSON.stringify({ ...config, requiredReferences: emptyLabel }, null, 2));
		assert.throws(() => readLaneConfig(configPath),
			(error) => error.message === LANE_SETUP_FAILURES.references, 'the controller reader refuses an empty label');
		assert.equal(validateLaneConfig({ ...config, requiredReferences: emptyLabel }, profile).reason,
			SETUP_FAILURES.references, 'the CLI reader refuses an empty label');

		// The shipped entry point, driven with that exact config path: the reader refuses, so the
		// handler emits nothing at all. No request event, no module resolution, no dispatch record.
		const { pi, emitted, input } = fakePi();
		const restore = [LANE_CONFIG_ENV, LANE_SUBAGENTS_ENV].map((name) => [name, process.env[name]]);
		process.env[LANE_CONFIG_ENV] = configPath;
		process.env[LANE_SUBAGENTS_ENV] = config.subagents;
		try {
			hyljaNativeLane(pi);
			assert.equal((await input()({ text: FIXED_LANE_INPUT })).action, 'handled');
		} finally {
			for (const [name, value] of restore) {
				if (value === undefined) delete process.env[name];
				else process.env[name] = value;
			}
		}
		assert.deepEqual(emitted, [], 'the controller reader refuses before anything is emitted');

		// The CLI, same config: the refusal precedes the spawn, so no child exists and nothing is written.
		const spawned = [];
		const result = await runNativeLane(['--config', configPath], { spawn: fakeSpawn({ record: spawned }) });
		assert.equal(result.reason, SETUP_FAILURES.references);
		assert.equal(spawned.length, 0, 'zero dispatch: the CLI reader refuses before Pi is spawned');
		for (const path of [config.receipt, config.dispatch, config.verification, config.progress]) {
			assert.equal(existsSync(path), false, `nothing was written to ${path}`);
		}

		// The control: the identical readable file under a non-empty label is admitted by both readers,
		// so what was refused is the label itself and nothing about the path.
		const control = [{ label: 'required contract', path: refs.file }];
		const controlPath = join(dir, 'lane-nonempty-label.json');
		writeFileSync(controlPath, JSON.stringify({ ...config, requiredReferences: control }, null, 2));
		assert.deepEqual(readLaneConfig(controlPath).requiredReferences, control);
		assert.equal(validateLaneConfig({ ...config, requiredReferences: control }, profile).ok, true);
	} finally {
		cleanup();
	}
});

/**
 * Real default adapters, real default platform. These cases exist because injected fake
 * dependencies passed while the shipped defaults did not: a fake range read honored the range while
 * the default read the whole file and sliced it, and fake signal hooks recorded a callback while the
 * default registered nothing at all. Nothing here needs an installed Pi, a provider or the network:
 * the temporary platform above supplies synthetic entrypoints and the child transport is fake, so the
 * only real components under test are the CLI's own default filesystem and signal registration.
 */
/** The wall clock the FIFO control is allowed. A blocking open hits it and the child is killed. */
const FIFO_CONTROL_TIMEOUT_MS = 15_000;

/**
 * The bounded subprocess control around the shipped probe. A FIFO with no writer cannot be probed in
 * the test runner itself without risking an unbounded wait there, so the wait is confined to a child
 * a finite timeout can kill. The child imports the real controller, runs the real probe over that
 * FIFO and then builds the real controller around it with the probe left unpatched.
 */
const fifoControlChild = (controllerUrl) => `
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLaneController, probeReferenceMetadata, readLaneConfig } from '${controllerUrl}';

const fifoPath = process.argv[2];
// The shipped probe over a FIFO nobody ever opens for writing: metadata and an open, never a read.
const metadata = probeReferenceMetadata(fifoPath);
const dir = mkdtempSync(join(tmpdir(), 'hylja-fifo-lane-'));
const guard = join(dir, 'guard.ts');
writeFileSync(guard, 'export default function syntheticGuard() {}\\n');
const dispatchPath = join(dir, 'dispatch.json');
const configPath = join(dir, 'lane.json');
writeFileSync(configPath, JSON.stringify({
	key: 'fifo-control',
	agent: 'hylja-reviewer',
	task: 'synthetic FIFO control task',
	cwd: dir,
	timeoutMs: 600000,
	requiredReferences: [{ label: 'synthetic fifo', path: fifoPath }],
	sessionDir: join(dir, 'sessions'),
	receipt: join(dir, 'receipt.json'),
	dispatch: dispatchPath,
	progress: join(dir, 'progress.ndjson'),
	guard,
}, null, 2));
const loaded = readLaneConfig(configPath);
const delegation = {
	SUBAGENT_DELEGATION_REQUEST_EVENT: 'prompt-template:subagent:request',
	SUBAGENT_DELEGATION_STARTED_EVENT: 'prompt-template:subagent:started',
	SUBAGENT_DELEGATION_UPDATE_EVENT: 'prompt-template:subagent:update',
	SUBAGENT_DELEGATION_RESPONSE_EVENT: 'prompt-template:subagent:response',
	SUBAGENT_DELEGATION_CANCEL_EVENT: 'prompt-template:subagent:cancel',
};
const emitted = [];
const pi = {
	events: { on: () => () => {}, emit: (event) => { emitted.push(event); } },
	on: () => {},
};
let preflightCalls = 0;
const preflight = {
	resolveSubagentLaunchContract: async (input) => {
		preflightCalls += 1;
		return {
			ok: true,
			contract: {
				version: 3,
				context: input.context,
				roots: { cwd: input.cwd },
				model: 'synthetic-fifo-control-model:max',
				thinking: 'max',
				intercomBridge: { active: false, mode: 'off' },
				tools: { configuredExtensions: [guard], runtimeExtensions: [], disableAmbientExtensions: true },
				launchContractDigest: 'synthetic-fifo-control-digest',
				digest: 'synthetic-fifo-control-digest:contract',
				diagnostics: [],
			},
		};
	},
};
const controller = await createLaneController(pi, loaded, { delegation, preflight }, { addSignalListener: () => () => {} });
const report = {
	metadata,
	setupFailure: controller.setupFailure,
	dispatched: emitted.filter((event) => event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT).length,
	preflightCalls,
	dispatchPersisted: existsSync(dispatchPath),
};
rmSync(dir, { recursive: true, force: true });
process.stdout.write(JSON.stringify(report));
`;

test('a writer-less FIFO is refused by the shipped probe inside a bounded subprocess, never by waiting on it', (t) => {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-fifo-control-'));
	try {
		// Platform honesty: a platform without a named pipe reports a skip, never a silent pass.
		const fifoPath = join(dir, 'required-reference.fifo');
		const made = spawnSync('mkfifo', [fifoPath]);
		if (made.error !== undefined || made.status !== 0 || !statSync(fifoPath).isFIFO()) {
			t.skip(`no writable FIFO on this platform: ${made.error?.code ?? `mkfifo exit ${made.status}`}`);
			return;
		}
		// The pre-open rejection is observable on any platform, with no blocking open involved at all.
		const subdir = join(dir, 'reference-subdir');
		mkdirSync(subdir);
		const childPath = join(dir, 'fifo-control-child.mjs');
		writeFileSync(childPath, fifoControlChild(pathToFileURL(resolve(repoRoot, '.pi', 'lib', 'hylja-native-lane.ts')).href));
		const control = spawnSync(process.execPath, [childPath, fifoPath],
			{ timeout: FIFO_CONTROL_TIMEOUT_MS, encoding: 'utf8' });
		// The bound is the proof: a blocking open exceeds it and the child is killed mid-probe.
		assert.equal(control.error, undefined,
			`the probe exceeded the ${FIFO_CONTROL_TIMEOUT_MS} ms bound: ${control.error?.code ?? control.signal}`);
		assert.equal(control.signal, null, 'the control was not killed by the bound');
		assert.equal(control.status, 0, control.stderr);
		const report = JSON.parse(control.stdout);
		assert.deepEqual(report.metadata, { isFile: false, isDirectory: false, readable: false },
			'non-regular metadata is refused without reading a byte');
		assert.equal(report.setupFailure, LANE_SETUP_FAILURES.references);
		assert.equal(report.preflightCalls, 0, 'no launch contract was resolved');
		assert.equal(report.dispatched, 0, 'zero dispatch');
		assert.equal(report.dispatchPersisted, false, 'no dispatch record was persisted');
		assert.deepEqual(probeReferenceMetadata(subdir), { isFile: false, isDirectory: true, readable: false },
			'a non-regular path is refused before it is opened, so it is never reported readable');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the real default filesystem reads a bounded positional progress tail and closes every fd', async () => {
	const { config, configPath, cleanup } = tempConfig();
	// A whole-file read of this planted progress file is 8 MiB; the tail cap is 128 KiB.
	const cap = MAX_PROGRESS_RECORDS * 512;
	const planted = `${'synthetic-padding-'.repeat(512 * 1024)}\n`
		+ `${JSON.stringify({ event: 'progress', key: config.key, runId: RUN_ID, model: REVIEWER_MODEL, toolCount: 53, elapsedMs: 296_680 })}\n`;
	assert.equal(planted.length > cap * 8, true, 'the planted file must exceed the cap by more than eight times');

	const realOpen = nodeFs.openSync;
	const realRead = nodeFs.readSync;
	const realClose = nodeFs.closeSync;
	const realReadFile = nodeFs.readFileSync;
	const opened = new Set();
	const closed = new Set();
	const positional = [];
	const wholeFile = [];
	nodeFs.openSync = (path, ...rest) => {
		const fd = realOpen(path, ...rest);
		if (path === config.progress) opened.add(fd);
		return fd;
	};
	nodeFs.readSync = (fd, buffer, offset, length, position) => {
		if (opened.has(fd)) positional.push({ allocated: buffer.length, length, position });
		return realRead(fd, buffer, offset, length, position);
	};
	nodeFs.closeSync = (fd) => {
		if (opened.has(fd)) closed.add(fd);
		return realClose(fd);
	};
	nodeFs.readFileSync = (path, ...rest) => {
		const data = realReadFile(path, ...rest);
		if (path === config.progress) wholeFile.push(data.length);
		return data;
	};
	syncBuiltinESMExports();
	try {
		// Only the child transport is injected, so the default filesystem is the one under test. The
		// leaf writes the oversized progress file, as a real lane would, after the freshness check.
		const result = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ onLaunch: () => {
				writeFileSync(config.progress, planted);
				assert.equal(statSync(config.progress).size > cap * 8, true, 'the planted file must exceed the cap');
			} }),
		});
		assert.equal(result.reason, SETUP_FAILURES.receipt);
		assert.deepEqual(wholeFile, [], 'the default platform must never read the whole progress file');
		assert.equal(positional.length >= 1, true, 'the default platform must read the tail positionally');
		for (const read of positional) {
			assert.equal(read.allocated <= cap, true, `allocation ${read.allocated} exceeds the ${cap} byte cap`);
			assert.equal(read.length <= cap, true, `read ${read.length} exceeds the ${cap} byte cap`);
			assert.equal(Number.isInteger(read.position) && read.position > 0, true, `positional read ${read.position}`);
		}
		assert.deepEqual([...opened], [...closed], 'every default-read descriptor is closed in a finally');
		// The bounded read is still the correct tail: the newest snapshot survives.
		const written = JSON.parse(readFileSync(config.verification, 'utf8'));
		assert.equal(written.progress.at(-1).toolCount, 53);
		assert.equal(written.progress.length <= MAX_PROGRESS_RECORDS, true, `${written.progress.length}`);
	} finally {
		nodeFs.openSync = realOpen;
		nodeFs.readSync = realRead;
		nodeFs.closeSync = realClose;
		nodeFs.readFileSync = realReadFile;
		syncBuiltinESMExports();
		cleanup();
	}
});

test('the real default signal hooks own SIGINT and SIGTERM, stop once, and are removed on completion', async () => {
	const { configPath, cleanup } = tempConfig();
	try {
		const kills = [];
		let childRef = null;
		const baseline = {
			SIGINT: process.listenerCount('SIGINT'),
			SIGTERM: process.listenerCount('SIGTERM'),
		};
		const pending = runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ hang: true, onLaunch: (_options, child) => {
				childRef = child;
				child.kill = (signal) => { kills.push(signal); return true; };
			} }),
		});
		await new Promise((resolve) => setImmediate(resolve));
		let result = null;
		try {
		assert.equal(process.listenerCount('SIGINT'), baseline.SIGINT + 1, 'the lane owns one SIGINT listener');
		assert.equal(process.listenerCount('SIGTERM'), baseline.SIGTERM + 1, 'the lane owns one SIGTERM listener');
		// Delivered to the installed listener, never to the operating system: no signal can reach the
		// test runner itself, because the handler is registered before anything is emitted.
		assert.equal(process.emit('SIGINT'), true);
		assert.deepEqual(kills, ['SIGTERM'], 'a signal stops exactly the owned child with SIGTERM first');
		assert.equal(process.emit('SIGTERM'), true);
		assert.equal(process.emit('SIGINT'), true);
		assert.deepEqual(kills, ['SIGTERM'], 'repeated stops are idempotent, never a second kill ladder');
		assert.equal(childRef.kill('SIGKILL'), true);
		kills.pop();

		childRef.emit('close', 143);
		result = await pending;
		// A signalled child is not a completed lane, and nothing owned outlives the promise.
		assert.equal(result.reason, SETUP_FAILURES.nativeExit);
		assert.equal(result.record.nativeExitCode, 143);
		assert.deepEqual(kills, ['SIGTERM']);
		assert.equal(process.listenerCount('SIGINT'), baseline.SIGINT, 'the SIGINT listener is removed');
		assert.equal(process.listenerCount('SIGTERM'), baseline.SIGTERM, 'the SIGTERM listener is removed');
		} finally {
			// A failed assertion must not leave a hung lane: the owned child is always closed out.
			childRef?.emit('close', 143);
			await pending;
		}
	} finally {
		cleanup();
	}
});

/**
 * The shipped entry point, run as a real child process. Every case above drives the exported function
 * in-process, so none of them can observe what root actually receives: whether the CLI prints
 * anything at all, and which exit code it hands back. An early refusal that exited 2 silently was
 * indistinguishable from a lane that was never attempted. No local Pi, provider or network is
 * involved: the temporary platform's `pi` is a synthetic script that records its own launch, which is
 * also how zero dispatch is proved at the process boundary rather than by an assertion about an
 * injected spawn.
 */
const laneCliPath = resolve(repoRoot, 'scripts', 'development', 'run-native-lane.mjs');
/** The bound on one whole CLI process. A real lane is minutes; these setups refuse before launch. */
const CLI_PROCESS_TIMEOUT_MS = 30_000;
const PLANTED_CLI_KEY = 'synthetic-planted-cli-key.invalid';
const PLANTED_CLI_TASK = 'synthetic-planted-cli-task.invalid';

test('the real CLI process prints one bounded JSON refusal for a setup it refuses before launch', () => {
	const { dir, config, configPath, cleanup } = tempConfig();
	// A planted key and task, obviously synthetic and never routable, so an echo into the record is
	// observable rather than inferred. The child records its own launch from the same platform.
	const markerPath = join(dir, 'pi-was-launched');
	writeFileSync(config.pi, `#!/bin/sh\n: > '${markerPath}'\nexit 0\n`);
	chmodSync(config.pi, 0o755);
	let variant = 0;
	const variantPath = (overrides) => {
		const path = join(dir, `lane-cli-process-${variant += 1}.json`);
		// `sessionDir: undefined` serializes to an absent field, which is the shape case below.
		writeFileSync(path, JSON.stringify({ ...config, key: PLANTED_CLI_KEY, task: PLANTED_CLI_TASK, ...overrides }, null, 2));
		return path;
	};
	try {
		const cases = [
			// The config file itself is absent, so nothing about it can be reported from it.
			{ name: 'missing config', path: join(dir, 'lane-cli-process-absent.json'), reason: SETUP_FAILURES.install },
			// A config that reads correctly but declares no session directory: the field is missing, so
			// the shape is refused before any path is probed.
			{ name: 'no sessionDir field', path: variantPath({ sessionDir: undefined }), reason: SETUP_FAILURES.config },
			// A declared but absent session directory: every field is well formed, so the refusal is the
			// freshness/existence check rather than the shape check.
			{ name: 'absent session directory', path: variantPath({ sessionDir: join(dir, 'absent-session-dir') }), reason: SETUP_FAILURES.install },
		];
		for (const { name, path, reason } of cases) {
			const run = spawnSync(process.execPath, [laneCliPath, '--config', path],
				{ cwd: repoRoot, timeout: CLI_PROCESS_TIMEOUT_MS, encoding: 'utf8' });
			assert.equal(run.error, undefined, `${name}: the CLI process exceeded its bound (${run.error?.code})`);
			assert.equal(run.signal, null, `${name}: the CLI process was not killed`);
			assert.equal(run.status, 2, `${name}: a setup failure stays exit 2`);
			assert.equal(run.stderr, '', `${name}: one stdout record, never a traceback or a warning`);
			const lines = run.stdout.split('\n');
			assert.equal(lines.length, 2, `${name}: exactly one record line, got ${lines.length - 1}`);
			assert.equal(lines[1], '', `${name}: that record is newline terminated`);
			const record = JSON.parse(lines[0]);
			assert.deepEqual(Object.keys(record), ['verdict', 'reason'], `${name}: two fixed fields and nothing else`);
			assert.deepEqual(record, { verdict: 'INCOMPLETE', reason }, `${name}: the fixed refusal`);
			for (const planted of [PLANTED_CLI_KEY, PLANTED_CLI_TASK, config.cwd, dir]) {
				assert.equal(run.stdout.includes(planted), false, `${name}: no ${planted} echo`);
			}
			assert.equal(existsSync(markerPath), false, `${name}: zero dispatch, the refusal preceded the spawn`);
			for (const written of [config.receipt, config.verification, config.progress, config.dispatch]) {
				assert.equal(existsSync(written), false, `${name}: nothing was written to ${written}`);
			}
		}

		// The control: the identical platform and the identical CLI with every declared path present,
		// so the same marker proves a real launch happened. Without it, the zero-dispatch assertions
		// above would also hold for a CLI that never spawns anything at all.
		const launched = spawnSync(process.execPath, [laneCliPath, '--config', configPath],
			{ cwd: repoRoot, timeout: CLI_PROCESS_TIMEOUT_MS, encoding: 'utf8' });
		assert.equal(launched.error, undefined, `control: ${launched.error?.code}`);
		assert.equal(launched.status, 2, `control: the fake child leaves no leaf evidence, stderr: ${launched.stderr}`);
		assert.equal(existsSync(markerPath), true, 'the control really launched the owned child');
		const lines = launched.stdout.split('\n');
		assert.equal(lines.length, 2, `one logged verification record and no refusal line, got ${lines.length - 1}`);
		const record = JSON.parse(lines[0]);
		assert.equal(record.key, config.key, 'the launched run logs its own verification record');
		assert.equal(record.agent, config.agent);
		assert.equal(record.verdict, 'INCOMPLETE');
		assert.equal(record.reason, SETUP_FAILURES.receipt, 'the synthetic child wrote no receipt');
		assert.equal(record.nativeExitCode, 0, 'the owned child ran and closed cleanly');
		assert.deepEqual(JSON.parse(readFileSync(config.verification, 'utf8')), record,
			'the printed record and the persisted one are the same record');
	} finally {
		cleanup();
	}
});

/**
 * The dedicated writer fallback. Root dispatches this role explicitly, in a fresh lane with fresh
 * evidence paths, only after the default writer route has actually failed and the previous child has
 * settled: exit 2 and INCOMPLETE are not provider failures, and the CLI never retries or re-routes on
 * its own. It is one named profile at one exact model, so the change is auditable as a third role
 * rather than as a general failover.
 */
test('the fallback writer is a third profile, admitted only at its exact Sol 6.1 medium model', () => {
	assert.equal(existsSync(resolve(repoRoot, '.pi', 'agents', `${FALLBACK_ROLE}.md`)), true,
		'the dedicated fallback profile exists');
	// The writer's own ceiling is unchanged; only the route moved.
	assert.deepEqual(readRoleProfile(FALLBACK_ROLE), { model: FALLBACK_MODEL, timeoutMs: 1_200_000 });
	assert.equal(readRoleProfile('hylja-implementer').model, WRITER_MODEL, 'the default writer pin is unchanged');
	assert.equal(readRoleProfile('hylja-reviewer').model, REVIEWER_MODEL, 'the reviewer pin is unchanged');
	assert.equal(readRoleProfile('hylja-implementer').timeoutMs, 1_200_000);
	assert.equal(readRoleProfile('hylja-reviewer').timeoutMs, 900_000);
	assert.deepEqual(LANE_ROLES, ['hylja-implementer', 'hylja-reviewer', FALLBACK_ROLE]);

	const { config, cleanup } = tempConfig();
	try {
		const fs = { exists: existsSync };
		const install = (agent, model) => checkInstall({ ...config, agent }, { model, timeoutMs: 1_200_000 }, fs);
		// Exactly three admitted pairs: each role at the one model its own profile declares.
		assert.equal(install('hylja-implementer', WRITER_MODEL).ok, true);
		assert.equal(install('hylja-reviewer', REVIEWER_MODEL).ok, true);
		assert.equal(install(FALLBACK_ROLE, FALLBACK_MODEL).ok, true, 'the fallback lane installs at its own model');
		// A foreign route or budget is refused before Pi is spawned, for all three roles alike.
		for (const [agent, model] of [
			[FALLBACK_ROLE, 'openai-codex/gpt-6.1-sol:max'],
			[FALLBACK_ROLE, 'openai-codex/gpt-6.1-sol:high'],
			[FALLBACK_ROLE, 'openai-codex/gpt-6.1-sol:medium:medium'],
			[FALLBACK_ROLE, WRITER_MODEL],
			['hylja-implementer', FALLBACK_MODEL],
			['hylja-implementer', 'opencode-go/space-bunny-free:medium'],
			['hylja-reviewer', FALLBACK_MODEL],
		]) {
			assert.equal(install(agent, model).reason, SETUP_FAILURES.install, `${agent} at ${model}`);
		}
		// No model override option exists for any role, the fallback included.
		const profile = { model: FALLBACK_MODEL, timeoutMs: 1_200_000 };
		assert.equal(validateLaneConfig({ ...config, agent: FALLBACK_ROLE }, profile).ok, true);
		assert.equal(validateLaneConfig({ ...config, agent: FALLBACK_ROLE, model: FALLBACK_MODEL }, profile).reason,
			SETUP_FAILURES.config);
	} finally {
		cleanup();
	}
});

test('the fallback lane verifies at Sol 6.1 medium and refuses every other route or budget', () => {
	const { config, cleanup } = tempConfig();
	const artifacts = { meta: join(config.sessionDir, 'fallback-meta.json'), output: join(config.sessionDir, 'fallback-output.md') };
	try {
		const writer = { ...config, agent: FALLBACK_ROLE };
		const profile = { model: FALLBACK_MODEL, timeoutMs: 1_200_000 };
		const own = dispatchRecord(writer).expected;
		const dispatch = dispatchRecord(writer, { expected: { ...own, model: FALLBACK_MODEL, thinking: 'medium' } });
		const text = 'Implemented the scoped change.\n';
		const leaf = receipt({ agent: FALLBACK_ROLE, model: FALLBACK_MODEL, thinking: 'medium', verdict: 'INCOMPLETE', result: { kind: 'text', text } });
		const withMeta = (value, output = text) => ({
			exists: () => true, readdir: () => [],
			readFile: (p) => (p === artifacts.meta ? JSON.stringify(value) : output),
		});
		const check = (m, r = leaf, d = dispatch, p = profile) => verifyArtifacts(writer, p, d, r, artifacts, withMeta(m));
		const ownMeta = meta({ agent: FALLBACK_ROLE, model: FALLBACK_MODEL, requestedModel: FALLBACK_MODEL });
		const verified = check(ownMeta);
		assert.equal(verified.ok, true, JSON.stringify(verified));
		assert.equal(verified.model, FALLBACK_MODEL, 'the model that ran is the one the dispatch expected');
		// A writer lane is reported honestly: the native gate did not run, and this is not approval.
		assert.equal(verified.writerAcceptanceGate, 'not-required');
		assert.equal(verified.acceptanceProvesApproval, false);
		assert.equal('acceptancePassed' in verified, false);
		// Every other route or budget is refused at the same bindings the existing roles keep: the
		// receipt, the public metadata and the profile all have to be the one fallback model.
		for (const [label, model] of [
			['a max fallback profile', 'openai-codex/gpt-6.1-sol:max'],
			['a higher budget', 'openai-codex/gpt-6.1-sol:high'],
			['the default writer route', WRITER_MODEL],
			['the reviewer route', REVIEWER_MODEL],
		]) {
			assert.equal(check(ownMeta, leaf, dispatch, { ...profile, model }).reason, SETUP_FAILURES.model, label);
			assert.equal(check({ ...ownMeta, model }, receipt({ ...leaf, model })).reason, SETUP_FAILURES.model, label);
		}
		// The existing roles keep their own `:max` requirement: a medium run is not one of their lanes.
		const reviewer = { ...config };
		assert.equal(verifyArtifacts(reviewer, { model: REVIEWER_MODEL.replace(':max', ':medium'), timeoutMs: 900_000 },
			dispatchRecord(reviewer), receipt(), artifacts, withMeta(meta())).reason, SETUP_FAILURES.model);
	} finally {
		cleanup();
	}
});

test('a fallback writer lane runs end to end and reports its own honest acceptance', async () => {
	const { config, configPath, cleanup } = tempConfig({ agent: FALLBACK_ROLE, timeoutMs: 1_200_000, softBudgetMs: 360_000 });
	try {
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		writeFileSync(join(artifactsDir, `${RUN_ID}_${FALLBACK_ROLE}_0_meta.json`),
			JSON.stringify(meta({ agent: FALLBACK_ROLE, model: FALLBACK_MODEL, requestedModel: FALLBACK_MODEL })));
		writeFileSync(join(artifactsDir, `${RUN_ID}_${FALLBACK_ROLE}_0_output.md`), 'Implemented the scoped change.\n');
		const result = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ onLaunch: () => {
				writeFileSync(config.receipt, JSON.stringify(receipt({
					agent: FALLBACK_ROLE, model: FALLBACK_MODEL, thinking: 'medium',
					verdict: 'INCOMPLETE', result: { kind: 'text', text: 'Implemented the scoped change.\n' },
				}), null, 2));
				const own = dispatchRecord(config).expected;
				writeFileSync(config.dispatch,
					`${JSON.stringify(dispatchRecord(config, { expected: { ...own, model: FALLBACK_MODEL, thinking: 'medium' } }), null, 2)}\n`);
				writeFileSync(config.progress, `${JSON.stringify({ event: 'dispatch', key: config.key, model: FALLBACK_MODEL })}\n`);
			} }),
		});
		assert.equal(result.ok, true, JSON.stringify(result));
		const written = JSON.parse(readFileSync(config.verification, 'utf8'));
		assert.equal(written.agent, FALLBACK_ROLE);
		assert.equal(written.model, FALLBACK_MODEL);
		assert.equal(written.verdict, 'INCOMPLETE', 'a writer result declaring no verdict is never an approval');
		assert.equal(written.writerAcceptanceGate, 'not-required', 'the fallback is reported as a writer lane');
		assert.equal(written.acceptanceProvesApproval, false);
		assert.equal(written.expectedLaunchContractDigest, EXPECTED_DIGEST);
	} finally {
		cleanup();
	}
});

test('the fallback role reads back as a lane config and receives the writer timing guide', async () => {
	const { config, cleanup } = tempConfig();
	try {
		const path = join(config.sessionDir, 'fallback-lane.json');
		writeFileSync(path, JSON.stringify({ ...config, agent: FALLBACK_ROLE, timeoutMs: 1_200_000, softBudgetMs: 360_000 }, null, 2));
		const loaded = readLaneConfig(path);
		assert.equal(loaded.agent, FALLBACK_ROLE);
		assert.equal(loaded.softBudgetMs, 360_000);
		const { pi } = fakePi();
		const preflight = fakePreflight({ guard: config.guard, model: FALLBACK_MODEL, thinking: 'medium' });
		const controller = await createLaneController(pi, loaded, { delegation, preflight }, { addSignalListener: noSignals });
		// A configured soft budget needs this role's own closing move, or the config is refused and no
		// lane can run under it at all.
		assert.equal(controller.setupFailure, null, String(controller.setupFailure));
		const guide = String(controller.request.task).slice(loaded.task.length);
		// The same writer paragraph the default writer gets: checks, then the commit, then the report,
		// and no review authority this role body does not already carry.
		assert.equal(/commit/i.test(guide), true);
		assert.equal(/report/i.test(guide), true);
		assert.equal(/\bverdict\b/i.test(guide), false);
		assert.equal(/grant/i.test(guide), true);
		assert.equal(preflight.calls[0].task, controller.request.task, 'one effective task binds the digest');
		completeLeaf(pi, controller, 'Implemented the scoped change.\n');
		await controller.settle();
	} finally {
		cleanup();
	}
});

/**
 * The lane config read is the one unbounded step that happens before any watchdog exists: the watchdog
 * that would bound the native lane is armed only after the config is admitted and Pi is spawned. Root
 * hands this CLI an exact path, so a config that is a FIFO nobody writes, a directory, something past
 * the byte window, or bytes that are not UTF-8 must each be the fixed refusal with zero children, and
 * none of them may become a stall, a traceback, a second exit code or an echo.
 *
 * The first case drives the shipped CLI as a real process, because that is the boundary where a stall
 * or an uncaught refusal actually reaches root. The refusals that need this process to hand the reader a
 * descriptor it did not admit run in one bounded child instead, so a broken reader cannot park the test
 * runner on the very wait it is looking for.
 */
const CONFIG_REFUSAL_TIMEOUT_MS = 10_000;

test('the real CLI refuses a non-regular lane config at once, launches nothing and echoes nothing', (t) => {
	const { dir, config, configPath, cleanup } = tempConfig();
	const markerPath = join(dir, 'pi-was-launched');
	writeFileSync(config.pi, `#!/bin/sh\n: > '${markerPath}'\nexit 0\n`);
	chmodSync(config.pi, 0o755);
	try {
		const fifoPath = join(dir, 'lane-config.fifo');
		const made = spawnSync('mkfifo', [fifoPath]);
		// Platform honesty: the named pipe is the case the root census stalled on. A host without one
		// gets the character device, which is the same non-regular claim on the same default reader,
		// and the diagnostic states which platform actually ran this.
		const fifoUsable = made.error === undefined && made.status === 0 && statSync(fifoPath).isFIFO();
		if (!fifoUsable) {
			t.diagnostic(`no writable FIFO here (${made.error?.code ?? `mkfifo exit ${made.status}`}): the character device is the non-regular control`);
		}
		const cases = [
			...(fifoUsable ? [{ name: 'writer-less fifo', path: fifoPath }] : []),
			{ name: 'character device', path: '/dev/null' },
			{ name: 'directory', path: dir },
		];
		for (const { name, path } of cases) {
			rmSync(markerPath, { force: true });
			const run = spawnSync(process.execPath, [laneCliPath, '--config', path],
				{ cwd: repoRoot, timeout: CONFIG_REFUSAL_TIMEOUT_MS, encoding: 'utf8' });
			assert.equal(run.error, undefined,
				`${name}: the config read stalled instead of refusing (${run.error?.code ?? run.signal})`);
			assert.equal(run.signal, null, `${name}: the refusal was not killed by the bound`);
			assert.equal(run.status, 2, `${name}: a setup failure stays exit 2`);
			assert.equal(run.stderr, '', `${name}: one stdout record, never a traceback or a warning`);
			const lines = run.stdout.split('\n');
			assert.equal(lines.length, 2, `${name}: exactly one record line, got ${lines.length - 1}`);
			assert.deepEqual(JSON.parse(lines[0]), { verdict: 'INCOMPLETE', reason: SETUP_FAILURES.config },
				`${name}: the fixed config refusal`);
			for (const planted of [PLANTED_CLI_KEY, PLANTED_CLI_TASK, config.cwd, dir]) {
				assert.equal(run.stdout.includes(planted), false, `${name}: no ${planted} echo`);
			}
			assert.equal(existsSync(markerPath), false, `${name}: zero dispatch, the refusal preceded the spawn`);
			for (const written of [config.receipt, config.verification, config.progress, config.dispatch]) {
				assert.equal(existsSync(written), false, `${name}: nothing was written to ${written}`);
			}
		}
		// The control: the identical platform and the identical CLI over one regular config really
		// launches, so the refusals above cannot be explained by a CLI that never spawns anything.
		rmSync(markerPath, { force: true });
		const control = spawnSync(process.execPath, [laneCliPath, '--config', configPath],
			{ cwd: repoRoot, timeout: CLI_PROCESS_TIMEOUT_MS, encoding: 'utf8' });
		assert.equal(control.status, 2, `control: the synthetic child leaves no leaf evidence (${control.stderr})`);
		assert.equal(existsSync(markerPath), true, 'a regular config launches the owned child');
	} finally {
		cleanup();
	}
});

test('the default config reader admits one bounded byte window, not a character count, and closes it', async () => {
	const { config, configPath, cleanup } = tempConfig();
	const realOpen = nodeFs.openSync;
	const realRead = nodeFs.readSync;
	const realClose = nodeFs.closeSync;
	const realReadFile = nodeFs.readFileSync;
	const opened = new Set();
	const closed = new Set();
	const reads = [];
	const wholeFile = [];
	nodeFs.openSync = (path, ...rest) => {
		const fd = realOpen(path, ...rest);
		if (path === configPath) opened.add(fd);
		return fd;
	};
	nodeFs.readSync = (fd, buffer, offset, length, position) => {
		if (opened.has(fd)) reads.push({ allocated: buffer.length, length, position });
		return realRead(fd, buffer, offset, length, position);
	};
	nodeFs.closeSync = (fd) => {
		if (opened.has(fd)) closed.add(fd);
		return realClose(fd);
	};
	nodeFs.readFileSync = (path, ...rest) => {
		const data = realReadFile(path, ...rest);
		if (path === configPath) wholeFile.push(data.length);
		return data;
	};
	syncBuiltinESMExports();
	const run = async (path) => {
		const record = [];
		const result = await runNativeLane(['--config', path], { spawn: fakeSpawn({ record }) });
		return { result, launched: record.length };
	};
	try {
		// Oversized by bytes while still inside the character count: a two-byte character costs twice
		// in the file and once in the decoded string, so a bound measured in characters admits this.
		const padded = JSON.stringify({ ...config, key: PLANTED_CLI_KEY, task: 'é'.repeat(32_768) }, null, 2);
		assert.equal(Buffer.byteLength(padded, 'utf8') > MAX_CONFIG_BYTES, true, 'the planted config is past the byte window');
		assert.equal(padded.length <= MAX_CONFIG_BYTES, true, 'the same config is inside the character count');
		writeFileSync(configPath, padded);
		const tooBig = await run(configPath);
		assert.equal(tooBig.result.reason, SETUP_FAILURES.config, 'a config past the byte window is refused');
		assert.equal(tooBig.launched, 0, 'an oversized config launches nothing');
		assert.equal(JSON.stringify(tooBig.result).includes(PLANTED_CLI_KEY), false, 'no planted key in the refusal');
		assert.equal(JSON.stringify(tooBig.result).includes('é'), false, 'no planted task character in the refusal');

		// Bytes that are not UTF-8 are a refusal, not a repaired replacement character inside a task.
		const decoded = Buffer.from(JSON.stringify({ ...config, task: `synthetic ${PLANTED_CLI_TASK}` }, null, 2), 'utf8');
		const at = decoded.indexOf(Buffer.from(PLANTED_CLI_TASK, 'utf8'));
		assert.equal(at > 0, true, 'the planted task is inside the config');
		decoded[at] = 0xff;
		writeFileSync(configPath, decoded);
		const broken = await run(configPath);
		assert.equal(broken.result.reason, SETUP_FAILURES.config, 'undecodable config bytes are refused');
		assert.equal(broken.launched, 0, 'an undecodable config launches nothing');

		// The control: the same reader over a regular config inside the window launches exactly once,
		// and the accounting below is what proves the read was bounded, positional and owned.
		writeFileSync(configPath, JSON.stringify({ ...config, key: PLANTED_CLI_KEY, task: PLANTED_CLI_TASK }, null, 2));
		const control = await run(configPath);
		assert.equal(control.launched, 1, 'a valid regular config launches the owned child');
		assert.equal(control.result.reason, SETUP_FAILURES.receipt, 'the synthetic child leaves no leaf evidence behind');
		assert.equal(JSON.parse(readFileSync(config.verification, 'utf8')).key, PLANTED_CLI_KEY,
			'the planted key reaches the record the launched lane wrote');

		assert.deepEqual(wholeFile, [], 'the default reader never reads the config as a whole file');
		for (const read of reads) {
			assert.equal(read.allocated <= MAX_CONFIG_BYTES + 1, true, `allocation ${read.allocated} exceeds the window`);
			assert.equal(read.length <= MAX_CONFIG_BYTES + 1, true, `read ${read.length} exceeds the window`);
			assert.equal(read.position, 0, 'the config is read from its own descriptor, once, at its start');
		}
		assert.equal(reads.length, 3, `one bounded read per config read, got ${reads.length}`);
		assert.deepEqual([...opened], [...closed], 'every descriptor the config reader opened is closed in a finally');
	} finally {
		nodeFs.openSync = realOpen;
		nodeFs.readSync = realRead;
		nodeFs.closeSync = realClose;
		nodeFs.readFileSync = realReadFile;
		syncBuiltinESMExports();
		cleanup();
	}
});

/**
 * Two faults a reader cannot see from its own happy path, both injected into the shipped default
 * reader over a real temporary config. A fault handed only to a fake adapter would prove the fake.
 *
 * The short read is driven over a file that is a complete valid JSON config followed by bytes that
 * are not JSON at all, so the only way to parse it is to parse a prefix and call that the file: the
 * descriptor still reports the full size, and the delivered bytes stop inside the config.
 */
test('a short config read is refused without a retry, never admitted as a JSON prefix', async () => {
	const { config, configPath, cleanup } = tempConfig();
	const realOpen = nodeFs.openSync;
	const realRead = nodeFs.readSync;
	const realClose = nodeFs.closeSync;
	const owned = new Set();
	const reads = [];
	let prefixBytes = 0;
	try {
		const valid = JSON.stringify({ ...config, key: PLANTED_CLI_KEY, task: PLANTED_CLI_TASK }, null, 2);
		const trailing = '\nnot-a-json-config-synthetic-trailing.invalid\n';
		writeFileSync(configPath, `${valid}${trailing}`);
		prefixBytes = Buffer.byteLength(valid, 'utf8');
		// The prefix is a whole valid config and the file is not: only a short read can admit the one
		// while refusing the other.
		assert.equal(JSON.parse(valid).key, PLANTED_CLI_KEY, 'the delivered prefix is complete valid JSON');
		assert.throws(() => JSON.parse(readFileSync(configPath, 'utf8')), 'the config file as a whole is not valid JSON');
		assert.equal(prefixBytes < statSync(configPath).size, true, 'the prefix stops inside the file');
		nodeFs.openSync = (path, ...rest) => {
			const fd = realOpen(path, ...rest);
			if (path === configPath) owned.add(fd);
			return fd;
		};
		// The fault: the descriptor delivers those bytes and reports only as many of them, which is
		// what a short read looks like from inside the reader. Nothing else in this lane is patched.
		nodeFs.readSync = (fd, buffer, offset, length, position) => {
			if (!owned.has(fd)) return realRead(fd, buffer, offset, length, position);
			const delivered = realRead(fd, buffer, offset, length, position);
			const reported = Math.min(delivered, prefixBytes);
			reads.push({ requested: length, reported });
			return reported;
		};
		nodeFs.closeSync = (fd) => {
			owned.delete(fd);
			return realClose(fd);
		};
		syncBuiltinESMExports();
		const record = [];
		const result = await runNativeLane(['--config', configPath], { spawn: fakeSpawn({ record }) });
		assert.equal(result.reason, SETUP_FAILURES.config, 'a short read is the fixed config refusal');
		assert.equal(record.length, 0, 'a short read launches nothing');
		assert.equal(reads.length, 1, `the read is issued once and never retried, got ${reads.length}`);
		assert.equal(reads[0].requested, MAX_CONFIG_BYTES + 1, 'still one bounded window request, never a smaller one');
		assert.equal(JSON.stringify(result).includes(PLANTED_CLI_KEY), false, 'no planted key in the refusal');
		assert.equal(JSON.stringify(result).includes(PLANTED_CLI_TASK), false, 'no planted task in the refusal');
		for (const written of [config.receipt, config.verification, config.progress, config.dispatch]) {
			assert.equal(existsSync(written), false, `nothing was written to ${written}`);
		}
	} finally {
		nodeFs.openSync = realOpen;
		nodeFs.readSync = realRead;
		nodeFs.closeSync = realClose;
		syncBuiltinESMExports();
		cleanup();
	}
});

/**
 * A close that fails is the other half of the same ownership claim. The descriptor is real and the
 * bytes really were read, so the reader must still refuse: it may not report cleanup it did not get.
 * The failed close leaves the descriptor open, so this test closes what it handed over rather than
 * claiming the lane left nothing behind.
 */
test('a config close that fails withholds admission and launches no child', async () => {
	const { config, configPath, cleanup } = tempConfig();
	const realOpen = nodeFs.openSync;
	const realClose = nodeFs.closeSync;
	const owned = new Set();
	const leaked = new Set();
	try {
		writeFileSync(configPath, JSON.stringify({ ...config, key: PLANTED_CLI_KEY, task: PLANTED_CLI_TASK }, null, 2));
		nodeFs.openSync = (path, ...rest) => {
			const fd = realOpen(path, ...rest);
			if (path === configPath) owned.add(fd);
			return fd;
		};
		// The fault: only the close of the descriptor the reader owns fails, and it fails before the
		// descriptor is released, so the descriptor number stays valid and this test can close it.
		nodeFs.closeSync = (fd) => {
			if (!owned.has(fd)) return realClose(fd);
			owned.delete(fd);
			leaked.add(fd);
			throw Object.assign(new Error('synthetic close failure'), { code: 'EIO' });
		};
		syncBuiltinESMExports();
		const record = [];
		const result = await runNativeLane(['--config', configPath], { spawn: fakeSpawn({ record }) });
		// This test owns the descriptor the failed close left open, so it closes it here. That is
		// cleanup the reader attempted and did not complete, not proof that it had closed anything.
		const unclosed = [...leaked];
		for (const fd of unclosed) {
			try {
				realClose(fd);
			} catch {
				// Already gone: nothing of this test's is left behind either way.
			}
		}
		assert.equal(result.reason, SETUP_FAILURES.config, 'a failed close is the fixed config refusal');
		assert.equal(record.length, 0, 'a failed close launches nothing');
		assert.equal(unclosed.length, 1, 'exactly one descriptor was left for this test to close');
		assert.equal(JSON.stringify(result).includes(PLANTED_CLI_KEY), false, 'no planted key in the refusal');
		assert.equal(JSON.stringify(result).includes(PLANTED_CLI_TASK), false, 'no planted task in the refusal');
		for (const written of [config.receipt, config.verification, config.progress, config.dispatch]) {
			assert.equal(existsSync(written), false, `nothing was written to ${written}`);
		}
		// The control: the identical config over a close that works really launches the owned child,
		// so the refusal above is the failed close and not a config this lane would never have run.
		nodeFs.openSync = realOpen;
		nodeFs.closeSync = realClose;
		syncBuiltinESMExports();
		const control = [];
		const launched = await runNativeLane(['--config', configPath], { spawn: fakeSpawn({ record: control }) });
		assert.equal(control.length, 1, 'a close that works admits the same config and launches the owned child');
		assert.equal(launched.reason, SETUP_FAILURES.receipt, 'the synthetic child leaves no leaf evidence behind');
	} finally {
		nodeFs.openSync = realOpen;
		nodeFs.closeSync = realClose;
		syncBuiltinESMExports();
		cleanup();
	}
});

/**
 * The refusals that need this process to hand the reader a descriptor it did not admit: an open that
 * resolves to a directory, a read that fails, and a path that turns into a writer-less FIFO between
 * the metadata check and the open. That last one blocks for as long as it has to, so all three run in
 * one child a finite bound can kill, and a child the bound kills is the failure this control exists for.
 */
const configDescriptorChild = `
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';

const [configPath, fifoPath, directoryPath, cliUrl] = process.argv.slice(2);
const lane = await import(cliUrl);
const realOpen = fs.openSync;
const realRead = fs.readSync;
const realClose = fs.closeSync;
// Per case, because the OS reuses a descriptor number as soon as one is closed: a set shared across
// cases would report a reused number as one it had already accounted for.
let seen = { opened: new Set(), closed: new Set() };
const fakeSpawn = (record) => (command, args) => {
	record.push({ command, args });
	const child = new EventEmitter();
	child.stderr = new EventEmitter();
	child.kill = () => true;
	child.pid = 4242;
	queueMicrotask(() => child.emit('close', 0));
	return child;
};
const caseFor = async (patch, restore) => {
	seen = { opened: new Set(), closed: new Set() };
	patch();
	syncBuiltinESMExports();
	const record = [];
	try {
		const result = await lane.runNativeLane(['--config', configPath], { spawn: fakeSpawn(record) });
		return {
			reason: result.reason, launched: record.length,
			opened: seen.opened.size,
			closed: [...seen.opened].filter((fd) => seen.closed.has(fd)).length,
		};
	} finally {
		restore();
		syncBuiltinESMExports();
	}
};
// Every descriptor this patch hands the reader is tracked, so the report can show it was closed.
const trackOpens = (over) => {
	fs.openSync = (path, ...rest) => {
		const fd = over(path, ...rest);
		seen.opened.add(fd);
		return fd;
	};
	fs.closeSync = (fd) => {
		if (seen.opened.has(fd)) seen.closed.add(fd);
		return realClose(fd);
	};
};
// The descriptor itself decides the type: a path that stats regular and opens as a directory is refused.
const openedDirectory = await caseFor(() => {
	trackOpens((path, ...rest) => (path === configPath ? realOpen(directoryPath, ...rest) : realOpen(path, ...rest)));
}, () => { fs.openSync = realOpen; fs.closeSync = realClose; });
// A read that fails is the fixed refusal, and the descriptor it owned is still closed.
const unreadable = await caseFor(() => {
	trackOpens((path, ...rest) => realOpen(path, ...rest));
	fs.readSync = (fd, ...rest) => {
		if (seen.opened.has(fd)) throw Object.assign(new Error('synthetic read failure'), { code: 'EIO' });
		return realRead(fd, ...rest);
	};
}, () => { fs.openSync = realOpen; fs.closeSync = realClose; fs.readSync = realRead; });
// Last, because it leaves the config path a FIFO: regular when the reader stats it, writer-less when
// the reader opens it, so the non-blocking open is what keeps the refusal from waiting for a writer.
const raced = await caseFor(() => {
	trackOpens((path, ...rest) => {
		if (path === configPath) fs.renameSync(fifoPath, configPath);
		return realOpen(path, ...rest);
	});
}, () => { fs.openSync = realOpen; fs.closeSync = realClose; });
process.stdout.write(JSON.stringify({ openedDirectory, unreadable, raced }));
`;

test('the config reader refuses a non-regular, unreadable or raced descriptor and closes each one', (t) => {
	const { dir, config, configPath, cleanup } = tempConfig();
	const childPath = join(dir, 'config-descriptor-child.mjs');
	try {
		const fifoPath = join(dir, 'raced-config.fifo');
		const made = spawnSync('mkfifo', [fifoPath]);
		if (made.error !== undefined || made.status !== 0 || !statSync(fifoPath).isFIFO()
			|| typeof nodeFs.constants.O_NONBLOCK !== 'number') {
			// Platform honesty: without a named pipe, or without a non-blocking open flag, there is no
			// bounded race to run here and a skip states that instead of passing silently.
			t.skip(`no FIFO or no O_NONBLOCK on this platform: ${made.error?.code ?? `mkfifo exit ${made.status}`}`);
			return;
		}
		writeFileSync(childPath, configDescriptorChild);
		const control = spawnSync(process.execPath,
			[childPath, configPath, fifoPath, dir, pathToFileURL(laneCliPath).href],
			{ timeout: FIFO_CONTROL_TIMEOUT_MS, encoding: 'utf8' });
		assert.equal(control.error, undefined,
			`the config read exceeded the ${FIFO_CONTROL_TIMEOUT_MS} ms bound: ${control.error?.code ?? control.signal}`);
		assert.equal(control.signal, null, 'the child was not killed by the bound');
		assert.equal(control.status, 0, control.stderr);
		const report = JSON.parse(control.stdout);
		assert.deepEqual(report.openedDirectory,
			{ reason: SETUP_FAILURES.config, launched: 0, opened: 1, closed: 1 },
			'a descriptor that is not a regular file is refused before a byte is read');
		assert.deepEqual(report.unreadable,
			{ reason: SETUP_FAILURES.config, launched: 0, opened: 1, closed: 1 },
			'a failed read is the fixed refusal and its descriptor is still closed');
		assert.deepEqual(report.raced,
			{ reason: SETUP_FAILURES.config, launched: 0, opened: 1, closed: 1 },
			'a path that becomes a writer-less FIFO after the stat is refused by the opened descriptor');
		assert.equal(statSync(configPath).isFIFO(), true, 'the raced path is left exactly as the refusal found it');
	} finally {
		cleanup();
	}
});

/**
 * The seam the default reader sits behind. An injected adapter is trusted with what it admits: this
 * process cannot re-prove a virtual filesystem, so a host that supplies its own config reader owns the
 * bytes that reader hands over. The real-file guarantee above belongs to the default alone and is not
 * something an adapter inherits or can widen by returning something else.
 */
test('an injected config reader owns its own bytes, and the default keeps the real-file guarantee', async () => {
	const { config, configPath, cleanup } = tempConfig();
	try {
		const absent = join(config.sessionDir, 'no-such-config.json');
		assert.equal(existsSync(absent), false);
		const record = [];
		const trusted = await runNativeLane(['--config', absent], {
			// The injected adapter owns every read this lane makes, the config included; the shipped
			// reader never sees the absent path. Every other path stays honest, so the freshness rule
			// the lane also enforces is not disabled along with the file the adapter is standing in for.
			fs: {
				exists: (path) => path === absent || existsSync(path),
				readFile: (path) => readFileSync(path, 'utf8'),
				readConfig: (path) => (path === absent ? Buffer.from(JSON.stringify(config)) : null),
			},
			spawn: fakeSpawn({ record }),
		});
		assert.equal(trusted.reason, SETUP_FAILURES.receipt, 'the injected bytes were admitted and the lane ran');
		assert.equal(record.length, 1, 'an injected reader drives exactly one owned child');

		// The same absent path with no injected reader is the fixed refusal: the default owns the file.
		const refused = await runNativeLane(['--config', absent], { spawn: fakeSpawn({ record: [] }) });
		assert.equal(refused.reason, SETUP_FAILURES.install, 'the default reader refuses a config path that is not there');
		// A reader that fails is contained as the fixed refusal rather than escaping to the caller.
		const throwing = await runNativeLane(['--config', configPath], {
			fs: { exists: () => true, readConfig: () => { throw new Error('synthetic reader failure'); } },
			spawn: fakeSpawn({ record: [] }),
		});
		assert.equal(throwing.reason, SETUP_FAILURES.config, 'a throwing injected reader is the fixed refusal');
		assert.equal(JSON.stringify(throwing).includes('synthetic reader failure'), false, 'no thrown text escapes');
	} finally {
		cleanup();
	}
});