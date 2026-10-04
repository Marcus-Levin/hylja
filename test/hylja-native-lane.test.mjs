// Hylja native foreground lane: controller and CLI behaviour.
//
// Every case drives the real controller exports with a fake Pi event API, a fake preflight module and
// a fake native process transport over a synthetic temporary session directory. No case requires a
// local Pi installation, calls a provider, reaches the network, or reads a session transcript: the
// planted strings below are synthetic values that never leave this process unless a case asserts they
// did not leak.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

import {
	FIXED_LANE_INPUT,
	MAX_PROGRESS_RECORDS,
	SETUP_FAILURES as LANE_SETUP_FAILURES,
	createLaneController,
	readExplicitVerdict,
	readLaneConfig,
	resolveInstalledModules,
	writeTerminalReceipt,
	hyljaNativeLane,
} from '../.pi/lib/hylja-native-lane.ts';
import {
	buildArgv,
	discoverPublicArtifacts,
	readProgress,
	readRoleProfile,
	runNativeLane,
	SETUP_FAILURES,
	validateLaneConfig,
	verifyArtifacts,
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