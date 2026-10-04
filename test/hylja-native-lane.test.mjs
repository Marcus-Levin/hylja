// Hylja native foreground lane: controller and CLI behaviour.
//
// Every case drives the real controller exports with a fake Pi event API and the real CLI with a fake
// native process transport plus a synthetic temporary session directory. Nothing here calls a
// provider, reaches the network, or reads a session transcript: the planted strings below are
// synthetic values that never leave this process unless a case asserts they did not leak.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
	FIXED_LANE_INPUT,
	createLaneController,
	readLaneConfig,
	readExplicitVerdict,
	writeTerminalReceipt,
} from '../.pi/lib/hylja-native-lane.ts';
import {
	SETUP_FAILURES,
	buildArgv,
	discoverPublicArtifacts,
	readRoleProfile,
	runNativeLane,
	validateLaneConfig,
	verifyArtifacts,
} from '../scripts/development/run-native-lane.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SUBAGENTS = '/home/marcus/.pi/agent/npm/node_modules/pi-subagents';
const PI = '/home/marcus/.pi/agent/bin/pi';

const PLANTED_REASONING = 'synthetic-planted-reasoning.invalid';
const PLANTED_TOOL_ARGS = '--synthetic-planted-argument.invalid';
const PLANTED_RECENT = 'synthetic-planted-recent-output.invalid';
const RUN_ID = 'ddfad7ad-07e1-4ad2-9af3-55fe1e38876b';
const OWNER = 'bad5596d-f94f-43c8-a17c-155fae12ca1b';

/** The documented event names, as the installed module declares them. */
const delegation = {
	SUBAGENT_DELEGATION_REQUEST_EVENT: 'prompt-template:subagent:request',
	SUBAGENT_DELEGATION_STARTED_EVENT: 'prompt-template:subagent:started',
	SUBAGENT_DELEGATION_UPDATE_EVENT: 'prompt-template:subagent:update',
	SUBAGENT_DELEGATION_RESPONSE_EVENT: 'prompt-template:subagent:response',
	SUBAGENT_DELEGATION_CANCEL_EVENT: 'prompt-template:subagent:cancel',
};

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
	return { pi, emitted, handlers };
}

function tempConfig(overrides = {}) {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-native-lane-'));
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
		pi: PI,
		subagents: SUBAGENTS,
		guard: join(repoRoot, '.pi', 'extensions', 'hylja-workflow-guard.ts'),
		controller: join(repoRoot, '.pi', 'lib', 'hylja-native-lane.ts'),
		...overrides,
	};
	mkdirSync(config.sessionDir, { recursive: true });
	const configPath = join(dir, 'lane.json');
	writeFileSync(configPath, JSON.stringify(config, null, 2));
	return { dir, config, configPath };
}

const meta = (overrides = {}) => ({
	runId: RUN_ID,
	agent: 'hylja-reviewer',
	model: 'openai-codex/gpt-6.1-sol:max',
	requestedModel: 'openai-codex/gpt-6.1-sol:max',
	launchContractDigest: '15a35ac671887105f555bd11745e682ad7a3ef4410dd12802558cdef74edda96',
	launchResolvedExtensions: {
		disableAmbientExtensions: true,
		configured: ['sha256:44e85c6c574d8360'],
		effective: ['sha256:09f3249c7287ea1a', 'sha256:44e85c6c574d8360'],
	},
	acceptance: { status: 'not-required', explicit: true },
	durationMs: 296_680,
	toolCount: 53,
	...overrides,
});

const receipt = (overrides = {}) => ({
	requestId: '39e040c4-3535-4971-bca8-76a61b08850d',
	ownerRunId: OWNER,
	nodeId: 'mapping-review-round2',
	status: 'completed',
	runId: RUN_ID,
	agent: 'hylja-reviewer',
	model: 'openai-codex/gpt-6.1-sol:max',
	thinking: 'max',
	exitCode: 0,
	launchContractDigest: '15a35ac671887105f555bd11745e682ad7a3ef4410dd12802558cdef74edda96',
	verdict: 'CHANGES REQUESTED',
	result: { kind: 'text', text: 'CHANGES REQUESTED\n\nBody.' },
	usage: { input: 124_991, output: 7_220, toolCalls: 53, durationMs: 296_680 },
	...overrides,
});

/** A fake native transport: one child, argv recorded, receipt and evidence written before close. */
function fakeSpawn({ onLaunch, record = [] } = {}) {
	return (command, args, options) => {
		record.push({ command, args, options });
		const child = new EventEmitter();
		child.stderr = new EventEmitter();
		child.kill = () => { child.killed = true; return true; };
		child.pid = 4242;
		queueMicrotask(() => {
			try {
				onLaunch?.(options, child);
			} finally {
				child.stderr.emit('data', Buffer.from('synthetic child stderr noise'));
				child.emit('close', 0);
			}
		});
		return child;
	};
}

test('the controller dispatches the exact role, context and task deadline, with no model override', async () => {
	const { dir, config, configPath } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi, emitted } = fakePi();
		const controller = createLaneController(pi, loaded, delegation);
		const requests = emitted.filter((e) => e.event === delegation.SUBAGENT_DELEGATION_REQUEST_EVENT);
		assert.equal(requests.length, 1);
		const request = requests[0].payload;
		assert.equal(request.agent, 'hylja-reviewer');
		assert.equal(request.context, 'fresh');
		assert.equal(request.cwd, repoRoot);
		assert.equal(request.timeoutMs, 600_000);
		assert.equal(request.task, 'Review the supplied evidence.');
		assert.equal('model' in request, false);
		assert.deepEqual(Object.keys(request).sort(),
			['agent', 'context', 'cwd', 'nodeId', 'ownerRunId', 'requestId', 'result', 'task', 'timeoutMs']);
		assert.equal(pi.live(delegation.SUBAGENT_DELEGATION_STARTED_EVENT), 1);

		// A terminal response for a different owner is not this controller's leaf.
		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT,
			{ ...receipt(), ownerRunId: 'synthetic-other-owner', requestId: request.requestId });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, { ...receipt(), requestId: 'synthetic-other-attempt' });
		let settledEarly = false;
		void controller.settle().then(() => { settledEarly = true; });
		await new Promise((r) => setImmediate(r));
		assert.equal(settledEarly, false, 'a mismatched tuple must not settle this attempt');

		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT,
			{ ...receipt(), requestId: request.requestId, ownerRunId: request.ownerRunId, nodeId: request.nodeId });
		const value = await controller.settle();
		assert.equal(value.status, 'completed');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('progress stays numeric and bounded: no recent output, tool arguments or reasoning', async () => {
	const { dir, config, configPath } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi } = fakePi();
		const controller = createLaneController(pi, loaded, delegation);
		pi.events.emit(delegation.SUBAGENT_DELEGATION_STARTED_EVENT, { ...controller.tuple, model: 'openai-codex/gpt-6.1-sol:max' });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT, {
			...controller.tuple,
			runId: RUN_ID,
			model: 'openai-codex/gpt-6.1-sol:max',
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
		// Every persisted progress field is a number, a status token or a model string.
		for (const line of progress.split('\n').filter((l) => l.length > 0)) {
			for (const [field, value] of Object.entries(JSON.parse(line))) {
				assert.equal(['event', 'key', 'model', 'runId', 'agent', 'timeoutMs', 'toolCount', 'elapsedMs'].includes(field), true, field);
				assert.equal(typeof value, ['string', 'number'].includes(typeof value) ? typeof value : 'object', field);
			}
		}
		assert.equal(JSON.parse(progress.split('\n').filter((l) => l.length > 0).at(-1)).toolCount, 53);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the controller cancels only its own tuple, once, and drains its listeners', async () => {
	const { dir, configPath } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		const { pi, emitted } = fakePi();
		const controller = createLaneController(pi, loaded, delegation);
		const cancels = () => emitted
			.filter((e) => e.event === delegation.SUBAGENT_DELEGATION_CANCEL_EVENT
				&& e.payload.requestId === controller.tuple.requestId)
			.map((e) => e.payload);
		// A cancel aimed at another attempt is observed, never acted on and never echoed.
		pi.events.emit(delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, { ...controller.tuple, requestId: 'synthetic-other-attempt' });
		assert.equal(cancels().length, 0);

		assert.equal(controller.cancel(), true);
		assert.equal(cancels().length, 1);
		assert.deepEqual(cancels()[0], controller.tuple);
		assert.equal(controller.cancel(), false, 'a settled or already-cancelled attempt is not cancelled twice');

		pi.events.emit(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, { ...receipt(), ...controller.tuple });
		await controller.settle();
		for (const event of [delegation.SUBAGENT_DELEGATION_STARTED_EVENT, delegation.SUBAGENT_DELEGATION_UPDATE_EVENT,
			delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT]) {
			assert.equal(pi.live(event), 0, `${event} listener drained`);
		}
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('completed is not approved: only a literal declared verdict is read', async () => {
	const { dir, configPath } = tempConfig();
	try {
		const loaded = readLaneConfig(configPath);
		assert.equal(readExplicitVerdict('APPROVED\n\nbody'), 'APPROVED');
		assert.equal(readExplicitVerdict('CHANGES REQUESTED\nbody'), 'CHANGES REQUESTED');
		assert.equal(readExplicitVerdict('INCOMPLETE\nbody'), 'INCOMPLETE');
		for (const text of ['approved\nbody', 'Looks good to me.\nbody', 'APPROVED and done', '', undefined]) {
			assert.equal(readExplicitVerdict(text), 'INCOMPLETE', String(text));
		}
		const written = writeTerminalReceipt(loaded, receipt({ status: 'completed', result: { kind: 'text', text: 'All good.\n' } }));
		assert.equal(written.status, 'completed');
		assert.equal(written.verdict, 'INCOMPLETE');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('a lane config outside the contract is refused before any process is launched', () => {
	const profile = { model: 'openai-codex/gpt-6.1-sol:max', timeoutMs: 900_000 };
	const { dir, config } = tempConfig();
	try {
		const base = { ...config };
		assert.equal(validateLaneConfig(base, profile).ok, true);
		// No model override option exists, so a supplied one is a refusal, not a preference.
		assert.equal(validateLaneConfig({ ...base, model: 'anthropic/claude' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, agent: 'hylja-coordinator' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, timeoutMs: 900_001 }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, timeoutMs: 1_200_000 }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, timeoutMs: 0 }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, cwd: 'relative/path' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, task: '' }, profile).reason, SETUP_FAILURES.config);
		assert.equal(validateLaneConfig(null, profile).reason, SETUP_FAILURES.config);
		// The implementer profile ceiling is its own 20-minute frontmatter deadline.
		const implementer = readRoleProfile('hylja-implementer');
		assert.equal(validateLaneConfig({ ...base, agent: 'hylja-implementer', timeoutMs: 1_200_001 }, implementer).reason,
			SETUP_FAILURES.config);
		assert.equal(validateLaneConfig({ ...base, agent: 'hylja-implementer', timeoutMs: 1_200_000 }, implementer).ok, true);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the argv loads only the three supplied extensions and sends one fixed input', () => {
	const { dir, config } = tempConfig();
	try {
		const argv = buildArgv(config);
		assert.deepEqual(argv.slice(0, 2), ['--print', '--no-extensions']);
		assert.equal(argv.includes('--no-skills'), true);
		assert.equal(argv.at(-1), FIXED_LANE_INPUT);
		assert.equal(argv.filter((a) => a === FIXED_LANE_INPUT).length, 1);
		assert.equal(argv.filter((a) => a === '--extension').length, 3);
		assert.deepEqual(argv.filter((a, i) => argv[i - 1] === '--extension'),
			[config.subagents, config.guard, config.controller]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('public artifacts are found with one listing, and only meta and output are opened', () => {
	const { dir, config } = tempConfig();
	try {
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		const mine = `${RUN_ID}_hylja-reviewer_0`;
		writeFileSync(join(artifactsDir, `${mine}_meta.json`), JSON.stringify(meta()));
		writeFileSync(join(artifactsDir, `${mine}_output.md`), 'CHANGES REQUESTED\n');
		writeFileSync(join(artifactsDir, `${mine}_transcript.jsonl`), PLANTED_REASONING);
		writeFileSync(join(artifactsDir, 'synthetic-other-session_meta.json'), '{}');
		const opened = [];
		const fs = { exists: existsSync, readdir: (p) => readdirSync(p), readFile: (p) => { opened.push(p); return readFileSync(p, 'utf8'); } };
		const found = discoverPublicArtifacts(config, RUN_ID, 'hylja-reviewer', fs);
		assert.equal(found.ok, true, JSON.stringify(found));
		assert.equal(found.artifacts.meta, join(artifactsDir, `${mine}_meta.json`));
		assert.equal(found.artifacts.output, join(artifactsDir, `${mine}_output.md`));
		// A runId with no artifacts is absent evidence, never a wider search.
		assert.equal(discoverPublicArtifacts(config, 'synthetic-absent-run', 'hylja-reviewer', fs).reason, SETUP_FAILURES.artifacts);
		assert.equal(discoverPublicArtifacts(config, RUN_ID, 'hylja-implementer', fs).reason, SETUP_FAILURES.artifacts);
		verifyArtifacts(config, { model: 'openai-codex/gpt-6.1-sol:max', timeoutMs: 900_000 }, receipt(), found.artifacts, fs);
		assert.equal(opened.some((p) => p.endsWith('_transcript.jsonl')), false);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the runtime record is checked, and absent or mismatched evidence is a setup failure', () => {
	const { dir, config } = tempConfig();
	const profile = { model: 'openai-codex/gpt-6.1-sol:max', timeoutMs: 900_000 };
	const artifacts = { meta: join(dir, 'meta.json'), output: join(dir, 'output.md') };
	try {
		const withMeta = (value) => ({ exists: () => true, readdir: () => [], readFile: (p) => (p === artifacts.meta ? JSON.stringify(value) : 'CHANGES REQUESTED') });
		assert.equal(verifyArtifacts(config, profile, receipt(), artifacts, withMeta(meta())).ok, true);
		// A different effective model, or one below :max, is refused.
		assert.equal(verifyArtifacts(config, profile, receipt(), artifacts, withMeta(meta({ model: 'openai-codex/gpt-6.1-sol:high' }))).reason, SETUP_FAILURES.model);
		assert.equal(verifyArtifacts(config, { model: 'openai-codex/gpt-6.1-sol:high', timeoutMs: 900_000 }, receipt(), artifacts, withMeta(meta())).reason, SETUP_FAILURES.model);
		// A role that is not the lane role is refused.
		assert.equal(verifyArtifacts(config, profile, receipt(), artifacts, withMeta(meta({ agent: 'hylja-implementer' }))).reason, SETUP_FAILURES.role);
		// Ambient extensions left on, or the declared guard missing from the effective set.
		assert.equal(verifyArtifacts(config, profile, receipt(), artifacts,
			withMeta(meta({ launchResolvedExtensions: { disableAmbientExtensions: false, configured: ['a'], effective: ['a'] } }))).reason, SETUP_FAILURES.guard);
		assert.equal(verifyArtifacts(config, profile, receipt(), artifacts,
			withMeta(meta({ launchResolvedExtensions: { disableAmbientExtensions: true, configured: [], effective: [] } }))).reason, SETUP_FAILURES.guard);
		// A launch contract digest the terminal response does not carry.
		assert.equal(verifyArtifacts(config, profile, receipt({ launchContractDigest: undefined }), artifacts, withMeta(meta())).reason, SETUP_FAILURES.contract);
		// Acceptance is checked, never inferred: an explicit writer record is required for a writer.
		const writerConfig = { ...config, agent: 'hylja-implementer' };
		assert.equal(verifyArtifacts(writerConfig, { model: 'opencode-go/space-bunny-free:max', timeoutMs: 1_200_000 },
			{ ...receipt(), agent: 'hylja-implementer' }, artifacts,
			withMeta(meta({ agent: 'hylja-implementer', model: 'opencode-go/space-bunny-free:max' }))).reason, SETUP_FAILURES.acceptance);
		assert.equal(verifyArtifacts(writerConfig, { model: 'opencode-go/space-bunny-free:max', timeoutMs: 1_200_000 },
			{ ...receipt(), agent: 'hylja-implementer' }, artifacts,
			withMeta(meta({ agent: 'hylja-implementer', model: 'opencode-go/space-bunny-free:max', acceptance: { status: 'accepted', explicit: true } }))).ok, true);
		assert.equal(verifyArtifacts(writerConfig, { model: 'opencode-go/space-bunny-free:max', timeoutMs: 1_200_000 },
			{ ...receipt(), agent: 'hylja-implementer' }, artifacts,
			withMeta(meta({ agent: 'hylja-implementer', model: 'opencode-go/space-bunny-free:max', acceptance: undefined }))).reason, SETUP_FAILURES.acceptance);
		// A non-completed terminal status is never a passed lane.
		assert.equal(verifyArtifacts(config, profile, receipt({ status: 'timed_out' }), artifacts, withMeta(meta())).reason, SETUP_FAILURES.status);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('a full lane runs the real CLI against a fake transport and writes a verified public record', async () => {
	const { dir, config, configPath } = tempConfig();
	try {
		const artifactsDir = join(config.sessionDir, 'subagent-artifacts');
		mkdirSync(artifactsDir, { recursive: true });
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_meta.json`), JSON.stringify(meta()));
		writeFileSync(join(artifactsDir, `${RUN_ID}_hylja-reviewer_0_output.md`), 'CHANGES REQUESTED\n');
		const record = [];
		const result = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({
				record,
				onLaunch(options, child) {
					assert.equal(options.env[ 'HYLJA_NATIVE_LANE_CONFIG' ], configPath);
					assert.equal(options.env.HYLJA_NATIVE_LANE_SUBAGENTS.endsWith('delegation.js'), true);
					child.stderr.emit('data', Buffer.from(PLANTED_REASONING));
					writeFileSync(config.receipt, JSON.stringify(receipt(), null, 2));
					writeFileSync(config.dispatch, JSON.stringify({ requestId: '39e040c4', ownerRunId: OWNER, nodeId: 'mapping-review-round2', pid: 4242 }, null, 2));
					writeFileSync(config.progress, `${JSON.stringify({ event: 'progress', key: 'mapping-review-round2', model: 'openai-codex/gpt-6.1-sol:max', toolCount: 53, elapsedMs: 296_680 })}\n`);
				},
			}),
		});
		assert.equal(result.ok, true, JSON.stringify(result));
		assert.equal(record.length, 1);
		assert.equal(record[0].command, PI);
		assert.equal(record[0].args.at(-1), FIXED_LANE_INPUT);
		const written = JSON.parse(readFileSync(config.verification, 'utf8'));
		assert.equal(written.verdict, 'CHANGES REQUESTED');
		assert.equal(written.model, 'openai-codex/gpt-6.1-sol:max');
		assert.equal(written.toolCount, 53);
		assert.equal(written.acceptance, 'not-required');
		assert.deepEqual(written.tuple.nodeId, 'mapping-review-round2');
		assert.equal(written.progress.at(-1).toolCount, 53);
		const publicText = readFileSync(config.verification, 'utf8');
		assert.equal(publicText.includes(PLANTED_REASONING), false, 'child stderr is never echoed into the record');
		assert.equal(publicText.includes('result'), false, 'the leaf text stays in its own receipt');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('a failed, timed-out or malformed receipt is explicit, and no watchdog timer survives', async () => {
	const { dir, config, configPath } = tempConfig();
	try {
		const missing = await runNativeLane(['--config', configPath], { spawn: fakeSpawn() });
		assert.equal(missing.reason, SETUP_FAILURES.receipt);
		const failed = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ onLaunch: () => writeFileSync(config.receipt, JSON.stringify(receipt({ status: 'failed' }))) }),
		});
		assert.equal(failed.reason, SETUP_FAILURES.status);
		assert.equal(JSON.parse(readFileSync(config.verification, 'utf8')).status, 'failed');
		const malformed = await runNativeLane(['--config', configPath], {
			spawn: fakeSpawn({ onLaunch: () => writeFileSync(config.receipt, '{ not json') }),
		});
		assert.equal(malformed.reason, SETUP_FAILURES.receipt);
		// A malformed invocation is refused by the CLI itself.
		assert.equal((await runNativeLane([], {}))?.reason, SETUP_FAILURES.argv);
		assert.equal((await runNativeLane(['--config', 'relative.json'], {}))?.reason, SETUP_FAILURES.argv);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the installed extension entrypoint and the project guard exist at the declared paths', () => {
	// Read-only validation of the exact operator paths a real run would use. No leaf is launched here.
	for (const path of [PI, SUBAGENTS, join(SUBAGENTS, 'index.js'),
		join(repoRoot, '.pi', 'extensions', 'hylja-workflow-guard.ts'),
		join(repoRoot, '.pi', 'lib', 'hylja-native-lane.ts'),
		join(repoRoot, '.pi', 'agents', 'hylja-implementer.md'),
		join(repoRoot, '.pi', 'agents', 'hylja-reviewer.md')]) {
		assert.equal(existsSync(path), true, path);
	}
	assert.equal(readRoleProfile('hylja-implementer').model, 'opencode-go/space-bunny-free:max');
	assert.equal(readRoleProfile('hylja-reviewer').model, 'openai-codex/gpt-6.1-sol:max');
	assert.equal(readRoleProfile('hylja-implementer').timeoutMs, 1_200_000);
	assert.equal(readRoleProfile('hylja-reviewer').timeoutMs, 900_000);
});
