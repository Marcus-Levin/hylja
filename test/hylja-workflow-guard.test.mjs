// Hylja development workflow guard.
//
// Behavioral tests for the two guarantees the guard makes to a Pi session: a machine-wide `find` never
// executes, and every builtin bash call carries a finite positive timeout. Cases call the real helper
// and the real Pi adapter (loaded through Node's own type stripping), so a wiring regression fails.
// No case runs a shell, touches a filesystem root, reads outside the repository, or logs anything: the
// blocked commands below are strings that never leave this process.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
	BLOCK_REASON_INVALID_TIMEOUT,
	BLOCK_REASON_MACHINE_WIDE_SEARCH,
	DEFAULT_COMMAND_TIMEOUT_SECONDS,
	MAX_COMMAND_TIMEOUT_SECONDS,
	INVALID_VALIDATION_APPROVAL,
	evaluateBashToolInput,
} from '../.pi/lib/hylja-command-guard.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const guardPath = resolve(root, '.pi', 'extensions', 'hylja-workflow-guard.ts');

// A foreground child is a session inside the parent process, so its worktree is reachable only from
// the handler context. These roots are synthetic and are never touched on disk.
const CHILD_CWD = '/srv/synthetic-lancer/worktree';
const CHILD_CONTEXT = { cwd: CHILD_CWD };
const VALIDATION_COMMANDS = [
	'PATH=/tmp/synthetic-toolchain/bin:$PATH npm test > /tmp/synthetic-test.log 2>&1',
	'PATH=/tmp/synthetic-toolchain/bin:$PATH npm run test:coverage > /tmp/synthetic-coverage.log 2>&1',
];
const approval = () => ({ cwd: CHILD_CWD, commands: [...VALIDATION_COMMANDS] });

async function installedHandler(record, ordinary = false) {
	const module = await import(guardPath);
	const handlers = [];
	const install = ordinary ? module.default : module.installHyljaWorkflowGuard;
	install({ on(name, handler) {
		assert.equal(name, 'tool_call'); handlers.push(handler);
	} }, record);
	assert.equal(handlers.length, 1);
	return handlers[0];
}

test('opt-in receipts use bound runtime callbacks, never extension factory actions', async () => {
	const module = await import(guardPath);
	const handlers = new Map();
	const receipts = [];
	let bound = false;
	const pi = {
		on(name, handler) { handlers.set(name, handler); },
		appendEntry(type, data) {
			assert.ok(bound, 'runtime actions require binding');
			receipts.push({ type, data });
		},
	};
	module.installHyljaWorkflowGuard(pi, approval(), true);
	assert.equal(receipts.length, 0);
	assert.equal(typeof handlers.get('session_start'), 'function');
	assert.deepEqual(bash(handlers.get('tool_call'), VALIDATION_COMMANDS[0], 600).result,
		{ block: true, reason: module.GUARD_RECEIPT_REFUSAL });
	bound = true;
	handlers.get('session_start')();
	assert.deepEqual(receipts, [{ type: 'hylja-workflow-guard-ready', data: { version: 1 } }]);
	const handler = handlers.get('tool_call');
	assert.equal(bash(handler, VALIDATION_COMMANDS[0], 600).input.timeout, 600);
	assert.deepEqual(receipts[1], { type: 'hylja-workflow-guard-timeout', data: { version: 1, effectiveSeconds: 600 } });
	assert.equal(bash(handler, 'npm run build', 600).input.timeout, 300);
	assert.deepEqual(receipts[2], { type: 'hylja-workflow-guard-timeout', data: { version: 1, effectiveSeconds: 300 } });
	assert.deepEqual(bash(handler, '# SYNTHETIC-GUARD-PROBE; find /', 15).result,
		{ block: true, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH });
	assert.deepEqual(bash(handler, VALIDATION_COMMANDS[0], 0).result,
		{ block: true, reason: BLOCK_REASON_INVALID_TIMEOUT });
	handler({ toolName: 'read', input: { path: 'synthetic-planted.invalid' } }, CHILD_CONTEXT);
	assert.equal(receipts.length, 3);
});

test('receipt failure returns a fixed block even when a host would swallow hook exceptions', async () => {
	const module = await import(guardPath);
	for (const phase of ['startup', 'timeout']) {
		const handlers = new Map();
		let fail = phase === 'startup';
		module.installHyljaWorkflowGuard({
			on(name, handler) { handlers.set(name, handler); },
			appendEntry() { if (fail) throw new Error('synthetic-receipt-failure.invalid'); },
		}, approval(), true);
		const refusal = { block: true, reason: module.GUARD_RECEIPT_REFUSAL };
		assert.doesNotThrow(() => handlers.get('session_start')());
		fail = true;
		assert.deepEqual(bash(handlers.get('tool_call'), VALIDATION_COMMANDS[0], 600).result, refusal);
		fail = false;
		assert.deepEqual(bash(handlers.get('tool_call'), VALIDATION_COMMANDS[0], 600).result, refusal);
		handlers.get('session_start')();
		assert.deepEqual(bash(handlers.get('tool_call'), VALIDATION_COMMANDS[0], 600).result, refusal);
	}
});

test('a snapshotted command window refuses expired, invalid and over-reserve admission', async () => {
	const helper = await import('../.pi/lib/hylja-command-guard.mjs');
	const record = { hardStopMs: 1000000, reserveSeconds: 180 };
	const window = helper.snapshotCommandWindow(record);
	record.hardStopMs = 2000000;
	record.reserveSeconds = 0;
	assert.deepEqual(window, { hardStopMs: 1000000, reserveSeconds: 180 });
	assert.equal(Object.isFrozen(window), true);
	assert.equal(helper.commandFitsWindow(window, 220000, 600), true);
	assert.equal(helper.commandFitsWindow(window, 220001, 600), false);
	assert.equal(helper.commandFitsWindow({ hardStopMs: Number.MAX_SAFE_INTEGER, reserveSeconds: 0 },
		Number.MAX_SAFE_INTEGER, 0.0001), false);
	for (const now of [1000000, 1000001, -1, NaN, Infinity, '220000'])
		assert.equal(helper.commandFitsWindow(window, now, 15), false);
	for (const seconds of [0, -1, NaN, Infinity, '600'])
		assert.equal(helper.commandFitsWindow(window, 220000, seconds), false);
	assert.equal(helper.snapshotCommandWindow(undefined), undefined);
	let reads = 0;
	for (const invalid of [null, {}, { ...window, extra: true }, { ...window, reserveSeconds: -1 },
		{ ...window, reserveSeconds: Infinity }, { ...window, hardStopMs: 'synthetic-planted.invalid' },
		{ ...window, hardStopMs: Number.MAX_SAFE_INTEGER + 1 },
		{ get hardStopMs() { reads++; throw new Error('synthetic-planted.invalid'); }, reserveSeconds: 180 }]) {
		assert.throws(() => helper.snapshotCommandWindow(invalid),
			(error) => error instanceof Error && error.message === helper.INVALID_COMMAND_WINDOW);
	}
	assert.equal(reads, 0);
});

test('the real adapter refuses an expired window before applying timeout or recording', async () => {
	const module = await import(guardPath);
	const handlers = new Map();
	module.installHyljaWorkflowGuard({ on(name, handler) { handlers.set(name, handler); } },
		approval(), false, { hardStopMs: 1, reserveSeconds: 180 });
	const input = { command: VALIDATION_COMMANDS[0], timeout: 600 };
	assert.deepEqual(handlers.get('tool_call')({ toolName: 'bash', input }, CHILD_CONTEXT),
		{ block: true, reason: module.GUARD_WINDOW_REFUSAL });
	assert.equal(input.timeout, 600);
	assert.equal(handlers.get('tool_call')({ toolName: 'read', input: {} }, CHILD_CONTEXT), undefined);
});

test('adapter window admits equality and closes permanently on late delivery or clock rollback', async () => {
	const module = await import(guardPath);
	const actualNow = Date.now;
	try {
		for (const phase of ['late', 'rollback']) {
			let now = 220000;
			Date.now = () => now;
			const handlers = new Map();
			module.installHyljaWorkflowGuard({ on(name, handler) { handlers.set(name, handler); } },
				approval(), false, { hardStopMs: 1000000, reserveSeconds: 180 });
			const handler = handlers.get('tool_call');
			assert.equal(bash(handler, VALIDATION_COMMANDS[0], 600).result, undefined);
			now += phase === 'late' ? 1 : -1;
			const refusal = { block: true, reason: module.GUARD_WINDOW_REFUSAL };
			assert.deepEqual(bash(handler, VALIDATION_COMMANDS[0], 600).result, refusal);
			now = 220000;
			assert.deepEqual(bash(handler, 'npm run build', 1).result, refusal);
		}
	} finally {
		Date.now = actualNow;
	}
});

function bash(handler, command, timeout, context = CHILD_CONTEXT) {
	const input = { command, ...(timeout !== undefined ? { timeout } : {}) };
	const result = handler({ toolName: 'bash', input }, context);
	return { input, result };
}

test('coordinator-approved exact test and coverage calls retain requested 600 through the real adapter', async () => {
	const handler = await installedHandler(approval());
	for (const command of VALIDATION_COMMANDS) {
		assert.equal(bash(handler, command, 600).input.timeout, 600);
	}
});

// Fixed roots so a case never depends on the machine it runs on.
const OPTIONS = { home: '/home/synthetic-lancer', cwd: '/home/synthetic-lancer/worktree' };

/** The exact command shape that burned eight minutes before the exact paths were used. */
const KNOWN_FAILURE = 'find / -name hylja-implementer.md | head -20';

test('approved and ordinary adapters retain timeout defaults, bounds, malformed refusals and other tools', async () => {
	for (const ordinary of [false, true]) {
		const handler = await installedHandler(approval(), ordinary);
		for (const command of VALIDATION_COMMANDS) {
			for (const [requested, expected] of [[undefined, 120], [0.5, 0.5], [300, 300], [600, ordinary ? 300 : 600], [9000, ordinary ? 300 : 600]]) {
				assert.equal(bash(handler, command, requested).input.timeout, expected);
			}
			for (const timeout of [null, 0, -1, '600', NaN, Infinity, {}]) {
				assert.deepEqual(bash(handler, command, timeout).result, { block: true, reason: BLOCK_REASON_INVALID_TIMEOUT });
			}
		}
		const input = { command: VALIDATION_COMMANDS[0], timeout: 9000 };
		assert.equal(handler({ toolName: 'read', input }, CHILD_CONTEXT), undefined);
		assert.equal(input.timeout, 9000);
	}
	const missing = await installedHandler(undefined);
	assert.equal(bash(missing, VALIDATION_COMMANDS[0], 600).input.timeout, 300);
});

test('approval requires exact whole command and exact session cwd with no inference', async () => {
	const handler = await installedHandler(approval());
	const command = VALIDATION_COMMANDS[0];
	for (const altered of [command + '; npm run build', command + '\necho synthetic', 'echo synthetic; ' + command,
		command + ' ', ' ' + command, command.replace('synthetic-test.log', 'synthetic-other.log'),
		'npm test', 'npm run test:coverage', 'npm run build']) {
		assert.equal(bash(handler, altered, 600).input.timeout, 300);
	}
	for (const cwd of [CHILD_CWD + '/', CHILD_CWD + '/child', '/srv/synthetic-other/worktree', undefined]) {
		assert.equal(bash(handler, command, 600, { cwd }).input.timeout, 300);
	}
});

test('installation snapshots approval and command array without later widening', async () => {
	const record = approval();
	const handler = await installedHandler(record);
	record.cwd = '/srv/synthetic-other/worktree';
	record.commands[0] = 'npm run build';
	record.commands.push('npm test');
	assert.equal(bash(handler, VALIDATION_COMMANDS[0], 600).input.timeout, 600);
	assert.equal(bash(handler, 'npm run build', 600).input.timeout, 300);
	assert.equal(bash(handler, 'npm test', 600).input.timeout, 300);
	assert.equal(bash(handler, VALIDATION_COMMANDS[0], 600, { cwd: record.cwd }).input.timeout, 300);
});

test('malformed approval fails installation whole with fixed non-echoing setup error', async () => {
	const module = await import(guardPath);
	let registrations = 0;
	let reads = 0;
	const accessor = { cwd: CHILD_CWD, get commands() { reads++; throw Error('synthetic-planted.invalid'); } };
	const arrayAccessor = [...VALIDATION_COMMANDS];
	Object.defineProperty(arrayAccessor, '0', { get() { reads++; throw Error('synthetic-planted.invalid'); } });
	const bad = [null, false, {}, { ...approval(), extra: true }, { ...approval(), cwd: 'relative' },
		{ ...approval(), cwd: '/' + 'x'.repeat(4096) }, { ...approval(), cwd: '/tmp/\0bad' }, accessor,
		Object.assign(Object.create({}), approval()),
		...[[], [''], [' '], [1], [VALIDATION_COMMANDS[0], VALIDATION_COMMANDS[0]],
			['x'.repeat(16385)], ['a', 'b', 'c'], new Array(1), arrayAccessor].map((commands) => ({ cwd: CHILD_CWD, commands }))];
	for (const record of bad) {
		assert.throws(() => module.installHyljaWorkflowGuard({ on() { registrations++; } }, record),
			(error) => error instanceof Error && error.message === INVALID_VALIDATION_APPROVAL);
	}
	assert.equal(registrations, 0);
	assert.equal(reads, 0);
});

test('validation approval never overrides the independent forbidden-find decision', async () => {
	const handler = await installedHandler({ cwd: CHILD_CWD, commands: [KNOWN_FAILURE, 'npm test'] });
	const { input, result } = bash(handler, KNOWN_FAILURE, 600);
	assert.deepEqual(result, { block: true, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH });
	assert.equal(input.timeout, 600);
});

test('the known machine-wide search is refused before execution', () => {
	const decision = evaluateBashToolInput({ command: KNOWN_FAILURE }, OPTIONS);
	assert.equal(decision.allowed, false);
	assert.equal(decision.reason, BLOCK_REASON_MACHINE_WIDE_SEARCH);
});

test('literal, quoted and absolute-executable variants of the same search are refused', () => {
	const variants = [
		'find "/" -name hylja-implementer.md',
		"find '/usr' -name 'hylja-implementer.md'",
		'/usr/bin/find / -name hylja-implementer.md',
		'/bin/find -L / -name hylja-implementer.md',
		'sudo find / -name hylja-implementer.md',
		'LC_ALL=C find / -name hylja-implementer.md',
		'echo ready && find //usr/ -name hylja-implementer.md',
		'git rev-parse HEAD\nfind /home -name hylja-implementer.md',
		'sh -c "find / -name hylja-implementer.md"',
		'bash -lc "find / -name hylja-implementer.md"',
		'xargs find /etc -name hylja-implementer.md',
	];
	for (const command of variants) {
		const decision = evaluateBashToolInput({ command }, OPTIONS);
		assert.equal(decision.allowed, false, command);
		assert.equal(decision.reason, BLOCK_REASON_MACHINE_WIDE_SEARCH);
	}
});

test('scoped discovery and the verification commands the pipeline needs stay allowed', () => {
	const allowed = [
		'find . -name "*.test.mjs"',
		'find src -maxdepth 2 -type f',
		'find .. -maxdepth 3 -name hylja-implementer.md',
		'find docs/development -name pipeline.md',
		'find /home/synthetic-lancer/worktree/src -name "*.ts"',
		'find /home/synthetic-lancer/.agents/skills -name SKILL.md',
		'find ~ -maxdepth 4 -name hylja-implementer.md',
		'find /tmp -maxdepth 2 -name scratch.mjs',
		'grep -rn "findSearchRoot" .pi/lib',
		'npm test',
	];
	for (const command of allowed) {
		assert.equal(evaluateBashToolInput({ command }, OPTIONS).allowed, true, command);
	}
});

test('a missing or non-string command is allowed and never throws', () => {
	for (const input of [{}, { command: '' }, { command: 42 }, null, undefined]) {
		const decision = evaluateBashToolInput(input, OPTIONS);
		assert.equal(decision.allowed, true);
		assert.equal(decision.timeout, DEFAULT_COMMAND_TIMEOUT_SECONDS);
	}
});

test('an omitted timeout gets the guard default', () => {
	assert.equal(evaluateBashToolInput({ command: 'npm test' }, OPTIONS).timeout, DEFAULT_COMMAND_TIMEOUT_SECONDS);
});

test('a tighter explicit timeout is preserved and an excessive one is clamped', () => {
	assert.equal(evaluateBashToolInput({ command: 'npm test', timeout: 30 }, OPTIONS).timeout, 30);
	assert.equal(evaluateBashToolInput({ command: 'npm test', timeout: 0.5 }, OPTIONS).timeout, 0.5);
	assert.equal(evaluateBashToolInput({ command: 'npm test', timeout: MAX_COMMAND_TIMEOUT_SECONDS }, OPTIONS).timeout,
		MAX_COMMAND_TIMEOUT_SECONDS);
	assert.equal(evaluateBashToolInput({ command: 'npm test', timeout: 3600 }, OPTIONS).timeout,
		MAX_COMMAND_TIMEOUT_SECONDS);
});

test('a malformed timeout is refused with the fixed reason, never the value', () => {
	const planted = 'synthetic-planted-timeout.invalid';
	for (const timeout of [0, -5, '120', planted, Number.NaN, Number.POSITIVE_INFINITY, null, {}]) {
		const decision = evaluateBashToolInput({ command: 'npm test', timeout }, OPTIONS);
		assert.equal(decision.allowed, false, String(timeout));
		assert.equal(decision.reason, BLOCK_REASON_INVALID_TIMEOUT);
		assert.equal(decision.reason.includes(planted), false);
	}
});

test('the adapter checks the child session directory, not the parent process directory', async () => {
	const module = await import(guardPath);
	const handlers = [];
	module.default({
		on(event, handler) {
			assert.equal(event, 'tool_call');
			handlers.push(handler);
		},
	});
	const handler = handlers[0];

	const scoped = { command: `find ${CHILD_CWD}/src -name "*.ts"` };
	assert.equal(handler({ toolName: 'bash', toolCallId: 'call-c1', input: scoped }, CHILD_CONTEXT), undefined);
	assert.equal(scoped.timeout, DEFAULT_COMMAND_TIMEOUT_SECONDS);

	const tighter = { command: `find ${CHILD_CWD} -name "*.ts"`, timeout: 45 };
	handler({ toolName: 'bash', toolCallId: 'call-c2', input: tighter }, CHILD_CONTEXT);
	assert.equal(tighter.timeout, 45);

	// The broad ancestor of the same child root stays refused.
	const broad = { command: 'find /srv -name "*.ts"' };
	assert.deepEqual(handler({ toolName: 'bash', toolCallId: 'call-c3', input: broad }, CHILD_CONTEXT),
		{ block: true, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH });
	assert.equal(broad.timeout, undefined);
});

test('the adapter blocks the known search, sets the timeout, and leaves other tools untouched', async () => {
	const module = await import(guardPath);
	const handlers = [];
	module.default({
		on(event, handler) {
			assert.equal(event, 'tool_call');
			handlers.push(handler);
		},
	});
	assert.equal(handlers.length, 1);
	const handler = handlers[0];

	const blockedInput = { command: KNOWN_FAILURE };
	const blocked = handler({ toolName: 'bash', toolCallId: 'call-1', input: blockedInput }, CHILD_CONTEXT);
	assert.deepEqual(blocked, { block: true, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH });
	// Refused before execution, so no timeout was applied and the input is otherwise untouched.
	assert.equal(blockedInput.timeout, undefined);

	const allowedInput = { command: 'npm test' };
	assert.equal(handler({ toolName: 'bash', toolCallId: 'call-2', input: allowedInput }, CHILD_CONTEXT), undefined);
	assert.equal(allowedInput.timeout, DEFAULT_COMMAND_TIMEOUT_SECONDS);

	const clampedInput = { command: 'npm test', timeout: 9000 };
	handler({ toolName: 'bash', toolCallId: 'call-3', input: clampedInput }, CHILD_CONTEXT);
	assert.equal(clampedInput.timeout, MAX_COMMAND_TIMEOUT_SECONDS);

	const readInput = { path: 'src/policy.ts' };
	assert.equal(handler({ toolName: 'read', toolCallId: 'call-4', input: readInput }, CHILD_CONTEXT), undefined);
	assert.deepEqual(readInput, { path: 'src/policy.ts' });
});

test('every role profile, fallback included, resolves its declared guard extension to a file that exists', () => {
	for (const name of ['hylja-implementer', 'hylja-reviewer', 'hylja-implementer-sol61']) {
		const profilePath = resolve(root, '.pi', 'agents', `${name}.md`);
		const match = /^extensions:\s*(\S.*)$/m.exec(readFileSync(profilePath, 'utf8'));
		assert.ok(match, `${name} declares extensions`);
		const declared = match[1].split(',')[0].trim();
		// pi-subagents resolves an entry that starts with `.` or `..` against the agent file's own
		// directory (src/agents/agents.js, resolveAgentRelativeExtensionPaths).
		const resolved = declared.startsWith('.') ? resolve(dirname(profilePath), declared) : declared;
		assert.ok(isAbsolute(resolved), `${name} resolves to an absolute path`);
		assert.ok(existsSync(resolved), `${name} extension exists: ${resolved}`);
		assert.equal(resolved, join(root, '.pi', 'extensions', 'hylja-workflow-guard.ts'));
	}
});
