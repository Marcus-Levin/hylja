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
	evaluateBashToolInput,
} from '../.pi/lib/hylja-command-guard.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const guardPath = resolve(root, '.pi', 'extensions', 'hylja-workflow-guard.ts');

// Fixed roots so a case never depends on the machine it runs on.
const OPTIONS = { home: '/home/synthetic-lancer', cwd: '/home/synthetic-lancer/worktree' };

/** The exact command shape that burned eight minutes before the exact paths were used. */
const KNOWN_FAILURE = 'find / -name hylja-implementer.md | head -20';

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
	const blocked = handler({ toolName: 'bash', toolCallId: 'call-1', input: blockedInput });
	assert.deepEqual(blocked, { block: true, reason: BLOCK_REASON_MACHINE_WIDE_SEARCH });
	// Refused before execution, so no timeout was applied and the input is otherwise untouched.
	assert.equal(blockedInput.timeout, undefined);

	const allowedInput = { command: 'npm test' };
	assert.equal(handler({ toolName: 'bash', toolCallId: 'call-2', input: allowedInput }), undefined);
	assert.equal(allowedInput.timeout, DEFAULT_COMMAND_TIMEOUT_SECONDS);

	const clampedInput = { command: 'npm test', timeout: 9000 };
	handler({ toolName: 'bash', toolCallId: 'call-3', input: clampedInput });
	assert.equal(clampedInput.timeout, MAX_COMMAND_TIMEOUT_SECONDS);

	const readInput = { path: 'src/policy.ts' };
	assert.equal(handler({ toolName: 'read', toolCallId: 'call-4', input: readInput }), undefined);
	assert.deepEqual(readInput, { path: 'src/policy.ts' });
});

test('both role profiles resolve their declared guard extension to a file that exists', () => {
	for (const name of ['hylja-implementer', 'hylja-reviewer']) {
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
