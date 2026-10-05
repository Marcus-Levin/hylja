// Focused evidence for the raw diagnostic assertion guard (#253).
//
// When an `assert` call fails, Node prints the compared actual and expected values itself, so a fixed
// assert message does not stop captured subprocess stdout/stderr from reaching the log. These cases
// drive the shipped guard over real sources parsed by the repository's own pinned TypeScript, pin the
// outcomes it accepts and refuses, and prove the trap on a real failing subprocess assertion with an
// unsafe negative control. No case calls a provider, reaches the network or reads private data, and
// every planted value is obviously synthetic and non-routable.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
	GUARDED_TEST_FILES,
	MAX_FILES,
	MAX_FILE_BYTES,
	MAX_ALIAS_HOPS,
	MAX_PRINTED_FINDINGS,
	findRisksInSource,
} from '../scripts/development/check-diagnostic-assertions.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const guardPath = join(root, 'scripts', 'development', 'check-diagnostic-assertions.mjs');

/** Obviously synthetic and non-routable: the captured original a failing assertion must not print. */
const PLANTED = 'synthetic-planted-subprocess-output.invalid';
/** The expected value both shapes compare against; it never appears in a diagnostic. */
const EXPECTED = 'synthetic-expected-original.invalid';
const SAFE_MESSAGE = 'control: the synthetic child wrote the planted original';
/** The same fact as the unsafe shape, compared so Node prints the comparison and not the value. */
const SAFE_ASSERTION = `assert.equal(captured.stdout === '${EXPECTED}', true, '${SAFE_MESSAGE}');`;
const UNSAFE_ASSERTION = `assert.equal(captured.stdout, '${EXPECTED}', '${SAFE_MESSAGE}');`;
/** One bound on a synthetic child, never a wait without one. */
const CHILD_TIMEOUT_MS = 30_000;

/** A fixture source under test, with its lines kept so an expected position is a real index. */
const fixture = (...lines) => ({ source: lines.join('\n'), lines });
/** The 1-based column a needle starts at in its own line. */
const columnOf = (line, needle) => line.indexOf(needle) + 1;
/** The findings reduced to the outcome a case is about, with no source text echoed. */
const shape = (risks) => risks.map((risk) => ({
	line: risk.line,
	column: risk.column,
	method: risk.method,
	position: risk.position,
	argument: risk.argument,
}));

test('captured stdout and stderr are refused as assertion operands and messages, fixed message or not', () => {
	const { source, lines } = fixture(
		"import assert from 'node:assert/strict';",
		"assert.equal(captured.stdout, expected, 'a fixed message');",
		"assert.notEqual(captured.stderr, '', 'a fixed message');",
		"assert.deepStrictEqual(captured.stdout.split('\\n'), expectedLines, 'a fixed message');",
		"assert.match(captured.stderr, /synthetic/, 'a fixed message');",
		"assert.equal(captured.status, 0, captured.stderr);",
		"assert.equal(JSON.parse(captured.stdout).status, 0, 'a fixed message');",
		"const lines = captured.stdout.split('\\n');",
		"assert.equal(lines[1], '', 'a fixed message');",
	);
	// A finding locates the start of the offending argument, so the column walks a reader straight to the
	// shape that has to change while the printed line still carries no source text.
	assert.deepEqual(shape(findRisksInSource(source, 'fixture.test.mjs')), [
		{ line: 2, column: columnOf(lines[1], 'captured.stdout'), method: 'equal', position: 'operand', argument: 0 },
		{ line: 3, column: columnOf(lines[2], 'captured.stderr'), method: 'notEqual', position: 'operand', argument: 0 },
		{ line: 4, column: columnOf(lines[3], 'captured.stdout'), method: 'deepStrictEqual', position: 'operand', argument: 0 },
		{ line: 5, column: columnOf(lines[4], 'captured.stderr'), method: 'match', position: 'operand', argument: 0 },
		{ line: 6, column: columnOf(lines[5], 'captured.stderr'), method: 'equal', position: 'message', argument: 2 },
		{ line: 7, column: columnOf(lines[6], 'JSON.parse'), method: 'equal', position: 'operand', argument: 0 },
		{ line: 9, column: columnOf(lines[8], 'lines[1]'), method: 'equal', position: 'operand', argument: 0 },
	]);
});

test('a simple local alias of captured output is refused wherever it reaches an assertion', () => {
	const { source, lines } = fixture(
		"import assert from 'node:assert/strict';",
		'const captured = spawnSync(process.execPath, [childPath]);',
		'const noise = captured.stderr;',
		"assert.equal(captured.status, 0, noise);",
		'const { stderr: childNoise } = captured;',
		"assert.equal(captured.status, 0, `control: (${childNoise})`);",
		'const trimmed = childNoise.trim();',
		"assert.equal(trimmed, '', 'a fixed message');",
		"assert.ok(childNoise, 'a fixed message');",
	);
	assert.deepEqual(shape(findRisksInSource(source, 'fixture.test.mjs')), [
		{ line: 4, column: columnOf(lines[3], 'noise'), method: 'equal', position: 'message', argument: 2 },
		{ line: 6, column: columnOf(lines[5], '`control:'), method: 'equal', position: 'message', argument: 2 },
		{ line: 8, column: columnOf(lines[7], 'trimmed'), method: 'equal', position: 'operand', argument: 0 },
		{ line: 9, column: columnOf(lines[8], 'childNoise'), method: 'ok', position: 'operand', argument: 0 },
	]);
});

test('the equivalent boolean comparisons keep their fixed message and are accepted', () => {
	const { source } = fixture(
		"import assert from 'node:assert/strict';",
		"assert.equal(captured.stderr === '', true, 'one stdout record, never a traceback');",
		'assert.equal(captured.stdout.includes(planted), false, \'no echo\');',
		"assert.equal(captured.stdout.length, 2, 'exactly one record line');",
		"assert.equal(captured.stdout.split('\\n').length, 2, 'exactly one record line');",
		"assert.ok(!captured.stderr, 'never a warning');",
		"assert.equal(captured.stdout.split('\\n')[0] === expected, true, 'the same record');",
		"assert.equal(captured.error, undefined, 'the process started and finished');",
		// The guard is about assertion diagnostics. A capture that reaches no assertion is reported by
		// the case that reads it, not by this guard, and pretending otherwise would overstate it.
		'const capturedOutput = captured.stdout;',
	);
	assert.deepEqual(shape(findRisksInSource(source, 'fixture.test.mjs')), []);
});

test('a capture inside an object or array literal operand is refused like any other operand', () => {
	// Both literals hold the same value in the same position. The array branch already traversed its
	// elements; the object branch used to read a PropertyAssignment as a bare node, fall through to the
	// unmodelled rule and report nothing, so the pair disagreed inside one modelled family.
	const arrayLiteral = fixture(
		"import assert from 'node:assert/strict';",
		'assert.deepEqual([captured.stdout], expected, "fixed");',
		'',
	);
	assert.ok(shape(findRisksInSource(arrayLiteral.source, 'fixture.test.mjs')).length > 0,
		'an array literal holding a capture is a finding');
	const objectLiteral = fixture(
		"import assert from 'node:assert/strict';",
		'assert.deepEqual({ got: captured.stdout }, expected, "fixed");',
		'',
	);
	assert.deepEqual(shape(findRisksInSource(objectLiteral.source, 'fixture.test.mjs')),
		shape(findRisksInSource(arrayLiteral.source, 'fixture.test.mjs')),
		'the object literal reports exactly what the equivalent array literal reports');
});

test('a file without an assert import, and one without any assertion, report nothing', () => {
	const withoutImport = fixture('const assert = helpers.assert;', "assert.equal(captured.stdout, expected, 'fixed');");
	const withoutAssertion = fixture(
		"import assert from 'node:assert/strict';",
		'const report = JSON.parse(captured.stdout);',
		'const observed = report.status;',
		'',
	);
	assert.deepEqual(shape(findRisksInSource(withoutImport.source, 'fixture.test.mjs')), [],
		'a local object that is not the assert module is outside this guard');
	assert.deepEqual(shape(findRisksInSource(withoutAssertion.source, 'fixture.test.mjs')), [],
		'a parsed capture that reaches no assertion operand or message is not reported');
});

test('the shipped guard refuses an unsafe file with a fixed location line and prints no captured value', () => {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-diagnostic-guard-'));
	try {
		// The planted original arrives at runtime through the environment, so neither the fixture nor
		// the finding line contains it: what the guard prints can only be its own fixed format.
		const unsafePath = join(dir, 'unsafe.test.mjs');
		writeFileSync(unsafePath, [
			"import assert from 'node:assert/strict';",
			"assert.equal(captured.stdout, process.env.HYLJA_SYNTHETIC_PLANTED, 'a fixed message');",
			'',
		].join('\n'));
		const unsafe = spawnSync(process.execPath, [guardPath, unsafePath],
			{ cwd: root, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS, env: { ...process.env, HYLJA_SYNTHETIC_PLANTED: PLANTED } });
		assert.equal(unsafe.error, undefined, 'the guard finished inside its bound');
		assert.equal(unsafe.status, 1, 'a raw diagnostic assertion is refused');
		assert.equal(unsafe.stdout, `${unsafePath}:2:14 equal operand 0\nchecked 1 file, 1 finding\n`,
			'one fixed location line and one fixed summary line, no source text');
		assert.equal(`${unsafe.stdout}${unsafe.stderr}`.includes(PLANTED), false, 'the planted original never reaches the log');
		assert.equal(unsafe.stderr, '', 'the refusal is one stdout line, never a traceback');

		const cleanPath = join(dir, 'clean.test.mjs');
		writeFileSync(cleanPath, [
			"import assert from 'node:assert/strict';",
			"assert.equal(captured.stderr === '', true, 'one stdout record, never a traceback');",
			'',
		].join('\n'));
		const clean = spawnSync(process.execPath, [guardPath, cleanPath], { cwd: root, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });
		assert.equal(clean.status, 0, 'a boolean comparison with a fixed message is accepted');
		assert.equal(clean.stdout, 'checked 1 file, 0 findings\n', 'one fixed summary line');
		assert.equal(clean.stderr, '', 'an accepted file prints no warning');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the guard refuses its own bounds instead of passing a file it did not read', () => {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-diagnostic-guard-bounds-'));
	try {
		const cleanPath = join(dir, 'clean.test.mjs');
		writeFileSync(cleanPath, "import assert from 'node:assert/strict';\nconst noise = captured.stderr;\n");
		const tooMany = spawnSync(process.execPath,
			[guardPath, ...Array.from({ length: MAX_FILES + 1 }, () => cleanPath)],
			{ cwd: root, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });
		assert.equal(tooMany.status, 2, 'more paths than the file bound is a refusal');
		assert.equal(tooMany.stderr, `diagnostic assertion guard: refused (more than ${MAX_FILES} paths)\n`);
		assert.equal(tooMany.stdout, '', 'a refused run reports no findings it did not read');

		const oversizedPath = join(dir, 'oversized.test.mjs');
		writeFileSync(oversizedPath, `// ${'x'.repeat(MAX_FILE_BYTES)}\n`);
		const oversized = spawnSync(process.execPath, [guardPath, oversizedPath],
			{ cwd: root, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });
		assert.equal(oversized.status, 2, 'a file past the byte window is a refusal');
		assert.equal(oversized.stderr, 'diagnostic assertion guard: refused (a file past the byte window)\n');
		assert.equal(oversized.stdout, '', 'an unread file is never a clean pass');

		// The hop bound used to return "no capture" at the cut-off, so six hops from a capture produced
		// "checked 1 file, 0 findings" and exit 0 - the guard's most misleading possible output.
		const deepPath = join(dir, 'deep.test.mjs');
		writeFileSync(deepPath, [
			"import assert from 'node:assert/strict';",
			'function capture(run) { return run; }',
			'const h0 = capture({ stdout: \'x\' }).stdout;',
			...Array.from({ length: MAX_ALIAS_HOPS }, (_, index) => `const h${index + 1} = h${index};`),
			`assert.equal(h${MAX_ALIAS_HOPS}, 'x', 'past the hop bound');`,
			'',
		].join('\n'));
		const deep = spawnSync(process.execPath, [guardPath, deepPath],
			{ cwd: root, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });
		assert.equal(deep.status, 2, 'a chain past the hop bound is a refusal, never a clean pass');
		assert.equal(deep.stdout, '', 'a truncated chain is not reported as clean');

		// The printed-findings bound truncates output but must still state the true count.
		const manyPath = join(dir, 'many.test.mjs');
		writeFileSync(manyPath, [
			"import assert from 'node:assert/strict';",
			...Array.from({ length: MAX_PRINTED_FINDINGS + 5 }, (_, index) =>
				`assert.equal(run${index}.stdout, '', 'finding ${index}');`),
			'',
		].join('\n'));
		const many = spawnSync(process.execPath, [guardPath, manyPath],
			{ cwd: root, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });
		assert.equal(many.status, 1, 'findings past the print bound still fail the run');
		const printed = many.stdout.split('\n').filter((line) => line.includes('equal operand')).length;
		assert.equal(printed, MAX_PRINTED_FINDINGS, 'only the printed bound is printed');
		assert.ok(many.stdout.includes(`${MAX_PRINTED_FINDINGS + 5} findings`),
			'the summary line states the true count, not the printed count');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('a real failing subprocess assertion keeps its fixed diagnostic, and the unsafe shape is the control', () => {
	const dir = mkdtempSync(join(tmpdir(), 'hylja-diagnostic-child-'));
	try {
		// One synthetic child, one real subprocess, two assertion shapes that assert the same fact about
		// the same capture and differ in one place: the compared operand. Both fail on a child that
		// writes the planted original, both carry the same fixed message, and the only difference in
		// what reaches the log is the shape. The capture is decoded to text on purpose: an undecoded
		// Buffer is printed as hex bytes, which would leave the negative control unproven.
		const childSource = (assertion) => [
			"import assert from 'node:assert/strict';",
			"import { spawnSync } from 'node:child_process';",
			'',
			`const planted = '${PLANTED}';`,
			"const captured = spawnSync(process.execPath, ['-e', 'process.stdout.write(process.argv[1])', planted],"
				+ " { encoding: 'utf8' });",
			assertion,
			'',
		].join('\n');
		const safeChild = join(dir, 'safe-child.mjs');
		const unsafeChild = join(dir, 'unsafe-child.mjs');
		writeFileSync(safeChild, childSource(SAFE_ASSERTION));
		writeFileSync(unsafeChild, childSource(UNSAFE_ASSERTION));
		// The same two sources the guard rules on are the two sources that then really run.
		assert.deepEqual(shape(findRisksInSource(readFileSync(safeChild, 'utf8'), safeChild)), [],
			'the boolean shape is one the guard accepts');
		assert.deepEqual(shape(findRisksInSource(readFileSync(unsafeChild, 'utf8'), unsafeChild)).map((risk) => risk.position),
			['operand'], 'the raw operand shape is the one the guard refuses');

		const run = (path) => {
			const result = spawnSync(process.execPath, [path], { cwd: dir, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS });
			assert.equal(result.error, undefined, 'the synthetic child finished inside its bound');
			return result;
		};
		const safe = run(safeChild);
		const safeOutput = `${safe.stdout}\n${safe.stderr}`;
		assert.notEqual(safe.status, 0, 'the boolean shape really failed, so this is a real diagnostic');
		assert.equal(safeOutput.includes(SAFE_MESSAGE), true, 'the fixed message is what the reader gets');
		assert.equal(safeOutput.includes(PLANTED), false, 'the captured original never reaches the log');
		assert.equal(safeOutput.includes(EXPECTED), false, 'no compared literal stands in for the captured output either');

		// The negative control: without it, the check above could only prove that Node kept quiet.
		const unsafe = run(unsafeChild);
		const unsafeOutput = `${unsafe.stdout}\n${unsafe.stderr}`;
		assert.notEqual(unsafe.status, 0, 'the raw operand shape really failed too');
		assert.equal(unsafeOutput.includes(SAFE_MESSAGE), true, 'the same fixed message is printed');
		assert.equal(unsafeOutput.includes(PLANTED), true,
			'Node prints the actual value, so a fixed message alone never hid the captured output');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the guarded native-lane test carries no captured output in an assertion diagnostic', () => {
	assert.deepEqual(GUARDED_TEST_FILES, ['test/hylja-native-lane.test.mjs'],
		'the guard covers exactly the named files, and extending it is an explicit edit');
	for (const file of GUARDED_TEST_FILES) {
		const source = readFileSync(join(root, file), 'utf8');
		const risks = shape(findRisksInSource(source, file));
		assert.deepEqual(risks, [], `${file} keeps captured subprocess output out of assertion diagnostics`);
	}
});
