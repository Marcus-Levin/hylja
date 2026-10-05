#!/usr/bin/env node
/**
 * Hylja raw diagnostic assertion guard.
 *
 *   node scripts/development/check-diagnostic-assertions.mjs [file ...]
 *
 * When an `assert` call fails, Node prints the compared actual and expected values itself, so a fixed
 * assert message does not stop captured subprocess stdout/stderr from reaching a test log. This guard
 * refuses the assertion shapes whose printed value can carry those bytes, so the shape has to change
 * before a failure prints the capture rather than after.
 *
 * It refuses an operand or a message that can hold captured output:
 * - a captured stream read, `run.stdout` or `run.stderr`, directly or through optional chaining or an
 *   element access with that literal property name, and one element of a capture-derived container,
 *   such as `lines[0]` where `lines` is `run.stdout.split('\n')`;
 * - a simple local alias of one: a `const`/`let`/`var` binding whose initializer is such a read, and a
 *   destructured `{ stdout }`/`{ stderr: text }` binding, followed through chains of those bindings;
 * - a string built from one by a template literal, a `+` concatenation or a call that is not a
 *   comparison, including `JSON.parse(captured.stdout)`.
 *
 * It accepts the boolean and numeric comparisons that assert the same fact without printing the value:
 * `assert.equal(run.stderr === '', true, message)`, `assert.ok(!run.stderr, message)`,
 * `assert.equal(run.stdout.includes(planted), false, message)` and `assert.equal(lines.length, 2, ...)`.
 *
 * Developer tooling, not runtime core, not a confidentiality guarantee and not an enforcement boundary:
 * it is a bounded syntactic guard over the assertion call shapes listed above, and it authenticates
 * nothing and sends no bytes. It is not taint analysis: a value that reaches an assertion through
 * another function, a mutation, a renamed binding, an exception's message, a file read or a
 * non-assertion API is outside it, and a reported finding is a shape to migrate rather than a
 * confirmed leak.
 *
 * Bounds: the guarded file list is named and explicit rather than a repository sweep, 32 paths, 2 MiB
 * per file, six alias hops, and 50 printed findings with the true count in the summary line. Exceeding
 * a bound is a fixed refusal, never a silent pass. Findings print only a location, the assert method,
 * the position class and the argument index: no source text, no value and no exception text.
 *
 * Exit codes: 0 no finding, 1 at least one finding, 2 a usage, bound or read refusal.
 */

import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

/**
 * The files this guard covers. Extending it is an explicit edit here and in the case that reads the
 * list, so the guarded surface is reviewable rather than whatever a glob happened to match.
 */
export const GUARDED_TEST_FILES = ['test/hylja-native-lane.test.mjs'];

/** Bounds. A refusal is a fixed message; nothing read, planted or thrown is echoed. */
export const MAX_FILES = 32;
export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_ALIAS_HOPS = 6;
export const MAX_PRINTED_FINDINGS = 50;

/** The captured streams: a read of either is the value this guard exists to keep out of a diagnostic. */
const STREAM_PROPERTIES = new Set(['stdout', 'stderr']);
/** Comparisons whose result is a boolean: the captured bytes are judged, never printed. */
const COMPARISON_OPERATORS = new Set([
	ts.SyntaxKind.EqualsEqualsToken,
	ts.SyntaxKind.ExclamationEqualsToken,
	ts.SyntaxKind.EqualsEqualsEqualsToken,
	ts.SyntaxKind.ExclamationEqualsEqualsToken,
	ts.SyntaxKind.LessThanToken,
	ts.SyntaxKind.GreaterThanToken,
	ts.SyntaxKind.LessThanEqualsToken,
	ts.SyntaxKind.GreaterThanEqualsToken,
]);
/** Calls whose result is a boolean or an index, so the compared value is never the captured text. */
const NON_ECHOING_METHODS = new Set([
	'includes', 'startsWith', 'endsWith', 'hasOwnProperty', 'isArray', 'some', 'every',
	'test', 'search', 'indexOf', 'charCodeAt', 'codePointAt',
]);
/** Properties whose result is a number, so the compared value is never the captured text. */
const NON_ECHOING_PROPERTIES = new Set(['length']);

/** Assert methods, the argument indices Node compares, and the argument index it prints as the message. */
const OPERAND_ARGUMENTS = {
	equal: [0, 1],
	notEqual: [0, 1],
	strictEqual: [0, 1],
	notStrictEqual: [0, 1],
	deepEqual: [0, 1],
	notDeepEqual: [0, 1],
	deepStrictEqual: [0, 1],
	notDeepStrictEqual: [0, 1],
	match: [0],
	doesNotMatch: [0],
	ok: [0],
};
const MESSAGE_ARGUMENTS = {
	equal: 2,
	notEqual: 2,
	strictEqual: 2,
	notStrictEqual: 2,
	deepEqual: 2,
	notDeepEqual: 2,
	deepStrictEqual: 2,
	notDeepStrictEqual: 2,
	match: 2,
	doesNotMatch: 2,
	ok: 1,
	fail: 0,
};
const ASSERT_METHODS = new Set([...Object.keys(OPERAND_ARGUMENTS), ...Object.keys(MESSAGE_ARGUMENTS)]);
const ASSERT_MODULES = new Set(['node:assert', 'node:assert/strict']);

/** The local names an assertion can be reached through: the assert object and any named import. */
function assertBindings(sourceFile) {
	const objects = new Set();
	const functions = new Map();
	for (const statement of sourceFile.statements) {
		if (!ts.isImportDeclaration(statement)) continue;
		if (!ts.isStringLiteral(statement.moduleSpecifier)) continue;
		if (!ASSERT_MODULES.has(statement.moduleSpecifier.text)) continue;
		const clause = statement.importClause;
		if (clause === undefined) continue;
		if (clause.name !== undefined) objects.add(clause.name.text);
		const named = clause.namedBindings;
		if (named === undefined || !ts.isNamedImports(named)) continue;
		for (const element of named.elements) {
			const imported = element.propertyName?.text ?? element.name.text;
			if (ASSERT_METHODS.has(imported)) functions.set(element.name.text, imported);
		}
	}
	return { objects, functions };
}

/** The assert method a call reaches, or null when it is not an assertion this guard reads. */
function assertionMethod(node, bindings) {
	if (!ts.isCallExpression(node)) return null;
	const callee = node.expression;
	if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)
		&& bindings.objects.has(callee.expression.text) && ASSERT_METHODS.has(callee.name.text)) {
		return callee.name.text;
	}
	if (ts.isIdentifier(callee)) return bindings.functions.get(callee.text) ?? null;
	return null;
}

/**
 * Every local binding this guard follows: a named binding whose initializer is an expression, and a
 * destructured `stdout`/`stderr` property binding that is the capture itself. One flat map per file,
 * later declaration wins, which is the bounded approximation this guard states about itself.
 */
function collectBindings(sourceFile) {
	const bindings = new Map();
	const bind = (name, initializer) => {
		if (ts.isIdentifier(name)) {
			bindings.set(name.text, { stream: null, expression: initializer });
			return;
		}
		if (!ts.isObjectBindingPattern(name)) return;
		for (const element of name.elements) {
			const property = element.propertyName ?? element.name;
			if (!ts.isIdentifier(property) || !STREAM_PROPERTIES.has(property.text)) continue;
			if (element.initializer !== undefined) continue;
			bind(element.name, null);
			bindings.set(element.name.text, { stream: property.text, expression: null });
		}
	};
	const visit = (node) => {
		if (ts.isVariableDeclaration(node) && node.initializer !== undefined) bind(node.name, node.initializer);
		ts.forEachChild(node, visit);
	};
	visit(sourceFile);
	return bindings;
}

/** Whether an identifier's binding carries captured output, followed through a bounded chain of hops. */
function bindingCarries(name, bindings, visited, hops) {
	if (hops >= MAX_ALIAS_HOPS) return false;
	const binding = bindings.get(name);
	if (binding === undefined || visited.has(name)) return false;
	if (binding.stream !== null) return true;
	visited.add(name);
	try {
		return carriesCapturedOutput(binding.expression, bindings, visited, hops + 1);
	} finally {
		visited.delete(name);
	}
}

/** The property name a read selects, for `run.stdout`, `run['stderr']` and the optional forms. */
function selectedProperty(node) {
	if (ts.isPropertyAccessExpression(node)) return node.name.text;
	if (ts.isElementAccessExpression(node) && node.argumentExpression !== undefined
		&& ts.isStringLiteralLike(node.argumentExpression)) return node.argumentExpression.text;
	return null;
}

/**
 * Whether the value of an expression can hold captured stdout/stderr. It reports the shapes listed in the
 * header and reports nothing for a shape it does not model, so it under-reports outside those shapes: an
 * unrecognised expression is unproven rather than safe, and the header states that as a limit.
 */
function carriesCapturedOutput(node, bindings, visited = new Set(), hops = 0) {
	if (node === undefined || node === null) return false;
	if (ts.isIdentifier(node)) return bindingCarries(node.text, bindings, visited, hops);
	// A read of a captured stream is the capture, whatever it is nested in.
	const property = selectedProperty(node);
	if (property !== null) {
		if (STREAM_PROPERTIES.has(property)) return true;
		if (NON_ECHOING_PROPERTIES.has(property)) return false;
		return carriesCapturedOutput(node.expression, bindings, visited, hops);
	}
	// One element of a capture-derived container carries as much as the container: `lines[0]` is bytes.
	if (ts.isElementAccessExpression(node)) {
		return carriesCapturedOutput(node.expression, bindings, visited, hops)
			|| carriesCapturedOutput(node.argumentExpression, bindings, visited, hops);
	}
	if (ts.isBinaryExpression(node)) {
		if (COMPARISON_OPERATORS.has(node.operatorToken.kind)) return false;
		return carriesCapturedOutput(node.left, bindings, visited, hops)
			|| carriesCapturedOutput(node.right, bindings, visited, hops);
	}
	if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
		if (node.operator === ts.SyntaxKind.ExclamationToken || node.operator === ts.SyntaxKind.TypeOfKeyword) return false;
		return carriesCapturedOutput(node.operand, bindings, visited, hops);
	}
	if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
		// A boolean-returning or index-returning method judges the capture; Node prints true/false.
		if (ts.isPropertyAccessExpression(node.expression)
			&& NON_ECHOING_METHODS.has(node.expression.name.text)) return false;
		return carriesCapturedOutput(node.expression, bindings, visited, hops)
			|| (node.arguments ?? []).some((argument) => carriesCapturedOutput(argument, bindings, visited, hops));
	}
	if (ts.isTemplateExpression(node)) {
		return node.templateSpans.some((span) => carriesCapturedOutput(span.expression, bindings, visited, hops));
	}
	if (ts.isTaggedTemplateExpression(node)) {
		return carriesCapturedOutput(node.tag, bindings, visited, hops)
			|| node.template.templateSpans.some((span) => carriesCapturedOutput(span.expression, bindings, visited, hops));
	}
	if (ts.isConditionalExpression(node)) {
		// The test is consumed as a boolean; only a chosen branch can carry bytes into the value.
		return carriesCapturedOutput(node.whenTrue, bindings, visited, hops)
			|| carriesCapturedOutput(node.whenFalse, bindings, visited, hops);
	}
	if (ts.isArrayLiteralExpression(node)) {
		return node.elements.some((element) => carriesCapturedOutput(element, bindings, visited, hops));
	}
	if (ts.isObjectLiteralExpression(node)) {
		return node.properties.some((property) => carriesCapturedOutput(property, bindings, visited, hops));
	}
	if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)
		|| ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node) || ts.isAwaitExpression(node)
		|| ts.isSpreadElement(node) || ts.isOptionalChain(node)) {
		return carriesCapturedOutput(node.expression, bindings, visited, hops);
	}
	// A literal carries nothing. Any other node is an expression shape this guard does not model: a
	// capture can only reach an assertion through a shape it recognizes, so an unrecognized node is a
	// value the guard has not been shown to be safe, and the caller above reports nothing for it.
	return false;
}

/**
 * The findings in one source, in source order. A finding is a location, the assert method, the
 * position class and the argument index: never the source text and never a value.
 */
export function findRisksInSource(sourceText, fileName = 'source') {
	const sourceFile = ts.createSourceFile(fileName, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
	const bindings = collectBindings(sourceFile);
	const assertNames = assertBindings(sourceFile);
	const risks = [];
	const record = (node, argument, method, position) => {
		const { line: startLine, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
		risks.push({ line: startLine + 1, column: character + 1, method, position, argument });
	};
	const visit = (node) => {
		const method = assertionMethod(node, assertNames);
		if (method !== null) {
			for (const index of OPERAND_ARGUMENTS[method] ?? []) {
				const operand = node.arguments[index];
				if (operand !== undefined && carriesCapturedOutput(operand, bindings)) record(operand, index, method, 'operand');
			}
			const messageIndex = MESSAGE_ARGUMENTS[method];
			const message = node.arguments[messageIndex];
			if (message !== undefined && carriesCapturedOutput(message, bindings)) record(message, messageIndex, method, 'message');
		}
		ts.forEachChild(node, visit);
	};
	visit(sourceFile);
	return risks;
}

/** One refused read: a fixed reason, no path and no exception text. */
class GuardRefusal extends Error {}

const refuse = (reason) => {
	throw new GuardRefusal(reason);
};

const readSource = (path) => {
	let stats;
	try {
		stats = statSync(path);
	} catch {
		refuse('a file that could not be inspected');
	}
	if (!stats.isFile()) refuse('a path that is not a regular file');
	if (stats.size > MAX_FILE_BYTES) refuse('a file past the byte window');
	try {
		return readFileSync(path, 'utf8');
	} catch {
		refuse('a file that could not be read');
	}
};

/** A path inside the working directory is reported relative to it; one outside it is reported as given. */
const displayPath = (path, cwd) => {
	const relativePath = relative(cwd, path);
	return relativePath !== '' && !relativePath.startsWith('..') && !isAbsolute(relativePath)
		? relativePath : path;
};

/**
 * Check named paths, or the guarded list when none are named. Returns the fixed summary line, the
 * finding lines and the exit code, so a caller reads the outcome rather than re-deriving it.
 */
export function checkPaths(paths, cwd = process.cwd()) {
	if (paths.length > MAX_FILES) refuse(`more than ${MAX_FILES} paths`);
	const findings = [];
	for (const path of paths) {
		const shown = displayPath(resolve(cwd, path), cwd);
		for (const risk of findRisksInSource(readSource(resolve(cwd, path)), shown)) findings.push({ ...risk, file: shown });
	}
	const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
	const printed = findings.slice(0, MAX_PRINTED_FINDINGS);
	const lines = printed.map((finding) => `${finding.file}:${finding.line}:${finding.column} ${finding.method} ${finding.position} ${finding.argument}`);
	return {
		code: findings.length === 0 ? 0 : 1,
		findings,
		summary: `checked ${plural(paths.length, 'file')}, ${plural(findings.length, 'finding')}`,
		lines,
	};
}

/** The process entry: named paths, else the guarded list, with a fixed refusal on stderr. */
export function runGuard(argv = process.argv.slice(2), { cwd = process.cwd(), stdout, stderr } = {}) {
	const out = stdout ?? ((text) => process.stdout.write(text));
	const err = stderr ?? ((text) => process.stderr.write(text));
	const paths = argv.length > 0 ? argv : GUARDED_TEST_FILES;
	try {
		const result = checkPaths(paths, cwd);
		for (const line of result.lines) out(`${line}\n`);
		out(`${result.summary}\n`);
		return result.code;
	} catch (error) {
		err(`diagnostic assertion guard: refused (${error instanceof GuardRefusal ? error.message : 'a check that did not complete'})\n`);
		return 2;
	}
}

const invokedDirectly = process.argv[1] !== undefined
	&& resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) process.exitCode = runGuard();
