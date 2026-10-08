// Developer workflow tests: synthetic VM and fake delegation, no provider or network.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../.pi/workflows/hylja-timed-review.js', import.meta.url), 'utf8');
const preparedAt = Date.parse('2026-10-08T13:02:26Z');
const deliveredAt = Date.parse('2026-10-08T14:10:02Z');

function execution(args, initialNow = preparedAt) {
	let now = initialNow;
	const calls = [];
	class SyntheticDate extends Date { static now() { return now; } }
	const context = vm.createContext({ args, Date: SyntheticDate,
		runs: { run(key, options) { calls.push({ key, options }); return Promise.resolve({ output: 'SYNTHETIC-REVIEW', ok: true }); } },
	}, { codeGeneration: { strings: false, wasm: false } });
	const script = new vm.Script(`(async () => {\n${source}\n})()`);
	return { calls, deliver(at) { now = at; return script.runInContext(context); } };
}

const reviewArgs = { mode: 'review', task: 'Review synthetic exact head.',
	model: 'synthetic-provider/synthetic-model:high', output: '/tmp/synthetic-review.invalid' };

test('delayed delivery derives its review stop inside execution, not during preparation', async () => {
	const run = execution(reviewArgs);
	await run.deliver(deliveredAt);
	assert.equal(run.calls.length, 1);
	const options = run.calls[0].options;
	assert.equal(options.timeoutMs, 900000);
	assert.equal(options.agent, 'hylja-reviewer');
	assert.ok(options.task.includes(new Date(deliveredAt + 720000).toISOString()));
	assert.equal(options.task.includes('2026-10-08T13:16:00.000Z'), false);
});

test('an imposed stale or insufficient task stop refuses before any delegation', async () => {
	for (const taskStopMs of [preparedAt + 720000, deliveredAt + 659999, NaN, Infinity, 'synthetic-planted.invalid']) {
		const run = execution({ ...reviewArgs, taskStopMs });
		const result = await run.deliver(deliveredAt);
		assert.equal(run.calls.length, 0);
		assert.equal(result.status, 'REFUSED');
	}
});

test('clock qualification is a zero-child execution and invalid time cannot dispatch', async () => {
	const run = execution({ mode: 'check' });
	const result = await run.deliver(deliveredAt);
	assert.equal(run.calls.length, 0);
	assert.equal(result.status, 'READY_NO_CHILD');
	assert.equal(result.observedAtMs, deliveredAt);
	assert.equal(result.hardStopMs, deliveredAt + 720000);
	for (const now of [NaN, Infinity, -1, Number.MAX_SAFE_INTEGER]) {
		const invalid = execution(reviewArgs);
		assert.equal((await invalid.deliver(now)).status, 'REFUSED');
		assert.equal(invalid.calls.length, 0);
	}
});
