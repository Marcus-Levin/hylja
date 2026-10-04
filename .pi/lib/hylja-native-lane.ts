/**
 * Hylja native foreground lane controller: the Pi adapter for the opt-in controller.
 *
 * Developer tooling, not runtime core, not a security boundary, not a shell sandbox. It handles one
 * fixed input (`hylja-native-lane`) so root can run one foreground `pi-subagents` leaf through the
 * documented structured delegation API without a coordinator-model turn. Any other input is left
 * untouched, and the CLI sends nothing else.
 *
 * Every decision that matters lives in `createLaneController` below, which this file tests directly
 * with a fake event API. What this adapter reads is the root-owned lane config at the exact operator
 * path in `HYLJA_NATIVE_LANE_CONFIG`; it never discovers a Pi binary, an extension or a role profile.
 *
 * Bounded by construction: the only fields this file ever writes are the identity tuple, status, model,
 * elapsed milliseconds, tool count and the leaf's own literal public result. `recentOutput`,
 * `currentToolArgs`, `recentTools`, the raw session transcript and provider reasoning are never read.
 */

import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

/** The one input this controller answers. Root sends exactly this, once. */
export const FIXED_LANE_INPUT = 'hylja-native-lane';

/** Root-supplied lane config path. Exact operator path, never searched for. */
export const LANE_CONFIG_ENV = 'HYLJA_NATIVE_LANE_CONFIG';

/** Root-supplied exact path of the installed `pi-subagents/delegation` module. */
export const LANE_SUBAGENTS_ENV = 'HYLJA_NATIVE_LANE_SUBAGENTS';

export const LANE_ROLES = ['hylja-implementer', 'hylja-reviewer'];

/** The only verdict tokens this file will read out of a leaf result. Anything else is INCOMPLETE. */
export const LANE_VERDICTS = ['APPROVED', 'CHANGES REQUESTED', 'INCOMPLETE'];

const MAX_TASK_CHARS = 1_048_576;

/** Fixed, non-echoing setup failures. A planted config value is never returned to the caller. */
export const SETUP_FAILURES = {
	config: 'SETUP_FAILED_LANE_CONFIG',
	dispatch: 'SETUP_FAILED_DISPATCH',
} as const;

/** Reads and validates the subset of the root-owned lane config this controller owns. */
export function readLaneConfig(path) {
	const raw = JSON.parse(readFileSync(path, 'utf8'));
	const required = ['key', 'agent', 'task', 'cwd', 'timeoutMs', 'receipt', 'dispatch', 'progress'];
	for (const field of required) {
		if (typeof raw[field] !== 'string' && typeof raw[field] !== 'number') throw new Error(SETUP_FAILURES.config);
	}
	if (!LANE_ROLES.includes(raw.agent)) throw new Error(SETUP_FAILURES.config);
	if (typeof raw.key !== 'string' || raw.key.length === 0 || raw.key.length > 128) throw new Error(SETUP_FAILURES.config);
	if (typeof raw.task !== 'string' || raw.task.length === 0 || raw.task.length > MAX_TASK_CHARS) {
		throw new Error(SETUP_FAILURES.config);
	}
	if (!Number.isInteger(raw.timeoutMs) || raw.timeoutMs <= 0) throw new Error(SETUP_FAILURES.config);
	for (const field of ['cwd', 'receipt', 'dispatch', 'progress']) {
		if (raw[field].length === 0 || !raw[field].startsWith('/')) throw new Error(SETUP_FAILURES.config);
	}
	return {
		key: raw.key,
		agent: raw.agent,
		task: raw.task,
		cwd: raw.cwd,
		timeoutMs: raw.timeoutMs,
		receipt: raw.receipt,
		dispatch: raw.dispatch,
		progress: raw.progress,
	};
}

/** The bounded dispatch tuple persisted for root. Cancellation affects only an exact tuple. */
function writeDispatch(path, tuple) {
	writeFileSync(path, `${JSON.stringify(tuple, null, 2)}\n`, { mode: 0o600 });
}

function boundedProgress(config, event, fields) {
	appendFileSync(config.progress, `${JSON.stringify({ event, key: config.key, ...fields })}\n`, { mode: 0o600 });
}

/** The leaf's literal first line, only when it is exactly one of the three declared verdicts. */
export function readExplicitVerdict(text) {
	const first = typeof text === 'string' ? text.split('\n', 1)[0]?.trim() : undefined;
	return first !== undefined && LANE_VERDICTS.includes(first) ? first : 'INCOMPLETE';
}

/**
 * The controller body. `pi` is the host event API, `delegation` is the `pi-subagents/delegation`
 * module. Returns a handle whose `cancel()` emits a cancel for this controller's own tuple only.
 */
export function createLaneController(pi, config, delegation) {
	const request = {
		requestId: randomUUID(),
		ownerRunId: randomUUID(),
		nodeId: config.key,
		agent: config.agent,
		task: config.task,
		context: 'fresh',
		cwd: config.cwd,
		timeoutMs: config.timeoutMs,
		result: { kind: 'text' },
	};
	const own = (value) => value?.requestId === request.requestId
		&& value?.ownerRunId === request.ownerRunId
		&& value?.nodeId === request.nodeId;
	const startedAt = Date.now();
	let settled = false;
	let cancelRequest = null;

	const offStarted = pi.events.on(delegation.SUBAGENT_DELEGATION_STARTED_EVENT, (value) => {
		if (own(value)) boundedProgress(config, 'started', { model: value.model });
	});
	const offUpdate = pi.events.on(delegation.SUBAGENT_DELEGATION_UPDATE_EVENT, (value) => {
		// A bounded snapshot, replaced rather than merged. No tool name, arguments or recent output.
		if (!own(value)) return;
		boundedProgress(config, 'progress', {
			model: value.model, toolCount: value.toolCount, elapsedMs: value.durationMs ?? Date.now() - startedAt,
		});
	});
	const offCancel = pi.events.on(delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, (value) => {
		if (own(value)) boundedProgress(config, 'cancel_observed', {});
	});
	const terminal = new Promise((resolve) => {
		const off = pi.events.on(delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, (value) => {
			if (!own(value)) return;
			off();
			resolve(value);
		});
		boundedProgress(config, 'dispatch', { agent: request.agent, timeoutMs: request.timeoutMs });
		pi.events.emit(delegation.SUBAGENT_DELEGATION_REQUEST_EVENT, request);
	});

	return {
		request,
		tuple: { requestId: request.requestId, ownerRunId: request.ownerRunId, nodeId: request.nodeId },
		/** Cancels only this controller's own in-flight attempt; a foreign tuple is never cancelled. */
		cancel() {
			if (settled || cancelRequest !== null) return false;
			cancelRequest = { requestId: request.requestId, ownerRunId: request.ownerRunId, nodeId: request.nodeId };
			pi.events.emit(delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, cancelRequest);
			return true;
		},
		async settle() {
			const value = await terminal;
			settled = true;
			offStarted();
			offUpdate();
			offCancel();
			return value;
		},
	};
}

/** Writes the public terminal receipt: literal public result plus authoritative usage and identity. */
export function writeTerminalReceipt(config, value) {
	const text = value?.result?.kind === 'text' ? value.result.text : null;
	const receipt = {
		requestId: value?.requestId,
		ownerRunId: value?.ownerRunId,
		nodeId: value?.nodeId,
		status: value?.status ?? 'unavailable',
		runId: value?.runId,
		agent: value?.agent ?? config.agent,
		model: value?.model,
		thinking: value?.thinking,
		exitCode: value?.exitCode,
		launchContractDigest: value?.launchContractDigest,
		usage: value?.usage,
		// Completed means completed: a completed leaf is never approval, so the verdict is only the
		// leaf's own literal verdict line, and INCOMPLETE when it declares none.
		verdict: text === null ? 'INCOMPLETE' : readExplicitVerdict(text),
		result: text === null ? null : { kind: 'text', text },
	};
	writeFileSync(config.receipt, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
	return receipt;
}

/**
 * The Pi entry point. Opt-in by an exact config path, so project extension discovery never loads it
 * for an ordinary session; the CLI passes `-e <controller>` deliberately.
 */
export default function hyljaNativeLane(pi) {
	let started = false;
	pi.on('input', async (event) => {
		if (event?.text !== FIXED_LANE_INPUT) return { action: 'continue' };
		if (started) return { action: 'handled' };
		started = true;
		let config;
		try {
			config = readLaneConfig(process.env[LANE_CONFIG_ENV]);
		} catch {
			return { action: 'handled' }; // A setup failure, not a fallback: no dispatch, no leaf.
		}
		const module = await import(process.env[LANE_SUBAGENTS_ENV]);
		const controller = createLaneController(pi, config, module);
		try {
			writeDispatch(config.dispatch, {
				requestId: controller.request.requestId,
				ownerRunId: controller.request.ownerRunId,
				nodeId: controller.request.nodeId,
				agent: controller.request.agent,
				timeoutMs: controller.request.timeoutMs,
				pid: process.pid,
			});
		} catch {
			return { action: 'handled' };
		}
		const value = await controller.settle();
		writeTerminalReceipt(config, value);
		return { action: 'handled' };
	});
}
