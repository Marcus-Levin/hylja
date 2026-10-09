/**
 * Hylja development workflow guard: the Pi adapter.
 *
 * Command decisions live in the pure helper `.pi/lib/hylja-command-guard.mjs`. This adapter applies
 * its result and optionally records runtime qualification metadata. Receipt actions run only in bound
 * callbacks; unavailable receipts refuse bash with a fixed reason, never a swallowed hook exception.
 * Developer tooling, not runtime core, not a policy or authorization point, not a shell sandbox.
 *
 * Wiring: project extension discovery loads this file for the coordinator session
 * (`<cwd>/.pi/extensions/`), and both native foreground role profiles list it explicitly under
 * `extensions:`, because an allowlist disables ambient extensions in a child.
 */

import { commandFitsWindow, evaluateBashToolInput, snapshotCommandWindow, snapshotValidationApproval } from '../lib/hylja-command-guard.mjs';

// Existing discovery/profile entry point adds no arbitrary command cap.
export default function hyljaWorkflowGuard(pi) {
	installHyljaWorkflowGuard(pi);
}

export const GUARD_RECEIPT_REFUSAL = 'Hylja workflow guard refused this call: runtime qualification receipt is unavailable.';
export const GUARD_WINDOW_REFUSAL = 'Hylja workflow guard refused this call: the declared command window or finish reserve is exhausted.';

/** Explicit run-owned entry point. The caller owns approval authority, clock bounds and command safety. */
export function installHyljaWorkflowGuard(pi, approval = undefined, recordReceipts = false, window = undefined) {
	const validationApproval = snapshotValidationApproval(approval);
	const commandWindow = snapshotCommandWindow(window);
	const recording = recordReceipts === true;
	let windowClosed = false;
	let lastObservedAt = commandWindow === undefined ? 0 : Date.now();
	let receiptState = recording ? 'pending' : 'off';
	if (recording) pi.on('session_start', () => {
		if (receiptState === 'failed') return;
		try {
			pi.appendEntry('hylja-workflow-guard-ready', { version: 1 });
			receiptState = 'ready';
		} catch {
			receiptState = 'failed';
		}
	});
	pi.on('tool_call', (event, ctx) => {
		if (event.toolName !== 'bash') return undefined;
		if (recording && receiptState !== 'ready') return { block: true, reason: GUARD_RECEIPT_REFUSAL };
		// A foreground child is a session inside the parent process, so the worktree it searches lives in
		// the session directory, not in process.cwd(). An absent context falls back to the process
		// directory inside the helper.
		const decision = evaluateBashToolInput(event.input, { cwd: ctx?.cwd, validationApproval });
		if (!decision.allowed) return { block: true, reason: decision.reason };
		if (commandWindow !== undefined) {
			const now = Date.now();
			if (windowClosed || !Number.isSafeInteger(lastObservedAt) || lastObservedAt < 0 || now < lastObservedAt ||
				!commandFitsWindow(commandWindow, now, decision.timeout)) {
				windowClosed = true;
				return { block: true, reason: GUARD_WINDOW_REFUSAL };
			}
			lastObservedAt = now;
		}
		// Installed Pi accepts an optional number, not null; omission means no backend timer.
		if (decision.timeout === undefined) delete event.input.timeout;
		else event.input.timeout = decision.timeout;
		if (recording) try {
			pi.appendEntry('hylja-workflow-guard-timeout', {
				version: 1, effectiveSeconds: decision.timeout ?? null, validationApproved: decision.validationApproved,
			});
		} catch {
			receiptState = 'failed';
			return { block: true, reason: GUARD_RECEIPT_REFUSAL };
		}
		return undefined;
	});
}
