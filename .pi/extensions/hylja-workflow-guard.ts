/**
 * Hylja development workflow guard: the Pi adapter.
 *
 * Thin on purpose. Every decision lives in the pure helper `.pi/lib/hylja-command-guard.mjs`, which
 * this repository tests directly; here it only reads a bash tool call, asks for a decision, and either
 * blocks the call with a fixed reason or writes the guaranteed timeout back into the mutable input.
 * Developer tooling, not runtime core, not a policy or authorization point, not a shell sandbox.
 *
 * Wiring: project extension discovery loads this file for the coordinator session
 * (`<cwd>/.pi/extensions/`), and both native foreground role profiles list it explicitly under
 * `extensions:`, because an allowlist disables ambient extensions in a child.
 */

import { evaluateBashToolInput, snapshotValidationApproval } from '../lib/hylja-command-guard.mjs';

// Existing discovery/profile entry point always installs the ordinary 300s guard.
export default function hyljaWorkflowGuard(pi) {
	installHyljaWorkflowGuard(pi);
}

/** Explicit run-owned entry point. The caller owns approval authority and command safety. */
export function installHyljaWorkflowGuard(pi, approval = undefined) {
	const validationApproval = snapshotValidationApproval(approval);
	pi.on('tool_call', (event, ctx) => {
		if (event.toolName !== 'bash') return undefined;
		// A foreground child is a session inside the parent process, so the worktree it searches lives in
		// the session directory, not in process.cwd(). An absent context falls back to the process
		// directory inside the helper.
		const decision = evaluateBashToolInput(event.input, { cwd: ctx?.cwd, validationApproval });
		if (!decision.allowed) return { block: true, reason: decision.reason };
		event.input.timeout = decision.timeout;
		return undefined;
	});
}
