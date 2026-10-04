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

import { evaluateBashToolInput } from '../lib/hylja-command-guard.mjs';

export default function hyljaWorkflowGuard(pi) {
	pi.on('tool_call', (event) => {
		if (event.toolName !== 'bash') return undefined;
		const decision = evaluateBashToolInput(event.input);
		if (!decision.allowed) return { block: true, reason: decision.reason };
		event.input.timeout = decision.timeout;
		return undefined;
	});
}
