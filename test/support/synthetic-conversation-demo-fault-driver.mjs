#!/usr/bin/env node
/**
 * TEST-ONLY fault driver for the #250 synthetic conversation demo. NOT an operator entry point.
 *
 * It exists because the demo's blocked-reply case must be shown to FAIL when the real fixed worker does
 * not really run, or does not really answer truthfully, and neither failure can be produced by any
 * operator argument, environment variable or file - adding one would make an unsafe behaviour reachable
 * from the command line. So the fixture faults live here, in test-only code, and this driver runs the
 * very same case, the very same summary and the very same fixed refusal text as the operator command.
 *
 * Fixed modes, and nothing else. Every one of them arms a fault for the REPLY-side child (the second
 * real one) only, so the request-side child still really runs and really returns `ALLOW`:
 *
 * - `terminate-second-worker`: the real second fixed worker child is terminated immediately after it is
 *   spawned, so the accepted runner really observes a crash and the accepted receiver really collapses
 *   that crash into `SENTINEL_BLOCKED`. The first child is left alone, so the run still shows one real
 *   `ALLOW` and the fault is provably narrow.
 * - `corrupt-reply-unknown-reason`, `corrupt-reply-foreign-binding` and `corrupt-reply-too-many-rules`:
 *   that child's reply is replaced by a well-formed frame that differs from the truth in exactly one
 *   documented way - one reason code this sentinel cannot produce, a payload digest this parent never
 *   computed, or one ref over the protocol's own rule bound. The child, the runner and the receiver are
 *   untouched, so the run really exercises the runner's own refusal and the receiver's own collapse.
 * - `leak-planted-diagnostics`: the same terminated run, plus the planted original and the planted secret
 *   echoed to stderr the way a native-diagnostic echo would echo them. It prints nothing that any other
 *   run prints, and exists so the confidentiality evidence is non-vacuous: the demonstration suite can
 *   put real protected material through a real subprocess into a real assertion path and observe that
 *   the reported TAP output still carries none of it.
 *
 * Any other argument is refused with one fixed line before anything exists, with nothing echoed, and
 * exits 2. Every fault is armed in this process only; the operator command is untouched.
 */
import {
  REPLY_FAULTS, injectReplyFrameFault, injectWorkerTermination, installWorkerObservation,
} from '../../scripts/lib/synthetic-conversation-worker-observation.mjs';

/** The one fixed ordinal this fixture may fault: the reply-side child, never the request-side one. */
const REPLY_SIDE_WORKER = 2;
const MODES = Object.freeze({
  TERMINATE_SECOND_WORKER: 'terminate-second-worker',
  LEAK_PLANTED_DIAGNOSTICS: 'leak-planted-diagnostics',
  CORRUPT_REPLY_UNKNOWN_REASON: 'corrupt-reply-unknown-reason',
  CORRUPT_REPLY_FOREIGN_BINDING: 'corrupt-reply-foreign-binding',
  CORRUPT_REPLY_TOO_MANY_RULES: 'corrupt-reply-too-many-rules',
});
/** How each reply fault is armed: either a real termination, or a reply this fixture substitutes. */
const ARMED_AS = Object.freeze({
  [MODES.TERMINATE_SECOND_WORKER]: 'TERMINATE',
  [MODES.LEAK_PLANTED_DIAGNOSTICS]: 'TERMINATE',
  [MODES.CORRUPT_REPLY_UNKNOWN_REASON]: REPLY_FAULTS.UNKNOWN_REASON,
  [MODES.CORRUPT_REPLY_FOREIGN_BINDING]: REPLY_FAULTS.FOREIGN_BINDING,
  [MODES.CORRUPT_REPLY_TOO_MANY_RULES]: REPLY_FAULTS.TOO_MANY_RULES,
});
const KNOWN = new Set(Object.values(MODES));
const REFUSED = 'hylja synthetic conversation demo fault driver: argument refused\n'
  + 'expected: terminate-second-worker | leak-planted-diagnostics'
  + ' | corrupt-reply-unknown-reason | corrupt-reply-foreign-binding | corrupt-reply-too-many-rules\n';

installWorkerObservation();

const {
  DEMO_DECLINED, demoCaseHolds, runDemoCase, summarizeDemoCase, DEMO_CASES,
} = await import('../../scripts/lib/synthetic-conversation-demo-cases.mjs');
const { PLANTED_ORIGINAL, PLANTED_SECRET } = await import('../../scripts/lib/synthetic-conversation-fixture.mjs');

const mode = process.argv.length === 3 && KNOWN.has(process.argv[2]) ? process.argv[2] : null;
if (mode === null) {
  process.stderr.write(REFUSED);
  process.exitCode = 2;
} else {
  // Armed before the case runs: either the fixture asks the OS to stop the reply-side child, or it
  // substitutes one reply for it. Every other part of the run stays exactly the operator run.
  if (ARMED_AS[mode] === 'TERMINATE') injectWorkerTermination(REPLY_SIDE_WORKER);
  else injectReplyFrameFault(REPLY_SIDE_WORKER, ARMED_AS[mode]);
  const seen = await runDemoCase(DEMO_CASES.BLOCKED_REPLY);
  process.stdout.write(`${summarizeDemoCase(DEMO_CASES.BLOCKED_REPLY, seen).join('\n')}\n`);
  if (mode === MODES.LEAK_PLANTED_DIAGNOSTICS) {
    // The planted values below are this fixture's own synthetic literals, printed on purpose so the
    // suite can prove that a subprocess really carrying them changes nothing about what the reported
    // TAP output contains. They are invented and non-routable, and they are printed only here.
    process.stderr.write(`hylja synthetic conversation demo fault driver: worker diagnostic echo\n${PLANTED_ORIGINAL}\n${PLANTED_SECRET}\n`);
  }
  if (!demoCaseHolds(DEMO_CASES.BLOCKED_REPLY, seen)) {
    process.stderr.write(DEMO_DECLINED);
    process.exitCode = 1;
  }
}
