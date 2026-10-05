#!/usr/bin/env node
/**
 * TEST-ONLY fault driver for the #250 synthetic conversation demo. NOT an operator entry point.
 *
 * It exists because the demo's blocked-reply case must be shown to FAIL when the real fixed worker does
 * not really run, and that failure cannot be produced by any operator argument, environment variable or
 * file - adding one would make an unsafe behaviour reachable from the command line. So the fixture fault
 * lives here, in test-only code, and this driver runs the very same case, the very same summary and the
 * very same fixed refusal text as the operator command.
 *
 * Two fixed modes, and nothing else:
 *
 * - `terminate-second-worker`: the real second fixed worker child is terminated immediately after it is
 *   spawned, so the accepted runner really observes a crash and the accepted receiver really collapses
 *   that crash into `SENTINEL_BLOCKED` - exactly the outcome an operator run could otherwise have mistaken
 *   for a genuine block over the registered original. The first child is left alone, so the run still
 *   shows one real `ALLOW` and the fault is provably narrow.
 * - `leak-planted-diagnostics`: the same terminated run, plus the planted original and the planted secret
 *   echoed to stderr the way a native-diagnostic echo would echo them. It prints nothing that any other
 *   run prints, and exists so the confidentiality evidence is non-vacuous: the demonstration suite can
 *   put real protected material through a real subprocess into a real assertion path and observe that
 *   the reported TAP output still carries none of it.
 *
 * Any other argument is refused with one fixed line before anything exists, with nothing echoed, and
 * exits 2. Every fault is armed in this process only; the operator command is untouched.
 */
import { injectWorkerTermination, installWorkerObservation }
  from '../../scripts/lib/synthetic-conversation-worker-observation.mjs';

/** The one fixed ordinal this fixture may terminate: the reply-side child, never the request-side one. */
const REPLY_SIDE_WORKER = 2;
const MODES = Object.freeze({
  TERMINATE_SECOND_WORKER: 'terminate-second-worker',
  LEAK_PLANTED_DIAGNOSTICS: 'leak-planted-diagnostics',
});
const KNOWN = new Set(Object.values(MODES));
const REFUSED = 'hylja synthetic conversation demo fault driver: argument refused\n'
  + 'expected: terminate-second-worker | leak-planted-diagnostics\n';

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
  // Armed before the case runs: the fixture asks the OS to stop the reply-side child, and every other
  // part of the run stays exactly the operator run.
  injectWorkerTermination(REPLY_SIDE_WORKER);
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