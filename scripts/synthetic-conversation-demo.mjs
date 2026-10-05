#!/usr/bin/env node
/**
 * #250 provider-free synthetic conversation demonstration.
 *
 *   npm run build && node scripts/synthetic-conversation-demo.mjs
 *   node scripts/synthetic-conversation-demo.mjs --case blocked-reply
 *   node scripts/synthetic-conversation-demo.mjs --case unsupported-request
 *
 * One command runs the REAL application-level local conversation owner -
 * `createOpenAiLocalConversation` from [`src/openai-local-conversation.ts`](../src/openai-local-conversation.ts)
 * - over a REAL standard HTTP peer bound to `127.0.0.1` on an OS-assigned ephemeral port. Nothing is
 * stubbed: `detectSecrets` runs over the sender's own private original request image, the accepted
 * policy engine selects the irreversible whole-message `MASK` of accepted decision 011, both fixed
 * egress-sentinel worker children really run, and the reply leaves the receiver's own guarded release
 * point. This is a demonstration, not a new transport, coordinator or policy authority: no provider,
 * no credential, no network beyond loopback, and no new production surface.
 *
 * Three cases, all over the same working fixture:
 *
 * - `default`: one synthetic request whose planted secret is really detected and really masked, one
 *   request at the peer, one guarded release, and both real children really returning `ALLOW`.
 * - `blocked-reply`: the same request, and a reply that carries the REGISTERED synthetic original. The
 *   request reaches the peer once; the second real child really runs, really exits cleanly and really
 *   blocks that reply over the known original, so nothing is released.
 * - `unsupported-request`: a request outside the strict complete-text subset. The strict codec refuses
 *   it before any child can exist, so no payload request reaches the peer, no worker runs and nothing
 *   is released.
 *
 * Both refusals are SUCCESSFUL demonstrations: this script exits 0 when the case behaved exactly as
 * declared above and non-zero otherwise, so a wrong refusal, a leaked original, a missed release or a
 * worker that crashed, was killed, stayed silent or returned a malformed frame is a failure rather than
 * a note. The accepted receiver reports `SENTINEL_BLOCKED` for a genuine block, a crashed child and a
 * malformed reply alike, so this script never treats that refusal code on its own as evidence: it also
 * reports what the real children did, read from their own replies and exits
 * ([scripts/lib/synthetic-conversation-demo-cases.mjs](lib/synthetic-conversation-demo-cases.mjs)).
 *
 * What is printed is a fixed human-readable summary derived from the real owner result and the real
 * peer, release, detector and worker counters, plus fixed labels naming what this run is. No original
 * value, key, model traffic, caller argument, signal name, native exception text or child reply text is
 * ever printed: arguments are matched against a fixed vocabulary and refused without echo before any
 * peer, owner or child exists, and an unexpected failure prints one fixed line and nothing else.
 *
 * There is no hidden mode. The fixture-only fault hooks used by the test evidence live in
 * [scripts/lib/synthetic-conversation-worker-observation.mjs](lib/synthetic-conversation-worker-observation.mjs)
 * and are reachable from fixture code only; no argument, environment variable or file reaches them from
 * here. Every fixture value is obviously synthetic and non-routable (`*.invalid`, loopback, a made-up
 * token literal). This run demonstrates a completed MVP over fixtures. It is not a gateway, it
 * authenticates nobody, it restores nothing, it streams nothing and it is not a held-out or scored
 * result.
 */
import { writeSync } from 'node:fs';
import { DEMO_ARGUMENT_REFUSED, DEMO_DECLINED } from './lib/synthetic-conversation-demo-text.mjs';

/**
 * EVERY exit path ends in one of three fixed outcomes and nothing else: the summary and exit 0, the fixed
 * decline and exit 1, or the fixed argument refusal and exit 2. That includes the paths that used to sit
 * outside the case runner's own catch - loading the accepted runtime, installing the observation, writing
 * the summary to a broken output pipe, and building the summary - so no native error message, code,
 * stack or path can reach the operator from any of them.
 *
 * - The two modules that need the real runtime are imported DYNAMICALLY, inside the guarded block below.
 *   The native `spawn` is captured BEFORE the accepted runtime is imported, because ESM links a whole
 *   module graph before any body in it runs and a builtin named import is a value snapshot taken at that
 *   link step: a capture installed after that graph was linked would never be seen by the real runner and
 *   every run would report zero workers.
 * - Output is written through a callback, with a permanent `error` listener on both streams, so a broken
 *   pipe (`EPIPE`, a destroyed stream) is an observed boolean here and never an unhandled `error` event.
 * - Anything that still escapes is caught by the last-resort handlers installed first: they print the
 *   same fixed decline, synchronously, and exit 1 without looking at what was thrown.
 */
const failClosed = () => {
  try { writeSync(2, DEMO_DECLINED); } catch { /* stderr is gone too: the non-zero exit is all that is left */ }
  process.exit(1);
};
process.on('uncaughtException', failClosed);
process.on('unhandledRejection', failClosed);
for (const name of ['stdout', 'stderr']) {
  try { process[name].on('error', () => {}); } catch { /* the stream cannot even be opened: writes fail closed below */ }
}

/** Write one fixed chunk and report whether the stream really accepted it. Never throws, never echoes. */
const emit = (stream, text) => new Promise((resolve) => {
  try {
    stream.write(text, (error) => { resolve(error === null || error === undefined); });
  } catch {
    resolve(false);
  }
});

/** Run the demonstration and return its exit code. The one place the fixed outcomes are chosen. */
async function main() {
  let outcome;
  try {
    const { installWorkerObservation } = await import('./lib/synthetic-conversation-worker-observation.mjs');
    installWorkerObservation();
    const cases = await import('./lib/synthetic-conversation-demo-cases.mjs');
    const name = cases.resolveDemoCase(process.argv.slice(2));
    if (name === null) {
      // Refused before any effect: no peer, no socket, no owner, no detector, no policy decision, no
      // child, and no echo of what was actually passed.
      outcome = { refused: true };
    } else {
      const seen = await cases.runDemoCase(name);
      outcome = { refused: false, summary: `${cases.summarizeDemoCase(name, seen).join('\n')}\n`, holds: cases.demoCaseHolds(name, seen) };
    }
  } catch {
    // A native error from any of the steps above lands here identically and identically unprinted.
    await emit(process.stderr, DEMO_DECLINED);
    return 1;
  }
  if (outcome.refused) {
    await emit(process.stderr, DEMO_ARGUMENT_REFUSED);
    return 2;
  }
  const written = await emit(process.stdout, outcome.summary);
  if (written && outcome.holds) return 0;
  // The case did not behave as declared, or the summary could not be delivered: one fixed line.
  await emit(process.stderr, DEMO_DECLINED);
  return 1;
}

process.exitCode = await main().catch(() => 1);
