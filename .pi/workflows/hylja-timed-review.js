// Native Pi workflow body. Developer admission only; no imports, host calls or automatic retries.
// Derive the phase window HERE, at actual execution, not in the model's prepared handoff.
const observedAtMs = Date.now();
const nativeTimeoutMs = 900000;
const phaseMs = 720000;
const requiredMs = 660000; // source/check reserve plus 90s reporting
const proposedStop = observedAtMs + phaseMs;
const imposedStop = args.taskStopMs;
if (!Number.isSafeInteger(observedAtMs) || observedAtMs < 0 ||
    !Number.isSafeInteger(proposedStop) || proposedStop > 8640000000000000 ||
    (imposedStop !== undefined && (!Number.isSafeInteger(imposedStop) || imposedStop <= 0))) {
  return { status: 'REFUSED', reason: 'REVIEW_CLOCK_OR_WINDOW_UNAVAILABLE' };
}
const hardStopMs = imposedStop === undefined ? proposedStop : Math.min(proposedStop, imposedStop);
if (hardStopMs - observedAtMs < requiredMs || !['check', 'review'].includes(args.mode)) {
  return { status: 'REFUSED', reason: 'REVIEW_CLOCK_OR_WINDOW_UNAVAILABLE' };
}
if (args.mode === 'check') {
  return { status: 'READY_NO_CHILD', observedAtMs, hardStopMs, nativeTimeoutMs };
}
if (typeof args.task !== 'string' || args.task.length === 0 ||
    typeof args.model !== 'string' || args.model.length === 0 ||
    typeof args.output !== 'string' || !args.output.startsWith('/')) {
  return { status: 'REFUSED', reason: 'REVIEW_INPUT_UNAVAILABLE' };
}
const effectiveTask = args.task + '\n\nCURRENT DISPATCH WINDOW: observed UTC ' +
  new Date(observedAtMs).toISOString() + '; absolute report stop ' +
  new Date(hardStopMs).toISOString() + '; native cap 900000ms from native startup. ' +
  'Reserve 90s reporting and use fresh UTC before effects. This header belongs only to this new phase; '
  + 'historical proposal timestamps are not current authority. Any real earlier task deadline still applies. '
  + 'No expired lane is renewed; no automatic retry or fallback.';
return await runs.run('review-exact-head', {
  agent: 'hylja-reviewer', model: args.model, task: effectiveTask,
  timeoutMs: nativeTimeoutMs, toolTimeoutMs: 120000,
  output: args.output, outputMode: 'file-only', context: 'fresh'
});
