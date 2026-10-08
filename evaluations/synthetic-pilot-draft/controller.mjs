/** PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY.
 * Complete public task answer staging; not authentication, policy or bulk lookup.
 * No caller objects/hooks, I/O, model, clock provider, persistent state or erasure.
 */
import { transformPilot } from './transform.mjs';
import { createPilotOwner } from './owner.mjs';
const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'PILOT_CONTROLLER_REFUSED' });
const REFERENCE = /^DRAFT-PILOT-REF-[a-f0-9]{64}(?![\s\S])/u;
function text(value, cap) {
  return typeof value === 'string' && value.length > 0 && value.length <= cap && !/[^\x20-\x7e]/u.test(value);
}
function ordered(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key, i) => actual[i] === key);
}
function parse(raw, cap) {
  if (!text(raw, cap)) return null;
  const value = JSON.parse(raw);
  return JSON.stringify(value) === raw ? value : null;
}
function integer(value, cap) { return Number.isSafeInteger(value) && value >= 0 && value <= cap; }
function prepared(raw) {
  const input = parse(raw, 32768);
  if (!ordered(input, ['version', 'context', 'message', 'log']) || input.version !== 1) return null;
  // P1 alone validates all nested input shapes, original namespace and set semantics.
  const contextJson = JSON.stringify(input.context);
  const transformed = transformPilot(contextJson, JSON.stringify(input.message), JSON.stringify(input.log));
  return transformed.status === 'TRANSFORMED' ? { input, contextJson, transformed } : null;
}
function validReply(reply, task, references) {
  if (!ordered(reply, ['version', 'task', 'results']) || reply.version !== 1 || reply.task !== task ||
    !Array.isArray(reply.results) || reply.results.length !== references.length) return false;
  return reply.results.every((record, i) => {
    const keys = task === 'ERROR_COUNTS' ? ['reference', 'errorCount'] : ['reference', 'firstError'];
    if (!ordered(record, keys) || typeof record.reference !== 'string' || !REFERENCE.test(record.reference) || record.reference !== references[i]) return false;
    if (task === 'ERROR_COUNTS') return integer(record.errorCount, 128);
    const first = record.firstError;
    return first === null || (ordered(first, ['tick', 'code']) && integer(first.tick, 1000000) &&
      (first.code === 'START' || first.code === 'STOP' || first.code === 'FAILURE'));
  });
}
function validControls(controls, assets) {
  return Array.isArray(controls) && controls.length === assets.length && controls.every((control, i) =>
    ordered(control, ['asset', 'configJson', 'displayJson', 'now', 'revokeJson']) && control.asset === assets[i] &&
    text(control.configJson, 1024) && text(control.displayJson, 1024) && integer(control.now, 1000000) &&
    (control.revokeJson === null || text(control.revokeJson, 1024)));
}
export function preparePilot(inputJson) {
  try { return prepared(inputJson)?.transformed ?? REFUSAL; } catch { return REFUSAL; }
}
export function completePilot(inputJson, replyJson, controlsJson) {
  try {
    // Primitive caps prevent all caller hooks; parsed owned records are inspected once.
    if (!text(inputJson, 32768) || !text(replyJson, 8192) || !text(controlsJson, 8192)) return REFUSAL;
    const unit = prepared(inputJson);
    if (unit === null) return REFUSAL;
    const { input, contextJson, transformed } = unit;
    const task = input.message.task;
    const reply = parse(replyJson, 8192);
    const controls = parse(controlsJson, 8192);
    // WHOLE reply and complete controls shape precede every restoration/formatting.
    if (!validReply(reply, task, transformed.references) || !validControls(controls, input.message.assets)) return REFUSAL;
    const staged = [];
    for (let i = 0; i < controls.length; i += 1) {
      const control = controls[i];
      const owner = createPilotOwner(control.configJson, contextJson, control.asset);
      if (owner.status !== 'OWNED') return REFUSAL;
      if (control.revokeJson !== null && owner.revoke(control.revokeJson, control.now).status !== 'REVOKED') return REFUSAL;
      const record = reply.results[i];
      const display = owner.displayOne(record.reference, control.displayJson, control.now);
      if (display.status !== 'DISPLAYED') return REFUSAL;
      // Provider data cannot supply control authority or change the restored asset.
      staged.push(task === 'ERROR_COUNTS' ? { asset: display.original, errorCount: record.errorCount } :
        { asset: display.original, firstError: record.firstError });
    }
    const answerJson = JSON.stringify({ version: 1, mode: 'PUBLIC_DRAFT_ONLY', task, results: staged });
    return Object.freeze({ status: 'DISPLAYED', mode: 'PUBLIC_DRAFT_ONLY', answerJson });
  } catch {
    // No inspected prefix, original, exception text or trace on any failure.
    return REFUSAL;
  }
}
