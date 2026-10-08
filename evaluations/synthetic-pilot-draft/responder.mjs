/** PROPOSED / PUBLIC_DRAFT_ONLY. Pure explicitly OFFLINE responder, not a model.
 * Complete closed reference-only request; no lookup, derivation, I/O or authority.
 */
const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'PILOT_RESPONDER_REFUSED' });
const REFERENCE = /^DRAFT-PILOT-REF-[a-f0-9]{64}(?![\s\S])/u;
function ordered(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key, i) => actual[i] === key);
}
function valid(image) {
  if (!ordered(image, ['version', 'mode', 'message', 'log']) || image.version !== 1 || image.mode !== 'PUBLIC_DRAFT_ONLY') return false;
  const { message, log } = image;
  if (!ordered(message, ['version', 'task', 'assets']) || message.version !== 1 ||
    (message.task !== 'ERROR_COUNTS' && message.task !== 'FIRST_ERRORS') || !Array.isArray(message.assets) ||
    message.assets.length < 1 || message.assets.length > 8 || !message.assets.every((ref) => typeof ref === 'string' && REFERENCE.test(ref)) ||
    new Set(message.assets).size !== message.assets.length) return false;
  if (!ordered(log, ['version', 'events']) || log.version !== 1 || !Array.isArray(log.events) || log.events.length < 1 || log.events.length > 128) return false;
  const observed = new Set();
  for (const entry of log.events) {
    if (!ordered(entry, ['asset', 'tick', 'level', 'code']) || !message.assets.includes(entry.asset) ||
      !Number.isSafeInteger(entry.tick) || entry.tick < 0 || entry.tick > 1000000 ||
      (entry.level !== 'INFO' && entry.level !== 'ERROR') ||
      (entry.code !== 'START' && entry.code !== 'STOP' && entry.code !== 'FAILURE')) return false;
    observed.add(entry.asset);
  }
  return observed.size === message.assets.length;
}
export function respondPilot(cloakedJson) {
  try {
    if (typeof cloakedJson !== 'string' || cloakedJson.length < 1 || cloakedJson.length > 32768 || /[^\x20-\x7e]/u.test(cloakedJson)) return REFUSAL;
    const image = JSON.parse(cloakedJson);
    if (!valid(image) || JSON.stringify(image) !== cloakedJson) return REFUSAL;
    const { task, assets } = image.message;
    const results = assets.map((reference) => {
      let count = 0;
      let firstError = null;
      for (const entry of image.log.events) {
        if (entry.asset !== reference || entry.level !== 'ERROR') continue;
        count += 1;
        // Strictly smaller only: equal tick retains earliest original input index.
        if (firstError === null || entry.tick < firstError.tick) firstError = { tick: entry.tick, code: entry.code };
      }
      return task === 'ERROR_COUNTS' ? { reference, errorCount: count } : { reference, firstError };
    });
    const replyJson = JSON.stringify({ version: 1, task, results });
    return Object.freeze({ status: 'RESPONDED', mode: 'PUBLIC_DRAFT_ONLY', replyJson });
  } catch { return REFUSAL; }
}
