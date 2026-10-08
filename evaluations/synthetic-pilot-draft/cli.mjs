/** PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY.
 * Descriptor-only public packet translation. No paths, provider, model, hooks,
 * private input, native blocking/confinement/rollback/authentication/erasure claim.
 */
import { Buffer } from 'node:buffer';
import { readSync, writeSync } from 'node:fs';
import { preparePilot, completePilot } from './controller.mjs';
import { respondPilot } from './responder.mjs';
const REFUSAL = '{"status":"REFUSED","reason":"PILOT_CONTROLLER_REFUSED"}';
function readPacket() {
  const buffer = Buffer.alloc(65538); // cap + optional terminal LF + overflow byte
  let used = 0;
  let eof = false;
  while (used < buffer.length) {
    const count = readSync(0, buffer, used, buffer.length-used, null);
    if (!Number.isInteger(count) || count < 0 || count > buffer.length-used) throw new Error('IO_REFUSED');
    if (count === 0) { eof = true; break; }
    used += count;
  }
  if (!eof) return null;
  if (used > 0 && buffer[used-1] === 10) used -= 1;
  if (used < 1 || used > 65536) return null;
  // Check original bytes BEFORE UTF-8 decoding; no high-bit masking/replacement.
  for (let i = 0; i < used; i += 1) if (buffer[i] < 32 || buffer[i] > 126) return null;
  const raw = buffer.toString('utf8', 0, used);
  try {
    const packet = JSON.parse(raw);
    if (JSON.stringify(packet) !== raw) return null;
    return packet;
  } catch { return null; }
}
function closed(packet, keys) {
  if (packet === null || typeof packet !== 'object' || Array.isArray(packet)) return false;
  const actual = Object.keys(packet);
  return packet.version === 1 && actual.length === keys.length && keys.every((key, i) => actual[i] === key);
}
function completePacket(verb, packet) {
  const keys = verb === 'cloak' ? ['version','inputJson'] : verb === 'display' ?
    ['version','inputJson','replyJson','controlsJson'] : ['version','inputJson','controlsJson'];
  if (!closed(packet, keys)) return null;
  if (verb === 'cloak') {
    const prepared = preparePilot(packet.inputJson);
    return prepared.status === 'TRANSFORMED' ? prepared.cloakedJson : null;
  }
  let replyJson = packet.replyJson;
  if (verb === 'demo') {
    const prepared = preparePilot(packet.inputJson);
    if (prepared.status !== 'TRANSFORMED') return null;
    const offline = respondPilot(prepared.cloakedJson);
    if (offline.status !== 'RESPONDED') return null;
    replyJson = offline.replyJson; // Explicitly offline; never native model evidence.
  }
  const displayed = completePilot(packet.inputJson, replyJson, packet.controlsJson);
  return displayed.status === 'DISPLAYED' ? displayed.answerJson : null;
}
try {
  let answer = null;
  if (process.argv.length === 3 && ['cloak','display','demo'].includes(process.argv[2])) {
    answer = completePacket(process.argv[2], readPacket());
  }
  // ALL logical validation/restoration completed before the first native write.
  const output = Buffer.from((answer ?? REFUSAL)+'\n', 'utf8');
  let sent = 0;
  while (sent < output.length) {
    const count = writeSync(1, output, sent, output.length-sent, null);
    if (!Number.isInteger(count) || count <= 0 || count > output.length-sent) throw new Error('IO_REFUSED');
    sent += count;
  }
  process.exitCode = answer === null ? 2 : 0;
} catch {
  // A native write may already have sent bytes. No second answer/error/rollback claim.
  process.exitCode = 1;
}
