/**
 * Fixed compiled child worker for the optional #147 egress sentinel local process wrapper. It is the
 * only worker this repository will run for this purpose, and its path is fixed next to this module: no
 * caller, option, environment variable or worker callback selects a different one.
 *
 * It reads exactly one capped request frame from stdin, runs `checkEgress` exactly once over the exact
 * bytes it was given, and writes exactly one capped reply frame to stdout. It opens no socket, reads
 * no file, loads no module beyond the sentinel itself, and has no retry, pool, restart or fallback
 * path: an unreadable request, an invalid registration or any internal failure exits non-zero with no
 * reply at all, which the parent treats as restrictive.
 *
 * The known-original handle is rebuilt here from the explicit bounded registration in the request,
 * because a process-local handle cannot be serialized. Omission is never read as `null`: `null` is a
 * value the parent had to state. Every failure path is a non-zero exit, never a successful zero-findings
 * result, and nothing is written to stderr so no value, path or traceback can reach a diagnostic channel.
 */
import { checkEgress, createKnownOriginals } from './egress-sentinel.js';
import {
  EGRESS_SENTINEL_PROCESS_LIMITS,
  decodeRequestFrame,
  encodeResponseFrame,
  isSentinelBlockReason,
} from './egress-sentinel-process-protocol.js';
import type { SentinelProcessSnapshot } from './egress-sentinel-process-protocol.js';

type DecodedRequest = Readonly<{ ok: true; value: SentinelProcessSnapshot }>;

/** Non-zero exit codes. The parent maps every one of them to a restrictive outcome. */
const EXIT_USAGE = 64;
const EXIT_BAD_REQUEST = 65;
const EXIT_INTERNAL = 70;

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.byteLength; }
  return out;
}

function reply(decoded: DecodedRequest): void {
  const snapshot = decoded.value;
  const known = snapshot.known;
  const handle = known === null
    ? null
    : createKnownOriginals(known.scope, known.key, known.entries.map((entry) => ({
      kind: entry.kind, value: entry.value, ref: entry.ref,
    })));
  const result = checkEgress({
    bytes: snapshot.payload,
    scope: snapshot.scope,
    destination: snapshot.observed,
    authorized: snapshot.authorized,
    known: handle,
  });
  // Only fixed sentinel reason codes and refs the parent itself registered ever enter the reply.
  const reasonCodes = result.reasons.filter(isSentinelBlockReason);
  const refs = new Set(snapshot.registeredRefs);
  const rules = result.findings.map((finding) => finding.rule).filter((rule) => refs.has(rule));
  const frame = encodeResponseFrame({
    requestId: snapshot.requestId,
    tenantRef: snapshot.scope.tenantRef,
    projectRef: snapshot.scope.projectRef,
    observedId: snapshot.observed.id,
    observedProfileDigest: snapshot.observed.profileDigest,
    authorizedId: snapshot.authorized.id,
    authorizedProfileDigest: snapshot.authorized.profileDigest,
    payloadDigest: snapshot.payloadDigest,
    response: {
      decision: result.decision,
      reasonCodes: Object.freeze([...new Set(reasonCodes)].sort()),
      rules: Object.freeze([...new Set(rules)].sort()),
    },
  });
  if (frame === null) { process.exitCode = EXIT_INTERNAL; return; }
  process.stdout.write(frame);
  process.exitCode = 0;
}

function main(): void {
  const stdin = process.stdin;
  if (stdin === null) { process.exitCode = EXIT_USAGE; return; }
  const chunks: Uint8Array[] = [];
  let size = 0;
  let overflow = false;
  stdin.on('data', (chunk: Uint8Array) => {
    if (overflow) return;
    size += chunk.byteLength;
    if (size > EGRESS_SENTINEL_PROCESS_LIMITS.maxRequestBytes + 1) { overflow = true; chunks.length = 0; return; }
    chunks.push(chunk);
  });
  stdin.on('error', () => { process.exitCode = EXIT_INTERNAL; });
  stdin.on('end', () => {
    if (overflow) { process.exitCode = EXIT_BAD_REQUEST; return; }
    let raw: Uint8Array;
    try { raw = concat(chunks, size); } catch { process.exitCode = EXIT_BAD_REQUEST; return; }
    chunks.length = 0;
    // The decoder owns the trailing-newline, truncation and duplicate-newline rules; a second
    // interpretation here would be a second place for them to drift.
    const decoded = decodeRequestFrame(raw);
    if (!decoded.ok) { process.exitCode = EXIT_BAD_REQUEST; return; }
    try { reply(decoded); } catch { process.exitCode = EXIT_INTERNAL; }
  });
}

main();