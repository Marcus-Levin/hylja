# Egress sentinel process contract

Status: draft foundation contract for issue #147. This documents the executable seam in
[`src/egress-sentinel-process.ts`](../../src/egress-sentinel-process.ts),
[`src/egress-sentinel-process-protocol.ts`](../../src/egress-sentinel-process-protocol.ts) and
[`src/egress-sentinel-process-worker.ts`](../../src/egress-sentinel-process-worker.ts): an **optional**
one-check local child-process wrapper around `checkEgress`. It is **not** a model gateway, an
authenticated effect boundary, an OS sandbox, a memory or RSS cap, a provider client or a policy
decision. The sentinel algorithm itself is unchanged and still owned by
[`src/egress-sentinel.ts`](../../src/egress-sentinel.ts); implementation status belongs only in
[capabilities.md](../capabilities.md).

## Why this exists and what it is not

`checkEgress` and its zlib work are synchronous. A same-thread promise or timer cannot interrupt them,
so a caller has no way to withhold release, stay responsive, or terminate a stalled check once a scan
has started. Moving one check into a child process gives the caller that lifecycle control.

The boundary is **local lifecycle isolation and nothing more**:

- it does not decide release; the child's own sentinel verdict does, and an `ALLOW` is still only a
  verdict about the exact bytes the parent snapshotted;
- it is not an authentication boundary: nothing here proves who the caller, tenant, destination or
  policy decision is. Trusted inputs are trusted because the trusted integration supplies them;
- it is not a sandbox. The child is an ordinary local process: it inherits the parent's working
  directory, the kernel's file and network permissions, and the host's process table. It simply does
  not use them;
- it caps no memory, no RSS, no CPU share and no process count beyond "at most one active child per
  runner". Aggregate and whole-process limits are not attempted;
- it never sends a byte, opens a socket or contacts a provider, and it makes no policy, classification
  or authorization decision of its own.

## Surface

| Call | Meaning |
| --- | --- |
| `createSentinelProcessRunner({ deadlineMs, cleanupGraceMs? })` | one runner owning at most one active child. Exactly those two own **data** properties are accepted; any other own key (a caller `signal`, a `worker` path, an `options` bag, a `shell` flag) or an accessor makes a runner whose every check is `INVALID_REQUEST`, decided before any child exists and without invoking the refused accessor |
| `runner.check(request)` | runs exactly one check in one child; resolves to `{ status: 'ALLOW', release }` or `{ status: 'BLOCK', code, reasonCodes, rules }` |
| `runner.cancel()` | runner-owned cancellation of the sole active request; a no-op when idle |
| `runner.state` | `'IDLE'`, `'BUSY'` or `'QUARANTINED'` |

Exported values: `EGRESS_SENTINEL_PROCESS_WORKER`, `EGRESS_SENTINEL_PROCESS_LIMITS`,
`EGRESS_SENTINEL_PROCESS_PROTOCOL`, `classifyReplyFraming`, `decodeRequestFrame`,
`decodeResponseFrame`, `encodeRequestFrame`, `encodeResponseFrame`, `isSentinelBlockReason`,
`newSentinelRequestId`, `snapshotSentinelRequest`, `createSentinelProcessRunner`.

### Accepted request

The request object must have **exactly** these five own properties, read from their own **data
descriptors**: an own accessor with a matching name is refused without being invoked, and a bounded
`Proxy` trap that throws is contained and reported as the same `INVALID_REQUEST` rather than escaping
`snapshotSentinelRequest` or `check()`. Caller byte and key buffers are admitted and copied through
captured standard intrinsics only: byte identity and length are read from the typed array's own
internal slots, so an own `byteLength`, `set`, `constructor`, `Symbol.species` or `Symbol.iterator`
accessor on an otherwise genuine `Uint8Array` is **ignored, never invoked**, and the copy is written
into a buffer this code allocates. Identity is decided from internal slots alone: the captured
`ArrayBuffer.isView` refuses a `Proxy` or any non-view on the [[ViewedArrayBuffer]] slot **before**
any `get`, `has`, `ownKeys`, `getOwnPropertyDescriptor` or `getPrototypeOf` trap can run, and the
captured intrinsic `Symbol.toStringTag` accessor then requires the real [[TypedArrayName]] to be
`Uint8Array`, so a narrow view, a subclass instance and a re-prototyped non-byte view are refused while
a `Buffer` is admitted. No species-producing method (`slice`, `subarray`, `filter`) and no prototype
identity comparison is used: the first dispatches caller `constructor[Symbol.species]` before any
restriction exists, and the second is mutable caller state that proves no element kind. The copy uses
the captured shared `%TypedArray%.prototype.set`, which reads internal slots. This is a local wrapper
boundary, not a sandbox: a caller `Proxy` record side effect outside these calls, and tampering with
the global builtins captured at module initialization, stay outside the guarantee. `entries` is snapshotted by index descriptor, so a caller iterator, a
sparse hole or an accessor element is refused, not executed.

Admission is claimed before any of this caller-observable inspection begins, so a re-entrant
`check()` from inside it observes `RUNNER_BUSY` and cannot start a second child. An invalid
pre-spawn snapshot releases the claim immediately and leaves the runner `IDLE`.

```js
{ bytes, scope: { tenantRef, projectRef },
  destination: { id, profileDigest },   // observed at the send point
  authorized: { id, profileDigest },    // what the policy decision authorized
  known }                               // registration, or an explicit null
```

`known` is the whole point of the redesign:

| `known` | meaning |
| --- | --- |
| an explicit `null` | egress with no known originals to protect; passed to `checkEgress` as `null` |
| `{ scope, key, entries }` | a bounded trusted registration with **its own** scope, a dedicated key of 32 to 64 bytes, and at most 4096 `{ kind, ref, value }` entries (`kind` is `ORIGINAL` or `CANARY`) |

Anything else is refused before a child exists with `INVALID_REQUEST`. In particular:

- **omitting** `known` is refused. It is never read as `null`, so a forgotten handle cannot silently
  weaken the check;
- a process-local `KnownOriginalsHandle` is refused. It is a WeakMap key, it cannot cross a process
  boundary, and serializing it as `{}` or as `null` would turn a protected check into a decorative one;
- a registration whose own `scope` differs from the check scope is refused;
- an unknown property is refused **without invoking its value**, so an unsupported cancellation hook,
  worker path, timeout or callback cannot run caller code at all.

`value` is CONTENT, not an identifier: strict UTF-8, non-empty and bounded, with newlines, spaces and
tabs preserved byte for byte. Only `tenantRef`, `projectRef`, destination `id`, `profileDigest`, entry
`ref` and the digests/codes are restricted to identifier shape, and a label containing a control
character stays refused.

This is deliberate: cancellation is `runner.cancel()`, a runner-owned method over private state. There
is no public `AbortSignal`, no custom callback, no runtime-selectable worker, no pool, no retry, no
compatibility layer, and nothing that walks Node-private symbols, WeakMap internals or caller listener
closures.

### Block codes

Every outcome other than `ALLOW` is restrictive. Transport and lifecycle codes carry empty
`reasonCodes` and `rules`; only `SENTINEL_BLOCK` carries the child's own verdict.

| code | meaning |
| --- | --- |
| `INVALID_REQUEST` | refused before spawn: unknown or missing property, bad label, oversized or unbounded input, bad deadline, scope mismatch, bad registration |
| `RUNNER_BUSY` | a second concurrent check; the runner holds one active child and never queues or pools |
| `RUNNER_QUARANTINED` | this runner is permanently unusable after an unconfirmed cleanup |
| `CANCELLED` | `runner.cancel()` was observed first |
| `DEADLINE_EXCEEDED` | the host-owned absolute deadline fired first |
| `SPAWN_FAILED` | the child could not be started, or its stdin/stdout failed |
| `CHILD_CRASHED` | the child exited non-zero |
| `REPLY_MISSING` | the child exited zero with no stdout |
| `REPLY_MALFORMED` | wrong magic/kind/length, an unknown or reordered field, a body shorter than the declared length, a missing trailing newline, trailing bytes after one complete frame, or an inconsistent decision |
| `REPLY_DUPLICATE` | a second complete frame concatenated after the first. Frames are binary and length-delimited: only the single byte after the declared body is a newline, so a length field, an id or a payload byte that happens to be `0x0a` is ordinary data, never a delimiter |
| `REPLY_TOO_LARGE` | stdout exceeded its cap |
| `REPLY_DUPLICATE` | a second complete frame concatenated after the first, which `classifyReplyFraming` finds from the declared length and never from a content scan |
| `REPLY_BINDING_MISMATCH` | the reply did not echo the request id, tenant/project, observed and authorized destination and profile, and the payload digest this parent actually sent |
| `DIAGNOSTIC_OVERFLOW` | stderr exceeded its cap |
| `CLEANUP_UNCONFIRMED` | the child was signalled but never confirmed gone; the runner is quarantined |
| `SENTINEL_BLOCK` | the child ran `checkEgress` and it blocked; `reasonCodes` holds fixed sentinel codes and `rules` holds refs this runner registered |

## Lifecycle rules

1. **The absolute deadline starts at spawn and is never reset by output.** A child that trickles bytes
   for longer than the deadline is still stopped at the deadline.
2. **The first observed stop wins.** A cancel, deadline, crash, framing failure or diagnostic overflow
   that is observed first is the outcome. No later reply overrides it: a valid `ALLOW` frame that
   arrives after the deadline has already fired is `DEADLINE_EXCEEDED`, never `ALLOW`.
3. **`SIGKILL` is a request, not a termination.** The runner reports the stop reason only once the
   child's `close` event confirms the exit. If `close` does not arrive within `cleanupGraceMs`, the
   outcome is `CLEANUP_UNCONFIRMED` and **the runner quarantines itself**, because a child this runner
   can no longer track is a child it can no longer stop.
4. **`ALLOW` requires an observed zero exit**, not just a decoded frame.
5. **No in-thread fallback.** There is no path where a failed or stalled child check becomes an
   in-process `checkEgress`, a cached verdict, or a pass.
6. **No retry, restart or pool.** One check, one child, one verdict.

## Privacy properties

- **The release is a private parent copy.** On `ALLOW`, `release` is a fresh copy of the bytes this
  parent snapshotted before spawning and that the child reported checking. It is never the caller's
  buffer, never a buffer the caller can still mutate, and never bytes the worker selected. The worker
  does not send payload bytes back at all; the reply carries a digest, not content.
- **Snapshot before async work.** Scope, destination, profile, entries and payload are validated, copied
  and capped before any child exists. A getter, a proxy or later caller mutation cannot change the
  image that is checked or released.
- **stdout is parsed into fixed codes.** A reply reason must be a code this sentinel version can
  produce, and a reply ref must be one this runner itself registered. A child that echoes a value, a
  path or any other free text produces `REPLY_MALFORMED`, and nothing from stdout reaches an ordinary
  result or an error message.
- **stderr is counted and dropped.** It is never materialised, reported or attached to an error; only
  its byte count matters, and exceeding the cap is `DIAGNOSTIC_OVERFLOW`.
- **Known originals are ephemeral local copies.** Originals and the sentinel key exist inside this
  process and the child as bounded IPC bytes. They are absent from ordinary results, errors, stdout,
  stderr and any report. Zeroing the parent's snapshot on completion is hygiene, **not** erasure: no
  heap, RSS or swap claim is made or proved here.

## Costs and limits, stated honestly

- **Copy overhead.** Every check copies the payload, and — when originals are registered — copies each
  entry and the key, on both sides of the process boundary, plus one private copy on `ALLOW`.
- **Startup overhead.** Every check starts a fresh Node process. The fixed worker is this module's
  compiled sibling, resolved from `import.meta.url`; there is no product option that can move it.
- **Fixed bounds.** `EGRESS_SENTINEL_PROCESS_LIMITS` caps the payload at the sentinel's own 1 MiB
  message cap, the request frame at 8 MiB, the reply frame and stdout at 1 MiB, stderr at 64 KiB, the
  deadline at 100 ms to 600 000 ms and the cleanup grace at 0 to 60 000 ms.
- **Not proved.** Whole-process or aggregate RSS, CPU and process limits, production throughput, hostile
  input, an authenticated binding to a real routed destination, and release safety under an OS-level
  adversary are all outside what this seam and its tests establish. A passing run here is a passing
  lifecycle and privacy test, not an enforcement proof.
- **Reason-code coupling.** The allowlist of sentinel reason codes in the protocol module must be
  updated when `checkEgress` gains one. That is intentional coupling, not drift: an unlisted reason is
  refused rather than passed through.
- **Not a JavaScript sandbox.** The byte-array boundary reads native internal state through captured
  intrinsics, so a shadowed caller property is never called and a `Proxy` over bytes is refused without
  running one trap. That is a local wrapper guarantee, not isolation: it says nothing about arbitrary
  hostile JavaScript running in the same realm, about caller code already executed elsewhere, or about
  a caller who has tampered with the global intrinsics themselves. Reflecting a caller `Proxy` around
  the **record** fields (scope, destination, entries) still runs that proxy's traps, contained by the
  try/catch and reported as `INVALID_REQUEST`.

## Verification

[`test/egress-sentinel-process.test.mjs`](../../test/egress-sentinel-process.test.mjs) runs the real
compiled worker for every sentinel-behaviour assertion, and installs generated stdlib-only synthetic
children into a private temporary copy of `dist/` for the lifecycle and framing assertions, so stall,
trickled output, cancellation, crash, malformed, duplicate, oversize, diagnostic overflow and
unconfirmed cleanup are each proved against a real process without a configurable product worker path.

Diagnostic confidentiality is checked independently of any returned result: a finite synthetic driver
runs the wrapper in its own process while the test captures that process's **own** stdout and stderr,
with a hostile synthetic child writing a planted protected marker on both of the wrapper's captured
child channels. The withholding run must show no marker on either captured channel, and a deliberately
leaking control run must show it, so a capture that silently observed nothing cannot pass.
Nothing in it calls a provider, uses a credential, reaches the network or reads private data.