# F1: timer, child-process and input-settlement source findings

Date: 2026-10-07. Status: **source evidence; proposed prerequisite; not independently reviewed or adopted**.

This record examines the frozen, unexecuted custody method discussed in [the preparation record](../2026-10-06/local-authentication-preparation.md). It contains no runtime experiment, private material or implementation. Current product scope belongs in [capabilities](../../capabilities.md); work status and sequencing belong in [#269](https://github.com/Marcus-Levin/hylja/issues/269) and the [roadmap](https://github.com/Marcus-Levin/hylja/issues/36).

## Problem and concrete trace

In the examined method, an outer controller can report UNKNOWN after GO, clear its cancellation/deadline timers, revoke its local authority and release its streams/handle. The holder can simultaneously retain an owner and an attempted input while awaiting the real input callback and child close. Its retained references and interval do not establish a finite lifetime.

The essential trace is:

```text
GO accepted → input attempt begins
            → actual end callback or child close remains absent
controller  → UNKNOWN → local release / timers cleared
holder      → retained request / owner / interval
```

Changing the holder's timer or dropping the controller's reference cannot, by itself, establish termination of that holder or all processes retaining attempted material. F3's real callback-and-close requirement must not be weakened to make this trace appear settled.

## Source evidence

The following public sources are pinned to Node v24.15.0. They were read as complete files or complete named sections/functions; the record does not claim whole-file inspection where only a defining section was used. Source identity is not installed-binary, build-configuration or running-kernel equivalence.

### Timers depend on dispatch progress

The actual call path is:

```text
lib/timers: setTimeout / setInterval
  → internal/timers: Timeout + insert
  → timers binding: Environment::ScheduleTimer
  → libuv: uv_timer_start
  → uv_run / uv__run_timers
  → Environment::RunTimers
  → internal/timers: processTimers / listOnTimeout
  → callback
```

`listOnTimeout` invokes the callback before its finally block and rescheduling. Libuv invokes timer callbacks sequentially from loop dispatch. A nonreturning callback or native operation prevents progress through that path; another timer on that path is not an independent preemption mechanism. The timer API expressly disclaims exact callback timing and order.

`unref()` changes liveness reference counts/flags. `clearTimeout()` removes a scheduled callback. Neither is a private-owner retirement or process-death observation.

Defining sources:

- [Timer API](https://github.com/nodejs/node/blob/v24.15.0/doc/api/timers.md), complete document; `setTimeout`, `ref`, `unref` and cancellation sections.
- [Public timers implementation](https://github.com/nodejs/node/blob/v24.15.0/lib/timers.js), complete file.
- [Internal timer dispatch](https://github.com/nodejs/node/blob/v24.15.0/lib/internal/timers.js), complete file, especially `insert`, `getTimerCallbacks` and `listOnTimeout`.
- [Native timer binding](https://github.com/nodejs/node/blob/v24.15.0/src/timers.cc), complete file.
- [Environment scheduling/dispatch](https://github.com/nodejs/node/blob/v24.15.0/src/env.cc#L1483-L1608), complete scheduling/ref/dispatch/clock-conversion functions, not the whole file.
- [Libuv timers](https://github.com/nodejs/node/blob/v24.15.0/deps/uv/src/timer.c), complete file; [loop dispatch](https://github.com/nodejs/node/blob/v24.15.0/deps/uv/src/unix/core.c#L393-L492), complete defining functions.

### Close, exit and signal delivery are distinct facts

Libuv obtains a wait status before invoking its process exit callback. Native `ProcessWrap::OnExit` forwards the status to JS. JS then destroys stdin, closes its process handle, emits `exit`, and advances stdio/child-close accounting. A child can exit before shared stdio closes.

Closing the native process handle removes its watcher and queues a handle-close callback. That close path does not send a kill signal or manufacture a wait status. The `ChildProcess` API states that `.killed` records successful signal delivery, not termination; killing a parent PID does not automatically terminate descendants. The Linux manual states that group-signal success means at least one delivery, not confirmation that every group member has died.

Consequently, a signal return, handle close or parent-PID observation cannot replace the required owned terminal facts. Missing facts remain UNKNOWN. No later signal/probe after UNKNOWN, exit, close, revocation or expiry is proposed here.

Defining sources:

- [ChildProcess API](https://github.com/nodejs/node/blob/v24.15.0/doc/api/child_process.md#L1416-L2313), complete class section, not the entire document.
- [JS constructor and stdio accounting](https://github.com/nodejs/node/blob/v24.15.0/lib/internal/child_process.js#L256-L558), complete relied-on constructor/spawn/kill/ref/unref functions; [`maybeClose`](https://github.com/nodejs/node/blob/v24.15.0/lib/internal/child_process.js#L1120-L1126). Unrelated IPC/parser portions were not qualified.
- [Process binding](https://github.com/nodejs/node/blob/v24.15.0/src/process_wrap.cc) and [handle binding](https://github.com/nodejs/node/blob/v24.15.0/src/handle_wrap.cc), complete files.
- [Libuv reaping](https://github.com/nodejs/node/blob/v24.15.0/deps/uv/src/unix/process.c#L101-L177), complete `uv__wait_children`; complete `uv_process_kill`, `uv_kill` and `uv__process_close` functions near the file end.
- [Libuv handle-close dispatch](https://github.com/nodejs/node/blob/v24.15.0/deps/uv/src/unix/core.c#L159-L240) and [close completion](https://github.com/nodejs/node/blob/v24.15.0/deps/uv/src/unix/core.c#L268-L380), complete relied-on functions.
- [Linux kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html), captured complete manual, man-pages6.19; not a running-kernel pin.

### Writable cancellation does not manufacture settlement

The Writable API distinguishes destruction requested (`destroyed`), close emitted (`closed`), end called (`writableEnded`), and finished state (`writableFinished`). The `write()` boolean describes queue/backpressure status after admitting a chunk. Destroying a stream can leave earlier writes undrained.

An actual input callback remains different from a local error, a destroy request, recipient consumption or erasure. F3 therefore still requires the actual end callback **and** actual child close for attempted-input retirement. A thrown end call is not a synthetic callback. API inspection alone does not establish a particular native queued-write/throw trace.

Source: [Writable class API](https://github.com/nodejs/node/blob/v24.15.0/doc/api/stream.md#L501-L1075), complete selected class section, not the whole stream document.

## Proposed prerequisite, not accepted authority

A possible draft topology is:

```text
caller/controller → lifetime owner → holder/request children
```

Before GO, the lifetime owner would need genuine ownership of the complete private-copy/descendant envelope, independent observation when caller reporting fails, and explicit terminal/UNKNOWN rules. It cannot acquire a stale PID after failure, rearm after its own UNKNOWN or terminal event, or rename the controller's revoked authority. Elapsed time, local release and signal success cannot mark COMPLETE.

This is a proposed ownership-contract change—not an adopted guardian or runtime policy. [Accepted decision014](../../decisions/014-authenticated-local-request-evidence.md) provides staged synthetic authentication direction, not adoption of this new owner. [Accepted decision012](../../decisions/012-synthetic-engineering-custody-preconditions.md) is not issuer-lifetime authority. Any accepted ownership change requires a new decision and human adoption before runtime wiring. No host privilege, cgroup, container, pidfd, helper or capability is assumed.

The next draft must define failure assumptions without silently weakening an accepted contract, freeze marker-only code and actual relied-on sources/declarations, retain genuine behavior RED→GREEN evidence, and specify a finite cleanup/UNKNOWN matrix. A separately admitted public runtime attempt and independent review are still required. None permits a private phase automatically.

## Evidence limits

Direct native Root inspection produced67 returned source reads with0 UNKNOWN in its frozen prefix. The unchanged observer preserved3 historical UNKNOWN reads elsewhere in the697-response whole-session journal; they are not this unit's missing inputs and were not retroactively qualified. All12 timer/child raw pins matched the original additive manifest. Read-response metadata and hashes do not prove comprehension or runtime safety.

No product code, tests, RED/GREEN sequence, public lifecycle experiment or private operation was delivered in this source unit. No broad suite was run for this prose-only record. Native coding-model traffic and metadata observer/hash commands occurred; they are not product-provider tests. The closed failed goal is not reopened by this evidence.

Runtime dependency closure remains incomplete if a candidate relies on uninspected linked-list/priority-queue/hook bodies, AsyncWrap callback internals, net/stream/pipe delegates, Writable.end implementation, spawn/fork/session details, platform polling/clock helpers, handle predicates or KeyObject memory semantics. These findings reject specific shortcuts; they do not prove that every architecture is impossible, establish bounded native/kernel behavior, prove erasure, or constitute independently reviewed F1_NOT_READY/private readiness.
