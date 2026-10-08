# F1 public-marker lifetime owner draft

Status: PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY. Not adopted.
This is a frozen abstract experiment contract, not accepted runtime authority.
[Decision017](../decisions/017-independent-public-lifetime-owner-draft.md) owns the proposed
ownership choice and human adoption gate. [#275](https://github.com/Marcus-Levin/hylja/issues/275)
owns work status; [capabilities](../capabilities.md) owns implemented behavior and software limits.

## Source basis

Read-only historical inputs (external retained records, not repository runtime dependencies):

- `/home/marcus/.herdr/worktrees/hylja/issue269-f1-containment-20261007/docs/research/2026-10-07/f1-private-lifetime.md`:
  source evidence / proposed prerequisite / unreviewed, not adopted.
- `/home/marcus/.local/state/hylja-delivery/f1-containment-2026-10-07/FINAL-REPORT.md`:
  historical outcome evidence, not contract authority or a qualified impossibility proof.
- `/home/marcus/.local/state/hylja-delivery/f1-containment-2026-10-07/baseline-packet/`:
  `method.md`, `method-manifest.json`, and all twelve frozen code/test bodies:
  `controller.mjs`, `entry.mjs`, `env-test.mjs`, `lifecycle.mjs`, `ownership-test.mjs`,
  `plan-test.mjs`, `plan.mjs`, `private-holder.mjs`, `public-files.mjs`, `req-pipe.sh`,
  `settlement-test.mjs`, `stop-test.mjs`. The manifest's thirteen `codeSha256` bindings,
  including `method.md`, identify the baseline; the new model must not import or execute it.

The baseline controller's `release()` clears its timers and revokes local ownership;
`unknown()` can resolve before holder retirement. The holder's `req()` retains requests,
`hold()` retains an interval, and `retire()` requires the input lifecycle predicate. Its end
attempt precedes `stdin.end`; a throw sets failure without inventing callback settlement.
The proposed owner must preserve those distinctions, not reuse the old authority after UNKNOWN.

Historical Node v24.15.0/libuv/Linux links in the source record identify inspected reference
bodies only. This abstract contract selects no native API and assumes no installed capability,
linked native dependency closure, kernel qualification or bounded process-control mechanism.
Any future concrete API needs exact version/source and complete relied-on bodies/types before
its separate native gate. No new source acquisition or host capability inspection is implied.
[Accepted012](../decisions/012-synthetic-engineering-custody-preconditions.md) gives no custody,
key or CREATE authority. [Accepted014](../decisions/014-authenticated-local-request-evidence.md)
and its [staged proposal](../development/proposals/2026-10-06/authenticated-local-request.md)
do not adopt this owner. Existing accepted v1 and decisions 013/014 stay unchanged.

## Supported abstract world and ownership

One lifetime owner, one immutable attempt, one holder and one input child form the complete
**modeled** envelope. No additional children, detached copies or shared owner exist in this
world. Events are serialized and finite; an independently provisioned observation owner reports
truthful synthetic facts. This assumption is test scaffolding, not OS authentication.

- Lifetime owner owns immutable identities, marker, absolute window, clock high-water, authority,
  effect counters, stop latch, input facts and terminal observations. It never transfers them.
- Control owner has only ACQUIRE, GO, INPUT_BEGIN, END_RETURN and END_THROW command access.
  It cannot assert callback, exit, close, reap or absence facts.
- Reporting controller may read a public snapshot and report its own loss. It cannot replace
  authority or clear timers/facts. Controller loss stops effects even if observation survives.
- Observation owner alone holds a distinct opaque observer handle for synthetic evidence.
  Owner/observer loss is UNKNOWN, not a handoff to the reporting controller.
- Holder/input child are labels in C1, not processes. The model emits only effect counts, never
  a real write, kill, close request, reap request or probe.

Acquisition must precede GO and input attempt. It establishes complete modeled ownership of
the envelope fixed at construction, not discovery of a stale PID after failure. A future native adapter must
establish that envelope independently before GO; if it cannot, it must refuse private admission.

## Exact future C1 surface

Only one module export is allowed: `createPublicLifetimeDraft(config)`. No core index export,
accepted policy/authorization/crypto import, ambient timer, filesystem or native effect.
The module belongs only in a separately admitted isolated evaluation directory.

Construction accepts exactly the own data fields:

| Field | Exact value domain |
|---|---|
| `ownerId`, `attemptId`, `controlId`, `observerId` | distinct ASCII strings matching `^SYNTHETIC-[A-Z0-9]{1,32}$` |
| `marker` | exactly `SYNTHETIC-PUBLIC-MARKER` |
| `began`, `deadline` | safe integer ticks, `0 <= began < deadline <= 1000000`; `deadline - began <= 10000` |

These are legitimate bounded public prototype inputs, not a corpus, private-holder input,
model-request budget, secret token, principal or authentication claim. No caller-selected path,
PID, signal, callback, executable, free text, private blob, credential or lookup is admitted.

Construction result is exactly `{status: 'CREATED', control, observer, report}` or
`{status: 'REFUSED', reason: 'INPUT_REFUSED'}`. The three created handles are distinct frozen,
nonserializable closure objects with only these methods:

- `control.apply(frame)`;
- `observer.observe(frame)`;
- `report.lost(now)` and `report.read()`.

Each construction has private state. A handle closes over only its own construction; calling it
cannot reach another owner's state, even when labels are equal. Frames with mismatched labels
refuse. Equal-label primitive frames are indistinguishable and are not authenticated provenance;
this model makes no replay/identity proof across equal-label constructions. The closure, not the
labels, isolates state. Possession of a test handle grants only access to that synthetic model.

A control frame has exactly `{ownerId, attemptId, controlId, kind, now}`; an observer frame has
exactly `{ownerId, attemptId, observerId, kind, now}`. Each identity equals the construction
snapshot. Kinds are the closed lists below. No payload or optional fields. `now` is a safe integer
in `[0, 1000000]`. `report.lost` accepts that primitive alone; `read` accepts no arguments.
Extra arguments refuse. A malformed read returns the fixed INPUT_REFUSED refusal without
mutating state; an ordinary read returns the snapshot below. All apply/observe/lost results are exactly
`{status: 'APPLIED', reason: 'NONE'}` or `{status: 'REFUSED', reason: R}`.
A valid transition, including an explicit stop/failure observation, returns APPLIED/NONE;
its state reason is read separately. A validation, clock or ordering refusal returns REFUSED
with that refusal reason. Accepted passive observations after UNKNOWN return APPLIED/NONE
without changing the state's first stop reason.

Fixed reason vocabulary: `NONE`, `INPUT_REFUSED`, `IDENTITY_REFUSED`, `ORDER_REFUSED`,
`CLOCK_ROLLBACK`, `EXPIRED`, `REVOKED`, `CONTROLLER_LOST`, `OWNER_LOST`, `OBSERVER_LOST`,
`FAULT`, `UNSUPPORTED`, `INPUT_FAILED`, `STOPPED`, `CLOSED`.
Never return an exception, submitted value, native error, event frame or marker image.
Construction refusal creates no owner. A valid owner's malformed call returns a fixed refusal
and latches UNKNOWN (`INPUT_REFUSED`), except already terminal owners as specified below.

Validate a capped snapshot of own property descriptors once at each boundary; only plain
objects with Object.prototype or null prototype and enumerable data properties are admitted.
Reject unknown/missing fields, symbols, accessors, arrays, coercion, noncanonical numbers
(including negative zero), inherited fields and hostile/throwing inspection. Do not re-enumerate
or invoke getters after validation. Snapshot strings/numbers and never retain caller objects.
Proxy traps/nonreturning inspection cannot be preempted by this pure seam; they are unsupported,
not claimed bounded in wall time. Descriptor/key-count caps are 7 for config and 5 for frames.

`report.read()` returns only a frozen snapshot with these fields, in this meaning:

| Fields | Domain / initial value |
|---|---|
| `status`, `reason` | `MODEL_PENDING` / `NONE`; terminal statuses `MODEL_COMPLETE`, `MODEL_UNKNOWN` |
| `highWater`, `deadline` | initial `began`, immutable construction `deadline` |
| `acquired`, `go`, `attempted`, `endReturned`, `endCallback`, `flushed`, `noInput` | booleans, initially false |
| `exited`, `childClosed`, `reaped`, `envelopeAbsent`, `retired` | booleans; initially false except `retired=true` (known no attempt) |
| `goEffects`, `inputEffects` | integers 0 or 1, initially 0 |

No event journal, identities, marker, original list/map, bulk resolution or raw input is returned.
`retired` means only model eligibility to release the input record, not erasure or envelope death.

## Clock, authority and effect order

For each well-shaped matched call with a clock, first compare `now` to high-water. A decrease
latches UNKNOWN/CLOCK_ROLLBACK; equality is permitted. Otherwise high-water becomes `now`.
If `now >= deadline`, latch UNKNOWN/EXPIRED before applying its action. Never reset began,
deadline or high-water; construction of another owner is not renewal of this attempt.
An invalid/foreign frame latches its fixed refusal without using its supplied clock.

Current effect authority means MODEL_PENDING, acquired, no stop, `now < deadline`, and no
observed exit or child close. Each GO/INPUT_BEGIN increments its corresponding counter once
in the same reduction as its last guard. There is no callback, await, host read or emitted native
effect between that guard and counter increment. All validation precedes mutation; refuse the
whole action, never a partial effect. Re-read no caller property at this point.

A clock supplied by a caller is only test input. Failure to advance it does not prove finite
wall-clock progress. No timer exists in C1, and no same-event-loop timer or reference drop
supplies independent preemption in C2. Stall, scheduler/kernel uncertainty and missing
independent observations must remain unsupported for private admission.

## Closed transitions

Every row also requires matched identities, valid clock and no earlier stop. Invalid ordering
latches MODEL_UNKNOWN/ORDER_REFUSED and emits no effect. No omitted transition is allowed.

| Handle / kind | Preconditions | Atomic change |
|---|---|---|
| control / `ACQUIRE` | pending, not acquired, no GO/input/terminal fact | acquired=true; no effect |
| control / `GO` | current authority, not go | go=true, goEffects=1 |
| control / `INPUT_BEGIN` | current authority, go, not attempted, not noInput | attempted=true, retired=false, inputEffects=1; input call is now on stack |
| control / `END_RETURN` | attempted, not endReturned | endReturned=true; recompute retirement |
| control / `END_THROW` | attempted, not endReturned | endReturned=true; UNKNOWN/INPUT_FAILED; no invented callback |
| observer / `END_OK` | attempted, not endCallback | endCallback=true, flushed=true; recompute retirement |
| observer / `END_FAILED` | attempted, not endCallback | endCallback=true, flushed=false; UNKNOWN/INPUT_FAILED; recompute retirement |
| observer / `EXIT_OK` | acquired, not exited | exited=true; revoke effect authority, not a settlement fact |
| observer / `CHILD_CLOSE` | exited, not childClosed | childClosed=true; revoke effect authority; recompute retirement |
| observer / `REAP` | exited, not reaped | reaped=true; independently owned wait-status observation, not signal success |
| observer / `ENVELOPE_ABSENT` | childClosed, reaped, not envelopeAbsent | envelopeAbsent=true; complete modeled holder/child envelope, not parent-only absence |
| observer / `NO_INPUT` | exited, childClosed, not attempted, not noInput | noInput=true; independent confirmation of never attempted |
| observer / `FINALIZE` | complete predicate below | MODEL_COMPLETE/NONE; no effect |
| observer / `REVOKE`, `OWNER_LOST`, `OBSERVER_LOST`, `FAULT`, `UNSUPPORTED` | pending | UNKNOWN with respective fixed reason (`REVOKE` maps to REVOKED) |
| report / lost | pending | UNKNOWN/CONTROLLER_LOST |

END_OK may arrive before END_RETURN or after CHILD_CLOSE; actual callback and actual child
close are independent facts. Retirement after an attempt requires `endReturned && endCallback
&& childClosed`, including failed callbacks: failure may settle but never authorize success.
Before any attempt, retirement is true, even though the acquired envelope may still exist.
No input success follows from writable-ended/destroyed flags, a synchronous throw, local
release, timeout, signal return, reported kill, handle close, or recipient consumption.

An exit/close is not itself UNKNOWN on the supported normal path: it permanently forbids
new effects but permits independently owned passive settlement/reap/absence observations.
REAP and ENVELOPE_ABSENT are **observations**, never instructions to probe or reap late.
A future native method must already own such observations; it cannot acquire them by a new
signal/probe after exit/close. Unknown exit status, abnormal exit, missing ownership or inability
to attest the entire envelope uses FAULT/UNSUPPORTED, never EXIT_OK or ENVELOPE_ABSENT.

## Sticky stops and terminal predicate

After MODEL_UNKNOWN, all effect/control/report-loss calls return REFUSED/STOPPED, never
increment counters. The sole control exception is passive END_RETURN/END_THROW bookkeeping
for the already attempted input. Only well-shaped matched passive END_OK/END_FAILED,
END_RETURN/END_THROW, EXIT_OK, CHILD_CLOSE, REAP, ENVELOPE_ABSENT and NO_INPUT may
record new facts under their original
ordering rules, as exceptions to the table's no-earlier-stop rule. Their clocks may only increase
high-water; a late rollback refuses without recording the fact, while expiry permits passive
fact recording. Neither clears the first reason. Any invalid late call refuses without altering
the first reason. Recording these facts allows F3 retirement to be distinguished from abandonment; FINALIZE always refuses.
No cleanup effect, signal, probe, escalation, retry, next attempt or authority reacquisition.
After MODEL_COMPLETE every mutation returns REFUSED/CLOSED; read remains available.

MODEL_COMPLETE requires all of:

- acquired, MODEL_PENDING, no sticky failure, fresh nonrollback clock;
- exited AND childClosed AND reaped AND envelopeAbsent;
- input either independently confirmed never attempted (`noInput && !attempted`), or attempted
  with real successful end callback, returned end call and retirement
  (`attempted && endReturned && endCallback && flushed && retired`);
- GO/input counters coherent with flags; attempted implies GO; no incomplete input stack.

Never-GO can therefore complete only with independently observed normal terminal facts and
NO_INPUT; lack of GO alone does not assert absence. GO without attempted input also needs
NO_INPUT. Completion cannot be manufactured from STOPPED/UNKNOWN, even if later facts settle.

This predicate is **MODEL_COMPLETE**, not native/private COMPLETE. A future native COMPLETE
requires real evidence corresponding to every fact, ownership of every process/copy in its
explicit supported envelope, and an independently progressing terminal observation path.
C1 JSON-shaped evidence cannot authenticate that. Native callback/close/reaping observation
does not prove heap, RSS, swap or native-copy erasure. No finite private lifetime is established
for stalled native calls, escaped descendants, owner loss, unknown scheduler/kernel faults,
missing callback/close, hostile hosts or observation outage. Refuse private work whenever such
unsupported facts remain; do not call that a universal impossibility proof or qualified NOT_READY.

## Deterministic examples and future RED matrix

Examples use distinct SYNTHETIC-A/B/C/D labels and began=0, deadline=100. Each event below
has the required bound frame and monotonically increasing ticks strictly below 100 unless
specified. Expected outcomes are independent of the implementation, not inferred from its labels.
All are future C1 tests, not executed evidence in this prose unit.

| Case | Trace / intervention | Expected invariant |
|---|---|---|
| Normal | ACQUIRE, GO, INPUT_BEGIN, END_OK, END_RETURN, EXIT_OK, CHILD_CLOSE, REAP, ENVELOPE_ABSENT, FINALIZE | MODEL_COMPLETE; counters 1/1, retired=true |
| Never GO | ACQUIRE, EXIT_OK, CHILD_CLOSE, NO_INPUT, REAP, ENVELOPE_ABSENT, FINALIZE | MODEL_COMPLETE; counters 0/0, noInput=true |
| Callback after close | ACQUIRE, GO, INPUT_BEGIN, END_RETURN, EXIT_OK, CHILD_CLOSE; then END_OK, REAP, ENVELOPE_ABSENT, FINALIZE | retired=false before callback, true after; completion only at final predicate |
| Callback withheld | Same attempted trace without END_OK, then FINALIZE | UNKNOWN/ORDER_REFUSED, retired=false; no fabricated settlement |
| Child close withheld | END_OK and END_RETURN, EXIT_OK, REAP; FINALIZE | UNKNOWN/ORDER_REFUSED; retired=false; parent reap is insufficient |
| Throw after callback | END_OK during input stack, then END_THROW | UNKNOWN/INPUT_FAILED; no premature completion; later close permits retirement only |
| Failed callback | END_FAILED, END_RETURN, EXIT_OK, CHILD_CLOSE | UNKNOWN/INPUT_FAILED; retired=true, flushed=false, no completion |
| Revoke | REVOKE before GO or after INPUT_BEGIN | UNKNOWN/REVOKED; future effects zero additional; attempted input remains until both facts |
| Expiry | GO at now=100 after acquisition | UNKNOWN/EXPIRED; goEffects=0; now=101 or a fresh controller cannot revive |
| Rollback | ACQUIRE at 10, GO at 9 | UNKNOWN/CLOCK_ROLLBACK; highWater=10, goEffects=0 |
| Reporting loss | INPUT_BEGIN then report.lost before callback/close | UNKNOWN/CONTROLLER_LOST; owner retains attempted record; passive settlement never completes |
| Owner/observer loss, fault/stall | OWNER_LOST / OBSERVER_LOST / FAULT / UNSUPPORTED | respective sticky UNKNOWN, no next effect; stall is an explicit unsupported event, not a timer proof |
| Foreign identity | Change one owner/attempt/control/observer binding | IDENTITY_REFUSED; only target owner stops; no other owner's state changes |
| Malformed / over-cap | Extra field, accessor, symbol, Unicode identity, bad tick, wrong marker | fixed INPUT_REFUSED, no getter/echo/partial effect |
| Late action / replay | GO twice, INPUT_BEGIN twice, GO after EXIT_OK/CHILD_CLOSE | UNKNOWN/ORDER_REFUSED; counters never exceed 1/1 |
| Unsupported envelope | Claimed signal success or parent-only absence instead of admitted evidence | INPUT_REFUSED or UNSUPPORTED, never MODEL_COMPLETE |

C1 must first retain real behavior RED cases for GO-before-acquisition, callback-only/close-only
retirement, controller-loss abandonment and completion-from-signal shortcuts, then GREEN without
weakening assertions. No prose/implementation grep counts as a behavior test. Generated cases
must cover bounded tick partitions (all boundaries plus varied interiors), both callback/close
orders, sticky-stop positions, repeated events, shape boundaries and interleaved owners. Properties:
counters never increase after stop/exit/close/expiry; no reacquisition; high-water never decreases;
attempted retirement implies callback AND child close AND returned call; UNKNOWN never completes;
handles cannot reach another owner's state and mismatched frames refuse; equal-label frames
carry no cross-owner provenance claim; caller mutation after snapshot cannot
retarget identities/window. All fixtures public and obviously synthetic; no skipped isolation proof.

## Separate public native C2 gate and exclusions

Only after separate Root source/method/provenance admission and independent C0/C1 review may
C2 propose bounded PUBLIC-marker process controls. Freeze actual instrumentation and failure
assumptions first. Pair positive normal/never-GO controls with revoke, expiry, rollback,
controller loss, owner/observer loss, withheld callback, withheld child close, fault/stall,
foreign binding and late-action controls. Observe actual owned input callbacks, exit/wait/reap,
descriptor/child close and full owned absence separately; a pure event double is not that evidence.
No broad public OS matrix is executed or authorized by C0. Missing supported mechanism means
unsupported and private refusal, not substitution by spawnSync timeout, `.killed`, signal return,
PID reuse checks, local descriptor close, timers, reference drops or inferred descendant death.

No private or protected input; keygen/export/DER/CSR/issuer/OpenSSL/TLS/socket/provider/model
operation, native control, authenticator/policy/adapter import, accepted-runtime wiring, scoring,
held-out access, production privacy guarantee, wall-clock preemption or erasure claim here.
Human ownership adoption plus separate source/custody/effect permission remains required before
any private phase; a public prototype, commit or AI approval schedules none automatically.
