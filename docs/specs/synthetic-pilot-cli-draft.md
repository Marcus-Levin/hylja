# Public-synthetic pilot controller and CLI draft

Status: PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY under
[proposed016](../decisions/016-synthetic-multi-asset-pilot-draft.md). No accepted
classification, policy, CREATE, DISPLAY, authentication, custody, provider or scoring
permission. [Capabilities](../capabilities.md) alone owns product implementation/limits.
This P3 contract is frozen before new behavior tests and all-refusing baselines.
The reviewed [P1](synthetic-pilot-draft.md) and [P2](synthetic-pilot-owner-draft.md)
contracts remain unchanged; legacy015 is neither modified nor adopted.

## Pure controller

[`controller.mjs`](../../evaluations/synthetic-pilot-draft/controller.mjs) exports ONLY
`preparePilot(inputJson)` and `completePilot(inputJson,replyJson,controlsJson)`.
Every parameter is a primitive string, nonempty printable ASCII, bounded before parsing,
complete compact canonical JSON (`JSON.stringify(parsed)===raw`), without caller hooks.
Only parsed owned records are inspected. Every object below has precisely the stated keys
in the stated order, except nested P1 components whose existing key-set semantics survive.
Fixed frozen failure: `{status:'REFUSED',reason:'PILOT_CONTROLLER_REFUSED'}` with no
answer, trace, prefix, exception, original or partial handle.

Input cap32768; exact ordered `{version:1,context:<P1>,message:<P1>,log:<P1>}`.
Reviewed `transformPilot` is the sole full input/reference authority: serialize the three
snapshotted components into its primitive arguments; retain every P1 cap/schema/set check.
`preparePilot` returns its exact frozen TRANSFORMED result, or controller refusal. No
originals map, list, lookup or new derivation is exported. The full input is public synthetic.

Reply cap8192; exact ordered `{version:1,task:<input task>,results:[1..8 records]}`.
Records must match the entire declared reference list in exact order, with no omission,
duplicate, extra, legacy, unknown, foreign or reordered reference. ERROR_COUNTS records
are exactly `{reference:<own80byte P1 ref>,errorCount:<integer0..128>}`. FIRST_ERRORS
records are exactly `{reference:<own ref>,firstError:null|{tick:<integer0..1000000>,
code:'START'|'STOP'|'FAILURE'}}`. INFO|ERROR and START|STOP|FAILURE remain the P1
enums; WARN/BOOT/READY/FAIL are never admitted. Unknown provider authority fields anywhere
(scope/session/context/purpose/operation/destination/revision/grant/clock/now included)
refuse, never grant anything. Validate the WHOLE reply before restoration. Do not compute
truth to replace or silently correct provider semantics: schema permission is not accuracy.

Controls cap8192; exact canonical ARRAY in declared original order, equal length.
Every item is ordered `{asset:<that public original>,configJson:<P2 config string>,
displayJson:<P2 DISPLAY string>,now:<integer0..1000000>,revokeJson:null|<P2 admin string>}`.
Each embedded string is primitive printable ASCII, nonempty, cap1024; P2 exclusively
validates its contract. Caller/operator supplies controls independently of provider reply.
No clock/config/grant default or inference from reply. Validate all control shapes first,
then construct one independent `createPilotOwner` per asset/context. If non-null, invoke
that owner's `revoke(revokeJson,now)` and require REVOKED. Invoke each `displayOne`
with only that pair's reply reference and independently supplied DISPLAY/now. Stage all
restored results privately. ANY constructor/admin/display denial discards the whole answer.
No prefix release, no bulk-reference lookup API. USE is not DISPLAY; DISPLAY is not EXPORT.
Fresh per-call owners are not persistent/global revocation, authentication or currentness.

Success is exactly frozen `{status:'DISPLAYED',mode:'PUBLIC_DRAFT_ONLY',answerJson:<string>}`.
The canonical answer is ordered `{version:1,mode:'PUBLIC_DRAFT_ONLY',task:<input task>,
results:[declared order]}`; records replace reference with `asset:<owner-restored original>`
then retain errorCount or firstError unchanged. All release predicates are PUBLIC FIXTURE
ONLY, not real authorization; no intermediate original or trace is returned.

## Explicit offline responder

[`responder.mjs`](../../evaluations/synthetic-pilot-draft/responder.mjs) exports ONLY
`respondPilot(cloakedJson)`, primitive canonical printable ASCII cap32768. Validate the
entire exact ordered P1 cloak shape, 1..8 unique80byte pilot refs, task, 1..128 ordered
closed events, reference membership/set equality, tick/enums. No original marker passes.
ERROR_COUNTS counts ERROR level irrespective of code. FIRST_ERRORS chooses minimum ERROR
tick, stable original input-index tie, with explicit null when none. Exact frozen success:
`{status:'RESPONDED',mode:'PUBLIC_DRAFT_ONLY',replyJson:<ordered reply above>}`; fixed frozen
failure `{status:'REFUSED',reason:'PILOT_RESPONDER_REFUSED'}`. Pure deterministic offline
fixture logic is NEVER real model utility evidence. No provider, keys, lookup or I/O.

## Descriptor-only CLI

[`cli.mjs`](../../evaluations/synthetic-pilot-draft/cli.mjs) accepts exactly one verb
cloak|display|demo. No paths/options/callback/shell/provider surface. Stdin contains ONE
canonical ordered packet, printable ASCII cap65536, plus ONE optional terminal LF:

- cloak: `{version:1,inputJson:<input string>}`
- display: `{version:1,inputJson:<input>,replyJson:<reply>,controlsJson:<controls>}`
- demo: `{version:1,inputJson:<input>,controlsJson:<controls>}`; explicitly offline responder.

Read descriptor0 only with `fs.readSync(0,buffer,offset,length,null)` into one zero-initialized
`Buffer.alloc(65538)` (cap+optionalLF+overflow). Positive progress is bounded by buffer size;
zero is EOF. Check raw bytes BEFORE decoding (`toString('utf8',0,end)`), so non-ASCII cannot
be masked by ASCII decoding. Strip at most one final LF; reject other nonprintable bytes,
empty/oversize/noncanonical/unknown packets. No open/file/path/descriptor substitution.
Invalid argv refuses before reading. On logical refusal stdout ONLY controller refusal JSON
plus LF; exitCode2. Success stdout exactly cloakedJson or answerJson plus LF; exitCode0.
Stage the entire authorized string before first write. `Buffer.from(text,'utf8')` then
positive-progress `fs.writeSync(1,buffer,offset,remaining,null)` owns descriptor1 only.
I/O/allocation exception gives exitCode1 without raw stderr or second refusal after output
begins. Partial OS output is NOT transactional rollback. No timer, shutdown/private-lifetime,
secure-erasure, descriptor provenance, finite native blocking or sandbox claim.

CLI tests use only fixed `process.execPath`, fixed repository CLI path and frozen finite
verbs/input cases via `spawnSync`, pipe stdio, shell:false, timeout2000ms, maxBuffer131072,
encoding:'utf8', and fixed PATH/LC_ALL/OPENSSL_CONF environment (no inherited NODE_OPTIONS).
Captured-output assertions compare only booleans/numbers, never raw captured diagnostics.
Timeout sends default SIGTERM; spawnSync waits for actual exit and may block if it is ignored.
The public child registers no signal handlers/extra children. This is no private containment
or independent wall-clock bound. Native API errors/closed-descriptor faults remain unproven.
Root's separate first physical-method gate precedes CLI RED and all physical/combined tests.

## Frozen public preparation corpus

[`cases.mjs`](../../evaluations/synthetic-pilot-draft/cases.mjs) exports ONLY frozen
`pilotCases`, exactly12 frozen `{id,inputJson,controlsJson}` objects C01..C12. No answers,
ground truth, provider/harness dependency or I/O in the export. Each context suffix is its
id for scope/session/context; originals are SYNTHETIC-ASSET-CnnA through CnnH as declared.
Independent per-asset display/admin destination suffixes are CnnA..H, createdAt10,
expiresAt100, revision1, now20, revokeJson:null. Each event below is in listed input order:

| Case/task | Events (asset suffix,tick,level,code) |
|---|---|
| C01 counts | A,1,INFO,FAILURE |
| C02 counts | A,1,ERROR,START; A,2,ERROR,STOP; A,3,INFO,FAILURE |
| C03 counts | A,9,ERROR,STOP; A,2,ERROR,STOP |
| C04 counts | A,4,INFO,FAILURE; B,2,ERROR,STOP |
| C05 counts | A,8,INFO,START; B,7,ERROR,STOP; C,6,INFO,FAILURE; D,5,ERROR,START; E,4,INFO,STOP; F,3,ERROR,FAILURE; G,2,INFO,START; H,1,ERROR,STOP |
| C06 counts | A,3,ERROR,START; A,2,INFO,FAILURE; B,1,INFO,FAILURE |
| C07 first | A,1,INFO,FAILURE |
| C08 first | A,9,ERROR,STOP; A,2,ERROR,FAILURE |
| C09 first | A,5,ERROR,START; A,5,ERROR,FAILURE |
| C10 first | A,8,INFO,FAILURE; B,2,ERROR,STOP; B,2,ERROR,FAILURE |
| C11 first | A,1000000,ERROR,STOP; A,0,ERROR,START |
| C12 first | A,1,INFO,START |

No corpus/prompt tuning after future observations. Independently prepared ORIGINAL and
CLOAKED requests have no experiment-specific whole-arm byte cap and use separate blind
native contexts. Freeze complete requests, including operational instructions, before model
traffic; provider context limits and admitted time/token budgets still apply. This does not
remove P1/P2/controller/CLI input, reply or control bounds or automatically admit the corpus
as model context. Ground truth stays separate and never shown to responders. Public
cases/tests are unscored, not held-out/promotion/release evidence.

## Verification boundary

The dedicated script names five literal transform/owner/controller/responder/cli test paths.
Default product test enumeration remains unchanged. Dedicated synthetic CI uses existing
pinned actions/Node24.15.0/npm10.9.9 and no model/deployment effects; actual CI requires a
published run receipt, not this proposal. Tests exercise known fixture invariants, generated
multi-reference cases, whole-answer late-denial atomicity and actual public stdin/stdout.
They establish no real authentication, protected egress, accepted reversible runtime, private
custody/erasure, production utility, authoritative scoring, human adoption or global lifecycle.
