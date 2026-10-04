# Egress send-point fixture evidence (E2)

Status: bounded **public synthetic development evidence** produced by [test/egress-sendpoint.e2e.test.mjs](../../test/egress-sendpoint.e2e.test.mjs) for [#154](https://github.com/Marcus-Levin/hylja/issues/154), the E2 slice of [the E2E critical-path proposal](proposals/2026-10-04/e2e-critical-path.md). It is **not** a held-out result, **not** a production adapter, **not** a gateway or a managed egress boundary, and **not** an authentication proof. It does not close, re-tick or satisfy parent [#19](https://github.com/Marcus-Levin/hylja/issues/19); implementation status still lives only in [capabilities.md](../capabilities.md).

## Command

```sh
npm ci --ignore-scripts --no-fund   # once per worktree; lockfile-driven, no lifecycle scripts
npm run build
node --test test/egress-sendpoint.e2e.test.mjs
```

The file matches the `test/*.test.mjs` glob in the [`npm test`](../../package.json) script, so the same file also runs in the full suite. `npm run check:docs` and `npm run check:fixtures` cover the note and the tracked paths.

## What the fixture is

- **Trusted test bindings.** The policy boundary, the bundle pin, the classification digest, the destination profile and the sentinel known-originals key are supplied by the test, exactly as a trusted integration would supply them. They are test fixtures, **not authenticated principals, workloads, tenant memberships or a trusted control plane**. The policy contract's own limitation stands: these inputs are trusted because the caller is trusted, not because the module verifies them.
- **Explicit serialization.** The body is serialized from ordered fields and the metadata from an ordered header list; the sentinel is checked over the **whole post-serialization wire image**, body and metadata together, which is the exact byte string the loopback sink receives.
- **A real loopback sink.** A `node:net` server bound to `127.0.0.1` on an **OS-assigned ephemeral port** records the raw inbound bytes, the connection count and the total byte count. This is the only transport used: no provider traffic, no external connection, no credentials, no real customer or infrastructure data. Every fixture value is invented and non-routable (`*.invalid`, `example.invalid`, loopback).
- **Policy owns the treatment.** The test-local send point requires the `decidePolicy` result as an argument and re-checks it itself: it releases only on `SELECTED` with treatment `KEEP` for this narrow fixture **and** sentinel `ALLOW`, on the prepared path and on the streaming path alike. A send argument assembled directly from a completed stream is not a release on its own; a semantic recommendation is never a release trigger, and the shipped [policy contract](../contracts/policy-contract.md) is unchanged.

## What each test proves

| Test | Claim |
|---|---|
| Safe fixture | Real `decidePolicy` returns `SELECTED`/`KEEP`, real `checkEgress` returns `ALLOW`, and the sink receives exactly the independently declared expected wire bytes, metadata included. |
| Caller buffer mutation | Rewriting the caller's serialized body after the check does not change the received copy: the sink receives the sentinel's private ALLOW copy, not the caller's buffer. |
| Planted original missed upstream | A planted original that the primary detector stack genuinely misses (`detectSecrets` finds nothing) is caught by the sentinel before send, and the sink receives zero bytes. This deliberately missed candidate is **not** counted as candidate-recall success anywhere. |
| Reintroduction and encoding | A planted original reintroduced during body serialization, during metadata serialization, or in a base64 metadata variant each produce zero received bytes. |
| Policy refusals | Real `DENIED` (`RULE_BLOCK`) and `HELD` (`RULE_REVIEW`) decisions produce zero sent bytes and no sentinel call. |
| Restrictive outcomes | `sentinelUnavailable()`, undecodable bytes, content the sentinel cannot inspect, a **same-destination different-profile-digest** mismatch at the send point, a destination-id mismatch and cross-tenant known-original handle misuse each produce zero sent bytes and zero connections. |
| Evidence hygiene | Policy decisions, sentinel results, regression records and a thrown configuration error carry no planted original. |
| Streaming holdback | Real `createStreamGate` released through the same policy gate as the prepared path: no chunk reaches the sink before `end()`, a planted secret split across chunk boundaries produces zero received bytes, and the completed safe stream sends only its approved complete-message copy. |
| Streaming under a refused decision | A stream whose real `decidePolicy` result is `DENIED` or `HELD` sends zero bytes and opens zero connections, although the sentinel's own `ALLOW` and its release copy are present — including when the send argument is assembled directly from the completed stream, which is the path an earlier revision left ungated. |

Deadlines are finite (a bounded rejection per loopback step and a per-test timeout), cleanup destroys every tracked client and server socket before closing the listener, and no test sleeps or polls to guess at timing.

## Red before green

### First round (initial implementation)

The release path was first made deliberately wrong in the test-local adapter: the policy gate was skipped, the send point wrote its own caller buffer instead of the sentinel's ALLOW copy, and the stream wrapper forwarded each chunk the instant it arrived. The same nine tests then failed (exit 1, 5 pass / 4 fail):

```text
not ok 2 - mutating the caller buffer after the check cannot change the received ALLOW copy
  error: Expected values to be strictly equal:  true !== false

not ok 5 - policy DENIED and HELD results reach the sink as zero bytes
  error: Expected values to be strictly equal:  + undefined  - 'policy'

not ok 8 - streaming releases nothing before completion and a split planted secret produces zero received bytes
  error: the completed stream is still the only thing the sink has
         602 !== 301

not ok 9 - a completed safe stream sends only its approved complete-message copy
  error: deadline exceeded: loopback response
```

That output is retained verbatim, including the assertion message as it read then. What the `602 !== 301` line actually establishes is narrower than an earlier draft of this note claimed: **602 is exactly twice the single approved 301-byte message** (`2 x 301`), so the sink received the safe stream's bytes a second time, which is what an ungated wrapper that forwarded bytes as they arrived and again at completion looks like. It is **not** a measurement of planted bytes arriving: the planted stream's own wire image is 275 bytes, so the count cannot be it either, and the failing assertion runs synchronously inside that stream's push loop, on its first 3-byte chunk, before the loopback can deliver writes that are still in flight. An earlier version of this note attributed the count to the split planted chunks, and that attribution was wrong. The counterexample therefore proves **holdback was missing** — bytes left the send point before the gate's decision — and nothing more. The planted-chunk claim is carried by the passing assertions, which run after an awaited send and so observe the whole exchange: 1 connection, 301 bytes, 1 capture. That in-loop assertion has since been reworded ("no planted-stream byte has been delivered while its chunks are pushed") and annotated to say why a synchronous counter is the weaker observation; the numbers it checks are unchanged.

Restoring the adapter produced exit 0 with 9 tests, 9 pass, 0 fail.

### Second round (independent review of tree `12a0556e0497056db09ae8751c5358cbbdd81809`)

Independent review of that tree returned CHANGES REQUESTED with four findings: the streaming release path took no policy decision, the profile-mismatch case changed the destination id instead of the profile digest, the red evidence above was misattributed, and a privacy assertion used a planted original as its own failure message. The first is a behavioural gap in the test-local send point; the other three are a strengthened negative case and two corrections.

Its counterexample: with the send point's policy requirement removed again — the exact pre-fix defect — one test failed (exit 1, 10 tests, 9 pass / 1 fail):

```text
not ok 9 - a stream whose real policy decision is DENIED or HELD releases zero bytes and makes no contact
  error: |-
    Expected values to be strictly equal:

    1 !== 0
```

That single failure is the defect itself: with the sentinel's `ALLOW` and its release copy in hand and a real `DENIED` decision from `decidePolicy`, one request still reached the sink. The neighbouring assertion through `prepareStream` passed in the same run, so the failure isolates the ungated send argument rather than the gate itself. Restoring the requirement produced exit 0 with 10 tests, 10 pass, 0 fail. The profile-digest case and the privacy-safe assertion label are additions to already-passing product behaviour and have no red state of their own.

## Limits

What this evidence does **not** establish:

- **No cloaking path.** There is no transformation engine, no rewriting of the payload, and no masking or removal step in this fixture. The released bytes equal the serialized input bytes; the claim is only that the final-byte check and policy gate decide *whether* those bytes are sent.
- **No production adapter, gateway or enforcement boundary.** The loopback adapter is test-local, binds an ephemeral port and authenticates nothing. Per [capabilities.md](../capabilities.md#assurance-governance-and-release-seams), the sentinel is a core with no adapter at a real send point; this note does not change that.
- **No authentication proof.** The trusted boundary, bundle pin and sentinel key are supplied by the test. No principal, workload, tenant membership, session, purpose or control-plane digest is verified by anything here.
- **Not a held-out or scored result.** It is public development evidence over synthetic fixtures. It does not tune, measure or claim recall against any frozen set, and it authorizes no freeze, custody, scoring or release. [Decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) stays `proposed`; no draft semantics are adopted here.
- **Not general streaming coverage.** Holdback is proved for one split-stream case over one fixture. SSE framing, UTF-8 and tool-argument delta boundaries, backpressure and late denial across real protocols remain with the gateway work.
- **Not coverage of every send point.** One controlled sink with one destination profile stands in for none of the production sinks named in [the threat model](../threat-model.md#priority-abuse-cases).

Still owned by [#19](https://github.com/Marcus-Levin/hylja/issues/19) and unclaimed here: full candidate-source and transform composition, semantic-shadow composition, production send-point coverage, general streaming protocols, and every other parent obligation.
