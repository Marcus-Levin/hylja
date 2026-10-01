import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ADAPTER_CONFORMANCE_VERSION, CONFORMANCE_REQUIREMENTS, MAX_CONFORMANCE_CASES,
  MAX_CONFORMANCE_SEND_BYTES, runAdapterConformance,
} from '../dist/adapter-conformance.js';
import { canonicalJson } from '../dist/canonical-json.js';
import {
  CLOAKED_TOKEN, PLANTED_CLOAKABLE, PLANTED_UNCLOAKABLE, SYNTHETIC_ADAPTER, SYNTHETIC_APPENDED_PAYLOAD,
  SYNTHETIC_DESTINATION, SYNTHETIC_PROFILE_DIGEST, SYNTHETIC_SCOPE, SYNTHETIC_SENTINEL_SCOPE,
  bypassSyntheticAdapter, compliantSyntheticAdapter, encodingCloakAdapter, sha256Hex,
  syntheticConformanceSuite, unboundReleaseAdapter,
} from '../scripts/synthetic-release-substrate.mjs';

const SUBJECT = Object.freeze({
  artifactSha256: 'a'.repeat(64),
  lockSha256: 'b'.repeat(64),
  sbomSha256: 'c'.repeat(64),
});
const run = (adapter, options = {}) => runAdapterConformance({
  adapter,
  suite: options.suite ?? syntheticConformanceSuite(),
  scopeRef: options.scopeRef ?? SYNTHETIC_SCOPE,
  sentinelScope: SYNTHETIC_SENTINEL_SCOPE,
  destinationProfileDigest: SYNTHETIC_PROFILE_DIGEST,
  subject: options.subject ?? SUBJECT,
  planted: options.planted ?? [PLANTED_CLOAKABLE, PLANTED_UNCLOAKABLE],
  completedAt: options.completedAt ?? 1_700_000_000_000,
});
const violations = (evidence, id) => evidence.cases.find((entry) => entry.id === id)?.violations ?? [];
const caseOutcome = (evidence, id) => evidence.cases.find((entry) => entry.id === id)?.outcome;

test('a compliant synthetic adapter satisfies every requirement of the suite', () => {
  const evidence = run(compliantSyntheticAdapter());
  assert.equal(evidence.version, ADAPTER_CONFORMANCE_VERSION);
  assert.equal(evidence.schemaVersion, 1);
  assert.equal(evidence.adapterId, SYNTHETIC_ADAPTER);
  assert.equal(evidence.scopeRef, SYNTHETIC_SCOPE);
  assert.deepEqual(evidence.subject, SUBJECT);
  assert.equal(evidence.functionalTests, 'PASS');
  assert.equal(evidence.plantedEgress, 'PASS');
  assert.equal(evidence.overall, 'PASS');
  assert.equal(evidence.cases.length, 5);
  for (const entry of evidence.cases) {
    assert.equal(entry.outcome, 'PASS', `${entry.id} must pass for a compliant adapter`);
    assert.ok(entry.requirements.length > 0);
  }
  assert.deepEqual(evidence.cases.map((entry) => entry.kind),
    ['FUNCTIONAL', 'PLANTED_EGRESS', 'PLANTED_EGRESS', 'OPAQUE_PART', 'DESTINATION_BINDING']);
});

test('an adapter that skips the pre-send check passes the functional test but fails conformance', () => {
  const evidence = run(bypassSyntheticAdapter());
  // The ordinary functional requirement still passes: a green unit test is not conformance.
  assert.equal(evidence.functionalTests, 'PASS');
  assert.equal(caseOutcome(evidence, 'functional-clean-request'), 'FAIL');
  assert.equal(caseOutcome(evidence, 'planted-egress-cloakable'), 'FAIL');
  assert.equal(caseOutcome(evidence, 'planted-egress-nested'), 'FAIL');
  assert.equal(caseOutcome(evidence, 'opaque-part-declared'), 'FAIL');
  assert.equal(caseOutcome(evidence, 'redirect-not-authorized'), 'FAIL');
  assert.equal(evidence.plantedEgress, 'FAIL');
  assert.equal(evidence.overall, 'FAIL');
  // The failing requirements are named, and nothing the adapter claimed appears in the evidence.
  const functional = evidence.cases[0];
  assert.equal(functional.outcome, 'FAIL');
  assert.ok(CONFORMANCE_REQUIREMENTS.includes('PRE_SEND_CHECK_CONSULTED'));
  assert.ok(!JSON.stringify(evidence).includes('"PASS","overall"'));
});

test('an adapter self-report cannot buy a conformance pass', () => {
  const liar = bypassSyntheticAdapter();
  const evidence = run({
    ...liar,
    release(request, controls) {
      const result = liar.release(request, controls);
      // Extra self-asserted fields are ignored: outcomes come from the harness observations.
      return { ...result, plantedEgress: 'PASS', overall: 'PASS', functionalTests: 'PASS', conformance: 'PASS' };
    },
  });
  assert.equal(evidence.plantedEgress, 'FAIL');
  assert.equal(evidence.overall, 'FAIL');
  assert.equal(evidence.functionalTests, 'PASS');
});

test('planted originals are found in captured bytes even when the adapter claims to block', () => {
  const declaredBlocker = {
    adapterId: SYNTHETIC_ADAPTER,
    declaredCoverage: { operations: ['model.input'], inspectableParts: ['body.field-0'], unsupportedParts: ['opaque-attachment-0'], sinks: [SYNTHETIC_DESTINATION] },
    release(request, controls) {
      // Sends the planted value and then claims BLOCKED.
      controls.send(request.sendDestinationId, new TextEncoder().encode(`leak = ${PLANTED_CLOAKABLE}`));
      return { fields: [], decision: 'BLOCKED' };
    },
  };
  const evidence = run(declaredBlocker);
  assert.equal(evidence.plantedEgress, 'FAIL');
  assert.equal(evidence.overall, 'FAIL');
  assert.equal(caseOutcome(evidence, 'planted-egress-cloakable'), 'FAIL');
  // The observed bytes are never copied into the evidence document.
  assert.ok(!JSON.stringify(evidence).includes(PLANTED_CLOAKABLE));
  assert.ok(!JSON.stringify(evidence).includes('leak = '));
});

test('a returned field value is treated as protected output too', () => {
  const returnsPlanted = {
    adapterId: SYNTHETIC_ADAPTER,
    declaredCoverage: { operations: ['model.input'], inspectableParts: ['body.field-0'], unsupportedParts: ['opaque-attachment-0'], sinks: [SYNTHETIC_DESTINATION] },
    release(request) {
      return { fields: [{ id: 'field-0', text: `value = ${PLANTED_CLOAKABLE}` }], decision: 'BLOCKED' };
    },
  };
  const evidence = run(returnsPlanted);
  assert.equal(caseOutcome(evidence, 'planted-egress-cloakable'), 'FAIL');
  assert.equal(evidence.plantedEgress, 'FAIL');
});

test('declaring a part unsupported is required and does not excuse releasing it', () => {
  const undeclared = {
    adapterId: SYNTHETIC_ADAPTER,
    declaredCoverage: { operations: ['model.input'], inspectableParts: ['body.field-0'], unsupportedParts: [], sinks: [SYNTHETIC_DESTINATION] },
    release(request, controls) {
      controls.preSendCheck({
        destinationId: request.sendDestinationId, authorizedDestinationId: request.authorizedDestinationId,
        bytes: new Uint8Array(0),
      });
      return { fields: [], decision: 'BLOCKED' };
    },
  };
  assert.equal(caseOutcome(run(undeclared), 'opaque-part-declared'), 'FAIL');

  const declaresButReleases = {
    ...undeclared,
    declaredCoverage: { ...undeclared.declaredCoverage, unsupportedParts: ['opaque-attachment-0'] },
    release(request, controls) {
      controls.preSendCheck({
        destinationId: request.sendDestinationId, authorizedDestinationId: request.authorizedDestinationId,
        bytes: new TextEncoder().encode('opaque bytes'),
      });
      controls.send(request.sendDestinationId, new TextEncoder().encode('opaque bytes'));
      return { fields: [], decision: 'SENT' };
    },
  };
  assert.equal(caseOutcome(run(declaresButReleases), 'opaque-part-declared'), 'FAIL');
});

test('an adapter exception, an oversized result and an oversized send fail the case, not the run', () => {
  const throws = { ...compliantSyntheticAdapter(), release() { throw new Error(`synthetic ${PLANTED_CLOAKABLE}`); } };
  const thrown = run(throws);
  assert.equal(thrown.overall, 'FAIL');
  for (const entry of thrown.cases) assert.equal(entry.outcome, 'FAIL');
  assert.ok(!JSON.stringify(thrown).includes(PLANTED_CLOAKABLE), 'adapter errors must not be echoed');

  const hugeField = {
    ...compliantSyntheticAdapter(),
    release() { return { fields: [{ id: 'field-0', text: 'a'.repeat(MAX_CONFORMANCE_SEND_BYTES + 1) }], decision: 'SENT' }; },
  };
  assert.equal(run(hugeField).overall, 'FAIL');

  const flood = {
    ...compliantSyntheticAdapter(),
    release(request, controls) {
      for (let index = 0; index < 64; index += 1) {
        controls.send(request.sendDestinationId, new TextEncoder().encode(`chunk-${index}`));
      }
      return { fields: [], decision: 'SENT' };
    },
  };
  const flooded = run(flood);
  assert.equal(flooded.overall, 'FAIL');
  assert.ok(!JSON.stringify(flooded).includes('chunk-'));
});

test('the suite digest is deterministic, covers the cases and changes when a case changes', () => {
  const first = run(compliantSyntheticAdapter());
  const second = run(compliantSyntheticAdapter());
  assert.equal(first.suiteSha256, second.suiteSha256);
  assert.equal(sha256Hex(canonicalJson(first)), sha256Hex(canonicalJson(second)));
  const suite = syntheticConformanceSuite();
  suite.cases[0].requirements = ['FUNCTIONAL_MATCH'];
  assert.notEqual(run(compliantSyntheticAdapter(), { suite }).suiteSha256, first.suiteSha256);
  const renamed = syntheticConformanceSuite();
  renamed.cases[0].id = 'functional-renamed';
  assert.notEqual(run(compliantSyntheticAdapter(), { suite: renamed }).suiteSha256, first.suiteSha256);
});

test('the evidence document is canonical and contains no planted value or request text', () => {
  const evidence = run(compliantSyntheticAdapter());
  const rendered = JSON.stringify(evidence);
  assert.ok(!rendered.includes(PLANTED_CLOAKABLE));
  assert.ok(!rendered.includes(PLANTED_UNCLOAKABLE));
  assert.ok(!rendered.includes('endpoint ='));
  assert.ok(rendered.includes(CLOAKED_TOKEN) === false, 'transformed field text is not recorded either');
  // The document is canonicalizable and stable: re-canonicalizing the parsed form is byte identical.
  const bytes = canonicalJson(evidence);
  assert.deepEqual(Buffer.from(canonicalJson(JSON.parse(Buffer.from(bytes).toString('utf8')))), Buffer.from(bytes));
});

test('B1: a recoverable encoding of a planted original is planted egress, not a pass', () => {
  // The adapter base64/hex "cloaks" instead of substituting. The released bytes are recoverable in the
  // project's own canonical views, so a literal byte search is not a sufficient observation.
  const evidence = run(encodingCloakAdapter());
  assert.equal(evidence.plantedEgress, 'FAIL', 'an encoded planted original must not pass');
  assert.equal(evidence.overall, 'FAIL');
  assert.ok(violations(evidence, 'planted-egress-cloakable').includes('PLANTED_ORIGINAL_RELEASED'),
    JSON.stringify(evidence.cases));
  assert.ok(violations(evidence, 'planted-egress-nested').includes('PLANTED_ORIGINAL_RELEASED'));
  // The evidence names the violated invariant and still contains no planted or encoded value.
  const rendered = JSON.stringify(evidence);
  assert.ok(!rendered.includes(PLANTED_CLOAKABLE) && !rendered.includes(PLANTED_UNCLOAKABLE));
  assert.ok(!rendered.includes(Buffer.from(PLANTED_CLOAKABLE).toString('base64')));
  assert.ok(!rendered.includes(Buffer.from(PLANTED_UNCLOAKABLE).toString('hex')));
  // A real synthetic-token substitution over the same suite still passes: this is not over-blocking.
  assert.equal(run(compliantSyntheticAdapter()).overall, 'PASS');
});

test('B3: released bytes must be the private copy the pre-send control cleared', () => {
  // The control is consulted with clean bytes and releases them; the adapter then sends different
  // bytes. Consulting the control must not be enough on its own.
  const evidence = run(unboundReleaseAdapter());
  assert.equal(evidence.overall, 'FAIL', 'releasing bytes the control never cleared is a failure');
  assert.equal(evidence.functionalTests, 'PASS', 'the functional requirement is unaffected');
  // The appended payload carries no planted original, so the planted verdict stays honest and the
  // failure is named for what it is: an unbound release.
  assert.equal(evidence.plantedEgress, 'PASS');
  const functional = evidence.cases.find((entry) => entry.id === 'functional-clean-request');
  assert.ok(violations(evidence, 'planted-egress-cloakable').includes('UNBOUND_RELEASE_BYTES'),
    JSON.stringify(evidence.cases));
  assert.ok(violations(evidence, 'functional-clean-request').includes('UNBOUND_RELEASE_BYTES'),
    'the invariant applies to every case, not only the planted ones');
  assert.equal(functional.outcome, 'FAIL');
  assert.ok(!violations(evidence, 'planted-egress-cloakable').includes('PLANTED_ORIGINAL_RELEASED'),
    'an appended clean payload is not a planted original');
  assert.ok(!JSON.stringify(evidence).includes(SYNTHETIC_APPENDED_PAYLOAD));
  // The control must hand back the exact bytes it cleared, so an adapter can send nothing else.
  const handed = [];
  const observing = {
    ...compliantSyntheticAdapter(),
    release(request, controls) {
      const decision = controls.preSendCheck({
        destinationId: request.sendDestinationId,
        authorizedDestinationId: request.authorizedDestinationId,
        bytes: new TextEncoder().encode('cleared-bytes.invalid'),
      });
      if (decision.decision === 'ALLOW' && decision.release) handed.push(Buffer.from(decision.release).toString('utf8'));
      return { fields: [], decision: 'BLOCKED' };
    },
  };
  run(observing);
  assert.ok(handed.length > 0, 'the control must hand back the bytes it cleared');
  assert.ok(handed.every((value) => value === 'cleared-bytes.invalid'), JSON.stringify(handed));
});

test('B2: adversarial release volume is bounded work, not a quadratic scan', () => {
  // Worst case for a literal byte search: every record shares a long prefix with every needle at
  // every offset, and each needle is one character longer than that prefix, so no match is ever
  // found and the scan cannot short-circuit. Measured on the reviewing host at the reviewed head:
  // 8 records x 64 KiB x 8 needles took 64,625 ms, and 4 x 32 KiB x 8 took 15,985 ms (4x per
  // dimension). With the independent final-byte check the same shape takes about 4,000 ms. The 30 s
  // threshold is a bounded-work regression guard, not a service budget: it is above the measured
  // linear cost with room for a contended host and well below the measured quadratic cost.
  const needles = Array.from({ length: 8 }, (unused, index) => `A${'A'.repeat(999)}${String.fromCharCode(66 + index)}`);
  const chunk = 'A'.repeat(64 * 1024);
  const flooding = {
    ...compliantSyntheticAdapter(),
    release(request, controls) {
      controls.preSendCheck({
        destinationId: request.sendDestinationId,
        authorizedDestinationId: request.authorizedDestinationId,
        bytes: new TextEncoder().encode('cleared.invalid'),
      });
      for (let index = 0; index < 8; index += 1) {
        controls.send(request.sendDestinationId, new TextEncoder().encode(chunk));
      }
      return { fields: [], decision: 'SENT' };
    },
  };
  const started = process.hrtime.bigint();
  const evidence = run(flooding, { planted: needles });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(evidence.overall, 'FAIL', 'a flood is not a conformance pass');
  assert.ok(elapsedMs < 30_000, `bounded work regression: ${elapsedMs.toFixed(0)} ms`);
});

test('a malformed suite, declaration or planted list is refused with a fixed error', () => {
  const cases = [
    { suite: 'not a suite' }, { suite: { suiteId: 'x' } },
    { suite: { ...syntheticConformanceSuite(), cases: [null] } },
    { suite: { ...syntheticConformanceSuite(), suiteId: 'not a valid id' } },
  ];
  for (const options of cases) {
    assert.throws(() => run(compliantSyntheticAdapter(), options), /adapter conformance/i);
  }
  const badRequirement = syntheticConformanceSuite();
  badRequirement.cases[0].requirements = ['NOT_A_REQUIREMENT'];
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: badRequirement }), /adapter conformance/i);
  const duplicateRequirement = syntheticConformanceSuite();
  duplicateRequirement.cases[0].requirements = ['FUNCTIONAL_MATCH', 'FUNCTIONAL_MATCH'];
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: duplicateRequirement }), /adapter conformance/i);
  const noSendCount = syntheticConformanceSuite();
  noSendCount.cases[0].expectedSendCount = null;
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: noSendCount }), /adapter conformance/i);
  const manyCases = syntheticConformanceSuite();
  manyCases.cases = manyCases.cases.concat(Array.from({ length: 40 }, (unused, index) => ({
    ...manyCases.cases[0], id: `extra-${index}`, kind: 'FUNCTIONAL',
  })));
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: manyCases }), /adapter conformance/i);
  for (const declaration of [{ operations: 'model.input' }, { ...compliantSyntheticAdapter().declaredCoverage, sinks: [7] }]) {
    assert.throws(() => run({ ...compliantSyntheticAdapter(), declaredCoverage: declaration }), /adapter conformance/i);
  }
  for (const planted of [[], ['a'.repeat(MAX_CONFORMANCE_SEND_BYTES + 1)], [7]]) {
    assert.throws(() => run(compliantSyntheticAdapter(), { planted }), /adapter conformance/i);
  }
  for (const subject of [{}, { ...SUBJECT, sbomSha256: 'zz' }]) {
    assert.throws(() => run(compliantSyntheticAdapter(), { subject }), /adapter conformance/i);
  }
  for (const completedAt of [-1, 1.5, '1700000000000']) {
    assert.throws(() => run(compliantSyntheticAdapter(), { completedAt }), /adapter conformance/i);
  }
  assert.throws(() => run({ ...compliantSyntheticAdapter(), release: 'not a function' }), /adapter conformance/i);
});

test('an out-of-contract suite or adapter is refused with a fixed error', () => {
  const empty = syntheticConformanceSuite();
  empty.cases = [];
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: empty }), /adapter conformance/i);

  const tooMany = syntheticConformanceSuite();
  tooMany.cases = Array.from({ length: MAX_CONFORMANCE_CASES + 1 }, (unused, index) => ({
    ...tooMany.cases[0], id: `case-${index}`,
  }));
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: tooMany }), /adapter conformance/i);

  const noPlanted = syntheticConformanceSuite();
  noPlanted.cases = noPlanted.cases.filter((entry) => entry.kind !== 'PLANTED_EGRESS');
  assert.throws(() => run(compliantSyntheticAdapter(), { suite: noPlanted }), /adapter conformance/i);

  assert.throws(() => run({ ...compliantSyntheticAdapter(), adapterId: 'not a valid id' }), /adapter conformance/i);
  assert.throws(() => run(compliantSyntheticAdapter(), { planted: [] }), /adapter conformance/i);
  assert.throws(() => run(compliantSyntheticAdapter(), { subject: { ...SUBJECT, artifactSha256: 'short' } }),
    /adapter conformance/i);
});
