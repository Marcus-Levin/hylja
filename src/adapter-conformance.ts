/**
 * #33 adapter conformance: a synthetic, offline harness that observes what an adapter actually
 * released instead of what it claims.
 *
 * The harness owns the case list, a controlled capture at the send point, the planted synthetic
 * originals and the #19 known-originals configuration. An adapter is only given a way to append to
 * the capture and to consult the injected pre-send control; every outcome is computed from the
 * harness's own observations, so an adapter self-report, a returned `conformance: 'PASS'` field or
 * an attempt to edit the capture record cannot buy a pass.
 *
 * Two properties are inherited from the project's own #19 Egress Sentinel rather than reinvented
 * here: the pre-send control is a real final-byte check over the same canonical views, and its ALLOW
 * hands back a private copy of exactly the checked bytes that the adapter must send. The harness then
 * re-checks what actually left, so a recoverable encoding of a planted original, a payload that is not
 * the copy the control cleared, and a destination that was never asserted are all observed failures.
 *
 * Case outcomes name the violated invariant from a fixed vocabulary and never contain request text,
 * field values, captured bytes or matched content.
 *
 * This is NOT a production adapter, Policy Engine, registry or release decision: it is the evidence
 * producer the #33 release gate consumes, and it proves nothing about any real surface, socket or
 * hosted action.
 */
import { checkEgress, createKnownOriginals, sentinelUnavailable } from './egress-sentinel.js';
import type { Destination, KnownOriginalsHandle, SentinelScope } from './egress-sentinel.js';
import { canonicalJson, sha256Hex } from './canonical-json.js';

export const ADAPTER_CONFORMANCE_VERSION = 'hylja.adapter-conformance.v1' as const;
export const CONFORMANCE_SUITE_FORMAT = 'hylja-conformance-suite/v1' as const;
export const MAX_CONFORMANCE_CASES = 64;
export const MAX_CONFORMANCE_SEND_BYTES = 1 << 20;
export const MAX_CONFORMANCE_RECORDS = 16;
/** Total bytes the harness will inspect for one run, across the control, the capture and the fields. */
export const MAX_CONFORMANCE_INSPECTED_BYTES = 4 << 20;
export const MAX_CONFORMANCE_FIELDS = 32;
export const MAX_CONFORMANCE_FIELD_CHARS = 8 << 10;
/** The #19 known-originals registry indexes values of 4..1024 compact characters. */
export const MAX_CONFORMANCE_PLANTED_CHARS = 1024;
const MAX_CASES_PER_KIND = 32;
const MAX_PLANTED = 32;

export const CONFORMANCE_REQUIREMENTS = Object.freeze([
  'FUNCTIONAL_MATCH', 'PLANTED_ORIGINAL_ABSENT', 'PRE_SEND_CHECK_CONSULTED', 'OPAQUE_NOT_RELEASED',
  'DECLARED_UNSUPPORTED', 'DESTINATION_BOUND',
] as const);
/**
 * Invariants the harness applies to every case regardless of what the suite declares, so a suite
 * author cannot opt out of them. `outcome` is FAIL when any of these is reported.
 */
export const CONFORMANCE_VIOLATIONS = Object.freeze([
  'ADAPTER_ERROR', 'BUDGET_EXCEEDED', 'PLANTED_ORIGINAL_RELEASED', 'PLANTED_ORIGINAL_RETURNED',
  'UNREVIEWED_RELEASE_BYTES', 'UNBOUND_RELEASE_BYTES',
] as const);
export const CONFORMANCE_CASE_KINDS = Object.freeze([
  'FUNCTIONAL', 'PLANTED_EGRESS', 'OPAQUE_PART', 'DESTINATION_BINDING',
] as const);
export type ConformanceRequirement = (typeof CONFORMANCE_REQUIREMENTS)[number];
export type ConformanceViolation = (typeof CONFORMANCE_VIOLATIONS)[number];
export type ConformanceCaseKind = (typeof CONFORMANCE_CASE_KINDS)[number];
export type ConformanceVerdict = 'PASS' | 'FAIL' | 'NOT_RUN';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PROFILE_DIGEST = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const encoder = new TextEncoder();

export class ConformanceFailure extends Error {
  constructor(readonly reason: string) {
    super('adapter conformance input is out of contract');
    this.name = 'ConformanceFailure';
  }
}
function reject(reason: string): never { throw new ConformanceFailure(reason); }

export interface ConformanceField { id: string; text: string }
export interface ConformanceOpaquePart { id: string }
export interface ConformanceCaseSpec {
  id: string;
  kind: ConformanceCaseKind;
  fields: readonly ConformanceField[];
  opaquePart: ConformanceOpaquePart | null;
  authorizedDestinationId: string;
  sendDestinationId: string;
  expectedFields: readonly ConformanceField[] | null;
  expectedSendCount: number | null;
  requirements: readonly ConformanceRequirement[];
}
export interface ConformanceSuite {
  suiteId: string;
  cases: readonly ConformanceCaseSpec[];
}
export interface ConformanceSubject {
  /** The exact artifact, lockfile and SBOM digests the adapters were exercised against. */
  artifactSha256: string; lockSha256: string; sbomSha256: string;
}
export interface ConformanceRequest {
  caseId: string;
  fields: readonly ConformanceField[];
  opaquePart: ConformanceOpaquePart | null;
  authorizedDestinationId: string;
  sendDestinationId: string;
}
export interface ConformanceCaptureRecord {
  readonly sequence: number; readonly destinationId: string; readonly bytes: Uint8Array;
}
export interface ConformancePreSendDecision {
  decision: 'ALLOW' | 'BLOCK';
  /**
   * #19 discipline: on ALLOW this is a private copy of exactly the bytes that were checked, and the
   * bytes the adapter releases must be this copy. Absent on BLOCK.
   */
  release?: Uint8Array;
}
export interface ConformanceControls {
  /** Append to the harness-owned capture. Returns false once a bound is reached. */
  send(destinationId: string, bytes: Uint8Array): boolean;
  /** The injected #19-equivalent control: a real final-byte check, not a callback. */
  preSendCheck(input: { destinationId: string; authorizedDestinationId: string; bytes: Uint8Array }):
    ConformancePreSendDecision;
  /** A frozen copy of the capture so far. Mutating it cannot change what the harness observed. */
  captured(): readonly ConformanceCaptureRecord[];
}
export interface ConformanceDeclaration {
  operations: readonly string[]; inspectableParts: readonly string[];
  unsupportedParts: readonly string[]; sinks: readonly string[];
}
export interface ConformanceAdapter {
  adapterId: string;
  declaredCoverage: ConformanceDeclaration;
  /** Synchronous by contract: an asynchronous release is a failing case in this substrate. */
  release(request: ConformanceRequest, controls: ConformanceControls): { fields?: unknown; decision?: unknown };
}
export interface ConformanceCaseResult {
  id: string; kind: ConformanceCaseKind; requirements: readonly ConformanceRequirement[];
  violations: readonly ConformanceViolation[]; outcome: 'PASS' | 'FAIL';
}
export interface ConformanceEvidence {
  schemaVersion: 1;
  version: string;
  suiteId: string;
  suiteSha256: string;
  adapterId: string;
  scopeRef: string;
  subject: ConformanceSubject;
  completedAt: number;
  cases: readonly ConformanceCaseResult[];
  /** Only the ordinary functional requirement. A pass here is NOT conformance. */
  functionalTests: ConformanceVerdict;
  plantedEgress: ConformanceVerdict;
  overall: 'PASS' | 'FAIL';
}
export interface ConformanceInput {
  adapter: ConformanceAdapter;
  suite: ConformanceSuite;
  scopeRef: string;
  /** #19 known-originals scope, owned by the harness. The adapter never sees it. */
  sentinelScope: SentinelScope;
  /** #19 destination profile digest asserted for every case. */
  destinationProfileDigest: string;
  subject: ConformanceSubject;
  planted: readonly string[];
  completedAt: number;
}

function identifier(value: unknown): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) reject('IDENTIFIER_INVALID');
  return value;
}
function digest(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) reject('DIGEST_INVALID');
  return value;
}
function copy(bytes: Uint8Array): Uint8Array { return Uint8Array.prototype.slice.call(bytes); }
function sameBytes(left: Uint8Array | null, right: Uint8Array): boolean {
  if (left === null || left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;
  return true;
}
function fieldList(value: unknown): readonly ConformanceField[] {
  if (!Array.isArray(value) || value.length > MAX_CONFORMANCE_FIELDS) reject('FIELDS_INVALID');
  const fields: ConformanceField[] = [];
  for (const item of value) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) reject('FIELDS_INVALID');
    const record = item as { id?: unknown; text?: unknown };
    const text = record.text;
    if (typeof text !== 'string' || text.length > MAX_CONFORMANCE_FIELD_CHARS) reject('FIELDS_INVALID');
    fields.push(Object.freeze({ id: identifier(record.id), text }));
  }
  return Object.freeze(fields);
}
function readSuite(suite: ConformanceSuite): ConformanceSuite {
  if (suite === null || typeof suite !== 'object' || !Array.isArray(suite.cases)) reject('SUITE_INVALID');
  const suiteId = identifier(suite.suiteId);
  if (suite.cases.length === 0 || suite.cases.length > MAX_CONFORMANCE_CASES) reject('SUITE_INVALID');
  const seen = new Set<string>();
  const perKind = new Map<string, number>();
  const cases: ConformanceCaseSpec[] = [];
  for (const item of suite.cases) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) reject('SUITE_INVALID');
    const id = identifier(item.id);
    if (seen.has(id)) reject('SUITE_INVALID');
    seen.add(id);
    if (!(CONFORMANCE_CASE_KINDS as readonly string[]).includes(item.kind)) reject('SUITE_INVALID');
    perKind.set(item.kind, (perKind.get(item.kind) ?? 0) + 1);
    if ((perKind.get(item.kind) as number) > MAX_CASES_PER_KIND) reject('SUITE_INVALID');
    const requirements = item.requirements;
    if (!Array.isArray(requirements) || requirements.length === 0
        || requirements.some((entry) => !(CONFORMANCE_REQUIREMENTS as readonly string[]).includes(entry))) {
      reject('SUITE_INVALID');
    }
    if (new Set(requirements).size !== requirements.length) reject('SUITE_INVALID');
    const expectedFields = item.expectedFields === null || item.expectedFields === undefined
      ? null : fieldList(item.expectedFields);
    const expectedSendCount = item.expectedSendCount === null || item.expectedSendCount === undefined
      ? null : item.expectedSendCount;
    if (expectedSendCount !== null && (!Number.isInteger(expectedSendCount) || expectedSendCount < 0
        || expectedSendCount > MAX_CONFORMANCE_RECORDS)) reject('SUITE_INVALID');
    if (item.kind === 'FUNCTIONAL' && (expectedFields === null || expectedSendCount === null)) reject('SUITE_INVALID');
    const opaquePart = item.opaquePart === null || item.opaquePart === undefined
      ? null : { id: identifier((item.opaquePart as { id?: unknown }).id) };
    cases.push(Object.freeze({
      id, kind: item.kind, fields: fieldList(item.fields), opaquePart,
      authorizedDestinationId: identifier(item.authorizedDestinationId),
      sendDestinationId: identifier(item.sendDestinationId),
      expectedFields, expectedSendCount,
      requirements: Object.freeze([...(requirements as ConformanceRequirement[])]) as readonly ConformanceRequirement[],
    }));
  }
  if (!cases.some((entry) => entry.kind === 'FUNCTIONAL')) reject('SUITE_INVALID');
  if (!cases.some((entry) => entry.kind === 'PLANTED_EGRESS')) reject('SUITE_INVALID');
  return Object.freeze({ suiteId, cases: Object.freeze(cases) });
}
function readDeclaration(adapter: ConformanceAdapter): ConformanceDeclaration {
  const declaration = adapter.declaredCoverage;
  if (declaration === null || typeof declaration !== 'object') reject('DECLARATION_INVALID');
  const read = (value: unknown): readonly string[] => {
    if (!Array.isArray(value) || value.length > 64) reject('DECLARATION_INVALID');
    return Object.freeze(value.map((entry) => identifier(entry)));
  };
  return Object.freeze({
    operations: read(declaration.operations),
    inspectableParts: read(declaration.inspectableParts),
    unsupportedParts: read(declaration.unsupportedParts),
    sinks: read(declaration.sinks),
  });
}
function sameFields(left: readonly ConformanceField[], right: readonly ConformanceField[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((field, index) => field.id === right[index]?.id && field.text === right[index]?.text);
}

type Verdict = 'ALLOW' | 'BLOCK' | 'PLANTED' | 'BUDGET';
interface Observer {
  /** Run the independent final-byte check. `authorized` is what the case declared as authorized. */
  inspect(bytes: Uint8Array, destination: string, authorized: string): Verdict;
  remaining(): number;
}

/**
 * Build the harness-owned #19 configuration. Any value the sentinel cannot index is an input error,
 * never a silently unmatched value: an unindexable planted value would look exactly like a clean run.
 */
function createObserver(input: ConformanceInput, planted: readonly string[]): Observer {
  const scope = input.sentinelScope;
  if (scope === null || typeof scope !== 'object'
      || typeof scope.tenantRef !== 'string' || typeof scope.projectRef !== 'string'
      || scope.tenantRef.length === 0 || scope.projectRef.length === 0
      || scope.tenantRef.length > 128 || scope.projectRef.length > 128) reject('SENTINEL_SCOPE_INVALID');
  if (typeof input.destinationProfileDigest !== 'string'
      || !PROFILE_DIGEST.test(input.destinationProfileDigest)) reject('DESTINATION_PROFILE_INVALID');
  let known: KnownOriginalsHandle;
  try {
    // A fixed per-run key keeps the harness self-contained; it protects nothing but the fingerprints.
    const key = new Uint8Array(32).fill(0x33);
    known = createKnownOriginals(
      { tenantRef: scope.tenantRef, projectRef: scope.projectRef }, key,
      planted.map((value, index) => Object.freeze({ kind: 'ORIGINAL' as const, value, ref: `planted.${index}` })),
    );
  } catch { reject('PLANTED_INVALID'); }
  const profileDigest = input.destinationProfileDigest;
  let inspected = 0;
  return {
    inspect(bytes: Uint8Array, destination: string, authorized: string): Verdict {
      // A bounded inspection budget is a harness invariant, not a per-case opt-in.
      if (bytes.length > MAX_CONFORMANCE_INSPECTED_BYTES - inspected) return 'BUDGET';
      inspected += bytes.length;
      const at = (id: string): Destination => ({ id, profileDigest });
      let result;
      try {
        result = checkEgress({
          bytes,
          scope: { tenantRef: scope.tenantRef, projectRef: scope.projectRef },
          destination: at(destination), authorized: at(authorized), known,
        });
      } catch { result = sentinelUnavailable(); }
      if (result.decision === 'ALLOW') return 'ALLOW';
      return result.findings.some((finding) => finding.kind !== 'PATTERN') ? 'PLANTED' : 'BLOCK';
    },
    remaining(): number { return MAX_CONFORMANCE_INSPECTED_BYTES - inspected; },
  };
}

/**
 * Run the suite and return the evidence document. Throws `ConformanceFailure` when the harness
 * contract itself is violated (a suite without a planted case, an untrusted adapter id, a subject
 * digest that is not a digest, a planted value the #19 registry cannot index); a misbehaving adapter
 * instead produces a failing case, never a throw, so one compromised adapter cannot hide the rest.
 */
export function runAdapterConformance(input: ConformanceInput): ConformanceEvidence {
  const suite = readSuite(input?.suite as ConformanceSuite);
  const adapter = input?.adapter;
  if (adapter === null || typeof adapter !== 'object' || typeof adapter.release !== 'function') {
    reject('ADAPTER_INVALID');
  }
  const adapterId = identifier(adapter.adapterId);
  const scopeRef = identifier(input?.scopeRef);
  const subject: ConformanceSubject = {
    artifactSha256: digest(input?.subject?.artifactSha256),
    lockSha256: digest(input?.subject?.lockSha256),
    sbomSha256: digest(input?.subject?.sbomSha256),
  };
  const completedAt = input?.completedAt;
  if (!Number.isSafeInteger(completedAt) || (completedAt as number) < 0) reject('COMPLETED_AT_INVALID');
  const plantedInput = input?.planted;
  if (!Array.isArray(plantedInput) || plantedInput.length === 0 || plantedInput.length > MAX_PLANTED
      || plantedInput.some((value) => typeof value !== 'string' || value.length < 4
        || value.length > MAX_CONFORMANCE_PLANTED_CHARS
        || /[\u0000-\u001f\u007f]/.test(value))) reject('PLANTED_INVALID');
  const planted = Object.freeze([...(plantedInput as readonly string[])]);
  const declaration = readDeclaration(adapter);
  const observer = createObserver(input, planted);
  // The suite digest covers the exact case bytes, so an easier suite is a different suite.
  const suiteSha256 = sha256Hex(canonicalJson({
    format: CONFORMANCE_SUITE_FORMAT, suiteId: suite.suiteId, cases: suite.cases,
  }));

  const results: ConformanceCaseResult[] = [];
  let functionalTests: ConformanceVerdict = 'NOT_RUN';
  let plantedEgress: ConformanceVerdict = 'NOT_RUN';
  let anyFunctional = false;
  let anyPlanted = false;
  let functionalHeld = true;
  let plantedHeld = true;
  let plantedViolation = false;

  for (const spec of suite.cases) {
    const records: { sequence: number; destinationId: string; bytes: Uint8Array; bound: boolean }[] = [];
    let preSendCalls = 0;
    let lastRelease: Uint8Array | null = null;
    const failures = new Set<ConformanceViolation>();
    const controls: ConformanceControls = Object.freeze({
      send(destinationId: string, bytes: Uint8Array): boolean {
        if (!(bytes instanceof Uint8Array) || bytes.length === 0
            || bytes.length > MAX_CONFORMANCE_SEND_BYTES
            || records.length >= MAX_CONFORMANCE_RECORDS
            || bytes.length > observer.remaining()) {
          failures.add('BUDGET_EXCEEDED');
          return false;
        }
        const snapshot = copy(bytes);
        records.push({
          sequence: records.length,
          destinationId: typeof destinationId === 'string' && destinationId.length <= 64 ? destinationId : '',
          // Copy once: later mutation of the adapter's buffer cannot change what was observed.
          bytes: snapshot,
          // #19 discipline: was this exact buffer the copy the control cleared?
          bound: sameBytes(lastRelease, snapshot),
        });
        return true;
      },
      preSendCheck(call: { destinationId: string; authorizedDestinationId: string; bytes: Uint8Array }):
        ConformancePreSendDecision {
        preSendCalls += 1;
        const bytes = call?.bytes;
        if (!(bytes instanceof Uint8Array) || bytes.length === 0
            || bytes.length > MAX_CONFORMANCE_SEND_BYTES || bytes.length > observer.remaining()) {
          failures.add('BUDGET_EXCEEDED');
          return { decision: 'BLOCK' };
        }
        const destinationId = typeof call?.destinationId === 'string' ? call.destinationId : '';
        const authorizedId = typeof call?.authorizedDestinationId === 'string' ? call.authorizedDestinationId : '';
        const verdict = observer.inspect(bytes, destinationId, authorizedId);
        if (verdict !== 'ALLOW') return { decision: 'BLOCK' };
        // Hand back a private copy of exactly the bytes that were cleared, never the caller's buffer.
        const release = copy(bytes);
        lastRelease = release;
        return { decision: 'ALLOW', release };
      },
      captured(): readonly ConformanceCaptureRecord[] {
        return Object.freeze(records.map((record) => Object.freeze({
          sequence: record.sequence, destinationId: record.destinationId, bytes: copy(record.bytes),
        })));
      },
    });

    const request: ConformanceRequest = Object.freeze({
      caseId: spec.id, fields: spec.fields, opaquePart: spec.opaquePart,
      authorizedDestinationId: spec.authorizedDestinationId, sendDestinationId: spec.sendDestinationId,
    });
    let returned: readonly ConformanceField[] = [];
    let returnedValid = false;
    try {
      const outcome = adapter.release(request, controls);
      if (outcome !== null && typeof outcome === 'object' && typeof (outcome as { then?: unknown }).then === 'function') {
        // A promise here means the adapter released without a bounded observation; refuse it.
        returnedValid = false;
      } else {
        const fields = outcome === null || typeof outcome !== 'object'
          ? null : (outcome as { fields?: unknown }).fields;
        if (fields === undefined || fields === null) returnedValid = true;
        else { returned = fieldList(fields); returnedValid = true; }
      }
    } catch {
      // An adapter exception is a failed case, never a silent pass and never a harness crash.
      returnedValid = false;
    }
    if (!returnedValid) failures.add('ADAPTER_ERROR');

    // Independent observation of what actually left, and of what the adapter handed back. Each byte
    // is inspected exactly once: the verdict drives both the unreviewed and the planted finding.
    for (const record of records) {
      const verdict = observer.inspect(record.bytes, record.destinationId, spec.authorizedDestinationId);
      if (verdict === 'BUDGET') failures.add('BUDGET_EXCEEDED');
      if (verdict === 'BLOCK') failures.add('UNREVIEWED_RELEASE_BYTES');
      if (verdict === 'PLANTED') {
        failures.add('UNREVIEWED_RELEASE_BYTES');
        failures.add('PLANTED_ORIGINAL_RELEASED');
      }
      if (!record.bound) failures.add('UNBOUND_RELEASE_BYTES');
    }
    for (const field of returned) {
      const verdict = observer.inspect(encoder.encode(field.text), spec.sendDestinationId, spec.authorizedDestinationId);
      if (verdict === 'BUDGET') failures.add('BUDGET_EXCEEDED');
      if (verdict === 'PLANTED') failures.add('PLANTED_ORIGINAL_RETURNED');
    }
    if (failures.has('PLANTED_ORIGINAL_RETURNED') || failures.has('PLANTED_ORIGINAL_RELEASED')) {
      plantedViolation = true;
    }

    const held = (requirement: ConformanceRequirement): boolean => {
      switch (requirement) {
        case 'FUNCTIONAL_MATCH':
          return returnedValid && sameFields(returned, spec.expectedFields ?? [])
            && records.length === (spec.expectedSendCount ?? -1);
        case 'PLANTED_ORIGINAL_ABSENT':
          return !failures.has('PLANTED_ORIGINAL_RELEASED') && !failures.has('PLANTED_ORIGINAL_RETURNED');
        case 'PRE_SEND_CHECK_CONSULTED':
          return preSendCalls > 0;
        case 'OPAQUE_NOT_RELEASED':
          return records.length === 0;
        case 'DECLARED_UNSUPPORTED':
          return spec.opaquePart !== null && declaration.unsupportedParts.includes(spec.opaquePart.id);
        case 'DESTINATION_BOUND':
          return records.every((record) => record.destinationId === spec.authorizedDestinationId);
        default:
          return false;
      }
    };
    const unmet = spec.requirements.filter((requirement) => !held(requirement));
    if (spec.kind === 'FUNCTIONAL') {
      anyFunctional = true;
      if (!held('FUNCTIONAL_MATCH')) functionalHeld = false;
    }
    if (spec.kind === 'PLANTED_EGRESS') {
      anyPlanted = true;
      // The planted-egress verdict is at least as strict as the declared requirements: a planted
      // case that released to an unasserted destination never counts as a pass.
      if (!held('PLANTED_ORIGINAL_ABSENT') || !held('DESTINATION_BOUND')) plantedHeld = false;
    }
    results.push(Object.freeze({
      id: spec.id, kind: spec.kind, requirements: spec.requirements,
      violations: Object.freeze(CONFORMANCE_VIOLATIONS.filter((code) => failures.has(code))) as readonly ConformanceViolation[],
      outcome: unmet.length === 0 && failures.size === 0 ? 'PASS' : 'FAIL',
    }));
  }

  if (anyFunctional) functionalTests = functionalHeld ? 'PASS' : 'FAIL';
  if (anyPlanted) plantedEgress = plantedHeld && !plantedViolation ? 'PASS' : 'FAIL';
  const overall = functionalTests === 'PASS' && plantedEgress === 'PASS'
    && results.every((entry) => entry.outcome === 'PASS') ? 'PASS' : 'FAIL';
  return Object.freeze({
    schemaVersion: 1, version: ADAPTER_CONFORMANCE_VERSION, suiteId: suite.suiteId, suiteSha256,
    adapterId, scopeRef, subject, completedAt: completedAt as number,
    cases: Object.freeze(results),
    functionalTests, plantedEgress, overall,
  });
}
