/**
 * Provider-neutral SYNTHETIC evaluation-only, NON-ENFORCING seam.
 * No real/private material, transport, policy effects or production isolation belongs here.
 * This exact-plaintext metric is not the independent final #19 byte sentinel: encoding,
 * fragmentation, contextual inference and unobserved surfaces are not checked.
 */
import { SEMANTIC_CLASSES, SENSITIVITIES, TRUST_LEVELS } from './classification.js';
import type { SemanticClass, Sensitivity, Trust } from './classification.js';
import { DEVELOPMENT_FAMILY_IDS } from './evaluation-partitions.js';
import { INTERACTION_OPERATIONS } from './interaction-envelope.js';

export type Treatment = 'KEEP' | 'MASK' | 'TOKENIZE' | 'SYNTHETIC' | 'GENERALIZE' |
  'REMOVE' | 'BLOCK' | 'REQUIRE_REVIEW';
export interface DevelopmentCase {
  version: 1;
  id: string;
  familyId: string;
  partition: 'development';
  fields: readonly { ref: string; content: string }[];
  sinks: readonly { id: string; surface: string; profileId: string }[];
  /** Synthetic-only fixture context; it is NOT authenticated runtime identity. */
  context?: { tenantId: string; projectId: string; sessionId: string; principalId: string;
    purpose: string; provenanceRef: string };
  task?: { id: string; prompt: string };
}
/** Independently planted source truth; never derived from candidate events or sentinel catches. */
export interface PlantedOccurrence {
  id: string;
  fieldRef: string;
  /** Half-open UTF-8 offsets in the original development case field. */
  start: number;
  end: number;
  value: string;
  semanticType: SemanticClass;
  subtype?: string;
  sensitivity: Sensitivity;
  trust: Trust;
  critical: boolean;
  expectedBySink: readonly { sinkId: string; treatment: Treatment }[];
}
export interface IndependentOracle {
  version: 1;
  caseId: string;
  occurrences: readonly PlantedOccurrence[];
  taskExpected?: string;
}
/** Candidate output uses field/byte offsets, not oracle IDs, labels or actual-release observations. */
export interface CandidateEvent {
  fieldRef: string;
  start: number;
  end: number;
  semanticType: SemanticClass;
  subtype?: string;
}
export interface SerializedRelease {
  caseId: string;
  sinkId: string;
  /** Actual post-serialization bytes: never reconstruct from a parsed object for scoring. */
  body: Uint8Array;
  /** Already serialized wire/adapter metadata, including headers where applicable. */
  metadata: Uint8Array;
}
export interface InMemorySinkCapture {
  capture(release: SerializedRelease): void;
  forCase(caseId: string): readonly SerializedRelease[];
  clear(): void;
}
export type EvaluationClaim = 'secret-plaintext-escape' | 'candidate-detection' | 'task-correctness' |
  'operational-measurement';
export type EvidenceProvenance = 'claim/docs' | 'source-inspected' | 'vendor-demonstrated' |
  'independently-executed' | 'untested';
export type ObservedOutcome = 'pass' | 'fail' | 'observed-only' | 'passthrough' |
  'unsupported' | 'outside architecture';
export interface ObservedEvidence {
  claim: EvaluationClaim;
  sinkId?: string;
  provenance: Exclude<EvidenceProvenance, 'untested'>;
  outcome: ObservedOutcome;
}
export interface UntestedEvidence {
  claim: EvaluationClaim;
  sinkId?: string;
  provenance: 'untested';
  reason: 'no-capture' | 'no-secret-control' | 'no-candidate-events' | 'no-task-control' |
    'no-task-result' | 'no-grader' | 'grader-error' | 'no-operational-observation';
  /** An untested claim has no observed outcome. */
  outcome?: never;
}
export interface EvaluationReport {
  version: 1;
  caseId: string;
  familyId: string;
  partition: 'development';
  observed: readonly ObservedEvidence[];
  untested: readonly UntestedEvidence[];
  privacy: { secretPlanted: number; testedSinkPairs: number; criticalPlaintextEscapes: number };
  candidates: {
    planted: number; matched: number; misses: number; falsePositives: number;
    recall: number | null; precision: number | null;
  };
  utility: { taskCorrect: boolean | null };
  operations: { latencyMs: number | null; computeMs: number | null; modelApiCostMicrounits: number | null };
}
/** Evaluator-origin timing/cost observation, not a candidate's self-reported assertion. */
export interface OperationalMeasurement {
  latencyMs: number;
  computeMs: number;
  modelApiCostMicrounits: number;
}
export type GradeTask = (expected: string, actual: string) => boolean;
/** Candidate-facing view excludes the independently planted oracle and task answer. */
export interface CandidateInput {
  version: 1;
  caseId: string;
  familyId: string;
  fields: readonly Readonly<{ ref: string; content: string }>[];
  sinks: readonly Readonly<{ id: string; surface: string; profileId: string }>[];
  context?: Readonly<{ tenantId: string; projectId: string; sessionId: string; principalId: string;
    purpose: string; provenanceRef: string }>;
  task?: Readonly<{ id: string; prompt: string }>;
}
export interface CandidateResult { events: readonly CandidateEvent[]; taskResult?: string }
/** Only the evaluator-provided local sink can observe already serialized body + metadata. */
export type ControlledSyntheticSend = (sinkId: string, serialized: Readonly<{ body: Uint8Array; metadata: Uint8Array }>) => void;
export type DevelopmentCandidate = (input: Readonly<CandidateInput>, send: ControlledSyntheticSend) =>
  CandidateResult | Promise<CandidateResult>;
export interface DevelopmentEvaluation {
  registerCase(record: DevelopmentCase): void;
  registerOracle(record: IndependentOracle): void;
  registerCandidateEvents(caseId: string, events: readonly CandidateEvent[]): void;
  runCandidate(caseId: string, candidate: DevelopmentCandidate, sink: InMemorySinkCapture): Promise<void>;
  recordTaskResult(caseId: string, actual: string): void;
  recordOperationalMeasurement(caseId: string, measurement: OperationalMeasurement): void;
  report(caseId: string, sink: InMemorySinkCapture, gradeTask?: GradeTask): EvaluationReport;
  clear(): void;
}

const encoder = new TextEncoder();
const issuedCaptures = new WeakSet<object>();
const MAX_FIELD_BYTES = 65_536;
const MAX_CAPTURE_BYTES = 1_048_576;
const MAX_CAPTURE_TOTAL_BYTES = 8 * MAX_CAPTURE_BYTES;
const MAX_CAPTURE_COUNT = 64;
function invalid(): never { throw new TypeError('Invalid synthetic evaluation input'); }
function safe<T>(action: () => T): T {
  try { return action(); } catch { return invalid(); }
}
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length < required.length || keys.length > required.length + optional.length) invalid();
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) invalid();
    result[key] = descriptor.value;
  }
  for (const key of required) if (!Object.hasOwn(result, key)) invalid();
  return result;
}
function list(value: unknown, cap: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
  const keys = Reflect.ownKeys(value);
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length > cap ||
    keys.length !== length + 1 || !keys.includes('length')) invalid();
  const items: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) invalid();
    items.push(descriptor.value);
  }
  return items;
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/u.test(value)) invalid();
  return value;
}
function scopeLabel(value: unknown): string {
  if (typeof value !== 'string' || !value.length || value.length > 256 || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) invalid();
  return value;
}
function subtype(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/u.test(value)) invalid();
  return value;
}
function plain(value: unknown, maxBytes = MAX_FIELD_BYTES): string {
  if (typeof value !== 'string' || value.length > maxBytes || encoder.encode(value).length > maxBytes) invalid();
  return value;
}
function nonnegativeMeasure(value: unknown, maximum: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > maximum) invalid();
  return value;
}
function offset(value: unknown, length: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > length) invalid();
  return value;
}
function enumeration<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) invalid();
  return value as T;
}
function caseRecord(input: unknown): DevelopmentCase {
  const record = object(input, ['version', 'id', 'familyId', 'partition', 'fields', 'sinks'], ['context', 'task']);
  if (record.version !== 1 || record.partition !== 'development') invalid();
  const familyId = enumeration(record.familyId, DEVELOPMENT_FAMILY_IDS);
  const fields = list(record.fields, 32).map((raw) => {
    const field = object(raw, ['ref', 'content']);
    return { ref: id(field.ref), content: plain(field.content) };
  });
  const sinks = list(record.sinks, 8).map((raw) => {
    const item = object(raw, ['id', 'surface', 'profileId']);
    return { id: id(item.id), surface: enumeration(item.surface, INTERACTION_OPERATIONS), profileId: id(item.profileId) };
  });
  if (!fields.length || !sinks.length || new Set(fields.map((field) => field.ref)).size !== fields.length ||
    new Set(sinks.map((sink) => sink.id)).size !== sinks.length ||
    fields.reduce((size, field) => size + encoder.encode(field.content).length, 0) > MAX_FIELD_BYTES) invalid();
  let context: DevelopmentCase['context'];
  if (Object.hasOwn(record, 'context')) {
    const inputContext = object(record.context, ['tenantId', 'projectId', 'sessionId',
      'principalId', 'purpose', 'provenanceRef']);
    context = { tenantId: scopeLabel(inputContext.tenantId), projectId: scopeLabel(inputContext.projectId),
      sessionId: scopeLabel(inputContext.sessionId), principalId: scopeLabel(inputContext.principalId),
      purpose: scopeLabel(inputContext.purpose), provenanceRef: scopeLabel(inputContext.provenanceRef) };
  }
  let task: DevelopmentCase['task'];
  if (Object.hasOwn(record, 'task')) {
    const inputTask = object(record.task, ['id', 'prompt']);
    task = { id: id(inputTask.id), prompt: plain(inputTask.prompt) };
  }
  return { version: 1, id: id(record.id), familyId, partition: 'development', fields, sinks,
    ...(context ? { context } : {}), ...(task ? { task } : {}) };
}
const treatments: readonly Treatment[] = [
  'KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE', 'BLOCK', 'REQUIRE_REVIEW',
];
function oracleRecord(input: unknown, record: DevelopmentCase): IndependentOracle {
  const candidate = object(input, ['version', 'caseId', 'occurrences'], ['taskExpected']);
  if (candidate.version !== 1 || candidate.caseId !== record.id) invalid();
  const occurrences = list(candidate.occurrences, 256).map((raw): PlantedOccurrence => {
    const plant = object(raw, ['id', 'fieldRef', 'start', 'end', 'value', 'semanticType',
      'sensitivity', 'trust', 'critical', 'expectedBySink'], ['subtype']);
    const fieldRef = id(plant.fieldRef);
    const field = record.fields.find((item) => item.ref === fieldRef);
    if (!field) invalid();
    const fieldBytes = encoder.encode(field.content);
    const start = offset(plant.start, fieldBytes.length);
    const end = offset(plant.end, fieldBytes.length);
    const value = plain(plant.value);
    const valueBytes = encoder.encode(value);
    if (start >= end || valueBytes.length !== end - start || valueBytes.length === 0 ||
      !fieldBytes.subarray(start, end).every((byte, index) => byte === valueBytes[index])) invalid();
    const semanticType = enumeration(plant.semanticType, SEMANTIC_CLASSES);
    const sensitivity = enumeration(plant.sensitivity, SENSITIVITIES);
    const trust = enumeration(plant.trust, TRUST_LEVELS);
    if (typeof plant.critical !== 'boolean') invalid();
    const expectedBySink = list(plant.expectedBySink, 8).map((rawTreatment) => {
      const target = object(rawTreatment, ['sinkId', 'treatment']);
      return { sinkId: id(target.sinkId), treatment: enumeration(target.treatment, treatments) };
    });
    if (expectedBySink.length !== record.sinks.length ||
      new Set(expectedBySink.map((target) => target.sinkId)).size !== record.sinks.length ||
      expectedBySink.some((target) => !record.sinks.some((sink) => sink.id === target.sinkId))) invalid();
    // A credential/secret semantic type has an unconditional SECRET sensitivity floor.
    // A contradictory planted oracle must never remove it from the escape denominator.
    if (semanticType === 'CREDENTIAL_OR_SECRET' && sensitivity !== 'SECRET') invalid();
    // Secret fixtures here use disallowed captured sinks; no policy exception is asserted.
    if (sensitivity === 'SECRET' && expectedBySink.some((target) => target.treatment === 'KEEP')) invalid();
    return { id: id(plant.id), fieldRef, start, end, value, semanticType, sensitivity, trust,
      critical: plant.critical, expectedBySink,
      ...(Object.hasOwn(plant, 'subtype') ? { subtype: subtype(plant.subtype) } : {}) };
  });
  if (new Set(occurrences.map((plant) => plant.id)).size !== occurrences.length) invalid();
  // Defense in depth: never reuse the full planted value as a fixture or reporting label.
  // Ordinary report case/sink references below are minted independently, not copied from IDs.
  const visible = [record.id, record.familyId, ...record.sinks.map((sink) => sink.id),
    'development', 'secret-plaintext-escape', 'candidate-detection', 'task-correctness',
    'operational-measurement', 'independently-executed', 'untested', 'pass', 'fail', 'observed-only'];
  if (occurrences.some((plant) => visible.some((entry) => entry.includes(plant.value)))) invalid();
  if (Object.hasOwn(candidate, 'taskExpected') && !record.task) invalid();
  return { version: 1, caseId: record.id, occurrences,
    ...(Object.hasOwn(candidate, 'taskExpected') ? { taskExpected: plain(candidate.taskExpected) } : {}) };
}
function candidateRecords(input: unknown, record: DevelopmentCase): CandidateEvent[] {
  return list(input, 256).map((raw) => {
    const item = object(raw, ['fieldRef', 'start', 'end', 'semanticType'], ['subtype']);
    const fieldRef = id(item.fieldRef);
    const field = record.fields.find((entry) => entry.ref === fieldRef);
    if (!field) invalid();
    const length = encoder.encode(field.content).length;
    const start = offset(item.start, length);
    const end = offset(item.end, length);
    if (start >= end) invalid();
    return { fieldRef, start, end, semanticType: enumeration(item.semanticType, SEMANTIC_CLASSES),
      ...(Object.hasOwn(item, 'subtype') ? { subtype: subtype(item.subtype) } : {}) };
  });
}
function capturedBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) invalid();
  if (value.byteLength > MAX_CAPTURE_BYTES) invalid();
  return new Uint8Array(value);
}
function copyRelease(release: SerializedRelease): SerializedRelease {
  return { caseId: release.caseId, sinkId: release.sinkId,
    body: new Uint8Array(release.body), metadata: new Uint8Array(release.metadata) };
}
/** Captures *already serialized* body and metadata at a controlled local sink; sends nothing. */
export function createInMemorySinkCapture(): InMemorySinkCapture {
  let records: SerializedRelease[] = [];
  let bytesHeld = 0;
  const capture: InMemorySinkCapture = {
    capture(release) {
      safe(() => {
        const v = object(release, ['caseId', 'sinkId', 'body', 'metadata']);
        const body = capturedBytes(v.body);
        const metadata = capturedBytes(v.metadata);
        const size = body.length + metadata.length;
        if (!size || size > MAX_CAPTURE_BYTES || records.length >= MAX_CAPTURE_COUNT ||
          bytesHeld + size > MAX_CAPTURE_TOTAL_BYTES) invalid();
        records.push({ caseId: id(v.caseId), sinkId: id(v.sinkId), body, metadata });
        bytesHeld += size;
      });
    },
    forCase(caseId) { return safe(() => records.filter((record) => record.caseId === id(caseId)).map(copyRelease)); },
    clear() { records = []; bytesHeld = 0; },
  };
  Object.freeze(capture);
  issuedCaptures.add(capture);
  return capture;
}
/** A linear-time byte matcher; decoding/re-serializing a capture would change the observation. */
function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  const prefix: number[] = Array(needle.length).fill(0) as number[];
  for (let i = 1, matched = 0; i < needle.length; i++) {
    while (matched && needle[i] !== needle[matched]) matched = prefix[matched - 1] ?? 0;
    if (needle[i] === needle[matched]) matched++;
    prefix[i] = matched;
  }
  for (let i = 0, matched = 0; i < haystack.length; i++) {
    while (matched && haystack[i] !== needle[matched]) matched = prefix[matched - 1] ?? 0;
    if (haystack[i] === needle[matched]) matched++;
    if (matched === needle.length) return true;
  }
  return false;
}
function measured(claim: EvaluationClaim, outcome: ObservedOutcome, sinkId?: string): ObservedEvidence {
  return { claim, ...(sinkId ? { sinkId } : {}), provenance: 'independently-executed', outcome };
}
function untested(claim: EvaluationClaim, reason: UntestedEvidence['reason'], sinkId?: string): UntestedEvidence {
  return { claim, ...(sinkId ? { sinkId } : {}), provenance: 'untested', reason };
}
/** Registry makes independent oracle registration precede candidate events; ordinary reports never expose it. */
export function createDevelopmentEvaluation(): DevelopmentEvaluation {
  const cases = new Map<string, DevelopmentCase>();
  // Local ordinal references are evaluator-minted: fixture IDs can contain planted prefixes.
  const reportCaseIds = new Map<string, string>();
  const oracles = new Map<string, IndependentOracle>();
  const candidates = new Map<string, CandidateEvent[]>();
  const taskResults = new Map<string, string>();
  const measurements = new Map<string, OperationalMeasurement>();
  return {
    registerCase(input) {
      safe(() => {
        const record = caseRecord(input);
        if (cases.has(record.id) || cases.size >= 256) invalid();
        reportCaseIds.set(record.id, `case-${cases.size + 1}`);
        cases.set(record.id, record);
      });
    },
    registerOracle(input) {
      safe(() => {
        const header = object(input, ['version', 'caseId', 'occurrences'], ['taskExpected']);
        const record = cases.get(id(header.caseId));
        if (!record || oracles.has(record.id)) invalid();
        oracles.set(record.id, oracleRecord(input, record));
      });
    },
    registerCandidateEvents(caseId, input) {
      safe(() => {
        const key = id(caseId);
        const record = cases.get(key);
        if (!record || !oracles.has(key) || candidates.has(key)) invalid();
        candidates.set(key, candidateRecords(input, record));
      });
    },
    async runCandidate(caseId, candidate, sink) {
      let key: string;
      let record: DevelopmentCase;
      try {
        key = id(caseId);
        const selected = cases.get(key);
        if (!selected || !oracles.has(key) || candidates.has(key) ||
          typeof candidate !== 'function' || !issuedCaptures.has(sink)) invalid();
        record = selected;
      } catch { return invalid(); }
      const view: CandidateInput = Object.freeze({
        version: 1, caseId: record.id, familyId: record.familyId,
        fields: Object.freeze(record.fields.map((field) => Object.freeze({ ...field }))),
        sinks: Object.freeze(record.sinks.map((target) => Object.freeze({ ...target }))),
        ...(record.context ? { context: Object.freeze({ ...record.context }) } : {}),
        ...(record.task ? { task: Object.freeze({ ...record.task }) } : {}),
      });
      let active = true;
      const send: ControlledSyntheticSend = (sinkId, serialized) => safe(() => {
        if (!active || !record.sinks.some((target) => target.id === id(sinkId))) invalid();
        const wire = object(serialized, ['body', 'metadata']);
        // Evaluation owns the controlled sink; this only observes bytes supplied after serialization.
        sink.capture({ caseId: key, sinkId, body: wire.body as Uint8Array,
          metadata: wire.metadata as Uint8Array });
      });
      try {
        const result = object(await candidate(view, send), ['events'], ['taskResult']);
        active = false;
        const events = candidateRecords(result.events, record);
        let taskResult: string | undefined;
        if (Object.hasOwn(result, 'taskResult')) {
          if (!record.task || oracles.get(key)?.taskExpected === undefined) invalid();
          taskResult = plain(result.taskResult);
          if (taskResults.has(key)) invalid();
        }
        candidates.set(key, events);
        if (taskResult !== undefined) taskResults.set(key, taskResult);
      } catch { active = false; return invalid(); }
    },
    recordTaskResult(caseId, actual) {
      safe(() => {
        const key = id(caseId);
        if (!oracles.has(key) || !cases.get(key)?.task || taskResults.has(key)) invalid();
        taskResults.set(key, plain(actual));
      });
    },
    recordOperationalMeasurement(caseId, measurement) {
      safe(() => {
        const key = id(caseId);
        if (!oracles.has(key) || measurements.has(key)) invalid();
        const m = object(measurement, ['latencyMs', 'computeMs', 'modelApiCostMicrounits']);
        measurements.set(key, {
          latencyMs: nonnegativeMeasure(m.latencyMs, 1_000_000_000),
          computeMs: nonnegativeMeasure(m.computeMs, 1_000_000_000),
          modelApiCostMicrounits: nonnegativeMeasure(m.modelApiCostMicrounits, 1_000_000_000_000),
        });
      });
    },
    report(caseId, sink, gradeTask) {
      return safe(() => {
        const key = id(caseId);
        const record = cases.get(key);
        const oracle = oracles.get(key);
        const reportCaseId = reportCaseIds.get(key);
        if (!record || !oracle || !reportCaseId || !issuedCaptures.has(sink)) invalid();
        const captures = sink.forCase(key);
        if (captures.some((capture) => !record.sinks.some((target) => target.id === capture.sinkId))) invalid();
        const observed: ObservedEvidence[] = [];
        const missing: UntestedEvidence[] = [];
        // Keep metric selection robust if a future oracle ingestion path weakens validation.
        const secrets = oracle.occurrences.filter((plant) => plant.sensitivity === 'SECRET' ||
          plant.semanticType === 'CREDENTIAL_OR_SECRET');
        let testedSinkPairs = 0;
        let criticalPlaintextEscapes = 0;
        for (const [index, target] of record.sinks.entries()) {
          const reportSinkId = `sink-${index + 1}`;
          const releases = captures.filter((capture) => capture.sinkId === target.id);
          if (!secrets.length) { missing.push(untested('secret-plaintext-escape', 'no-secret-control', reportSinkId)); continue; }
          if (!releases.length) { missing.push(untested('secret-plaintext-escape', 'no-capture', reportSinkId)); continue; }
          testedSinkPairs += secrets.length;
          let leaked = false;
          for (const plant of secrets) {
            const value = encoder.encode(plant.value);
            if (releases.some((capture) => containsBytes(capture.body, value) ||
              containsBytes(capture.metadata, value))) {
              leaked = true;
              if (plant.critical) criticalPlaintextEscapes++;
            }
          }
          observed.push(measured('secret-plaintext-escape', leaked ? 'fail' : 'pass', reportSinkId));
        }
        const emitted = candidates.get(key);
        let matched = 0;
        let falsePositives = 0;
        if (emitted) {
          const used = new Set<number>();
          for (const planted of oracle.occurrences) {
            const hit = emitted.findIndex((event, index) => !used.has(index) &&
              event.fieldRef === planted.fieldRef && event.start === planted.start &&
              event.end === planted.end && event.semanticType === planted.semanticType &&
              event.subtype === planted.subtype);
            if (hit >= 0) { used.add(hit); matched++; }
          }
          falsePositives = emitted.length - used.size;
          observed.push(measured('candidate-detection', 'observed-only'));
        } else missing.push(untested('candidate-detection', 'no-candidate-events'));
        let taskCorrect: boolean | null = null;
        if (!record.task || oracle.taskExpected === undefined) missing.push(untested('task-correctness', 'no-task-control'));
        else if (!taskResults.has(key)) missing.push(untested('task-correctness', 'no-task-result'));
        else if (typeof gradeTask !== 'function') missing.push(untested('task-correctness', 'no-grader'));
        else {
          // A grader's exception/non-boolean result is an unknown measurement, never a pass.
          try {
            const result: unknown = gradeTask(oracle.taskExpected, taskResults.get(key) as string);
            if (typeof result !== 'boolean') missing.push(untested('task-correctness', 'grader-error'));
            else { taskCorrect = result; observed.push(measured('task-correctness', result ? 'pass' : 'fail')); }
          } catch { missing.push(untested('task-correctness', 'grader-error')); }
        }
        const measurement = measurements.get(key);
        if (measurement) observed.push(measured('operational-measurement', 'observed-only'));
        else missing.push(untested('operational-measurement', 'no-operational-observation'));
        const planted = oracle.occurrences.length;
        const candidatesReport = { planted, matched, misses: emitted ? planted - matched : 0, falsePositives,
          recall: emitted && planted ? matched / planted : null,
          precision: emitted && emitted.length ? matched / emitted.length : null };
        return { version: 1, caseId: reportCaseId, familyId: record.familyId, partition: 'development',
          observed, untested: missing, privacy: { secretPlanted: secrets.length, testedSinkPairs, criticalPlaintextEscapes },
          candidates: candidatesReport, utility: { taskCorrect },
          operations: { latencyMs: measurement?.latencyMs ?? null, computeMs: measurement?.computeMs ?? null,
            modelApiCostMicrounits: measurement?.modelApiCostMicrounits ?? null } };
      });
    },
    clear() { cases.clear(); reportCaseIds.clear(); oracles.clear(); candidates.clear(); taskResults.clear(); measurements.clear(); },
  };
}
