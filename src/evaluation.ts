/**
 * Synthetic evaluation-only, NON-ENFORCING seam. Never send real or private material here.
 * Not a production isolation boundary, policy engine, or the final #19 byte sentinel.
 * Post-serialization captures are ephemeral in-memory test observations, not permission to send.
 */
import type { SemanticClass, Sensitivity, Trust } from './classification.js';

export type Treatment = 'KEEP' | 'MASK' | 'TOKENIZE' | 'SYNTHETIC' | 'GENERALIZE' |
  'REMOVE' | 'BLOCK' | 'REQUIRE_REVIEW';
export interface DevelopmentCase {
  version: 1;
  id: string;
  familyId: string;
  partition: 'development';
  fields: readonly { ref: string; content: string }[];
  sinks: readonly { id: string; surface: string; profileId: string }[];
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
export function createInMemorySinkCapture(): InMemorySinkCapture {
  return { capture(_release) {}, forCase(_caseId) { return []; }, clear() {} };
}
export type EvaluationClaim = 'secret-plaintext-escape' | 'candidate-detection' | 'task-correctness';
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
    'no-task-result' | 'no-grader' | 'grader-error';
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
}
export type GradeTask = (expected: string, actual: string) => boolean;
export interface DevelopmentEvaluation {
  registerCase(record: DevelopmentCase): void;
  registerOracle(record: IndependentOracle): void;
  registerCandidateEvents(caseId: string, events: readonly CandidateEvent[]): void;
  recordTaskResult(caseId: string, actual: string): void;
  report(caseId: string, sink: InMemorySinkCapture, gradeTask?: GradeTask): EvaluationReport;
  clear(): void;
}
export function createDevelopmentEvaluation(): DevelopmentEvaluation {
  return {
    registerCase(_record) {}, registerOracle(_record) {}, registerCandidateEvents(_caseId, _events) {},
    recordTaskResult(_caseId, _actual) {},
    report(caseId) {
      return { version: 1, caseId, familyId: '', partition: 'development', observed: [], untested: [],
        privacy: { secretPlanted: 0, testedSinkPairs: 0, criticalPlaintextEscapes: 0 },
        candidates: { planted: 0, matched: 0, misses: 0, falsePositives: 0, recall: null, precision: null },
        utility: { taskCorrect: null } };
    },
    clear() {},
  };
}
