import { createHash } from 'node:crypto';
import { SEMANTIC_CLASSES, SENSITIVITIES, TRUST_LEVELS } from './classification.js';
import type { Classification, ClassificationClaim, EvidenceRecord, SemanticClass, Sensitivity, Trust } from './classification.js';
import type { Destination, Endpoint, RequestContext, Subject } from './interaction-envelope.js';

/** Policy is a pure decision seam. Only a trusted integration may supply boundary, bundle and review. */
export const POLICY_TREATMENTS = [
  'KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE', 'BLOCK', 'REQUIRE_REVIEW',
] as const;
export type Treatment = (typeof POLICY_TREATMENTS)[number];
export type ReleaseTreatment = Exclude<Treatment, 'BLOCK' | 'REQUIRE_REVIEW'>;
export const POLICY_OPERATIONS = ['SEND', 'USE', 'DISPLAY', 'EXPORT'] as const;
export type PolicyOperation = (typeof POLICY_OPERATIONS)[number];
export const KNOWN_POLICY_BUNDLE = Object.freeze({ id: 'hylja.foundation', version: '1' });
export interface PolicyRequest {
  version: 1;
  interactionRef: string;
  /** Opaque candidate-unit reference, supplied separately by trusted integration. */
  candidateRef: string;
  subject: Subject;
  context: RequestContext;
  source: Endpoint;
  destination: Destination;
  classification: Classification;
  operation: PolicyOperation;
  policy: { id: string; version: string };
  /** Classification/model advice is never a policy rule or authorization. */
  semanticRecommendation?: Treatment;
}
export interface PolicyBoundary {
  interactionRef: string;
  candidateRef: string;
  /** Independently pinned digest of the trusted composer output for this candidate. */
  classificationDigest: string;
  authenticated: { subject: Subject; context: RequestContext };
  observed: { source: Endpoint & { trust: Trust }; destination: Destination };
  /** Independently pinned control-plane SHA-256 of the exact normalized bundle snapshot. */
  policy: { id: string; version: string; digest: string };
}
export interface DestinationProfile {
  id: string;
  sink: Destination;
  exposure: 'LOCAL' | 'EXTERNAL';
  permittedTreatments: readonly ReleaseTreatment[];
  maxCleartextSensitivity: Sensitivity;
}
export interface PolicyRule {
  id: string;
  profileId: string;
  semanticType: SemanticClass;
  sensitivities: readonly Sensitivity[];
  sourceTrust: readonly Trust[];
  operations: readonly PolicyOperation[];
  decision: Treatment;
  reviewTreatments?: readonly ReleaseTreatment[];
}
export interface PolicyBundle {
  id: string;
  version: string;
  profiles: readonly DestinationProfile[];
  rules: readonly PolicyRule[];
}
export interface PolicyDecision {
  version: 1;
  state: 'DENIED' | 'HELD' | 'SELECTED';
  treatment: Treatment;
  reason: string;
  /** Unkeyed replay fingerprint, NOT an authorization token or proof of review. */
  decisionRef?: string;
}
export interface TrustedReviewOutcome {
  version: 1;
  decisionRef: string;
  policy: { id: string; version: string; digest: string };
  binding: {
    interactionRef: string;
    candidateRef: string;
    classificationDigest: string;
    subject: Subject;
    context: RequestContext;
    source: Endpoint & { trust: Trust };
    destination: Destination;
  };
  reviewerRef: string;
  treatment: ReleaseTreatment;
}

// In-process values are untrusted structurally: use own data descriptors rather than getters,
// inherited properties, model strings or arbitrary exception text. Authentication and route
// observation themselves are obligations of the separate, trusted caller of this pure seam.
type Fields = Record<string, unknown>;
class Invalid extends Error { constructor(readonly code: string) { super(code); } }
function fail(code: string): never { throw new Invalid(code); }
function fields(value: unknown, required: readonly string[], optional: readonly string[] = []): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_INPUT');
  // A single bounded key snapshot prevents Proxy ownKeys from changing between reflections.
  const keys = Reflect.ownKeys(value);
  if (keys.length > 64 || keys.some((key) => typeof key !== 'string')) fail('INVALID_INPUT');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) fail('INVALID_INPUT');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_INPUT');
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail('INVALID_INPUT');
  return result;
}
function text(value: unknown, limit = 256): string {
  if (typeof value !== 'string' || !value.length || value.length > limit || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) fail('INVALID_INPUT');
  return value;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) fail('INVALID_INPUT');
  return value as T;
}
function items<T>(value: unknown, convert: (part: unknown) => T, limit: number,
  nonempty = false): T[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail('INVALID_INPUT');
  const keys = Reflect.ownKeys(value);
  if (keys.length > limit + 1 || keys.some((key) => typeof key !== 'string')) fail('INVALID_INPUT');
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  const length: unknown = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || (length as number) < 0 ||
    (length as number) > limit || (nonempty && length === 0) ||
    keys.length !== (length as number) + 1 || !keys.includes('length')) fail('INVALID_INPUT');
  const result: T[] = [];
  for (let i = 0; i < (length as number); i++) {
    const part = Object.getOwnPropertyDescriptor(value, String(i));
    if (!part?.enumerable || !('value' in part)) fail('INVALID_INPUT');
    result.push(convert(part.value));
  }
  return result;
}
function unique<T extends string>(value: unknown, choices: readonly T[]): T[] {
  const result = items(value, (v) => member(v, choices), choices.length, true);
  if (new Set(result).size !== result.length) fail('INVALID_INPUT');
  return result.sort();
}
function subject(value: unknown): Subject {
  const v = fields(value, ['principalId'], ['workloadId']);
  return { principalId: text(v.principalId),
    ...(Object.hasOwn(v, 'workloadId') ? { workloadId: text(v.workloadId) } : {}) };
}
function context(value: unknown): RequestContext {
  const v = fields(value, ['tenantId', 'sessionId', 'purpose'], ['projectId']);
  return { tenantId: text(v.tenantId),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: text(v.projectId) } : {}),
    sessionId: text(v.sessionId), purpose: text(v.purpose) };
}
function endpoint(value: unknown): Endpoint {
  const v = fields(value, ['kind', 'ref', 'trustZone']);
  return { kind: text(v.kind), ref: text(v.ref, 2048), trustZone: text(v.trustZone) };
}
function destination(value: unknown): Destination {
  const v = fields(value, ['kind', 'ref', 'trustZone', 'profileId']);
  return { kind: text(v.kind), ref: text(v.ref, 2048), trustZone: text(v.trustZone),
    profileId: text(v.profileId) };
}
function sourceWithTrust(value: unknown): Endpoint & { trust: Trust } {
  const v = fields(value, ['kind', 'ref', 'trustZone', 'trust']);
  return { kind: text(v.kind), ref: text(v.ref, 2048), trustZone: text(v.trustZone),
    trust: member(v.trust, TRUST_LEVELS) };
}
function identity(value: unknown): { id: string; version: string } {
  const v = fields(value, ['id', 'version']);
  return { id: text(v.id), version: text(v.version) };
}
function pinnedDigest(value: unknown): string {
  const digest = text(value);
  if (!/^[a-f0-9]{64}$/u.test(digest)) fail('INVALID_CONTEXT');
  return digest;
}
function pinnedIdentity(value: unknown): PolicyBoundary['policy'] {
  const v = fields(value, ['id', 'version', 'digest']);
  return { id: text(v.id), version: text(v.version), digest: pinnedDigest(v.digest) };
}
function evidenceRecord(value: unknown): EvidenceRecord {
  const v = fields(value, ['version', 'source', 'status'], ['id', 'provenance', 'claim']);
  if (v.version !== 1) fail('INVALID_CLASSIFICATION');
  const source = member(v.source, ['detector', 'parser', 'semantic']);
  if (v.status === 'INVALID') {
    if (Object.hasOwn(v, 'id') || Object.hasOwn(v, 'provenance') || Object.hasOwn(v, 'claim')) {
      fail('INVALID_CLASSIFICATION');
    }
    return { version: 1, source, status: 'INVALID' };
  }
  const status = member(v.status, ['FOUND', 'ABSTAIN', 'FAILURE']);
  const p = fields(v.provenance, ['inputRef', 'producerId', 'producerVersion'],
    source === 'semantic' ? ['questionSetVersion', 'modelId'] : []);
  const provenance = { inputRef: text(p.inputRef, 1024), producerId: text(p.producerId),
    producerVersion: text(p.producerVersion),
    ...(source === 'semantic' ? { questionSetVersion: text(p.questionSetVersion),
      modelId: text(p.modelId) } : {}) };
  const id = text(v.id);
  if (status !== 'FOUND') {
    if (Object.hasOwn(v, 'claim')) fail('INVALID_CLASSIFICATION');
    return { version: 1, id, source, provenance, status };
  }
  const c = fields(v.claim, ['semanticType'], ['subtype', 'sensitivity', 'reversible', 'scope', 'confidence']);
  if (Object.hasOwn(c, 'reversible') && typeof c.reversible !== 'boolean') fail('INVALID_CLASSIFICATION');
  if (Object.hasOwn(c, 'confidence') && (source !== 'semantic' ||
    typeof c.confidence !== 'number' || !Number.isFinite(c.confidence) ||
    c.confidence < 0 || c.confidence > 1)) fail('INVALID_CLASSIFICATION');
  const claim: ClassificationClaim = { semanticType: text(c.semanticType, 64),
    ...(Object.hasOwn(c, 'subtype') ? { subtype: text(c.subtype, 64) } : {}),
    ...(Object.hasOwn(c, 'sensitivity') ? { sensitivity: member(c.sensitivity, SENSITIVITIES) } : {}),
    ...(Object.hasOwn(c, 'reversible') ? { reversible: c.reversible as boolean } : {}),
    ...(Object.hasOwn(c, 'scope') ? { scope: member(c.scope, ['request', 'session', 'project', 'tenant']) } : {}),
    ...(Object.hasOwn(c, 'confidence') ? { confidence: c.confidence as number } : {}) };
  return { version: 1, id, source, provenance, status, claim };
}
function classification(value: unknown): Classification {
  const v = fields(value, ['version', 'status', 'semanticType', 'sensitivity', 'trust',
    'reversible', 'scope', 'reasons', 'evidence', 'provenance'], ['subtype']);
  if (v.version !== 1 || typeof v.reversible !== 'boolean') fail('INVALID_CLASSIFICATION');
  const status = member(v.status, ['RESOLVED', 'UNRESOLVED']);
  const semanticType = member(v.semanticType, [...SEMANTIC_CLASSES, 'UNKNOWN']);
  const sensitivity = member(v.sensitivity, [...SENSITIVITIES, 'UNKNOWN']);
  const trust = member(v.trust, TRUST_LEVELS);
  const scope = member(v.scope, ['request', 'session', 'project', 'tenant']);
  const provenance = fields(v.provenance, ['interactionRef', 'sourceRef']);
  const reasons = items(v.reasons, text, 64);
  const evidence = items(v.evidence, evidenceRecord, 768);
  const subtype = Object.hasOwn(v, 'subtype') ? text(v.subtype, 64) : undefined;
  if (status === 'RESOLVED') {
    if (semanticType === 'UNKNOWN' || sensitivity === 'UNKNOWN' || reasons.length !== 0 ||
      evidence.length === 0 || !evidence.some((record) => record.source === 'detector' &&
        record.status === 'FOUND') || evidence.some((record) => record.status !== 'FOUND' ||
          !record.claim || record.claim.semanticType !== semanticType ||
          record.claim.sensitivity !== undefined && record.claim.sensitivity !== sensitivity ||
          record.claim.sensitivity === undefined && semanticType !== 'CREDENTIAL_OR_SECRET' ||
          record.claim.subtype !== undefined && record.claim.subtype !== subtype) ||
      new Set(evidence.map((record) => record.status === 'FOUND' ? record.id : '')).size !== evidence.length ||
      semanticType === 'CREDENTIAL_OR_SECRET' && sensitivity !== 'SECRET' ||
      sensitivity === 'SECRET' && v.reversible === true) fail('INVALID_CLASSIFICATION');
  }
  return { version: 1, status, semanticType, ...(subtype ? { subtype } : {}), sensitivity,
    trust, reversible: v.reversible, scope, reasons, evidence,
    provenance: { interactionRef: text(provenance.interactionRef), sourceRef: text(provenance.sourceRef, 2048) } };
}
function request(value: unknown): PolicyRequest {
  const v = fields(value, ['version', 'interactionRef', 'candidateRef', 'subject', 'context', 'source',
    'destination', 'classification', 'operation', 'policy'], ['semanticRecommendation']);
  if (v.version !== 1) fail('INVALID_REQUEST');
  return { version: 1, interactionRef: text(v.interactionRef), candidateRef: text(v.candidateRef),
    subject: subject(v.subject),
    context: context(v.context), source: endpoint(v.source), destination: destination(v.destination),
    classification: classification(v.classification), operation: member(v.operation, POLICY_OPERATIONS),
    policy: identity(v.policy),
    ...(Object.hasOwn(v, 'semanticRecommendation') ?
      { semanticRecommendation: member(v.semanticRecommendation, POLICY_TREATMENTS) } : {}) };
}
function boundary(value: unknown): PolicyBoundary {
  const v = fields(value, ['interactionRef', 'candidateRef', 'classificationDigest',
    'authenticated', 'observed', 'policy']);
  const a = fields(v.authenticated, ['subject', 'context']);
  const o = fields(v.observed, ['source', 'destination']);
  return { interactionRef: text(v.interactionRef), candidateRef: text(v.candidateRef),
    classificationDigest: pinnedDigest(v.classificationDigest),
    authenticated: { subject: subject(a.subject), context: context(a.context) },
    observed: { source: sourceWithTrust(o.source), destination: destination(o.destination) },
    policy: pinnedIdentity(v.policy) };
}
const RELEASE_TREATMENTS = POLICY_TREATMENTS.slice(0, 6) as readonly ReleaseTreatment[];
function profile(value: unknown): DestinationProfile {
  const v = fields(value, ['id', 'sink', 'exposure', 'permittedTreatments', 'maxCleartextSensitivity']);
  const sink = destination(v.sink);
  const id = text(v.id);
  const exposure = member(v.exposure, ['LOCAL', 'EXTERNAL']);
  if (id !== sink.profileId || sink.trustZone !== exposure) fail('INVALID_BUNDLE');
  return { id, sink, exposure, permittedTreatments: unique(v.permittedTreatments, RELEASE_TREATMENTS),
    maxCleartextSensitivity: member(v.maxCleartextSensitivity, SENSITIVITIES) };
}
function rule(value: unknown): PolicyRule {
  const v = fields(value, ['id', 'profileId', 'semanticType', 'sensitivities', 'sourceTrust',
    'operations', 'decision'], ['reviewTreatments']);
  const decision = member(v.decision, POLICY_TREATMENTS);
  const review = Object.hasOwn(v, 'reviewTreatments') ?
    unique(v.reviewTreatments, RELEASE_TREATMENTS) : undefined;
  if ((decision === 'REQUIRE_REVIEW') !== (review !== undefined)) fail('INVALID_BUNDLE');
  return { id: text(v.id), profileId: text(v.profileId),
    semanticType: member(v.semanticType, SEMANTIC_CLASSES),
    sensitivities: unique(v.sensitivities, SENSITIVITIES),
    sourceTrust: unique(v.sourceTrust, TRUST_LEVELS),
    operations: unique(v.operations, POLICY_OPERATIONS), decision,
    ...(review ? { reviewTreatments: review } : {}) };
}
function bundle(value: unknown): PolicyBundle {
  const v = fields(value, ['id', 'version', 'profiles', 'rules']);
  const result: PolicyBundle = { id: text(v.id), version: text(v.version),
    profiles: items(v.profiles, profile, 256), rules: items(v.rules, rule, 4096) };
  if (new Set(result.profiles.map((p) => p.id)).size !== result.profiles.length ||
    new Set(result.rules.map((r) => r.id)).size !== result.rules.length ||
    result.rules.some((r) => !result.profiles.some((p) => p.id === r.profileId))) fail('INVALID_BUNDLE');
  return result;
}
function canonicalBundle(config: PolicyBundle): object {
  return { id: config.id, version: config.version,
    profiles: [...config.profiles].sort((a, z) => a.id < z.id ? -1 : a.id > z.id ? 1 : 0),
    rules: [...config.rules].sort((a, z) => a.id < z.id ? -1 : a.id > z.id ? 1 : 0) };
}
function hash(value: object): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
/** Computes a content commitment; the caller must independently pin and protect this digest. */
export function digestPolicyBundle(value: unknown): string {
  try { return hash(canonicalBundle(bundle(value))); }
  catch { throw new TypeError('Invalid policy bundle'); }
}
/** Content commitment for a validated composer record; only an independent trusted pin is authoritative. */
export function digestClassification(value: unknown): string {
  try { return hash(classification(value)); }
  catch { throw new TypeError('Invalid classification'); }
}
function equal(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function denied(reason: string): PolicyDecision {
  return { version: 1, state: 'DENIED', treatment: 'BLOCK', reason };
}
function safeTreatment(treatment: ReleaseTreatment, p: DestinationProfile, c: Classification): boolean {
  if (!p.permittedTreatments.includes(treatment)) return false;
  const secret = c.sensitivity === 'SECRET' || c.semanticType === 'CREDENTIAL_OR_SECRET';
  if (p.exposure === 'EXTERNAL' && secret && !['MASK', 'REMOVE'].includes(treatment)) return false;
  if (treatment === 'KEEP' && SENSITIVITIES.indexOf(c.sensitivity as Sensitivity) >
    SENSITIVITIES.indexOf(p.maxCleartextSensitivity)) return false;
  return true;
}
function fingerprint(r: PolicyRequest, b: PolicyBoundary, config: PolicyBundle, selected: PolicyRule): string {
  // Deliberately excludes raw candidate evidence, payload and advice. Canonical order survives
  // JSON replay and profile/rule array reorder; the bundle CONTENT is pinned, not just its label.
  const canonical = { policy: canonicalBundle(config),
    binding: { interactionRef: b.interactionRef, candidateRef: b.candidateRef,
      classificationDigest: b.classificationDigest, subject: b.authenticated.subject,
      context: b.authenticated.context, source: b.observed.source, destination: b.observed.destination },
    classification: { status: r.classification.status, semanticType: r.classification.semanticType,
      subtype: r.classification.subtype ?? null, sensitivity: r.classification.sensitivity,
      trust: r.classification.trust, provenance: r.classification.provenance },
    operation: r.operation, rule: selected.id };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}
function checked(requestValue: unknown, boundaryValue: unknown, bundleValue: unknown): {
  decision: PolicyDecision; rule?: PolicyRule; profile?: DestinationProfile;
  request?: PolicyRequest; boundary?: PolicyBoundary;
} {
  let r: PolicyRequest;
  let b: PolicyBoundary;
  let config: PolicyBundle;
  try { r = request(requestValue); } catch { return { decision: denied('INVALID_REQUEST') }; }
  try { b = boundary(boundaryValue); } catch { return { decision: denied('INVALID_CONTEXT') }; }
  if (!equal(r.subject, b.authenticated.subject) || !equal(r.context, b.authenticated.context) ||
    r.interactionRef !== b.interactionRef || r.candidateRef !== b.candidateRef || !equal(r.source, {
      kind: b.observed.source.kind, ref: b.observed.source.ref, trustZone: b.observed.source.trustZone,
    }) || !equal(r.destination, b.observed.destination) ||
    !equal(r.classification.provenance, { interactionRef: b.interactionRef, sourceRef: b.observed.source.ref }) ||
    r.classification.trust !== b.observed.source.trust) return { decision: denied('CONTEXT_MISMATCH') };
  if (hash(r.classification) !== b.classificationDigest) {
    return { decision: denied('CLASSIFICATION_MISMATCH') };
  }
  if (!equal(r.policy, { id: b.policy.id, version: b.policy.version }) ||
    !equal(r.policy, KNOWN_POLICY_BUNDLE)) return { decision: denied('UNKNOWN_POLICY') };
  try { config = bundle(bundleValue); } catch { return { decision: denied('UNAVAILABLE_BUNDLE') }; }
  if (!equal({ id: config.id, version: config.version }, r.policy)) {
    return { decision: denied('UNKNOWN_POLICY') };
  }
  if (hash(canonicalBundle(config)) !== b.policy.digest) {
    return { decision: denied('BUNDLE_MISMATCH') };
  }
  const matches = config.profiles.filter((p) => p.id === b.observed.destination.profileId);
  if (matches.length !== 1 || !equal(matches[0]!.sink, b.observed.destination) ||
    matches[0]!.exposure !== b.observed.destination.trustZone) {
    return { decision: denied('PROFILE_MISMATCH') };
  }
  const p = matches[0]!;
  // Unresolved evidence never becomes benign through semantic advice or an absent rule.
  if (r.classification.status !== 'RESOLVED' || r.classification.semanticType === 'UNKNOWN' ||
    r.classification.sensitivity === 'UNKNOWN') return { decision: denied('UNRESOLVED_CLASSIFICATION') };
  const rules = config.rules.filter((item) => item.profileId === p.id &&
    item.semanticType === r.classification.semanticType &&
    item.sensitivities.includes(r.classification.sensitivity as Sensitivity) &&
    item.sourceTrust.includes(b.observed.source.trust) && item.operations.includes(r.operation));
  if (rules.length !== 1) return { decision: denied(rules.length ? 'AMBIGUOUS_RULE' : 'NO_RULE') };
  const selected = rules[0]!;
  if (selected.decision === 'BLOCK') return { decision: denied('RULE_BLOCK') };
  const treatments = selected.decision === 'REQUIRE_REVIEW' ? selected.reviewTreatments! :
    [selected.decision as ReleaseTreatment];
  if (!treatments.every((t) => safeTreatment(t, p, r.classification))) {
    return { decision: denied('UNSAFE_TREATMENT') };
  }
  const decisionRef = fingerprint(r, b, config, selected);
  return { request: r, boundary: b, profile: p, rule: selected,
    decision: { version: 1, state: selected.decision === 'REQUIRE_REVIEW' ? 'HELD' : 'SELECTED',
      treatment: selected.decision, reason: selected.decision === 'REQUIRE_REVIEW' ? 'RULE_REVIEW' : 'RULE_SELECTED',
      decisionRef } };
}

/** Select only a treatment or deny/hold; this function never transforms, reveals, sends or brokers bytes. */
export function decidePolicy(requestValue: unknown, trustedBoundary: unknown,
  trustedBundle: unknown): PolicyDecision {
  try { return checked(requestValue, trustedBoundary, trustedBundle).decision; }
  catch { return denied('INVALID_INPUT'); }
}

/** Caller must authenticate and authorize the review independently before supplying its outcome. */
export function decideReviewedPolicy(requestValue: unknown, trustedBoundary: unknown,
  trustedBundle: unknown, previous: unknown, trustedOutcome: unknown): PolicyDecision {
  try {
    const current = checked(requestValue, trustedBoundary, trustedBundle);
    if (current.decision.state !== 'HELD' || !current.rule || !current.request || !current.boundary) {
      return current.decision.state === 'DENIED' ? current.decision : denied('STALE_REVIEW');
    }
    // A caller-provided earlier decision is only a congruence check, never review authority.
    if (!equal(previous, current.decision)) return denied('STALE_REVIEW');
    if (trustedOutcome === undefined) return current.decision;
    let review: TrustedReviewOutcome;
    try {
      const v = fields(trustedOutcome, ['version', 'decisionRef', 'policy', 'binding',
        'reviewerRef', 'treatment']);
      const binding = fields(v.binding, ['interactionRef', 'candidateRef', 'classificationDigest',
        'subject', 'context', 'source', 'destination']);
      if (v.version !== 1) fail('INVALID_REVIEW');
      review = { version: 1, decisionRef: text(v.decisionRef), policy: pinnedIdentity(v.policy),
        binding: { interactionRef: text(binding.interactionRef), candidateRef: text(binding.candidateRef),
          classificationDigest: pinnedDigest(binding.classificationDigest), subject: subject(binding.subject),
          context: context(binding.context), source: sourceWithTrust(binding.source),
          destination: destination(binding.destination) },
        reviewerRef: text(v.reviewerRef), treatment: member(v.treatment, RELEASE_TREATMENTS) };
    } catch { return current.decision; } // Missing/invalid approval remains held.
    if (!equal(review.policy, current.boundary.policy) ||
      review.decisionRef !== current.decision.decisionRef ||
      !equal(review.binding, { interactionRef: current.boundary.interactionRef,
        candidateRef: current.boundary.candidateRef,
        classificationDigest: current.boundary.classificationDigest,
        subject: current.boundary.authenticated.subject, context: current.boundary.authenticated.context,
        source: current.boundary.observed.source, destination: current.boundary.observed.destination }) ||
      !current.rule.reviewTreatments?.includes(review.treatment)) return current.decision;
    return { version: 1, state: 'SELECTED', treatment: review.treatment,
      reason: 'REVIEW_SELECTED', decisionRef: current.decision.decisionRef };
  } catch { return denied('INVALID_INPUT'); }
}
