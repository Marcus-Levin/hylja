/** Provider-neutral classification vocabulary; this module makes no policy or release decisions. */
export const SEMANTIC_CLASSES = [
  'PERSON', 'CREDENTIAL_OR_SECRET', 'USER_ACCOUNT', 'NETWORK_IDENTIFIER',
  'HOST_OR_SERVICE', 'CLOUD_RESOURCE', 'FILE_OR_RESOURCE_PATH',
  'CUSTOMER_OR_PARTNER', 'PROJECT_OR_CONTRACT', 'APPLICATION_OR_ENVIRONMENT',
  'ENGINEERING_IDENTIFIER', 'BUSINESS_CONFIDENTIAL',
] as const;
export type SemanticClass = (typeof SEMANTIC_CLASSES)[number];
export const SENSITIVITIES = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET'] as const;
export type Sensitivity = (typeof SENSITIVITIES)[number];
export const TRUST_LEVELS = ['CONTROL', 'TRUSTED', 'VERIFIED_EXTERNAL', 'UNTRUSTED', 'HOSTILE'] as const;
export type Trust = (typeof TRUST_LEVELS)[number];
export const SCOPES = ['request', 'session', 'project', 'tenant'] as const;
export type Scope = (typeof SCOPES)[number];
export type SubtypeRegistry = Readonly<Record<SemanticClass, readonly string[]>>;

const initialSubtypes: SubtypeRegistry = {
  PERSON: ['NAME', 'EMAIL', 'PHONE'],
  CREDENTIAL_OR_SECRET: [
    'PASSWORD', 'API_KEY', 'PRIVATE_KEY', 'ACCESS_TOKEN', 'REFRESH_TOKEN', 'COOKIE',
    'CONNECTION_SECRET', 'CERTIFICATE_SECRET',
  ],
  USER_ACCOUNT: [],
  NETWORK_IDENTIFIER: ['IP', 'PORT', 'DOMAIN', 'URL', 'MAC', 'SUBNET'],
  HOST_OR_SERVICE: [],
  CLOUD_RESOURCE: [
    'TENANT_ID', 'SUBSCRIPTION_ID', 'ACCOUNT_ID', 'ARN', 'PROJECT_ID', 'RESOURCE_GROUP',
    'BUCKET', 'VAULT', 'SERVICE_ACCOUNT',
  ],
  FILE_OR_RESOURCE_PATH: [], CUSTOMER_OR_PARTNER: [], PROJECT_OR_CONTRACT: [],
  APPLICATION_OR_ENVIRONMENT: [],
  ENGINEERING_IDENTIFIER: [
    'ASSET_TAG', 'DRAWING_NUMBER', 'PART_NUMBER', 'ITEM_ID', 'DOCUMENT_ID',
    'FUNCTIONAL_LOCATION', 'PLC_TAG', 'SCADA_TAG',
  ],
  BUSINESS_CONFIDENTIAL: [],
};
const issuedRegistries = new WeakSet<object>();
function freezeRegistry(registry: SubtypeRegistry): SubtypeRegistry {
  for (const subtypes of Object.values(registry)) Object.freeze(subtypes);
  Object.freeze(registry);
  issuedRegistries.add(registry);
  return registry;
}
export const DEFAULT_SUBTYPES = freezeRegistry(initialSubtypes);

function data(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length > required.length + optional.length || keys.some((key) => typeof key !== 'string')) return null;
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
    result[key] = descriptor.value;
  }
  for (const key of required) if (!Object.hasOwn(result, key)) return null;
  return result;
}
function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit &&
    value.trim() === value && !/[\u0000-\u001f\u007f]/u.test(value);
}
function inSet<T extends string>(value: unknown, set: readonly T[]): value is T {
  return typeof value === 'string' && set.includes(value as T);
}

/** Extend only known parent classes; registry construction is a trusted configuration operation. */
export function extendSubtypeRegistry(extensions: unknown, base: SubtypeRegistry = DEFAULT_SUBTYPES): SubtypeRegistry {
  if (!issuedRegistries.has(base)) throw new TypeError('Invalid subtype registry');
  try {
    const fields = data(extensions, [], SEMANTIC_CLASSES);
    if (!fields) throw new TypeError('Invalid subtype extension');
    const result = Object.fromEntries(SEMANTIC_CLASSES.map((kind) => [kind, [...base[kind]]])) as
      Record<SemanticClass, string[]>;
    for (const [kind, values] of Object.entries(fields)) {
      if (!inSet(kind, SEMANTIC_CLASSES) || !Array.isArray(values) || values.length > 128) {
        throw new TypeError('Invalid subtype extension');
      }
      for (const subtype of values) {
        if (typeof subtype !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/u.test(subtype) ||
          result[kind].includes(subtype)) throw new TypeError('Invalid subtype extension');
        result[kind].push(subtype);
      }
    }
    return freezeRegistry(result);
  } catch {
    throw new TypeError('Invalid subtype extension');
  }
}

/** The integration, not model/tool/payload text, supplies this separately bound source context. */
export interface ClassificationContext { interactionRef: string; sourceRef: string; trust: Trust }
export interface EvidenceProvenance {
  inputRef: string;
  producerId: string;
  producerVersion: string;
  questionSetVersion?: string;
  modelId?: string;
}
export interface ClassificationClaim {
  semanticType: string;
  subtype?: string;
  sensitivity?: Sensitivity;
  reversible?: boolean;
  scope?: Scope;
  confidence?: number;
}
export interface ClassificationEvidence {
  version: 1;
  id: string;
  source: 'detector' | 'parser' | 'semantic';
  provenance: EvidenceProvenance;
  status: 'FOUND' | 'ABSTAIN' | 'FAILURE';
  claim?: ClassificationClaim;
}
export type EvidenceRecord = ClassificationEvidence | Readonly<{
  version: 1;
  source: ClassificationEvidence['source'];
  status: 'INVALID';
}>;
/** Evidence channels must be assembled by the trusted integration, never copied from an envelope payload. */
export interface EvidenceInputs {
  detectorEvidence?: readonly unknown[];
  semanticJudgments?: readonly unknown[];
  parserEvidence?: readonly unknown[];
}
export interface Classification {
  version: 1;
  status: 'RESOLVED' | 'UNRESOLVED';
  semanticType: SemanticClass | 'UNKNOWN';
  subtype?: string;
  sensitivity: Sensitivity | 'UNKNOWN';
  /** Source influence trust from the independent context, never an evidence/model assertion. */
  trust: Trust;
  /** Recommendation only; no vault or broker authorization follows from this boolean. */
  reversible: boolean;
  /** Recommendation only; policy separately selects any actual scope. */
  scope: Scope;
  reasons: readonly string[];
  evidence: readonly EvidenceRecord[];
  provenance: Readonly<{ interactionRef: string; sourceRef: string }>;
}

function validateEvidence(raw: unknown, source: ClassificationEvidence['source']): EvidenceRecord {
  try {
    const v = data(raw, ['version', 'id', 'status', 'provenance'], ['claim']);
    if (!v || v.version !== 1 || !label(v.id) ||
      !inSet(v.status, ['FOUND', 'ABSTAIN', 'FAILURE'])) throw new TypeError();
    const p = data(v.provenance, ['inputRef', 'producerId', 'producerVersion'],
      source === 'semantic' ? ['questionSetVersion', 'modelId'] : []);
    if (!p || !label(p.inputRef, 1024) || !label(p.producerId) || !label(p.producerVersion) ||
      (source === 'semantic' && (!label(p.questionSetVersion) || !label(p.modelId)))) throw new TypeError();
    const provenance: EvidenceProvenance = {
      inputRef: p.inputRef, producerId: p.producerId, producerVersion: p.producerVersion,
      ...(source === 'semantic' ? { questionSetVersion: p.questionSetVersion as string,
        modelId: p.modelId as string } : {}),
    };
    let claim: ClassificationClaim | undefined;
    if (v.status === 'FOUND') {
      const c = data(v.claim, ['semanticType'], ['subtype', 'sensitivity', 'reversible', 'scope', 'confidence']);
      if (!c || !label(c.semanticType, 64) ||
        (Object.hasOwn(c, 'subtype') && !label(c.subtype, 64)) ||
        (Object.hasOwn(c, 'sensitivity') && !inSet(c.sensitivity, SENSITIVITIES)) ||
        (Object.hasOwn(c, 'reversible') && typeof c.reversible !== 'boolean') ||
        (Object.hasOwn(c, 'scope') && !inSet(c.scope, SCOPES)) ||
        (Object.hasOwn(c, 'confidence') && (source !== 'semantic' || typeof c.confidence !== 'number' ||
          !Number.isFinite(c.confidence) || c.confidence < 0 || c.confidence > 1))) throw new TypeError();
      claim = {
        semanticType: c.semanticType,
        ...(Object.hasOwn(c, 'subtype') ? { subtype: c.subtype as string } : {}),
        ...(Object.hasOwn(c, 'sensitivity') ? { sensitivity: c.sensitivity as Sensitivity } : {}),
        ...(Object.hasOwn(c, 'reversible') ? { reversible: c.reversible as boolean } : {}),
        ...(Object.hasOwn(c, 'scope') ? { scope: c.scope as Scope } : {}),
        ...(Object.hasOwn(c, 'confidence') ? { confidence: c.confidence as number } : {}),
      };
    } else if (Object.hasOwn(v, 'claim')) throw new TypeError();
    return Object.freeze({ version: 1, id: v.id, source, provenance: Object.freeze(provenance),
      status: v.status, ...(claim ? { claim: Object.freeze(claim) } : {}) }) as ClassificationEvidence;
  } catch {
    // Never echo malformed or forged metadata into a classification or error.
    return Object.freeze({ version: 1, source, status: 'INVALID' });
  }
}
function channels(input: unknown): { fields: Record<string, unknown>; invalid: boolean } {
  const fields: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input))) return { fields, invalid: true };
    const keys = Reflect.ownKeys(input);
    if (keys.length > 16) return { fields, invalid: true };
    let invalid = false;
    for (const key of keys) {
      if (typeof key !== 'string') { invalid = true; continue; }
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) { invalid = true; continue; }
      if (!['detectorEvidence', 'parserEvidence', 'semanticJudgments'].includes(key)) {
        invalid = true;
        continue;
      }
      fields[key] = descriptor.value;
    }
    return { fields, invalid };
  } catch { return { fields: Object.create(null) as Record<string, unknown>, invalid: true }; }
}
function arrayItems(input: unknown): { values: unknown[]; invalid: boolean } {
  try {
    if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) {
      return { values: [], invalid: true };
    }
    const keys = Reflect.ownKeys(input);
    if (keys.length > 257 || keys.some((key) => typeof key !== 'string')) {
      return { values: [], invalid: true };
    }
    // Read descriptor data, not a Proxy's time-varying `get(length)` trap.
    const length: unknown = Object.getOwnPropertyDescriptor(input, 'length')?.value;
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0 || length > 256) {
      return { values: [], invalid: true };
    }
    const values: unknown[] = [];
    let invalid = keys.length !== length + 1;
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
        values.push(undefined);
        invalid = true;
      } else values.push(descriptor.value);
    }
    return { values, invalid };
  } catch { return { values: [], invalid: true }; }
}
function sortEvidence(left: EvidenceRecord, right: EvidenceRecord): number {
  const sourceOrder = { detector: 0, parser: 1, semantic: 2 };
  const a = left.status === 'INVALID' ? 1 : 0;
  const b = right.status === 'INVALID' ? 1 : 0;
  if (a !== b) return a - b;
  if (sourceOrder[left.source] !== sourceOrder[right.source]) return sourceOrder[left.source] - sourceOrder[right.source];
  const first = JSON.stringify(left);
  const second = JSON.stringify(right);
  return first < second ? -1 : first > second ? 1 : 0;
}

/** Compose independently produced evidence. An unresolved record MUST go to deterministic policy. */
export function composeClassification(inputs: EvidenceInputs, context: ClassificationContext,
  registry: SubtypeRegistry = DEFAULT_SUBTYPES): Classification {
  // Neither context nor subtype extensions are accepted from model/tool/payload content.
  if (!issuedRegistries.has(registry)) throw new TypeError('Invalid subtype registry');
  let boundary: Record<string, unknown> | null;
  try { boundary = data(context, ['interactionRef', 'sourceRef', 'trust']); } catch { boundary = null; }
  if (!boundary || !label(boundary.interactionRef) || !label(boundary.sourceRef, 1024) ||
    !inSet(boundary.trust, TRUST_LEVELS)) throw new TypeError('Invalid classification context');
  const provenance = Object.freeze({ interactionRef: boundary.interactionRef, sourceRef: boundary.sourceRef });
  const reasons = new Set<string>();
  const request = channels(inputs);
  if (request.invalid) reasons.add('INVALID_EVIDENCE');
  const records: EvidenceRecord[] = [];
  for (const [key, source] of [
    ['detectorEvidence', 'detector'], ['parserEvidence', 'parser'], ['semanticJudgments', 'semantic'],
  ] as const) {
    const channel = request.fields[key];
    if (channel === undefined) continue;
    const items = arrayItems(channel);
    if (items.invalid) reasons.add('INVALID_EVIDENCE');
    for (const item of items.values) records.push(validateEvidence(item, source));
  }
  records.sort(sortEvidence);
  const ids = new Set<string>();
  const found: ClassificationEvidence[] = [];
  for (const record of records) {
    if (record.status === 'INVALID') { reasons.add('INVALID_EVIDENCE'); continue; }
    if (ids.has(record.id)) reasons.add('DUPLICATE_EVIDENCE_ID');
    ids.add(record.id);
    if (record.status === 'FAILURE') reasons.add(`${record.source.toUpperCase()}_FAILURE`);
    if (record.status === 'ABSTAIN') reasons.add('ABSTAINED');
    if (record.status === 'FOUND' && record.claim) found.push(record);
  }
  if (!found.length) reasons.add('MISSING_EVIDENCE');
  if (found.length && !found.some((record) => record.source === 'detector')) {
    reasons.add('MISSING_DETECTOR_EVIDENCE');
  }

  const types = new Set<SemanticClass>();
  const subtypes = new Set<string>();
  const sensitivities = new Set<Sensitivity>();
  const scopes = new Set<Scope>();
  const reversible = new Set<boolean>();
  let credential = false;
  for (const record of found) {
    const claim = record.claim!;
    if (claim.semanticType === 'UNKNOWN') reasons.add('UNKNOWN_CLASS');
    else if (inSet(claim.semanticType, SEMANTIC_CLASSES)) {
      types.add(claim.semanticType);
      if (claim.subtype !== undefined) {
        if (registry[claim.semanticType].includes(claim.subtype)) subtypes.add(claim.subtype);
        else reasons.add('UNSUPPORTED_SUBTYPE');
      }
      if (claim.semanticType === 'CREDENTIAL_OR_SECRET') credential = true;
    } else reasons.add('UNSUPPORTED_CLASS');
    if (claim.sensitivity !== undefined) sensitivities.add(claim.sensitivity);
    else if (claim.semanticType !== 'CREDENTIAL_OR_SECRET') reasons.add('MISSING_SENSITIVITY');
    if (claim.scope !== undefined) scopes.add(claim.scope);
    if (claim.reversible !== undefined) reversible.add(claim.reversible);
  }
  if (credential) sensitivities.add('SECRET');
  if (types.size > 1) reasons.add('CONFLICTING_SEMANTIC_TYPE');
  if (subtypes.size > 1) reasons.add('CONFLICTING_SUBTYPE');
  if (sensitivities.size > 1) reasons.add('CONFLICTING_SENSITIVITY');
  if (scopes.size > 1) reasons.add('CONFLICTING_SCOPE');
  if (reversible.size > 1) reasons.add('CONFLICTING_REVERSIBILITY');
  if (!sensitivities.size && found.length) reasons.add('MISSING_SENSITIVITY');

  const sensitivity = sensitivities.size ?
    SENSITIVITIES[[...sensitivities].reduce((highest, current) =>
      Math.max(highest, SENSITIVITIES.indexOf(current)), 0)]! : 'UNKNOWN';
  const status = reasons.size ? 'UNRESOLVED' : 'RESOLVED';
  const semanticType = status === 'RESOLVED' && types.size === 1 ? [...types][0]! : 'UNKNOWN';
  const subtype = status === 'RESOLVED' && subtypes.size === 1 ? [...subtypes][0] : undefined;
  // A semantic suggestion alone cannot propose a stored mapping or broader scope.
  const detectorClaims = found.filter((item) => item.source === 'detector').map((item) => item.claim!);
  const candidateReversible = status === 'RESOLVED' && sensitivity !== 'SECRET' && !credential &&
    detectorClaims.some((claim) => claim.reversible === true) && !reversible.has(false);
  const recommendedScope = status === 'RESOLVED' && detectorClaims.some((claim) => claim.scope !== undefined) &&
    scopes.size === 1 ? [...scopes][0]! : 'request';
  return Object.freeze({ version: 1, status, semanticType, ...(subtype ? { subtype } : {}),
    sensitivity, trust: boundary.trust, reversible: candidateReversible, scope: recommendedScope,
    reasons: Object.freeze([...reasons].sort()), evidence: Object.freeze(records), provenance });
}
