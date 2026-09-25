/** Compileable TDD stub: behavior is deliberately not implemented. */
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
export type Scope = 'request' | 'session' | 'project' | 'tenant';
export type SubtypeRegistry = Readonly<Record<SemanticClass, readonly string[]>>;
export const DEFAULT_SUBTYPES: SubtypeRegistry = {
  PERSON: ['NAME', 'EMAIL', 'PHONE'], CREDENTIAL_OR_SECRET: [
    'PASSWORD', 'API_KEY', 'PRIVATE_KEY', 'ACCESS_TOKEN', 'REFRESH_TOKEN', 'COOKIE',
    'CONNECTION_SECRET', 'CERTIFICATE_SECRET',
  ], USER_ACCOUNT: [], NETWORK_IDENTIFIER: ['IP', 'PORT', 'DOMAIN', 'URL', 'MAC', 'SUBNET'],
  HOST_OR_SERVICE: [], CLOUD_RESOURCE: [
    'TENANT_ID', 'SUBSCRIPTION_ID', 'ACCOUNT_ID', 'ARN', 'PROJECT_ID', 'RESOURCE_GROUP',
    'BUCKET', 'VAULT', 'SERVICE_ACCOUNT',
  ], FILE_OR_RESOURCE_PATH: [], CUSTOMER_OR_PARTNER: [], PROJECT_OR_CONTRACT: [],
  APPLICATION_OR_ENVIRONMENT: [], ENGINEERING_IDENTIFIER: [
    'ASSET_TAG', 'DRAWING_NUMBER', 'PART_NUMBER', 'ITEM_ID', 'DOCUMENT_ID',
    'FUNCTIONAL_LOCATION', 'PLC_TAG', 'SCADA_TAG',
  ], BUSINESS_CONFIDENTIAL: [],
};
export interface ClassificationContext { interactionRef: string; sourceRef: string; trust: Trust }
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
  trust: Trust;
  reversible: boolean;
  scope: Scope;
  reasons: readonly string[];
  evidence: readonly unknown[];
  provenance: { interactionRef: string; sourceRef: string };
}
export function extendSubtypeRegistry(_extensions: unknown): SubtypeRegistry {
  return DEFAULT_SUBTYPES;
}
export function composeClassification(_inputs: EvidenceInputs, context: ClassificationContext,
  _registry: SubtypeRegistry = DEFAULT_SUBTYPES): Classification {
  return { version: 1, status: 'UNRESOLVED', semanticType: 'UNKNOWN',
    sensitivity: 'UNKNOWN', trust: context.trust, reversible: false, scope: 'request',
    reasons: ['MISSING_EVIDENCE'], evidence: [],
    provenance: { interactionRef: context.interactionRef, sourceRef: context.sourceRef } };
}
