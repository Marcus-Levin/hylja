/**
 * #11 narrow TypeSafe / Jev ("System One") protocol adapter: pure request translation and strict
 * response validation. It has NO transport, no credential handling, no SDK dependency and no network
 * capability of any kind, so this repository cannot send a judge request to a hosted endpoint from
 * this module. Wiring a real transport is a separate future step that would first need core
 * destination policy for the judge sink, an authenticated binding to the real routed destination,
 * and an independent #19 check of the exact serialized outbound bytes.
 *
 * Source-inspected protocol (retrieved 2026-09-28 from the primary documentation and the published
 * SDK tarball; re-verify against the live documents before any future hosted integration). Nothing
 * below is executed, installed or vendored, and no account, key or endpoint is contacted:
 *   - https://docs.typesafe.ai/api -- `POST https://api.typesafe.ai/v1/systemone`,
 *     `Authorization: Bearer <API_KEY>`, request `{ state, model, questions }`, response
 *     `{ model, answers, usage: { input_tokens, output_tokens } }`; question types `noul` (optional
 *     `criteria: { true, false }`), `choice` (`criteria`: map, at most 255 options) and `score`
 *     (`criteria`: ordered array, at least two and at most ten levels); answers `{ type, noul }`,
 *     `{ type, choice, probabilities, confidence }`,
 *     `{ type, score, legend, probabilities, confidence }`; documented statuses 401/422/429/529.
 *   - https://docs.typesafe.ai/primitives -- question `id` keys identify answers, are never sent to
 *     the model and are not used in inference, so an id may carry no protected value.
 *   - https://docs.typesafe.ai/models -- `model` may be the `jev-latest` or `jev-preview` alias or a
 *     versioned id such as `jev-1.13.0`; an alias moves when a release ships, and the response's
 *     `model` field reports the versioned id that actually answered. Hylja records served-model
 *     evidence, so it pins a versioned id and refuses a moving alias by design.
 *   - https://docs.typesafe.ai/primitives/choice, /primitives/score, /primitives/noul -- every
 *     answer is constrained to the supplied options or levels, `choice` is the highest-probability
 *     option, `probabilities` covers every option or level, and `noul` carries no separate
 *     confidence (it is that answer's whole two-outcome distribution).
 *   - https://docs.typesafe.ai/confidence -- `confidence` is derived from the reported distribution
 *     and exists only on Choice and Score answers.
 *   - https://docs.typesafe.ai/model-jaggedness/jev-1.13 -- score levels are weak in numerical
 *     calibration and must not be interpolated into a magnitude, a question and its negation are not
 *     complementary, and adversarial state content can move an answer. Hylja therefore derives any
 *     discrete level itself, by argmax, and keeps arithmetic and invariants in deterministic code.
 *   - npm `@typesafe-ai/sdk@0.6.0` (`dist/index.d.mts`, `dist/index.mjs`; inspected as a tarball,
 *     never installed or executed) -- the published request/answer types, `POST /v1/systemone`,
 *     `GET /v1/models`, the `x-typesafe-request-id` response header, `APITimeoutError`,
 *     `APIUserAbortError`, `RateLimitError` for 429 and `InternalServerError` for any 5xx.
 */
import {
  SHADOW_MAX_CHOICE_OPTIONS, SHADOW_MAX_SCORE_LEVELS, SHADOW_MIN_SCORE_LEVELS,
  isIssuedShadowQuestionSet, isIssuedShadowRequest,
} from './semantic-judge-shadow.js';
import type {
  MinimizedShadowRequest, ShadowCanonicalPayload, ShadowQuestionSet, ShadowReasonCode,
} from './semantic-judge-shadow.js';

/** Documented protocol constants, pinned for reproducible evidence. This module never calls them. */
export const SYSTEM_ONE_PROTOCOL = Object.freeze({
  id: 'typesafe.system-one',
  version: '1',
  /** Documented evaluation path. Recorded for evidence; this module never requests it. */
  evaluationPath: '/v1/systemone',
  /** Documented model-listing path, for a future pre-flight pin of an available versioned id. */
  modelListingPath: '/v1/models',
  requestIdHeader: 'x-typesafe-request-id',
  /**
   * Documented moving aliases. They are pinned here only so the seam can refuse them: the alias
   * target changes between releases, and shadow evidence must name the version that answered.
   */
  movingModelAliases: Object.freeze(['jev-latest', 'jev-preview']),
  maxChoiceOptions: SHADOW_MAX_CHOICE_OPTIONS,
  minScoreLevels: SHADOW_MIN_SCORE_LEVELS,
  maxScoreLevels: SHADOW_MAX_SCORE_LEVELS,
  /** Documented non-2xx statuses. Each maps to a distinct closed Hylja shadow reason. */
  errorStatuses: Object.freeze({
    '401': 'PROVIDER_UNAUTHORIZED',
    '422': 'PROVIDER_REJECTED',
    '429': 'PROVIDER_RATE_LIMITED',
    '529': 'PROVIDER_OVERLOADED',
  }),
} as const);

/** Documented wire question body. `criteria` shape depends on `type`. */
export type SystemOneQuestion =
  | Readonly<{ type: 'noul'; instructions: string; criteria?: Readonly<{ true?: string; false?: string }> }>
  | Readonly<{ type: 'choice'; instructions: string; criteria: Readonly<Record<string, string>> }>
  | Readonly<{ type: 'score'; instructions: string; criteria: readonly string[] }>;
export interface SystemOneRequestBody {
  readonly state: unknown;
  readonly model: string;
  readonly questions: Readonly<Record<string, SystemOneQuestion>>;
}

type Fields = Record<string, unknown>;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const MODEL_SHAPE = /^[a-z][a-z0-9.-]{0,63}$/u;
class Invalid extends Error { constructor(readonly code: ShadowReasonCode) { super(code); } }
function fail(code: ShadowReasonCode): never { throw new Invalid(code); }
/**
 * Same snapshot-then-descriptor discipline as the core reader, with the context's own closed code:
 * `INVALID_REQUEST` while translating a request Hylja built, `MALFORMED_RESPONSE` while reading a
 * provider body. An unknown key is `UNEXPECTED_FIELD`, so an added `treatment`, `sensitivity`,
 * `instructions` or `authorization` field is refused rather than passed through.
 */
function fields(value: unknown, required: readonly string[], optional: readonly string[] = [],
  code: ShadowReasonCode = 'INVALID_REQUEST'): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) fail(code);
  if (keys.length > required.length + optional.length) fail('UNEXPECTED_FIELD');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) fail('UNEXPECTED_FIELD');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail(code);
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail(code);
  return result;
}
function closed(value: unknown, limit: number, code: ShadowReasonCode): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > limit || CONTROL.test(value)) {
    fail(code);
  }
  return value;
}

/**
 * Translate a minimized request into the documented request body.
 *
 * The state is the minimized placeholder view only: opaque candidate ordinals, neighbour ordinals
 * and enumerated non-secret context codes. No raw value exists at this point, and the request must
 * carry this module's brand, so a hand-built look-alike cannot inject one. The function is pure,
 * total for an issued question set, and has no I/O of any kind.
 */
export function buildSystemOneBody(request: unknown, set: unknown,
  model?: string): SystemOneRequestBody {
  try {
    return readSystemOneBody(request, set, model);
  } catch (error) {
    // A caller-supplied Proxy exception is not a Hylja reason code and never leaves this module.
    throw error instanceof Invalid ? error : new Invalid('INVALID_REQUEST');
  }
}
function readSystemOneBody(request: unknown, set: unknown, model?: string): SystemOneRequestBody {
  if (!isIssuedShadowRequest(request) || !isIssuedShadowQuestionSet(set)) fail('INVALID_REQUEST');
  const value = request as MinimizedShadowRequest;
  const questions = value.questions;
  if (!Array.isArray(questions) || questions.length < 1) fail('INVALID_REQUEST');
  if (typeof model !== 'string' || model.length < 1) fail('MODEL_ID_REQUIRED');
  const modelId = closed(model, 64, 'MODEL_ID_REQUIRED');
  if ((SYSTEM_ONE_PROTOCOL.movingModelAliases as readonly string[]).includes(modelId)) {
    fail('MODEL_ALIAS_NOT_PINNED');
  }
  if (!MODEL_SHAPE.test(modelId)) fail('MODEL_ID_REQUIRED');
  // Bind the translation to the exact question set the request was minimized for.
  const setValue = set as ShadowQuestionSet;
  if (value.questionSet.id !== setValue.id || value.questionSet.version !== setValue.version ||
    questions.length !== setValue.questions.length) fail('INVALID_REQUEST');
  const wire: Record<string, SystemOneQuestion> = Object.create(null) as Record<string, SystemOneQuestion>;
  for (const question of questions) {
    const source = setValue.questions.find((item) => item.id === question.id);
    if (source === undefined || source.kind !== question.kind || Object.hasOwn(wire, question.id)) {
      fail('INVALID_REQUEST');
    }
    // The core already bounds and character-checks instruction text; re-check the bound here so a
    // translation can never produce a body larger than the request it was built from.
    const instructions = closed(question.instructions, 1024, 'INVALID_REQUEST');
    if (question.kind === 'noul') {
      const criteria = question.criteria as { true?: string; false?: string } | undefined;
      if (criteria !== undefined) {
        const c = fields(criteria, [], ['true', 'false']);
        wire[question.id] = Object.freeze({ type: 'noul', instructions,
          criteria: Object.freeze({
            ...(c.true === undefined ? {} : { true: closed(c.true, 512, 'INVALID_REQUEST') }),
            ...(c.false === undefined ? {} : { false: closed(c.false, 512, 'INVALID_REQUEST') }),
          }) });
        continue;
      }
      wire[question.id] = Object.freeze({ type: 'noul', instructions });
      continue;
    }
    if (question.kind === 'choice') {
      const raw = question.criteria;
      if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail('INVALID_REQUEST');
      const entries = Object.entries(raw as Record<string, unknown>);
      if (entries.length < 2 || entries.length > SYSTEM_ONE_PROTOCOL.maxChoiceOptions) fail('INVALID_REQUEST');
      const criteria: Record<string, string> = Object.create(null) as Record<string, string>;
      for (const [key, value] of entries) {
        criteria[key] = closed(value, 512, 'INVALID_REQUEST');
      }
      wire[question.id] = Object.freeze({ type: 'choice', instructions,
        criteria: Object.freeze(criteria) });
      continue;
    }
    if (!Array.isArray(question.criteria)) fail('INVALID_REQUEST');
    const levels = question.criteria as readonly unknown[];
    if (levels.length < SYSTEM_ONE_PROTOCOL.minScoreLevels || levels.length > SYSTEM_ONE_PROTOCOL.maxScoreLevels) {
      fail('INVALID_REQUEST');
    }
    wire[question.id] = Object.freeze({ type: 'score', instructions,
      criteria: Object.freeze(levels.map((level) => closed(level, 512, 'INVALID_REQUEST'))) });
  }
  return Object.freeze({
    // The state is rebuilt from the issued request's placeholder view only.
    state: Object.freeze({
      candidate: Object.freeze({ placeholder: value.state.candidate.placeholder,
        kind: value.state.candidate.kind }),
      neighbors: Object.freeze(value.state.neighbors.map((neighbor) => Object.freeze({
        placeholder: neighbor.placeholder, kind: neighbor.kind,
      }))),
      context: Object.freeze(value.state.context.map((entry) => Object.freeze({ key: entry.key,
        code: entry.code }))),
    }),
    model: modelId,
    questions: Object.freeze(wire),
  });
}

export interface ParsedSystemOneResponse {
  readonly payload: ShadowCanonicalPayload;
  readonly servedModel: string;
  readonly problems: readonly ShadowReasonCode[];
  /** Legend text the provider echoed for a Score answer. Recorded as a count, never as text. */
  readonly scoreLegendLevels: number;
}

/**
 * Strictly validate a documented response body into the provider-independent canonical payload.
 *
 * Rejects unknown fields rather than passing them through, so a provider addition, a model-generated
 * extra field and a proxy-smuggled instruction are one malformed response, not new semantics.
 * Nothing from the body except closed enum values and numbers is ever returned, so arbitrary model
 * or error text cannot reach a Hylja record. Structural defects throw a closed code; per-answer
 * defects become closed problems, so one bad answer cannot hide the rest.
 */
export function parseSystemOneResponse(body: unknown, set: unknown): ParsedSystemOneResponse {
  try {
    return readSystemOneResponse(body, set);
  } catch (error) {
    // A body that cannot even be read is one malformed response, and a caller's own exception
    // message is never a Hylja reason code.
    throw error instanceof Invalid ? error : new Invalid('MALFORMED_RESPONSE');
  }
}
function readSystemOneResponse(body: unknown, set: unknown): ParsedSystemOneResponse {
  if (!isIssuedShadowQuestionSet(set)) fail('INVALID_REQUEST');
  const setValue = set as ShadowQuestionSet;
  const v = fields(body, ['model', 'answers', 'usage'], [], 'MALFORMED_RESPONSE');
  const servedModel = closed(v.model, 64, 'MALFORMED_RESPONSE');
  const usageFields = fields(v.usage, ['input_tokens', 'output_tokens'], [], 'MALFORMED_RESPONSE');
  for (const key of ['input_tokens', 'output_tokens'] as const) {
    const value = usageFields[key];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) fail('MALFORMED_RESPONSE');
  }
  const expected = new Map(setValue.questions.map((question) => [question.id, question]));
  if (v.answers === null || typeof v.answers !== 'object' || Array.isArray(v.answers) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(v.answers))) fail('MALFORMED_RESPONSE');
  const keys = Reflect.ownKeys(v.answers);
  if (keys.some((key) => typeof key !== 'string')) fail('MALFORMED_RESPONSE');
  if (keys.length > expected.size + 32) fail('MALFORMED_RESPONSE');
  const answers: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  const problems = new Set<ShadowReasonCode>();
  let scoreLegendLevels = 0;
  for (const id of keys as string[]) {
    if (id.length > 32) fail('MALFORMED_RESPONSE');
    const descriptor = Object.getOwnPropertyDescriptor(v.answers, id);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('MALFORMED_RESPONSE');
    const question = expected.get(id);
    if (question === undefined) { problems.add('UNKNOWN_ANSWER'); continue; }
    if (Object.hasOwn(answers, id)) { problems.add('DUPLICATE_ANSWER_ID'); continue; }
    try {
      const parsed = answer(descriptor.value, question, id);
      scoreLegendLevels += parsed.legendLevels;
      answers[id] = parsed.answer;
    } catch (error) {
      problems.add(error instanceof Invalid ? error.code : 'MALFORMED_RESPONSE');
    }
  }
  return Object.freeze({
    payload: Object.freeze({ servedModel, answers: Object.freeze(answers),
      usage: Object.freeze({ inputTokens: usageFields.input_tokens as number,
        outputTokens: usageFields.output_tokens as number }) }),
    servedModel, problems: Object.freeze([...problems].sort()), scoreLegendLevels,
  });
}
function answer(raw: unknown, question: { readonly kind: string; readonly criteria?: unknown },
  id: string): { answer: unknown; legendLevels: number } {
  const kind = question.kind;
  const required = kind === 'noul' ? ['type', 'noul'] :
    kind === 'choice' ? ['type', 'choice', 'probabilities', 'confidence'] :
    ['type', 'score', 'legend', 'probabilities', 'confidence'];
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail('MALFORMED_RESPONSE');
  const type = Object.getOwnPropertyDescriptor(raw, 'type');
  // The documented answer type matches the question type. Check that first, so a score-shaped answer
  // to a Noul is one type mismatch rather than a pile of surplus-field complaints.
  if (!type?.enumerable || !('value' in type) || type.value !== kind) fail('TYPE_MISMATCH');
  const v = fields(raw, required, [], 'MALFORMED_RESPONSE');
  if (kind === 'noul') {
    if (typeof v.noul !== 'number' || !Number.isFinite(v.noul) || v.noul < 0 || v.noul > 1) {
      fail('NOUL_OUT_OF_RANGE');
    }
    return { answer: Object.freeze({ kind, noul: v.noul }), legendLevels: 0 };
  }
  if (kind === 'choice') {
    const criteria = question.criteria;
    if (criteria === null || typeof criteria !== 'object' || Array.isArray(criteria)) {
      fail('UNKNOWN_CHOICE_LABEL');
    }
    const choice = closed(v.choice, 64, 'UNKNOWN_CHOICE_LABEL');
    if (!Object.hasOwn(criteria, choice)) fail('UNKNOWN_CHOICE_LABEL');
    // Documented: the answer reports a probability for every option it was given.
    const probabilities = probabilityMap(v.probabilities, Object.keys(criteria));
    confidence(v.confidence);
    return { answer: Object.freeze({ kind, choice, probabilities, confidence: v.confidence as number }),
      legendLevels: 0 };
  }
  if (!Array.isArray(question.criteria)) fail('SCORE_LEVELS_INVALID');
  const levels = question.criteria as readonly string[];
  if (v.score === null || typeof v.score !== 'number' || !Number.isFinite(v.score)) fail('SCORE_NOT_FINITE');
  const levelKeys = levels.map((_level, index) => String(index));
  // The echoed legend must map exactly the requested levels. Its text is provider text: shape-checked
  // and counted, never returned, so rubric wording cannot reach a record.
  legend(v.legend, levelKeys);
  const probabilities = probabilityMap(v.probabilities, levelKeys);
  confidence(v.confidence);
  return { answer: Object.freeze({ kind, score: v.score, probabilities,
    confidence: v.confidence as number }), legendLevels: levelKeys.length };
}
/** The documented Score legend: exactly the requested level keys, each mapped to provider text. */
function legend(raw: unknown, keys: readonly string[]): void {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) fail('MALFORMED_RESPONSE');
  const own = Reflect.ownKeys(raw);
  if (own.length !== keys.length || keys.some((key) => !own.includes(key))) fail('MALFORMED_RESPONSE');
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || typeof descriptor.value !== 'string') {
      fail('MALFORMED_RESPONSE');
    }
  }
}
function confidence(value: unknown): void {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    fail('CONFIDENCE_OUT_OF_RANGE');
  }
}
/** Exactly the documented option or level keys, each a finite probability in `[0, 1]`. */
function probabilityMap(raw: unknown, keys: readonly string[]): Readonly<Record<string, number>> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) fail('PROBABILITIES_MISMATCH');
  const own = Reflect.ownKeys(raw);
  if (own.length !== keys.length || keys.some((key) => !own.includes(key))) fail('PROBABILITIES_MISMATCH');
  const result: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('PROBABILITIES_MISMATCH');
    const value = descriptor.value;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
      fail('PROBABILITY_OUT_OF_RANGE');
    }
    result[key] = value;
  }
  return Object.freeze(result);
}

/**
 * Map a documented HTTP status onto a closed Hylja shadow reason.
 *
 * Any other status -- including a success code -- is an `UNEXPECTED_PROVIDER_STATUS`: this seam
 * accepts a judged payload only through the validated answer path, never through a status code.
 */
export function systemOneStatusToShadowReason(status: unknown): ShadowReasonCode {
  if (typeof status !== 'number' || !Number.isSafeInteger(status)) return 'UNEXPECTED_PROVIDER_STATUS';
  const known = SYSTEM_ONE_PROTOCOL.errorStatuses as Readonly<Record<string, ShadowReasonCode>>;
  return known[String(status)] ?? 'UNEXPECTED_PROVIDER_STATUS';
}