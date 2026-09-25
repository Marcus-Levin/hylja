// Exploratory, unscored public D01/D02/D05 smoke bridge; evaluation-only, NON-ENFORCING.
// The only sink is a controlled #5 in-memory observation, NEVER network or a release permission.
import { SEMANTIC_CLASSES } from '../dist/classification.js';
import { runReferenceCandidate } from './candidates/reference.mjs';

const encoder = new TextEncoder();
const projections = new WeakMap();
const SINK_ID = 'CAPTURE-DEMO-MODEL'; // Existing reference candidate's local capture ID.
const MAX_FIELD_BYTES = 65_536; // #5's cumulative field limit.
const MAX_CAPTURE_BYTES = 1_048_576;
const MAX_JSON_NODES = 256;
function invalid() { throw new TypeError('Invalid public development adapter input'); }
function safe(action) { try { return action(); } catch { return invalid(); } }

// Inspect bounded own data descriptors once, without invoking ignored fixture controls/getters.
function data(value, required, optional = [], ignored = []) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  const allowed = [...required, ...optional, ...ignored];
  if (keys.length < required.length || keys.length > allowed.length) invalid();
  const copy = Object.create(null);
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.includes(key)) invalid();
    if (ignored.includes(key)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    copy[key] = descriptor.value;
  }
  for (const key of required) if (!Object.hasOwn(copy, key)) invalid();
  return copy;
}
function array(value, max) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
  const keys = Reflect.ownKeys(value);
  const count = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (!Number.isSafeInteger(count) || count < 0 || count > max ||
    keys.length !== count + 1 || !keys.includes('length')) invalid();
  const items = [];
  for (let index = 0; index < count; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    items.push(descriptor.value);
  }
  return items;
}
function id(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(value)) invalid();
  return value;
}
function utf8(value, limit = MAX_FIELD_BYTES) {
  if (typeof value !== 'string' || value.length > limit) invalid();
  // TextEncoder silently replaces unpaired surrogates; unsupported source text must not drift.
  for (let index = 0; index < value.length; index++) {
    const point = value.charCodeAt(index);
    if (point >= 0xdc00 && point <= 0xdfff) invalid();
    if (point >= 0xd800 && point <= 0xdbff) {
      const low = value.charCodeAt(++index);
      if (!(low >= 0xdc00 && low <= 0xdfff)) invalid();
    }
  }
  if (encoder.encode(value).byteLength > limit) invalid();
  return value;
}
function jsonCanonical(value, state, depth = 0) {
  if (++state.nodes > MAX_JSON_NODES || depth > 8) invalid();
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return utf8(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) invalid();
    return value;
  }
  if (Array.isArray(value)) return array(value, 64).map((item) => jsonCanonical(item, state, depth + 1));
  const entries = dataJsonObject(value);
  const canonical = Object.create(null);
  for (const [key, item] of entries) canonical[key] = jsonCanonical(item, state, depth + 1);
  return canonical;
}
function dataJsonObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 32 || keys.some((key) => typeof key !== 'string')) invalid();
  const entries = [];
  for (const key of keys.sort()) {
    utf8(key, 256);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    entries.push([key, descriptor.value]);
  }
  return entries;
}
function localSinkRecord(input) {
  const sink = data(input, ['id', 'profileId']);
  if (sink.id !== SINK_ID || typeof sink.profileId !== 'string' ||
    !/^EVAL-LOCAL-[A-Z0-9-]{1,47}$/.test(sink.profileId)) invalid();
  return Object.freeze({ id: SINK_ID, profileId: id(sink.profileId) });
}
function projectedFields(fixture) {
  const familyId = fixture.familyId;
  const source = data(fixture.input, ['format'], ['text', 'lines', 'value']);
  let texts;
  let pointers;
  let hint;
  if (familyId === 'D01' && source.format === 'text' &&
    Object.hasOwn(source, 'text') && Object.keys(source).length === 2) {
    texts = [utf8(source.text)];
    pointers = ['/input/text'];
  } else if (familyId === 'D02' && source.format === 'log-lines' &&
    Object.hasOwn(source, 'lines') && Object.keys(source).length === 2) {
    texts = array(source.lines, 32).map((line) => utf8(line));
    pointers = texts.map((_, index) => `/input/lines/${index}`);
  } else if (familyId === 'D05' && source.format === 'json-object' &&
    Object.hasOwn(source, 'value') && Object.keys(source).length === 2) {
    if (source.value === null || Array.isArray(source.value)) invalid();
    texts = [utf8(JSON.stringify(jsonCanonical(source.value, { nodes: 0 })))];
    pointers = ['/input/value']; // No decoded JSON leaf -> serialized source span projection here.
    hint = 'json';
  } else invalid();
  if (!texts.length || texts.reduce((sum, text) => sum + encoder.encode(text).byteLength, 0) > MAX_FIELD_BYTES) invalid();
  return { texts, pointers, hint };
}

/** Snapshot only public input/prompt. The source-pointer association stays evaluator-side. */
export function projectPublicDevelopmentFixture(input, sinkInput) {
  return safe(() => {
    const fixture = data(input, ['fixtureId', 'familyId', 'partition', 'input'],
      ['taskControl'], ['interactionProposal', 'actualRoute']);
    const caseId = id(fixture.fixtureId);
    if (!['D01', 'D02', 'D05'].includes(fixture.familyId) ||
      !caseId.startsWith(`${fixture.familyId}-DEV-`) || fixture.partition !== 'development') invalid();
    const localSink = localSinkRecord(sinkInput);
    const { texts, pointers, hint } = projectedFields(fixture);
    let taskPrompt;
    if (Object.hasOwn(fixture, 'taskControl')) {
      // Expected answer/semantic validity are explicitly IGNORED, even when accessors throw.
      const task = data(fixture.taskControl, ['prompt'], [], ['expectedAnswer', 'semanticValidity']);
      taskPrompt = utf8(task.prompt, 4096);
    }
    const fields = Object.freeze(texts.map((content, index) =>
      Object.freeze({ ref: `field-${index}`, content })));
    const candidateFields = Object.freeze(texts.map((text, index) =>
      Object.freeze({ id: `f${index}`, text, ...(hint ? { hint } : {}) })));
    const developmentCase = Object.freeze({ version: 1, id: caseId, familyId: fixture.familyId,
      partition: 'development', fields,
      sinks: Object.freeze([Object.freeze({ id: localSink.id, surface: 'model.input',
        profileId: localSink.profileId })]),
      ...(taskPrompt !== undefined ? { task: Object.freeze({ id: 'task-1', prompt: taskPrompt }) } : {}) });
    const fieldByPointer = new Map(pointers.map((path, index) => [path, `field-${index}`]));
    const projection = Object.freeze({ developmentCase,
      fieldRefForSourcePointer(pointer) {
        return typeof pointer === 'string' ? fieldByPointer.get(pointer) : undefined;
      } });
    projections.set(projection, Object.freeze({ caseId, localSink, candidateFields, taskPrompt }));
    return projection;
  });
}

function parsedJsonObject(text) {
  // Exploratory DEV structural check only: no approved rubric, task semantics, or JSON
  // duplicate-key fidelity. The independently configured evaluator grader owns correctness.
  const parsed = JSON.parse(text);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) invalid();
  return parsed;
}
function d05TaskShape(text) {
  const parsed = parsedJsonObject(text);
  const strings = ['customer', 'project', 'protocol', 'endpointUrl', 'os', 'outputPath'];
  const numbers = ['port', 'timeoutMs'];
  if (Object.keys(parsed).length !== strings.length + numbers.length ||
    strings.some((key) => typeof parsed[key] !== 'string') ||
    numbers.some((key) => !Number.isSafeInteger(parsed[key]))) invalid();
}
function outputFields(value, original) {
  const items = array(value, 32);
  if (items.length !== original.length) invalid();
  let total = 0;
  return Object.freeze(items.map((item, index) => {
    const field = data(item, ['id', 'text'], ['hint']);
    const expected = original[index];
    if (field.id !== expected.id || field.hint !== expected.hint) invalid();
    const text = utf8(field.text);
    if (expected.hint === 'json') parsedJsonObject(text); // D05 cannot serialize invalid JSON as usable config.
    total += encoder.encode(text).byteLength;
    if (total > MAX_FIELD_BYTES) invalid();
    return Object.freeze({ id: expected.id, text, ...(expected.hint ? { hint: expected.hint } : {}) });
  }));
}
function candidateEvents(value, fields) {
  const items = array(value, 256);
  if (!items.length) return [];
  // One bounded pass per projected field, not a new full-field UTF-8 Set per event.
  const spans = fields.map(({ text }) => {
    const boundaries = new Set([0]);
    let byteLength = 0;
    for (const symbol of text) { byteLength += encoder.encode(symbol).length; boundaries.add(byteLength); }
    return { byteLength, boundaries };
  });
  return items.map((raw) => {
    const event = data(raw, ['fieldId', 'startByte', 'endByte', 'semanticType'], ['subtype']);
    const index = fields.findIndex((field) => field.id === event.fieldId);
    if (index < 0 || !SEMANTIC_CLASSES.includes(event.semanticType)) invalid();
    const { byteLength, boundaries } = spans[index];
    const { startByte, endByte } = event;
    if (!Number.isSafeInteger(startByte) || !Number.isSafeInteger(endByte) ||
      startByte < 0 || endByte <= startByte || endByte > byteLength) invalid();
    if (!boundaries.has(startByte) || !boundaries.has(endByte)) invalid();
    if (event.subtype !== undefined &&
      (typeof event.subtype !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(event.subtype))) invalid();
    return Object.freeze({ fieldRef: `field-${index}`, start: startByte, end: endByte,
      semanticType: event.semanticType, ...(event.subtype ? { subtype: event.subtype } : {}) });
  });
}
function candidateResult(input, state, hasTaskExpected) {
  const result = data(input, ['disposition', 'events'],
    ['reason', 'transformedFields', 'taskResponse']);
  const events = candidateEvents(result.events, state.candidateFields);
  if (result.disposition === 'BLOCK') {
    if (Object.hasOwn(result, 'transformedFields') || Object.hasOwn(result, 'taskResponse') ||
      (result.reason !== undefined &&
        (typeof result.reason !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}$/.test(result.reason)))) invalid();
    return { disposition: 'BLOCK', events };
  }
  if (result.disposition !== 'TRANSFORMED' || !Object.hasOwn(result, 'transformedFields') ||
    Object.hasOwn(result, 'reason')) invalid();
  const fields = outputFields(result.transformedFields, state.candidateFields);
  let taskResult;
  if (Object.hasOwn(result, 'taskResponse')) {
    if (state.taskPrompt === undefined || !hasTaskExpected) invalid();
    taskResult = utf8(result.taskResponse);
    if (state.candidateFields.some((field) => field.hint === 'json')) d05TaskShape(taskResult);
  }
  return { disposition: 'TRANSFORMED', events, fields, taskResult };
}

/** Deterministic last-step serializer for this controlled local observation, not a transport. */
export function serializeControlledRelease(fields, sinkInput) {
  return safe(() => {
    const sink = localSinkRecord(sinkInput);
    const values = array(fields, 32);
    if (!values.length) invalid();
    let total = 0;
    const serializable = values.map((item, index) => {
      const field = data(item, ['id', 'text'], ['hint']);
      if (field.id !== `f${index}` || field.hint !== undefined && field.hint !== 'json') invalid();
      const text = utf8(field.text);
      total += encoder.encode(text).length;
      if (total > MAX_FIELD_BYTES) invalid();
      return { id: `f${index}`, text, ...(field.hint ? { hint: field.hint } : {}) };
    });
    const body = encoder.encode(JSON.stringify({ fields: serializable }));
    const metadata = encoder.encode(JSON.stringify({ sinkId: sink.id, profileId: sink.profileId,
      surface: 'model.input', representation: 'application/json; charset=utf-8' }));
    if (body.length + metadata.length > MAX_CAPTURE_BYTES) invalid();
    return { body, metadata };
  });
}
function finalBytes(raw) {
  const serialized = data(raw, ['body', 'metadata']);
  if (Object.getPrototypeOf(serialized.body) !== Uint8Array.prototype ||
    Object.getPrototypeOf(serialized.metadata) !== Uint8Array.prototype) invalid();
  const body = new Uint8Array(serialized.body);
  const metadata = new Uint8Array(serialized.metadata);
  if (!body.length || !metadata.length || body.length + metadata.length > MAX_CAPTURE_BYTES) invalid();
  return { body, metadata };
}
function assertObserved(observeLocalSink, state) {
  if (typeof observeLocalSink !== 'function') invalid();
  const observed = data(observeLocalSink(), ['sinkId', 'profileId']);
  if (id(observed.sinkId) !== state.localSink.id ||
    id(observed.profileId) !== state.localSink.profileId) invalid();
}

/** Register the independently supplied evaluator oracle, then run through #5's callback seam.
 * Test-only candidate/serialize hooks let adversarial cases exercise the controlled observation;
 * neither hook creates release authority. The oracle is never inspected for content or sent to the candidate.
 */
export async function runPublicReferenceCandidate(options) {
  try {
    const args = data(options, ['projection', 'evaluation', 'capture', 'oracle', 'observeLocalSink'],
      ['candidate', 'serialize']);
    const state = projections.get(args.projection);
    if (!state || typeof args.evaluation?.runCandidate !== 'function' ||
      typeof args.capture?.forCase !== 'function') invalid();
    const candidate = args.candidate === undefined ? runReferenceCandidate : args.candidate;
    const serialize = args.serialize === undefined ? serializeControlledRelease : args.serialize;
    if (typeof candidate !== 'function' || typeof serialize !== 'function') invalid();
    // Snapshot top-level oracle descriptors once. #5 must register that SAME record: a
    // time-varying raw taskExpected could otherwise make #5 reject AFTER capture.
    // Planted content and nested oracle validation remain exclusively #5's responsibility.
    const oracle = data(args.oracle, ['version', 'caseId', 'occurrences'], ['taskExpected']);
    const hasTaskExpected = Object.hasOwn(oracle, 'taskExpected') && typeof oracle.taskExpected === 'string';
    assertObserved(args.observeLocalSink, state);
    args.evaluation.registerCase(args.projection.developmentCase);
    args.evaluation.registerOracle(oracle);
    let disposition;
    await args.evaluation.runCandidate(state.caseId, async (_view, send) => {
      const input = Object.freeze({ sinkId: state.localSink.id,
        fields: state.candidateFields,
        ...(state.taskPrompt !== undefined ? { taskPrompt: state.taskPrompt } : {}) });
      // #5's runCandidate accepts send() before it validates events/taskResult. Validate EVERY
      // candidate-controlled field here first, so malformed results cannot leave captured bytes.
      const result = candidateResult(await candidate(input), state, hasTaskExpected);
      if (result.disposition === 'BLOCK') {
        disposition = 'BLOCK';
        return { events: result.events }; // No send, no task result; candidate BLOCK is not a scored pass.
      }
      assertObserved(args.observeLocalSink, state); // Repeat immediately before serialization/send.
      const { body, metadata } = finalBytes(serialize(result.fields, state.localSink));
      send(state.localSink.id, { body, metadata }); // #5 copies exact final arrays; no later mutation.
      disposition = 'TRANSFORMED';
      return { events: result.events,
        ...(result.taskResult !== undefined ? { taskResult: result.taskResult } : {}) };
    }, args.capture);
    if (!disposition) invalid();
    return Object.freeze({ disposition }); // Observation ONLY; never an authorized safe-send claim.
  } catch {
    return invalid(); // Generic, non-echoing errors for fixture/candidate/route/serializer failures.
  }
}
