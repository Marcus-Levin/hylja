// #113 bounded local Presidio trial: bridges the narrow candidate-source adapter to #5's
// development evaluation and #39's public development fixtures.
//
// Exploratory, UNSCORED, synthetic-only, NON-ENFORCING. It sends nothing: there is no `send` call,
// no socket and no controlled capture, so #5 reports the secret-escape claim and task correctness as
// `untested` rather than claiming a safety pass. What it does produce is a candidate-detection
// observation plus an honest record of what the configuration could not see.
//
// The oracle below is a *development control* authored from the public fixture text by locating
// values in that text. It is not the official #39 oracle, it is not a blind label set, and a miss is
// reported as a miss: nothing here tunes Presidio, and nothing here establishes #39 v0 eligibility.
//
//   usage: node evaluations/presidio-development-trial.mjs \
//            --python <interpreter-or-sandbox-wrapper> --manifest <manifest.json> \
//            [--case D01-DEV-001 ...] [--tenant tenant-synthetic-01] [--project project-synthetic-01]
//            [--worker presidio_worker.py] [--workdir /path] [--worker-manifest /trial/manifest.json]
//
// `--manifest` is the host path this process reads the pin from; `--worker-manifest` is the path the
// worker itself opens, which inside a sandbox is a different path and defaults to `--manifest`.
//
// `python` may be a bubblewrap wrapper that runs the disposable trial environment with the network
// unshared; see evaluations/presidio-worker/README.md for the exact invocation. `--case` restricts the
// run to the named cases; without it every case with a development control is analysed.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { normalizeInput } from '../dist/normalization.js';
import { createDevelopmentEvaluation, createInMemorySinkCapture } from '../dist/evaluation.js';
import { projectPublicDevelopmentFixture } from './public-development-adapter.mjs';
import { PRESIDIO_MAPPING_VERSION, completePresidioAnalysis, preparePresidioAnalysis }
  from '../dist/presidio-candidate-source.js';
import { PRESIDIO_WORKER_LIMITS, runPresidioWorker } from '../dist/presidio-worker-process.js';

const PUBLIC_FIXTURES = new URL('../docs/research/issue-39-public-development-fixtures-p0.1.json', import.meta.url);
const LOCAL_SINK = Object.freeze({ id: 'CAPTURE-DEMO-MODEL', profileId: 'EVAL-LOCAL-PRESIDIO-TRIAL' });
const encoder = new TextEncoder();

/**
 * Independent development controls: the public values a reviewer can find by reading the fixture,
 * with the Hylja v1 class/subtype the pinned mapping would give them. Written before any Presidio
 * run, derived from the source text, and never from a worker reply.
 */
const CONTROLS = Object.freeze({
  'D01-DEV-001': [
    { fieldRef: 'field-0', value: 'Demo Person Alpha', semanticType: 'PERSON' },
    { fieldRef: 'field-0', value: 'person.alpha@example.invalid', semanticType: 'PERSON', subtype: 'EMAIL' },
    { fieldRef: 'field-0', value: '+1 202-555-0101', semanticType: 'PERSON', subtype: 'PHONE' },
  ],
  'D02-DEV-001': [
    { fieldRef: 'field-0', value: '192.0.2.17', semanticType: 'NETWORK_IDENTIFIER', subtype: 'IP' },
    { fieldRef: 'field-1', value: 'diag-node.example.invalid', semanticType: 'HOST_OR_SERVICE' },
  ],
});

function occurrenceId(value, semanticType, subtype) {
  // #5 refs are `[A-Za-z][A-Za-z0-9-]{0,63}`; the digest suffix keeps two same-typed values apart
  // without carrying the value itself.
  const tag = `${semanticType}${subtype ? `_${subtype}` : ''}`.toLowerCase().replace(/_/g, '-');
  return `control-${tag}-${Buffer.from(value, 'utf8').toString('hex').slice(0, 8)}`;
}
function bytes(text) { return encoder.encode(text); }

/**
 * Locate a control in the projected field by exact substring. A control that is absent, or that occurs
 * more than once, is **counted as dropped** rather than silently discarded: an unreported drop would
 * make `planted` in the record read lower than the declared control list with nothing to explain it.
 */
function plant(control, field, dropped) {
  const position = field.content.indexOf(control.value);
  if (position < 0 || field.content.lastIndexOf(control.value) !== position) {
    dropped.push({ semanticType: control.semanticType, subtype: control.subtype ?? null,
      reason: position < 0 ? 'CONTROL_ABSENT' : 'CONTROL_AMBIGUOUS' });
    return null;
  }
  const start = bytes(field.content.slice(0, position)).length;
  return { id: occurrenceId(control.value, control.semanticType, control.subtype),
    fieldRef: control.fieldRef, start, end: start + bytes(control.value).length, value: control.value,
    semanticType: control.semanticType, sensitivity: 'CONFIDENTIAL', trust: 'UNTRUSTED', critical: false,
    expectedBySink: [{ sinkId: LOCAL_SINK.id, treatment: 'MASK' }],
    ...(control.subtype ? { subtype: control.subtype } : {}) };
}

/** #5 candidate events are UTF-8 byte spans in a field, so only an exact original placement counts. */
function toEvent(fieldRef, field, candidate) {
  const { start, end } = candidate.original.span;
  return { fieldRef, start: bytes(field.content.slice(0, start)).length,
    end: bytes(field.content.slice(0, end)).length,
    semanticType: candidate.evidence.claim.semanticType,
    ...(candidate.evidence.claim.subtype ? { subtype: candidate.evidence.claim.subtype } : {}) };
}

/**
 * One Presidio candidate-source pass over already-projected development fields.
 *
 * This is the #113 arm runner, extracted so that the matched #40 comparison reuses it instead of
 * re-implementing the field loop, the #6 root-view target, the pinned-scope preparation and the
 * `#5`-shaped byte-span conversion. It performs no comparison, no scoring and no merging: it returns
 * the emitted events plus the adapter's own status, reasons, limitations and provenance, and the
 * caller decides what to compare. Nothing here is sent, captured or authorized.
 *
 * `events` are `#5` `CandidateEvent` values (`fieldRef`, UTF-8 byte `start`/`end`, `semanticType`,
 * optional `subtype`); they carry no matched text, no span text and no worker label.
 */
export async function runPresidioDevelopmentArm({ command, fields, manifest, workdir, scope,
  requestPrefix }) {
  if (!Array.isArray(fields) || typeof requestPrefix !== 'string' || !requestPrefix.length) {
    throw new TypeError('invalid Presidio development arm request');
  }
  const record = { status: 'COMPLETE', reasons: [], limitations: new Set(), unsupported: new Set(),
    provenance: null, inexact: 0, transport: [], declaredUnsupported: 0, unpinnedUnsupported: 0,
    unpinnedLabels: 0, processes: 0, fields: [] };
  let requestCounter = 0;
  for (const field of fields) {
    const normalized = normalizeInput(field.content);
    // The trial analyses the whole field as one #6 root view. A decoded or folded representation is
    // reachable through the same adapter, but this trial records only the exact root placement.
    const prepared = preparePresidioAnalysis(normalized,
      { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } },
      { requestId: `${requestPrefix}-${requestCounter++}`, inputRef: `${requestPrefix}-${field.ref}`,
        tenantRef: scope.tenantRef, projectRef: scope.projectRef,
        // Pinned from the manifest, exactly as the worker will report it. The adapter checks all
        // three and only ever carries the pinned values into the record, so neither a worker-chosen
        // string in `runtime.version`/`runtime.language` nor a worker-claimed NER capability can reach
        // a shared report or erase its own coverage limits.
        expectedProducerVersion: scope.expectedProducerVersion, expectedLanguage: scope.expectedLanguage,
        expectedNerAvailable: scope.expectedNerAvailable });
    if (!prepared.ok) {
      record.status = 'FAILURE';
      record.reasons.push(prepared.reason);
      continue;
    }
    const outcome = await runPresidioWorker(prepared.plan.line,
      { ...command, args: [manifest], cwd: workdir });
    record.processes += 1;
    if (outcome.status !== 'REPLY') {
      record.status = 'FAILURE';
      record.transport.push({ fieldRef: field.ref, reason: outcome.reason });
      continue;
    }
    const result = completePresidioAnalysis(prepared.plan, outcome.line);
    if (result.status === 'FAILURE') record.status = 'FAILURE';
    else if (result.status === 'PARTIAL' && record.status !== 'FAILURE') record.status = 'PARTIAL';
    record.reasons.push(...result.reasons);
    for (const code of result.limitations) record.limitations.add(code);
    // Only a type this repository pins may be named in a shared record; every other refused label is
    // worker-chosen text and reaches it as a count. The label itself is never read again here.
    for (const item of result.unsupported) {
      if (item.entityType === null) record.unpinnedUnsupported += item.count;
      else record.unsupported.add(item.entityType);
    }
    record.declaredUnsupported += result.declaredUnsupportedTypes;
    record.unpinnedLabels += result.unpinnedUnsupportedTypes;
    record.provenance = result.provenance;
    const emitted = result.candidates.filter((item) => item.original.kind === 'ORIGINAL_EXACT')
      .map((item) => toEvent(field.ref, field, item));
    for (const candidate of result.candidates) {
      if (candidate.original.kind !== 'ORIGINAL_EXACT') record.inexact += 1;
    }
    record.fields.push({ fieldRef: field.ref, emitted: emitted.length, events: emitted, entities:
      Object.fromEntries([...new Set(emitted.map((item) => `${item.semanticType}${
        item.subtype ? `/${item.subtype}` : ''}`))].sort().map((key) => [key,
        emitted.filter((item) => `${item.semanticType}${item.subtype ? `/${item.subtype}` : ''}` === key).length])) });
  }
  return Object.freeze({ status: record.status,
    reasons: [...new Set(record.reasons)].sort(),
    limitations: [...record.limitations].sort(),
    unsupported: [...record.unsupported].sort(), provenance: record.provenance,
    inexact: record.inexact, transport: record.transport,
    declaredUnsupported: record.declaredUnsupported, unpinnedUnsupported: record.unpinnedUnsupported,
    unpinnedLabels: record.unpinnedLabels, processes: record.processes, fields: record.fields });
}

export async function runPresidioDevelopmentTrial(options) {
  const { command, caseIds, scope } = options;
  const fixtures = JSON.parse(readFileSync(PUBLIC_FIXTURES, 'utf8'));
  const evaluation = createDevelopmentEvaluation();
  const capture = createInMemorySinkCapture();
  const cases = [];
  for (const caseId of caseIds) {
    const source = fixtures.fixtures.find((item) => item.fixtureId === caseId);
    if (!source) throw new TypeError('unknown public development fixture');
    const projection = projectPublicDevelopmentFixture({
      fixtureId: source.fixtureId, familyId: source.familyId, partition: 'development',
      input: structuredClone(source.input),
    }, LOCAL_SINK);
    const record = { caseId, familyId: source.familyId, droppedControls: [] };
    const arm = await runPresidioDevelopmentArm({ command, fields: projection.developmentCase.fields,
      manifest: options.manifest, workdir: options.workdir, scope, requestPrefix: `trial-${caseId}` });
    const controls = (CONTROLS[caseId] ?? []).map((control) => plant(control,
      projection.developmentCase.fields.find((item) => item.ref === control.fieldRef),
      record.droppedControls)).filter(Boolean);
    evaluation.registerCase(projection.developmentCase);
    evaluation.registerOracle({ version: 1, caseId, occurrences: controls });
    const events = arm.fields.flatMap((item) => item.events);
    evaluation.registerCandidateEvents(caseId, events);
    const report = evaluation.report(caseId, capture);
    cases.push({
      caseId: report.caseId, familyId: record.familyId, adapterStatus: arm.status,
      reasons: arm.reasons, limitations: arm.limitations,
      unsupportedEntityTypes: arm.unsupported, inexactPlacements: arm.inexact,
      // Refused results whose detector-native type this repository does not pin, summed per analysed
      // field, plus how many distinct labels were dropped. The dropped evidence stays countable and no
      // worker's label becomes reportable.
      unpinnedUnsupportedResults: arm.unpinnedUnsupported,
      unpinnedUnsupportedLabels: arm.unpinnedLabels,
      // A worker-declared type with no result behind it is counted, never named: a declaration is a
      // claim rather than evidence, and its label is worker-chosen text in a record this trial shares.
      declaredUnsupportedTypes: arm.declaredUnsupported,
      transportFailures: arm.transport, emittedEvents: events.length,
      report: { candidates: report.candidates, observed: report.observed.map((item) => item.claim),
        untested: report.untested.map((item) => `${item.claim}/${item.reason}`) },
      // Pinned values only: `provenance.producerVersion`/`language` are the trusted configuration's,
      // already checked against the reply, so a worker cannot name itself in this record.
      provenance: arm.provenance && { producerId: arm.provenance.producerId,
        producerVersion: arm.provenance.producerVersion, mappingVersion: arm.provenance.mappingVersion,
        labelVocabularyVersion: arm.provenance.labelVocabularyVersion,
        language: arm.provenance.language, nerAvailable: arm.provenance.nerAvailable },
      droppedControls: record.droppedControls,
      fields: arm.fields.map(({ events: _events, ...rest }) => rest),
    });
    evaluation.clear();
  }
  capture.clear();
  return { version: 1, kind: 'presidio-development-trial', scored: false, enforcing: false,
    mappingVersion: PRESIDIO_MAPPING_VERSION, protocol: 'hylja.presidio.worker', cases };
}

export const PRESIDIO_TRIAL_LIMITS = Object.freeze(PRESIDIO_WORKER_LIMITS);
function parseArgs(argv) {
  // `--case` restricts the run; without it every case with a development control is analysed. Adding
  // to the defaults instead would make `--case D01-DEV-001` silently analyse D02 as well.
  const values = { caseIds: [], tenantRef: 'tenant-synthetic-01',
    projectRef: 'project-synthetic-01', workerScript: resolve('evaluations/presidio-worker/presidio_worker.py') };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (value === undefined) throw new TypeError('missing trial argument');
    if (key === '--python') values.pythonPath = value;
    else if (key === '--worker') values.workerScript = resolve(value);
    else if (key === '--manifest') values.manifest = resolve(value);
    // The path the *worker* reads, which inside a sandbox differs from the host path above.
    else if (key === '--worker-manifest') values.workerManifest = value;
    else if (key === '--workdir') values.workdir = resolve(value);
    else if (key === '--tenant') values.tenantRef = value;
    else if (key === '--project') values.projectRef = value;
    else if (key === '--case') values.caseIds.push(value);
    else throw new TypeError('unknown trial argument');
  }
  if (!values.caseIds.length) values.caseIds = Object.keys(CONTROLS);
  if (!values.pythonPath || !values.manifest) throw new TypeError('missing trial argument');
  values.workerManifest ??= values.manifest;
  return values;
}

/**
 * Read the pinned analyzer identity out of the manifest: the version, the language and whether the
 * pinned configuration has an NER-capable engine. The version is normalised the way the worker
 * normalises it (`2.2.364` -> `2_2_364`) so the adapter's equality check is on the same string on both
 * sides. It is the *manifest*, not the worker, that decides what a record may say: the adapter checks
 * all three against the reply and carries only these values, so a worker claiming an NER capability
 * the pin does not have is refused instead of being allowed to erase `NO_NER`/`NO_TEXT_CONTEXT` and
 * turn a degraded run into a clean `COMPLETE`.
 */
export function pinnedRuntime(manifestPath) {
  let manifest;
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')); } catch { return null; }
  const artifacts = Array.isArray(manifest?.artifacts) ? manifest.artifacts : [];
  const analyzer = artifacts.find((item) => typeof item?.name === 'string' &&
    item.name.toLowerCase().replace(/_/g, '-') === 'presidio-analyzer');
  const version = typeof analyzer?.version === 'string' ? analyzer.version : null;
  const language = manifest?.configuration?.language;
  const nerAvailable = manifest?.configuration?.nlpEngine?.nerAvailable;
  if (!version || typeof language !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(language) ||
    typeof nerAvailable !== 'boolean') return null;
  return { expectedProducerVersion: version.replace(/[^A-Za-z0-9_-]/g, '_'),
    expectedLanguage: language, expectedNerAvailable: nerAvailable };
}

/** Stable, value-free identity of the pinned manifest, so a record says which pin produced it. */
export function manifestDigest(manifestPath) {
  try {
    return createHash('sha256').update(readFileSync(manifestPath)).digest('hex').slice(0, 32);
  } catch { return 'UNAVAILABLE'; }
}

if (process.argv[1] && process.argv[1].endsWith('presidio-development-trial.mjs')) {
  const values = parseArgs(process.argv.slice(2));
  const pinned = pinnedRuntime(values.manifest);
  if (!pinned) throw new TypeError('manifest does not pin an analyzer version, language and NER capability');
  const trial = await runPresidioDevelopmentTrial({
    command: { pythonPath: values.pythonPath, workerScript: values.workerScript,
      startupTimeoutMs: PRESIDIO_TRIAL_LIMITS.startupTimeoutMs,
      executionTimeoutMs: PRESIDIO_TRIAL_LIMITS.executionTimeoutMs },
    caseIds: [...new Set(values.caseIds)], manifest: values.workerManifest, workdir: values.workdir,
    scope: { tenantRef: values.tenantRef, projectRef: values.projectRef, ...pinned },
  });
  // Fixed codes, counts and privacy-safe provenance only: no value, no span and no fixture text.
  process.stdout.write(`${JSON.stringify({ ...trial, manifestDigest: manifestDigest(values.manifest) }, null, 2)}\n`);
}
