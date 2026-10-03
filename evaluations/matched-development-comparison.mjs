// #40 incremental matched, UNSCORED public-development comparison of three candidate-generation arms
// on the SAME fixed synthetic public D01/D02 development cases: the current native Hylja baseline,
// the already-pinned and #46-screened Presidio configuration, and the union of the two.
//
// Exploratory, NON-ENFORCING, synthetic-only, sent-nothing. What this file is:
//   - an owner-reusing arm runner (`runPresidioDevelopmentArm` from the #113 bridge, plus #6's
//     `detectNormalizedCandidates` for the native arm) driven over one projected field set each;
//   - one predeclared public development control set, planted from the public fixture text before
//     any arm runs and never derived from candidate output, scored per control and per subtype;
//   - a privacy-safe record of counts, codes and evaluator-minted references.
//
// What this file is NOT, and what its numbers may not be read as:
//   - not a scored comparison, not #39 v0, not a freeze, not held-out evidence, not a #40 closure,
//     not an adoption or #48 selection, and not a policy outcome;
//   - not downstream task-utility or protected-egress evidence: nothing is sent, so #5 reports the
//     escape and task claims as `untested` for every arm;
//   - not a merge implementation. The combined arm is a **measurement-only union** of two event sets
//     so the incremental recall, false positives and overlap of joining them can be counted. It
//     applies no policy, resolves no mapping and composes no classification. A production merge
//     belongs to #13/#114, and #114's evidence-to-rewrite overlap contract is required whichever
//     detector or reuse option is eventually selected;
//   - not a claim that a detector is better. Candidate recall here is **generation** recall: a
//     semantic judge or a sentinel catch can never be counted back into it, and no arm uses one.
//
// The native arm is #6's own `detectNormalizedCandidates` over the projected field, not
// `evaluations/candidates/reference.mjs`: that reference candidate carries fixture-shaped demo
// patterns and performs a transformation, so it is neither the product candidate-generation seam
// nor a source whose numbers could be compared against a third-party detector.
//
// The OpenAI Privacy Filter arm is deliberately **absent**: it is not installed, not screened and not
// run, and its row is recorded as `PENDING` rather than as a zero.
//
//   usage: node evaluations/matched-development-comparison.mjs
//            --python <interpreter-or-sandbox-wrapper> --manifest <manifest.json>
//            [--case D01-DEV-001 ...] [--tenant tenant-synthetic-01] [--project project-synthetic-01]
//            [--worker presidio_worker.py] [--workdir /path] [--worker-manifest /trial/manifest.json]
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { DEFAULT_SUBTYPES, SEMANTIC_CLASSES } from '../dist/classification.js';
import { createDevelopmentEvaluation, createInMemorySinkCapture } from '../dist/evaluation.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';
import { PRESIDIO_MAPPING_VERSION, PRESIDIO_LABEL_VOCABULARY_VERSION, PRESIDIO_WORKER_PROTOCOL,
  PRESIDIO_WORKER_PROTOCOL_VERSION, PRESIDIO_PRODUCER_ID } from '../dist/presidio-candidate-source.js';
import { projectPublicDevelopmentFixture } from './public-development-adapter.mjs';
import { manifestDigest, pinnedRuntime, runPresidioDevelopmentArm, PRESIDIO_TRIAL_LIMITS }
  from './presidio-development-trial.mjs';

const PUBLIC_FIXTURES = new URL('../docs/research/issue-39-public-development-fixtures-p0.1.json', import.meta.url);
const PUBLIC_ORACLE = new URL('../docs/research/issue-39-public-development-oracle-p0.1.json', import.meta.url);
const LOCAL_SINK = Object.freeze({ id: 'CAPTURE-DEMO-MODEL', profileId: 'EVAL-LOCAL-MATCHED-TRIAL' });
const encoder = new TextEncoder();

/** Bumped whenever the control set, the arm set or the outcome vocabulary below changes. */
export const MATCHED_COMPARISON_VERSION = 'matched-development-comparison/2';
export const MATCHED_ARMS = Object.freeze(['NATIVE', 'PRESIDIO', 'COMBINED']);
/** Every arm is measured without a semantic judge and without a sentinel; neither may credit recall. */
export const MATCHED_JUDGE_AND_SENTINEL = 'ABSENT_NO_RECALL_CREDIT';
export const MATCHED_PRIVACY_FILTER_ARM = Object.freeze({ arm: 'PRIVACY_FILTER', status: 'PENDING',
  reason: 'NOT_INSTALLED_NOT_SCREENED_NOT_RUN' });

/**
 * The predeclared public development control set, declared here before any arm runs. Every label is a
 * **currently accepted v1** class/subtype: nothing from the proposed decision-010 dimensions or the
 * #65/#66/#68 drafts is used, and no `subtype` outside `DEFAULT_SUBTYPES` is planted.
 *
 * `declaration` records where a control came from, and it is the honest limit of the set:
 * - `MATCHED_TRIAL_CONTROL` is byte-identical to a control the #113 bridge already declared, so those
 *   outcomes stay directly comparable with the recorded trial result;
 * - `ORACLE_DRAFT_OCCURRENCE` is an occurrence the independent #39 **public development oracle
 *   draft** plants for the same case and span. Every occurrence of that draft that this
 *   comparison's cases contain, and whose class is accepted v1, is included, so the positive-control
 *   set is no longer a subset that silently excludes a planted occurrence. The draft's own subtype
 *   (`oracleDraftLabel`) is carried as a cross-reference only: it is **not** the scored label,
 *   because v1 accepts none of `CUSTOMER_NAME`, `PROJECT_ID`, `HOSTNAME`, `ACCOUNT_NAME` or
 *   `CORRELATION_ID`. The draft is development-only with no scoring authority;
 * - `COMPARISON_CONTROL` is declared here only, for the engineering coverage #40's appendix asks for
 *   and the two cases do not otherwise carry.
 *
 * Extending the set from the independent oracle is what makes an unmatched event mean something: an
 * event that matches no control is now either a duplicate, a label disagreement on a planted
 * occurrence, a contradiction of an oracle-declared negative, or genuinely unresolved - never simply
 * "a planted value the controls happened to omit".
 */
const CONTROLS = Object.freeze([
  Object.freeze({ controlRef: 'control-1', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'Demo Person Alpha', semanticType: 'PERSON', subtype: 'NAME', group: 'CONTACT',
    declaration: 'MATCHED_TRIAL_CONTROL', oracleDraftLabel: 'PERSON.NAME' }),
  Object.freeze({ controlRef: 'control-2', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'person.alpha@example.invalid', semanticType: 'PERSON', subtype: 'EMAIL', group: 'CONTACT',
    declaration: 'MATCHED_TRIAL_CONTROL', oracleDraftLabel: 'PERSON.EMAIL' }),
  Object.freeze({ controlRef: 'control-3', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: '+1 202-555-0101', semanticType: 'PERSON', subtype: 'PHONE', group: 'CONTACT',
    declaration: 'MATCHED_TRIAL_CONTROL', oracleDraftLabel: 'PERSON.PHONE' }),
  Object.freeze({ controlRef: 'control-9', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'Demo Person Beta', semanticType: 'PERSON', subtype: 'NAME', group: 'CONTACT',
    declaration: 'ORACLE_DRAFT_OCCURRENCE', oracleDraftLabel: 'PERSON.NAME' }),
  Object.freeze({ controlRef: 'control-10', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'person.beta@example.invalid', semanticType: 'PERSON', subtype: 'EMAIL', group: 'CONTACT',
    declaration: 'ORACLE_DRAFT_OCCURRENCE', oracleDraftLabel: 'PERSON.EMAIL' }),
  Object.freeze({ controlRef: 'control-11', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'Customer Demo-North', semanticType: 'CUSTOMER_OR_PARTNER', subtype: null, group: 'BUSINESS',
    declaration: 'ORACLE_DRAFT_OCCURRENCE', oracleDraftLabel: 'CUSTOMER_OR_PARTNER.CUSTOMER_NAME' }),
  Object.freeze({ controlRef: 'control-12', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'PROJECT-DEMO-01', semanticType: 'PROJECT_OR_CONTRACT', subtype: null, group: 'BUSINESS',
    declaration: 'ORACLE_DRAFT_OCCURRENCE', oracleDraftLabel: 'PROJECT_OR_CONTRACT.PROJECT_ID' }),
  Object.freeze({ controlRef: 'control-4', caseId: 'D02-DEV-001', fieldRef: 'field-0',
    value: '192.0.2.17', semanticType: 'NETWORK_IDENTIFIER', subtype: 'IP', group: 'ENGINEERING',
    declaration: 'MATCHED_TRIAL_CONTROL', oracleDraftLabel: 'NETWORK_IDENTIFIER.IP' }),
  Object.freeze({ controlRef: 'control-5', caseId: 'D02-DEV-001', fieldRef: 'field-0',
    value: 'diag-node.example.invalid', semanticType: 'HOST_OR_SERVICE', subtype: null,
    group: 'ENGINEERING', declaration: 'MATCHED_TRIAL_CONTROL', oracleDraftLabel: 'HOST_OR_SERVICE.HOSTNAME' }),
  Object.freeze({ controlRef: 'control-13', caseId: 'D02-DEV-001', fieldRef: 'field-0',
    value: 'demo.operator', semanticType: 'USER_ACCOUNT', subtype: null, group: 'CONTACT',
    declaration: 'ORACLE_DRAFT_OCCURRENCE', oracleDraftLabel: 'USER_ACCOUNT.ACCOUNT_NAME' }),
  Object.freeze({ controlRef: 'control-14', caseId: 'D02-DEV-001', fieldRef: 'field-0',
    value: 'TRACE-DEMO-02', semanticType: 'APPLICATION_OR_ENVIRONMENT', subtype: null,
    group: 'ENGINEERING', declaration: 'ORACLE_DRAFT_OCCURRENCE',
    oracleDraftLabel: 'APPLICATION_OR_ENVIRONMENT.CORRELATION_ID' }),
  Object.freeze({ controlRef: 'control-8', caseId: 'D02-DEV-001', fieldRef: 'field-0',
    value: 'DEMO-NONLIVE-TOKEN-NOT-VALID', semanticType: 'CREDENTIAL_OR_SECRET', subtype: 'ACCESS_TOKEN',
    group: 'SECRET', declaration: 'COMPARISON_CONTROL', oracleDraftLabel: 'CREDENTIAL_OR_SECRET.ACCESS_TOKEN' }),
  Object.freeze({ controlRef: 'control-15', caseId: 'D02-DEV-001', fieldRef: 'field-1',
    value: 'diag-node.example.invalid', semanticType: 'HOST_OR_SERVICE', subtype: null,
    group: 'ENGINEERING', declaration: 'ORACLE_DRAFT_OCCURRENCE',
    oracleDraftLabel: 'HOST_OR_SERVICE.HOSTNAME' }),
  Object.freeze({ controlRef: 'control-6', caseId: 'D02-DEV-001', fieldRef: 'field-1',
    value: '8443', semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', group: 'ENGINEERING',
    declaration: 'COMPARISON_CONTROL', oracleDraftLabel: null }),
  Object.freeze({ controlRef: 'control-7', caseId: 'D02-DEV-001', fieldRef: 'field-1',
    value: 'https://diag-node.example.invalid:443/health', semanticType: 'NETWORK_IDENTIFIER',
    subtype: 'URL', group: 'ENGINEERING', declaration: 'COMPARISON_CONTROL', oracleDraftLabel: null }),
]);

/**
 * Every declared control occurs exactly once in its projected field, so `indexOf` locates it
 * unambiguously; a value that were absent or repeated would be recorded as a named drop instead.
 * `declaredOracleSpan` below is the span the independent #39 oracle draft plants for the controls it
 * declares, and the runner refuses a comparison in which a computed span disagrees with it - so the
 * oracle-derived part of the set is bound to the oracle's own spans rather than to this file's
 * reading of the text.
 */
const DECLARED_ORACLE_SPANS = Object.freeze({
  'control-1': [44, 61], 'control-2': [94, 122], 'control-3': [124, 139], 'control-9': [142, 158],
  'control-10': [174, 201], 'control-11': [4, 23], 'control-12': [27, 42],
  'control-4': [79, 89], 'control-5': [50, 75], 'control-13': [31, 44], 'control-14': [102, 115],
  'control-8': [122, 150], 'control-15': [43, 68],
});

/** The declared control metadata with its values removed, for a record that must not carry span text. */
export const MATCHED_CONTROL_SUMMARY = Object.freeze(CONTROLS.map(({ value: _value, ...rest }) =>
  Object.freeze(rest)));

/** The SECRET floor is unconditional: a credential class never carries a sensitivity below SECRET. */
const sensitivityOf = (control) => (control.semanticType === 'CREDENTIAL_OR_SECRET' ? 'SECRET' : 'CONFIDENTIAL');
const criticalOf = (control) => control.semanticType === 'CREDENTIAL_OR_SECRET';

function bytes(text) { return encoder.encode(text).length; }
function labelOf(event) { return `${event.semanticType}${event.subtype ? `/${event.subtype}` : ''}`; }

/** Only an accepted v1 class, and only a subtype the accepted registry lists, may be reported. */
function admissibleClaim(semanticType, subtype) {
  if (typeof semanticType !== 'string' || !SEMANTIC_CLASSES.includes(semanticType)) return false;
  if (subtype === undefined || subtype === null) return true;
  const subtypes = DEFAULT_SUBTYPES[semanticType];
  return Array.isArray(subtypes) && subtypes.includes(subtype);
}

/**
 * Plant one control in its projected field. A control that is absent, that occurs more than once, or
 * whose field is missing is **recorded as a named drop** rather than filtered away: an unreported
 * drop would make `planted` read lower than the declared control list with nothing to explain it.
 * Occurrence ids are evaluator-minted ordinals, so no control value or fragment can reach a record
 * through an id. Exported for the deterministic suite, which drives the drop reasons directly.
 */
export function plantDevelopmentControl(control, fields, dropped) {
  const field = fields.find((item) => item.ref === control.fieldRef);
  const position = field ? field.content.indexOf(control.value) : -1;
  if (!field || position < 0 || field.content.lastIndexOf(control.value) !== position) {
    dropped.push({ controlRef: control.controlRef, group: control.group,
      semanticType: control.semanticType, subtype: control.subtype ?? null,
      reason: !field ? 'FIELD_ABSENT' : position < 0 ? 'CONTROL_ABSENT' : 'CONTROL_AMBIGUOUS' });
    return null;
  }
  const start = bytes(field.content.slice(0, position));
  const declared = DECLARED_ORACLE_SPANS[control.controlRef];
  // The oracle's own span, when it declares this occurrence, must be the span computed here. A
  // disagreement means the control set drifted from the independent source it claims to extend.
  if (declared !== undefined && (declared[0] !== start ||
    declared[1] !== start + bytes(control.value))) {
    dropped.push({ controlRef: control.controlRef, group: control.group,
      semanticType: control.semanticType, subtype: control.subtype ?? null,
      reason: 'CONTROL_SPAN_DISAGREES_WITH_DECLARED_ORACLE_SPAN' });
    return null;
  }
  return Object.freeze({ id: control.controlRef, fieldRef: control.fieldRef, start,
    end: start + bytes(control.value), value: control.value, semanticType: control.semanticType,
    ...(control.subtype ? { subtype: control.subtype } : {}),
    sensitivity: sensitivityOf(control), trust: 'UNTRUSTED', critical: criticalOf(control),
    // Nothing is sent, so the treatment is never exercised; #5 only requires the shape to be
    // complete and to respect the SECRET floor.
    expectedBySink: Object.freeze([Object.freeze({ sinkId: LOCAL_SINK.id, treatment: 'MASK' })]) });
}

/* -------------------------------------------------------------------------- native arm --------- */

/**
 * The current native Hylja baseline, configured by **omission only**: no tenant name dictionary, no
 * #10 configured-candidate handle, no fingerprint key and no asserted #7 format. That is the honest
 * baseline for public text, and it is deliberately not "helped": building a name dictionary out of
 * the fixture's own planted names would be tuning a detector against the cases being measured.
 *
 * The consequence is stated rather than hidden: #37 finds NAME only through a tenant/project-scoped
 * `names` dictionary, so an unconfigured run is measured with no NAME source at all, and NAME recall
 * for a *configured* native deployment is **not measured here**.
 */
export function runNativeArm(fields, scope, requestPrefix) {
  const events = [];
  const reasons = new Set();
  let status = 'COMPLETE';
  let uninspected = 0;
  let inexact = 0;
  let refusedClaims = 0;
  const perField = [];
  for (const field of fields) {
    const result = detectNormalizedCandidates({ input: field.content,
      inputRef: `${requestPrefix}-${field.ref}`,
      scope: { tenantRef: scope.tenantRef, projectRef: scope.projectRef } });
    if (result.status === 'FAILURE') status = 'FAILURE';
    else if (result.status === 'PARTIAL' && status !== 'FAILURE') status = 'PARTIAL';
    for (const reason of result.reasons) reasons.add(`NATIVE_${reason}`);
    uninspected += result.uninspected.length;
    let emitted = 0;
    for (const candidate of result.candidates) {
      const claim = candidate.evidence.claim;
      const subtype = claim.subtype ?? null;
      if (!admissibleClaim(claim.semanticType, subtype)) { refusedClaims += 1; continue; }
      // Only an exact original placement is comparable: a covering span or an encoded-run envelope
      // is not the planted occurrence, so counting it would credit recall for a different span.
      if (candidate.original.kind !== 'ORIGINAL_EXACT') { inexact += 1; continue; }
      events.push(Object.freeze({ fieldRef: field.ref,
        start: bytes(field.content.slice(0, candidate.original.span.start)),
        end: bytes(field.content.slice(0, candidate.original.span.end)),
        semanticType: claim.semanticType, ...(subtype ? { subtype } : {}) }));
      emitted += 1;
    }
    perField.push(Object.freeze({ fieldRef: field.ref, emitted,
      uninspected: result.uninspected.length }));
  }
  return Object.freeze({ status, reasons: [...reasons].sort(), uninspected, inexact, refusedClaims,
    events, fields: perField });
}

/* ---------------------------------------------------------------------- combination arm -------- */

/**
 * The measurement-only union. Two events are the same event only when the field, the exact byte
 * span, the class and the subtype all agree, so a differently-labelled finding on the same span is
 * kept rather than absorbed. There is no merging, no preference order, no policy and no
 * classification composition: the union exists only so the *incremental* recall, false positives and
 * overlap of joining the two sources can be counted against the same controls.
 *
 * An exactly identical event is emitted once. That can make the union emit **fewer** events than the
 * native arm alone, because #6 keeps two rules that matched one occurrence as two candidates; the
 * duplicate is counted here as `duplicateEventsRemoved` rather than left to look like a recall or
 * false-positive change it is not.
 */
export function combineArms(nativeEvents, presidioEvents) {
  const keyOf = (event) => `${event.fieldRef}|${event.start}|${event.end}|${labelOf(event)}`;
  const nativeKeys = new Set(nativeEvents.map(keyOf));
  const presidioKeys = new Set(presidioEvents.map(keyOf));
  const events = [];
  const seen = new Set();
  let identical = 0;
  let nativeOnly = 0;
  let presidioOnly = 0;
  for (const event of nativeEvents) {
    const key = keyOf(event);
    if (seen.has(key)) continue;
    seen.add(key);
    events.push(event);
    if (presidioKeys.has(key)) identical += 1; else nativeOnly += 1;
  }
  for (const event of presidioEvents) {
    const key = keyOf(event);
    if (seen.has(key)) continue;
    seen.add(key);
    events.push(event);
    presidioOnly += 1;
  }
  events.sort((left, right) => left.fieldRef.localeCompare(right.fieldRef) || left.start - right.start ||
    left.end - right.end || labelOf(left).localeCompare(labelOf(right)));
  return Object.freeze({ events, overlap: Object.freeze({ combinedEvents: events.length,
    identicalToBothArms: identical, nativeOnly, presidioOnly,
    // The union property this arm is measured by: combining may add a finding but never removes a
    // distinct one. `nativeEvents`/`presidioEvents` are the distinct keys; `*Emitted` are the raw
    // emitted counts. The two ways an event can disappear are named separately, because they are
    // different facts: an *intra-arm* duplicate is one source emitting one occurrence twice (for
    // the native arm, two rules that matched the same occurrence), while `identicalToBothArms` is
    // one event both sources emitted, which the union keeps once.
    nativeEvents: nativeKeys.size, presidioEvents: presidioKeys.size,
    nativeEmitted: nativeEvents.length, presidioEmitted: presidioEvents.length,
    intraArmDuplicatesNative: nativeEvents.length - nativeKeys.size,
    intraArmDuplicatesPresidio: presidioEvents.length - presidioKeys.size,
    totalEmittedEventsFoldedAway: nativeEvents.length + presidioEvents.length - events.length }) });
}

/* ------------------------------------------------------------- independent oracle negatives --- */

/**
 * The #39 public development oracle draft's `unplantedNegatives`, read from the committed draft at
 * run time rather than copied here, reduced to what this comparison can use honestly.
 *
 * A negative declares that a span is **not** one of the classes in its `notA` list. That is a
 * declaration about specific classes, not a claim that the span carries nothing: `N-f1409371f5`
 * declares the HTTPS port `443` to be neither a phone nor a credential and says nothing about
 * `NETWORK_IDENTIFIER.PORT`. So a candidate overlapping a negative span counts as *contradicting the
 * negative* only when the candidate's own accepted-v1 class is one the negative names. Everything
 * else stays **unresolved**, which is the honest state and is never folded into a false-positive total.
 *
 * The draft's `notA` entries are draft labels; only the **class** part is used, and an entry naming
 * no accepted-v1 class is dropped rather than guessed at. No negative text reaches a record.
 */
export function loadOracleNegatives(fixtures, oracle, caseIds) {
  const wanted = new Set(caseIds);
  const out = [];
  for (const negative of Array.isArray(oracle?.unplantedNegatives) ? oracle.unplantedNegatives : []) {
    if (!wanted.has(negative?.fixtureId)) continue;
    const index = fixtures.fixtures.findIndex((item) => item.fixtureId === negative.fixtureId);
    const location = /^\/fixtures\/(\d+)\/input\/(?:text|lines\/(\d+))$/.exec(String(negative?.source?.path ?? ''));
    if (index < 0 || !location || Number(location[1]) !== index) continue;
    const span = negative?.source?.sourceSpan;
    if (!span || !Number.isSafeInteger(span.start) || !Number.isSafeInteger(span.end)) continue;
    const classes = [...new Set((Array.isArray(negative.notA) ? negative.notA : [])
      .map((entry) => String(entry).split('.')[0]).filter((entry) => SEMANTIC_CLASSES.includes(entry)))]
      .sort();
    if (!classes.length) continue;
    out.push(Object.freeze({ negativeId: String(negative.negativeId ?? 'UNNAMED'),
      caseId: negative.fixtureId,
      fieldRef: location[2] === undefined ? 'field-0' : `field-${location[2]}`,
      start: span.start, end: span.end, notAClasses: Object.freeze(classes) }));
  }
  return Object.freeze(out);
}

/* ------------------------------------------------------------------------------ scoring ------ */

/**
 * Score one arm's events against the planted occurrences with **#5's own rule**: identical
 * `fieldRef`, identical UTF-8 start and end, identical class and identical subtype, each event
 * consumed once. A semantic judge or a sentinel catch can never be read back into candidate recall,
 * because nothing here consults one.
 *
 * The vocabulary is deliberately narrow and says exactly what was measured:
 * - `MATCHED`: an event covers the control's exact span with the control's exact accepted-v1 label;
 * - `SPAN_COVERED_LABEL_DIFFERS`: an event covers the control's exact span under a different label -
 *   a real label disagreement on a planted value;
 * - `NO_CANDIDATE_AT_SPAN`: **no event covers the control's span**, so the finding is missing
 *   candidate generation rather than a span-level near miss. `sameLabelElsewhere` counts events on
 *   the same field carrying the control's label at a *different* span; those are not candidates for
 *   this control, and reading them as one is exactly how a missing generation turns into an apparent
 *   near miss. `sameSpanLabels` names the labels that did cover the span, if any.
 */
export function scoreArm(occurrences, events, negatives = []) {
  const used = new Set();
  const outcomes = new Map();
  for (const plant of occurrences) {
    const hit = events.findIndex((event, index) => !used.has(index) &&
      event.fieldRef === plant.fieldRef && event.start === plant.start && event.end === plant.end &&
      event.semanticType === plant.semanticType && event.subtype === plant.subtype);
    if (hit >= 0) {
      used.add(hit);
      outcomes.set(plant.id, Object.freeze({ outcome: 'MATCHED', sameSpanLabels: Object.freeze([]),
        sameLabelElsewhere: 0 }));
      continue;
    }
    const sameSpan = events.filter((event, index) => !used.has(index) &&
      event.fieldRef === plant.fieldRef && event.start === plant.start && event.end === plant.end);
    const sameLabel = events.filter((event, index) => !used.has(index) &&
      event.fieldRef === plant.fieldRef && event.semanticType === plant.semanticType &&
      event.subtype === plant.subtype);
    outcomes.set(plant.id, Object.freeze({
      outcome: sameSpan.length ? 'SPAN_COVERED_LABEL_DIFFERS' : 'NO_CANDIDATE_AT_SPAN',
      sameSpanLabels: Object.freeze([...new Set(sameSpan.map(labelOf))].sort()),
      sameLabelElsewhere: sameLabel.length }));
  }
  const unmatched = events.filter((_event, index) => !used.has(index));
  return Object.freeze({ outcomes, consumed: used,
    matched: [...outcomes.values()].filter((item) => item.outcome === 'MATCHED').length,
    unmatched, unmatchedClasses: classifyUnmatched(unmatched, occurrences, negatives),
    falsePositives: unmatched.length });
}

/**
 * Classify each event that matched no control. `falsePositives` is #5's field name and its arithmetic;
 * this is the honest reading of what those events are, and the four categories are deliberately not
 * collapsed into one:
 *
 * - `DUPLICATE_OF_PLANTED_OCCURRENCE`: the same span and label as a planted occurrence, beyond the
 *   one already matched. A real detection, counted twice by the owner's arithmetic.
 * - `PLANTED_OCCURRENCE_LABEL_DIFFERS`: the exact span of a planted occurrence under a different
 *   label - a labelling disagreement, not a new value.
 * - `ORACLE_DECLARED_NEGATIVE_CONTRADICTED`: the event **overlaps** an oracle-declared unplanted
 *   negative whose `notA` list names this candidate's own accepted-v1 class. Overlap rather than
 *   equality, because the declaration covers a span and a candidate inside that span contradicts it
 *   just as much as one equal to it. This is the only category that is an established error against
 *   an independent declaration.
 * - `UNRESOLVED`: everything else. Neither a planted occurrence nor a declared error. It is **not** a
 *   measured false positive and must not be reported as one.
 */
export function classifyUnmatched(unmatched, occurrences, negatives) {
  const entries = unmatched.map((event) => {
    const planted = occurrences.find((plant) => plant.fieldRef === event.fieldRef &&
      plant.start === event.start && plant.end === event.end);
    let category = 'UNRESOLVED';
    let negativeId = null;
    let spanRelation = null;
    if (planted) {
      category = planted.semanticType === event.semanticType && planted.subtype === event.subtype
        ? 'DUPLICATE_OF_PLANTED_OCCURRENCE' : 'PLANTED_OCCURRENCE_LABEL_DIFFERS';
    } else {
      const negative = negatives.find((item) => item.fieldRef === event.fieldRef &&
        item.start < event.end && event.start < item.end &&
        item.notAClasses.includes(event.semanticType));
      if (negative) {
        category = 'ORACLE_DECLARED_NEGATIVE_CONTRADICTED';
        negativeId = negative.negativeId;
        spanRelation = negative.start === event.start && negative.end === event.end
          ? 'EXACT' : 'OVERLAPS_DECLARED_NEGATIVE';
      }
    }
    return Object.freeze({ fieldRef: event.fieldRef, start: event.start, end: event.end,
      semanticType: event.semanticType, ...(event.subtype ? { subtype: event.subtype } : {}),
      category, ...(negativeId ? { oracleNegativeId: negativeId, spanRelation } : {}) });
  });
  return Object.freeze(entries);
}

/** Event counts by accepted-v1 label. A closed vocabulary, never a value or a span. */
function countByLabel(events) {
  return countBy(events.map(labelOf));
}

/** Counts keyed by a closed vocabulary of strings this module produced; sorted for stability. */
function countBy(keys) {
  const counts = new Map();
  for (const key of keys) counts.set(key, (counts.get(key) ?? 0) + 1);
  return Object.freeze(Object.fromEntries([...counts.entries()].sort(([left], [right]) =>
    left.localeCompare(right))));
}

function bySubtype(occurrences, outcomes) {
  const groups = new Map();
  for (const plant of occurrences) {
    const key = controlLabelOfOccurrence(plant);
    const entry = groups.get(key) ?? { planted: 0, matched: 0, missed: 0 };
    entry.planted += 1;
    if (outcomes.get(plant.id)?.outcome === 'MATCHED') entry.matched += 1; else entry.missed += 1;
    groups.set(key, entry);
  }
  return Object.freeze(Object.fromEntries([...groups.entries()].sort(([left], [right]) =>
    left.localeCompare(right)).map(([key, value]) => [key, Object.freeze(value)])));
}
function controlLabelOfOccurrence(plant) {
  return `${plant.semanticType}${plant.subtype ? `/${plant.subtype}` : ''}`;
}

/** #5 is the owner of the aggregate; this comparison only re-reads what it already decided. */
function measureWithEvaluation(cases, occurrencesByCase, eventsByCase, wallClockMs) {
  const evaluation = createDevelopmentEvaluation();
  const capture = createInMemorySinkCapture();
  const reports = [];
  for (const entry of cases) {
    evaluation.registerCase(entry.developmentCase);
    evaluation.registerOracle({ version: 1, caseId: entry.caseId, occurrences: occurrencesByCase.get(entry.caseId) });
    evaluation.registerCandidateEvents(entry.caseId, eventsByCase.get(entry.caseId));
    evaluation.recordOperationalMeasurement(entry.caseId, { latencyMs: wallClockMs.get(entry.caseId) ?? 0,
      computeMs: 0, modelApiCostMicrounits: 0 });
    const report = evaluation.report(entry.caseId, capture);
    reports.push(Object.freeze({ caseId: report.caseId, familyId: report.familyId,
      candidates: report.candidates, privacy: report.privacy,
      observed: report.observed.map((item) => `${item.claim}/${item.outcome}`),
      untested: report.untested.map((item) => `${item.claim}/${item.reason}`) }));
  }
  evaluation.clear();
  capture.clear();
  return reports;
}

/** A declared control can only vanish as a named drop; anything else is a refused run. */
export function assertNoSilentControlDrop(plantedCount, dropped, declaredCount) {
  if (plantedCount + dropped.length !== declaredCount) {
    throw new TypeError('matched comparison lost a declared control');
  }
}

/** #5 owns the aggregate; the comparison refuses to print a breakdown that disagrees with it. */
export function assertOwnerAgreement(report, scored, occurrenceCount) {
  if (report.planted !== occurrenceCount || report.matched !== scored.matched ||
    report.falsePositives !== scored.falsePositives) {
    throw new TypeError('matched comparison disagrees with the evaluation owner');
  }
}

/* --------------------------------------------------- pre-execution screen verification ----- */

/**
 * Verify, before any third-party execution is accepted as evidence, that the selected runtime is
 * exactly the set of **name-and-digest-verified screened artifacts** the pin describes, and that the
 * process which will run cannot execute an unscrewed startup hook.
 *
 * The work is done by the committed standard-library-only helper
 * `evaluations/presidio-worker/verify_selected_runtime.py`, spawned here with a fixed minimal
 * environment, a bounded runtime and a bounded output, because wheel inspection needs a ZIP reader
 * and this repository has no third-party runtime to do it with.
 *
 * It runs on the **host**, with its own plain interpreter and never the worker's sandbox wrapper:
 * the verification reads the pinned manifest, the cached wheels, the screen report and the candidate
 * runtime's own `site-packages`, none of which the sandbox binds. Using the sandboxed interpreter
 * would make the check unable to see what it must verify, and it would also verify the wrong bytes.
 *
 * This function's own job is the untrusted-boundary half: **the helper's stdout is untrusted
 * content**, so its output is shape-checked, every field is re-derived from a fixed vocabulary, and
 * no string it returns is carried into a record without passing that check. The one field that is a
 * claim about the whole verification rather than a count - the helper's `status` - is **not copied**: it
 * is derived here from the checks the bridge itself accepted, and a reply whose own status disagrees
 * with them is refused rather than believed. stderr is counted and never materialised. A missing input
 * yields `NOT_PERFORMED`, never a pass.
 */
export function verifySelectedRuntime(options) {
  const pythonPath = typeof options?.pythonPath === 'string' ? options.pythonPath : 'python3';
  const scriptPath = typeof options?.scriptPath === 'string' ? options.scriptPath : null;
  const arguments_ = ['manifestPath', 'wheelDirectory', 'screenPath', 'sitePackagesPath']
    .map((key) => options?.[key]);
  if (!scriptPath || arguments_.some((value) => typeof value !== 'string')) {
    return Object.freeze({ status: 'NOT_PERFORMED',
      reason: 'SCRIPT_OR_VERIFICATION_INPUTS_NOT_SUPPLIED', checks: Object.freeze([]) });
  }
  let result;
  try {
    result = spawnSync(pythonPath, [scriptPath, ...arguments_], {
      encoding: 'utf8', timeout: 300_000, maxBuffer: 1 << 20, windowsHide: true,
      // The fixed minimal environment the transport declares for the worker, plus a probe that
      // writes bytecode: this helper must not depend on user site or inherited configuration.
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PYTHONHASHSEED: '0',
        PYTHONDONTWRITEBYTECODE: '1', PYTHONNOUSERSITE: '1', PYTHONUNBUFFERED: '1' },
    });
  } catch {
    // `spawnSync` reports an unusable interpreter through `error`/`status` rather than by throwing,
    // so the check below already covers it; this net is kept so a future platform change cannot raise
    // a path or a message out of this function, and it is documented as not reachable behaviour.
    return Object.freeze({ status: 'NOT_PERFORMED', reason: 'VERIFICATION_PROCESS_FAILED_TO_START',
      checks: Object.freeze([]) });
  }
  if (result.error || result.signal || result.status !== 0) {
    return Object.freeze({ status: 'NOT_PERFORMED', reason: 'VERIFICATION_PROCESS_DID_NOT_SUCCEED',
      checks: Object.freeze([]) });
  }
  const stdout = typeof result.stdout === 'string' ? result.stdout : '';
  if (!stdout || stdout.length > (1 << 20) || stdout.indexOf('\n') !== stdout.length - 1) {
    return Object.freeze({ status: 'NOT_PERFORMED', reason: 'VERIFICATION_OUTPUT_SHAPE_REJECTED',
      checks: Object.freeze([]) });
  }
  const parsed = verificationRecord(safeJson(stdout.slice(0, -1)));
  return Object.freeze(parsed);
}

/** A helper that emits malformed JSON is a fixed refusal, never an exception out of this module. */
function safeJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

const VERIFICATION_STATUSES = ['VERIFIED', 'VERIFIED_WITH_EXCLUSIONS', 'MISMATCH'];
/**
 * The checks that decide whether the executed subset is verified. This list is the authority, not the
 * helper's own reply: a status is **derived** from these, so a reply that claims `VERIFIED` while one of
 * them is not ok is refused rather than recorded.
 */
const VERIFICATION_EXECUTED_CHECKS = ['PINNED_DIGESTS_PRESENT',
  'SELECTED_ARTIFACTS_NAME_AND_SCREEN_VERIFIED', 'RUNTIME_FILE_PROVENANCE',
  'RUNTIME_DISTRIBUTION_SET', 'RUNTIME_STARTUP_HOOKS', 'DECLARED_EXECUTED_SUBSET'];
/** The check that is about the PIN rather than the executed subset; it never decides the status. */
const VERIFICATION_PIN_CHECKS = ['PINNED_RECORDS_ALL_RESOLVED'];
const VERIFICATION_CODES = new Set(['PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT',
  'PINNED_DIGEST_NOT_IN_THE_WHEEL_DIRECTORY', 'ARTIFACT_UNREADABLE', 'PINNED_RECORD_SHAPE',
  'ARTIFACT_OWNS_NO_SINGLE_TOP_LEVEL_DIST_INFO', 'DIGEST_NOT_CACHED', 'SCREEN_RECORD_MISSING_OR_STALE',
  'RUNTIME_FILE_NOT_IN_SELECTED_WHEELS', 'RUNTIME_DISTRIBUTION_NOT_SELECTED',
  'RUNTIME_HAS_PTH_STARTUP_HOOK', 'NON_REGULAR_RUNTIME_ENTRY', 'RUNTIME_ENTRY_UNREADABLE',
  'RUNTIME_FILE_TOO_LARGE_TO_COMPARE', 'RUNTIME_SCAN_TRUNCATED', 'RUNTIME_SELECTED_FILE_MISSING',
  'DECLARED_SUBSET_DISAGREES_WITH_VERIFIED_SELECTION',
  'MANIFEST_OR_SCREEN_UNREADABLE', 'MANIFEST_OR_SCREEN_SHAPE', 'MANIFEST_ARTIFACT_RECORDS',
  'WHEEL_DIRECTORY_UNREADABLE', 'RUNTIME_SITE_PACKAGES_NOT_A_DIRECTORY',
  'RUNTIME_SITE_PACKAGES_UNREADABLE', 'SELECTED_ARTIFACT_UNREADABLE', 'INTERNAL_CHECK_SET_MISMATCH',
  'ARITY']);
const REFUSAL_REASONS = new Set(['SCRIPT_OR_VERIFICATION_INPUTS_NOT_SUPPLIED',
  'VERIFICATION_PROCESS_FAILED_TO_START', 'VERIFICATION_PROCESS_DID_NOT_SUCCEED',
  'VERIFICATION_OUTPUT_SHAPE_REJECTED', 'VERIFICATION_STATUS_DISAGREES_WITH_ACCEPTED_CHECKS',
  'VERIFICATION_CHECK_SET_INCOMPLETE']);

const VERIFICATION_CHECK_NAMES = new Set([...VERIFICATION_EXECUTED_CHECKS, ...VERIFICATION_PIN_CHECKS]);

/** Re-derive a verification reply into the closed vocabulary above; anything else is `MISMATCH`. */
function verificationRecord(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
    raw.protocol !== 'hylja.presidio.runtime-verification' || raw.version !== 1 ||
    !VERIFICATION_STATUSES.includes(raw.status)) {
    return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
  }
  if (raw.status === 'MISMATCH' && (Array.isArray(raw.checks) ? raw.checks : []).length === 0 &&
      typeof raw.reason === 'string' && VERIFICATION_CODES.has(raw.reason)) {
    return notPerformed(raw.reason);
  }
  const count = (value) => (Number.isSafeInteger(value) && value >= 0 && value <= 1 << 30 ? value : null);
  const checks = Array.isArray(raw.checks) && raw.checks.length <= 16 ? raw.checks : null;
  if (!checks) return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
  const rebuilt = [];
  for (const check of checks) {
    const name = check?.check;
    if (!VERIFICATION_CHECK_NAMES.has(name) || typeof check?.ok !== 'boolean') {
      return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
    }
    // `ok` and `code` can never disagree here: a code is only accepted on a check that is not ok.
    if (check.ok && check.code !== null) return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
    if (!check.ok && check.code === null) return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
    if (check.code !== null && !VERIFICATION_CODES.has(check.code)) {
      return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
    }
    const detail = check.detail;
    if (detail === null || typeof detail !== 'object' || Array.isArray(detail)) {
      return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
    }
    const numbers = {};
    for (const [key, value] of Object.entries(detail)) {
      // `declared` is the one key that may be null: it is null when the manifest declares no
      // executed subset at all, which is a fact about the manifest rather than a failed check.
      if (key === 'declared' && value === null) { numbers[key] = null; continue; }
      const parsed = count(value);
      if (parsed === null) return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
      numbers[key] = parsed;
    }
    rebuilt.push(Object.freeze({ check: name, ok: check.ok,
      code: check.code === null ? null : check.code, detail: Object.freeze(numbers) }));
  }
  const excluded = Array.isArray(raw.excludedArtifactRecords) &&
    raw.excludedArtifactRecords.length <= 64 ? raw.excludedArtifactRecords : null;
  if (excluded === null) return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
  const reasons = excluded.map((item) => item?.reason).filter((reason) => VERIFICATION_CODES.has(reason));
  if (reasons.length !== excluded.length) return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
  // The counts the record quotes must themselves be counts: a helper that answers with a string or a
  // negative number is refused rather than silently read as zero.
  const selectedArtifacts = count(raw.selectedArtifacts);
  const screenRecords = count(raw.screen?.records);
  const runtimeDistributions = count(raw.runtime?.distributions);
  const runtimeFiles = count(raw.runtime?.files);
  const runtimeStartupHookFiles = count(raw.runtime?.pthFiles);
  if (selectedArtifacts === null || screenRecords === null || runtimeDistributions === null ||
    runtimeFiles === null || runtimeStartupHookFiles === null) {
    return notPerformed('VERIFICATION_OUTPUT_SHAPE_REJECTED');
  }
  // The status is derived here, not copied. The helper's own `status` is an untrusted claim about the
  // whole verification, so it is compared with what the accepted checks actually say: a reply that
  // claims VERIFIED while an executed check is not ok is refused, and so is a reply that claims
  // MISMATCH while every executed check passed. Either way the record never shows a status the checks
  // do not support.
  const executed = rebuilt.filter((item) => VERIFICATION_EXECUTED_CHECKS.includes(item.check));
  const executedNames = executed.map((item) => item.check);
  if (executed.length !== VERIFICATION_EXECUTED_CHECKS.length ||
    new Set(executedNames).size !== executed.length ||
    VERIFICATION_EXECUTED_CHECKS.some((name) => !executedNames.includes(name))) {
    return notPerformed('VERIFICATION_CHECK_SET_INCOMPLETE');
  }
  const derived = executed.every((item) => item.ok)
    ? (excluded.length ? 'VERIFIED_WITH_EXCLUSIONS' : 'VERIFIED') : 'MISMATCH';
  if (raw.status !== derived) return notPerformed('VERIFICATION_STATUS_DISAGREES_WITH_ACCEPTED_CHECKS');
  return Object.freeze({ status: derived, checks: Object.freeze(rebuilt),
    selectedArtifacts,
    excludedArtifactRecords: excluded.length,
    excludedReasons: Object.freeze([...new Set(reasons)].sort()),
    screenRecords, runtimeDistributions, runtimeFiles, runtimeStartupHookFiles });
}
function notPerformed(reason) {
  // A reason is either one of this module's own refusal codes or a fixed code the helper itself
  // reported for a refusal it could not perform. Both are closed vocabularies; anything else
  // collapses to the single shape-rejected code rather than carrying an unchecked string.
  const known = REFUSAL_REASONS.has(reason) || VERIFICATION_CODES.has(reason);
  return Object.freeze({ status: 'NOT_PERFORMED', reason: known ? reason
    : 'VERIFICATION_OUTPUT_SHAPE_REJECTED', checks: Object.freeze([]) });
}

/** The run's execution-environment claim, or the fixed code for why there is not one. */
function environmentClaim(verification) {
  if (verification.status === 'NOT_PERFORMED') {
    return Object.freeze({ status: 'NOT_PERFORMED', code: verification.reason });
  }
  // The accepted checks are carried so a reader can see *which* check passed, and that
  // `PINNED_RECORDS_ALL_RESOLVED` is deliberately not ok in a verified-with-exclusions run rather than
  // being invisible beside a green status.
  return Object.freeze({ status: verification.status, selectedArtifacts: verification.selectedArtifacts,
    excludedArtifactRecords: verification.excludedArtifactRecords,
    excludedReasons: verification.excludedReasons,
    runtimeStartupHookFiles: verification.runtimeStartupHookFiles,
    checks: verification.checks.map((item) => Object.freeze({ check: item.check, ok: item.ok,
      code: item.code, detail: item.detail })),
    note: 'The status is DERIVED from the checks listed here by the bridge, not copied from the helper, '
      + 'and a helper whose own status disagrees with them is refused. VERIFIED and '
      + 'VERIFIED_WITH_EXCLUSIONS cover the executed subset only: they are not a statement that every '
      + 'pinned record corresponds to the artifact it names, and the excluded records are listed with '
      + 'their reason.' });
}

/* --------------------------------------------------------------------------------- runner ---- */

/**
 * Run all three arms over the same projected fields and the same planted controls.
 *
 * `options.command` is the bounded worker transport configuration, `options.manifest` the path the
 * worker opens and `options.scope` the trusted pins (analyzer version, language, NER capability)
 * read from the pinned manifest by the caller. There is no arm-injection seam: both arms are the
 * delivered ones, so the deterministic suite drives this same runner with the generated worker.
 */
export async function runMatchedDevelopmentComparison(options) {
  const { command, caseIds, scope } = options;
  if (!Array.isArray(caseIds) || !caseIds.length) throw new TypeError('invalid matched comparison request');
  const fixtures = JSON.parse(readFileSync(PUBLIC_FIXTURES, 'utf8'));
  const oracle = JSON.parse(readFileSync(PUBLIC_ORACLE, 'utf8'));
  const negativesByCase = new Map();
  for (const negative of loadOracleNegatives(fixtures, oracle, caseIds)) {
    const list = negativesByCase.get(negative.caseId) ?? [];
    list.push(negative);
    negativesByCase.set(negative.caseId, list);
  }
  const verification = verifySelectedRuntime({ pythonPath: options.verificationPython ?? 'python3',
    scriptPath: options.verificationScript, manifestPath: options.verificationManifest,
    wheelDirectory: options.wheelDirectory, screenPath: options.screenReport,
    sitePackagesPath: options.sitePackages });
  const projections = [];
  for (const caseId of caseIds) {
    const source = fixtures.fixtures.find((item) => item.fixtureId === caseId);
    if (!source) throw new TypeError('unknown public development fixture');
    projections.push({ caseId, familyId: source.familyId, dropped: [],
      developmentCase: projectPublicDevelopmentFixture({ fixtureId: source.fixtureId,
        familyId: source.familyId, partition: 'development', input: structuredClone(source.input) },
      LOCAL_SINK).developmentCase });
  }
  const occurrencesByCase = new Map();
  for (const entry of projections) {
    const controls = CONTROLS.filter((control) => control.caseId === entry.caseId);
    occurrencesByCase.set(entry.caseId, controls.map((control) =>
      plantDevelopmentControl(control, entry.developmentCase.fields, entry.dropped)).filter(Boolean));
    assertNoSilentControlDrop(occurrencesByCase.get(entry.caseId).length, entry.dropped, controls.length);
  }

  const nativeByCase = new Map();
  const presidioByCase = new Map();
  const nativeStatus = [];
  const presidioStatus = [];
  const presidioLimits = new Set();
  const nativeWall = new Map();
  const presidioWall = new Map();
  const combinedWall = new Map();
  let presidioProcesses = 0;
  for (const entry of projections) {
    const nativeStart = process.hrtime.bigint();
    const native = runNativeArm(entry.developmentCase.fields, scope, `matched-${entry.caseId}-native`);
    nativeWall.set(entry.caseId, Number((process.hrtime.bigint() - nativeStart) / 1_000_000n));
    nativeStatus.push({ caseId: entry.caseId, status: native.status, reasons: native.reasons,
      uninspected: native.uninspected, inexactPlacements: native.inexact ?? 0,
      refusedClaims: native.refusedClaims ?? 0, fields: native.fields ?? [] });
    nativeByCase.set(entry.caseId, native.events);
    const presidioStart = process.hrtime.bigint();
    const presidio = await runPresidioDevelopmentArm({ command,
      fields: entry.developmentCase.fields, manifest: options.manifest, workdir: options.workdir,
      scope, requestPrefix: `matched-${entry.caseId}-presidio` });
    presidioWall.set(entry.caseId, Number((process.hrtime.bigint() - presidioStart) / 1_000_000n));
    for (const code of presidio.limitations) presidioLimits.add(code);
    presidioStatus.push({ caseId: entry.caseId, status: presidio.status, reasons: presidio.reasons,
      limitations: presidio.limitations, transportFailures: presidio.transport,
      inexactPlacements: presidio.inexact, declaredUnsupportedTypes: presidio.declaredUnsupported,
      unpinnedUnsupportedResults: presidio.unpinnedUnsupported,
      unpinnedUnsupportedLabels: presidio.unpinnedLabels, fields: presidio.fields });
    presidioProcesses += presidio.processes;
    presidioByCase.set(entry.caseId, presidio.fields.flatMap((item) => item.events));
  }

  const combinedByCase = new Map();
  const overlapByCase = new Map();
  for (const entry of projections) {
    const combinedStart = process.hrtime.bigint();
    const combined = combineArms(nativeByCase.get(entry.caseId) ?? [], presidioByCase.get(entry.caseId) ?? []);
    combinedWall.set(entry.caseId, Number((process.hrtime.bigint() - combinedStart) / 1_000_000n));
    combinedByCase.set(entry.caseId, combined.events);
    overlapByCase.set(entry.caseId, combined.overlap);
  }

  const arms = {};
  for (const [arm, eventsByCase, wall] of [['NATIVE', nativeByCase, nativeWall],
    ['PRESIDIO', presidioByCase, presidioWall], ['COMBINED', combinedByCase, combinedWall]]) {
    const reports = measureWithEvaluation(projections, occurrencesByCase, eventsByCase, wall);
    arms[arm] = { reports, byCase: new Map(projections.map((entry, index) => {
      const occurrences = occurrencesByCase.get(entry.caseId);
      const events = eventsByCase.get(entry.caseId) ?? [];
      const scored = scoreArm(occurrences, events, negativesByCase.get(entry.caseId) ?? []);
      const report = reports[index];
      assertOwnerAgreement(report.candidates, scored, occurrences.length);
      return [entry.caseId, { caseId: report.caseId, familyId: report.familyId,
        events: events.length, eventsByLabel: countByLabel(events),
        // What the owner's `falsePositives` count actually consists of. #5's arithmetic is
        // "emitted events that matched no control"; these categories are the honest reading, and
        // only `ORACLE_DECLARED_NEGATIVE_CONTRADICTED` is an established error against an
        // independent declaration. `UNRESOLVED` is neither and must never be counted as one.
        unmatchedByCategory: countBy(scored.unmatchedClasses.map((item) => item.category)),
        unmatchedByCategoryAndLabel: countBy(scored.unmatchedClasses
          .map((item) => `${item.category}:${labelOf(item)}`)),
        controls: occurrences.map((plant) => {
          const control = CONTROLS.find((item) => item.controlRef === plant.id);
          return { controlRef: plant.id, group: control.group, semanticType: plant.semanticType,
            subtype: plant.subtype ?? null, declaration: control.declaration,
            oracleDraftLabel: control.oracleDraftLabel,
            ...scored.outcomes.get(plant.id) };
        }), bySubtype: bySubtype(occurrences, scored.outcomes),
        candidates: report.candidates, privacy: report.privacy, observed: report.observed,
        untested: report.untested }];
    })) };
  }

  const declaredControls = CONTROLS.filter((control) => caseIds.includes(control.caseId));
  return Object.freeze({ version: 1, kind: 'matched-development-comparison',
    comparisonVersion: MATCHED_COMPARISON_VERSION, scored: false, enforcing: false,
    sentBytes: 0, sentFields: 0, capturedReleases: 0,
    semanticJudgeAndSentinel: MATCHED_JUDGE_AND_SENTINEL,
    privacyFilterArm: MATCHED_PRIVACY_FILTER_ARM,
    executionEnvironment: environmentClaim(verification),
    oracle: Object.freeze({ draftId: typeof oracle?.draftId === 'string' ? oracle.draftId : 'UNKNOWN',
      releaseAuthority: false,
      declaredNegativesUsed: [...negativesByCase.values()].reduce((sum, list) => sum + list.length, 0),
      note: 'The #39 public development oracle is a development-only draft with no scoring authority. It is read for the occurrences and unplanted negatives this control set and the unmatched-event classification use. Every scored label is accepted v1.' }),
    identity: Object.freeze({ protocol: PRESIDIO_WORKER_PROTOCOL,
      protocolVersion: PRESIDIO_WORKER_PROTOCOL_VERSION, mappingVersion: PRESIDIO_MAPPING_VERSION,
      labelVocabularyVersion: PRESIDIO_LABEL_VOCABULARY_VERSION, producerId: PRESIDIO_PRODUCER_ID,
      producerVersion: scope.expectedProducerVersion, language: scope.expectedLanguage,
      nerAvailable: scope.expectedNerAvailable,
      // Named for what it hashes: the committed manifest on the **host**, read for the pins above.
      // The worker opens `--worker-manifest`; the documented invocation binds the committed manifest
      // itself read-only into the sandbox, so the two are the same bytes - but this digest is a fact
      // about the host copy and is not a claim about some other sandboxed copy.
      hostManifestDigest: manifestDigest(options.manifestPath ?? options.manifest),
      // The controls declared for the cases this run actually analysed, without their values.
      declaredControlsForRun: MATCHED_CONTROL_SUMMARY.filter((control) =>
        caseIds.includes(control.caseId)) }),
    resources: Object.freeze({ nativeArmCaseCount: projections.length,
      presidioWorkerProcessCount: presidioProcesses,
      nativeWallClockMs: Object.freeze(Object.fromEntries(nativeWall)),
      presidioWallClockMs: Object.freeze(Object.fromEntries(presidioWall)),
      combinedUnionWallClockMs: Object.freeze(Object.fromEntries(combinedWall)),
      note: 'One Presidio worker process per analysed field, one-shot, no pooling and no persistent worker. Wall clock includes process spawn and import; it is not a latency SLA and no peak-RSS figure is measured here.' }),
    limitations: Object.freeze({ presidio: [...presidioLimits].sort(),
      native: Object.freeze(['NATIVE_NAME_SOURCE_UNCONFIGURED',
        'NATIVE_CONFIGURED_SOURCE_ABSENT_C10_TENANT_TERMS_TEMPLATES_FIELD_HINTS']),
      combined: Object.freeze(['COMBINED_IS_A_MEASUREMENT_UNION_NOT_A_MERGE',
        'UPSTREAM_FILTERING_OBSERVABLE_ONLY_AS_REPORTED_LIMITATIONS']) }),
    nativeArm: Object.freeze(nativeStatus),
    presidioArm: Object.freeze(presidioStatus),
    overlap: Object.freeze(Object.fromEntries(overlapByCase)),
    cases: Object.freeze(projections.map((entry, index) => Object.freeze({ caseId: entry.caseId,
      familyId: entry.familyId, controlsPlanted: occurrencesByCase.get(entry.caseId).length,
      droppedControls: entry.dropped,
      arms: Object.freeze(Object.fromEntries(MATCHED_ARMS.map((arm) => [arm,
        arms[arm].byCase.get(entry.caseId)]))),
      reportCaseIds: Object.freeze(Object.fromEntries(MATCHED_ARMS.map((arm) => [arm,
        arms[arm].reports[index].caseId]))) }))),
    limits: Object.freeze([
      'UNSCORED_PUBLIC_DEVELOPMENT_PROBE_NOT_39_V0_NOT_HELD_OUT_NOT_A_FREEZE',
      'NO_SEMANTIC_JUDGE_AND_NO_SENTINEL_SO_NEITHER_CAN_CREDIT_CANDIDATE_RECALL',
      'NOTHING_SENT_SO_ESCAPE_AND_TASK_CLAIMS_ARE_UNTESTED_FOR_EVERY_ARM',
      'NATIVE_ARM_IS_UNCONFIGURED_SO_CONFIGURED_NATIVE_NAME_RECALL_IS_NOT_MEASURED',
      'NO_THRESHOLD_TUNING_NO_DETECTOR_CHANGE_NO_POLICY_OUTCOME_NO_MERGE_IMPLEMENTATION',
      // #5's `falsePositives` is emitted events matching no control. It is a bounded-subset
      // over-generation count and NOT a measured detector precision: an unmatched event may be a
      // duplicate of a planted occurrence, a label disagreement on one, a value the control set
      // does not name, or simply unresolved. `unmatchedByCategory` separates those, and only
      // `ORACLE_DECLARED_NEGATIVE_CONTRADICTED` is an established error.
      'FALSE_POSITIVE_IS_NOT_DETECTOR_PRECISION_AND_UNMATCHED_IS_NOT_AN_ESTABLISHED_ERROR',
      'UNRESOLVED_UNMATCHED_EVENTS_REMAIN_UNRESOLVED',
      'PRIVACY_FILTER_ARM_PENDING_NOT_INSTALLED_NOT_SCREENED_NOT_RUN',
      'UTILILITY_ENERGY_COST_PERSISTENT_WORKER_AND_SWEDISH_FAMILIES_REMAIN_UNMEASURED',
      // The record names the public fixture ids it ran so a reviewer can find the inputs; #5's own
      // report refs remain minted ordinals and no planted value is carried anywhere.
      'RECORD_NAMES_PUBLIC_FIXTURE_IDS_AND_CARRIES_NO_PLANTED_VALUE',
      ...(verification.status === 'NOT_PERFORMED'
        ? ['EXECUTION_ENVIRONMENT_NOT_VERIFIED_NO_THIRD_PARTY_EXECUTION_EVIDENCE_ACCEPTED']
        : ['EXECUTION_ENVIRONMENT_VERIFIES_THE_EXECUTED_SUBSET_ONLY_NOT_EVERY_PINNED_RECORD']),
    ]),
  });
}

export const MATCHED_TRIAL_LIMITS = Object.freeze(PRESIDIO_TRIAL_LIMITS);

function parseArgs(argv) {
  const values = { caseIds: [], tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
    workerScript: resolve('evaluations/presidio-worker/presidio_worker.py') };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (value === undefined) throw new TypeError('missing comparison argument');
    if (key === '--python') values.pythonPath = value;
    else if (key === '--worker') values.workerScript = resolve(value);
    else if (key === '--manifest') { values.manifest = resolve(value); values.manifestPath = values.manifest; }
    // The path the *worker* reads, which inside a sandbox differs from the host path above.
    else if (key === '--worker-manifest') values.workerManifest = value;
    else if (key === '--workdir') values.workdir = resolve(value);
    // Pre-execution screen verification inputs. All four are required together; the run refuses to
    // accept third-party execution evidence without them and says so with a fixed code.
    else if (key === '--verify-script') values.verificationScript = resolve(value);
    else if (key === '--verify-python') values.verificationPython = value;
    else if (key === '--verify-manifest') values.verificationManifest = resolve(value);
    else if (key === '--wheels') values.wheelDirectory = resolve(value);
    else if (key === '--screen') values.screenReport = resolve(value);
    else if (key === '--site-packages') values.sitePackages = resolve(value);
    else if (key === '--tenant') values.tenantRef = value;
    else if (key === '--project') values.projectRef = value;
    else if (key === '--case') values.caseIds.push(value);
    else throw new TypeError('unknown comparison argument');
  }
  if (!values.caseIds.length) values.caseIds = [...new Set(CONTROLS.map((control) => control.caseId))];
  if (!values.pythonPath || !values.manifest) throw new TypeError('missing comparison argument');
  values.workerManifest ??= values.manifest;
  return values;
}

if (process.argv[1] && process.argv[1].endsWith('matched-development-comparison.mjs')) {
  const values = parseArgs(process.argv.slice(2));
  const pinned = pinnedRuntime(values.manifest);
  if (!pinned) throw new TypeError('manifest does not pin an analyzer version, language and NER capability');
  const comparison = await runMatchedDevelopmentComparison({
    command: { pythonPath: values.pythonPath, workerScript: values.workerScript,
      startupTimeoutMs: MATCHED_TRIAL_LIMITS.startupTimeoutMs,
      executionTimeoutMs: MATCHED_TRIAL_LIMITS.executionTimeoutMs },
    caseIds: [...new Set(values.caseIds)], manifest: values.workerManifest, manifestPath: values.manifest,
    workdir: values.workdir, scope: { tenantRef: values.tenantRef, projectRef: values.projectRef, ...pinned },
    verificationScript: values.verificationScript, verificationManifest: values.verificationManifest,
    verificationPython: values.verificationPython,
    wheelDirectory: values.wheelDirectory, screenReport: values.screenReport,
    sitePackages: values.sitePackages,
  });
  process.stdout.write(`${JSON.stringify(comparison, null, 2)}\n`);
}