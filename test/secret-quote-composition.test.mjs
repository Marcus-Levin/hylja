import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassificationUnits } from '../dist/classification-units.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';
import { detectSecrets } from '../dist/secret-detectors.js';

// Missing-coverage controls on the already-fixed #8 source, not a new RED or an egress proof.
// Public synthetic words separated by spaces/punctuation cannot become one long encoded-looking run.
// The private quote window counts its opener; this fixed literal sizes cases without changing budgets.
const QWIN = 65536;
const filler = (length) => 'synthetic public filler! '.repeat(Math.ceil(length / 24)).slice(0, length - 1) + '!';
const scope = Object.freeze({ tenantRef: 'tenant-a', projectRef: 'project-a' });
// Same valid trusted synthetic context shape as configured-units.test.mjs; never derived from payload.
const context = Object.freeze({ interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
const callers = [
  { name: 'assignment', prefix: 'synthetic command password=', folded: 'synthetic command ｐａｓｓｗｏｒｄ=', rule: 'context.key-assignment' },
  { name: 'cli', prefix: '--password ', folded: '--ｐａｓｓｗｏｒｄ ', rule: 'context.cli-flag' },
  { name: 'kubernetes', prefix: 'name: DB_PASSWORD\nvalue: ', folded: 'name: ＤＢ＿ＰＡＳＳＷＯＲＤ\nvalue: ', rule: 'context.named-value' },
];
const keys = [
  { name: 'unkeyed', options: {}, keyed: false },
  { name: 'keyed', options: { fingerprintKey: new Uint8Array(32).fill(9) }, keyed: true },
];
const inputs = [
  { name: 'RAW string', folded: false, bytes: false },
  { name: 'UTF8 bytes', folded: false, bytes: true },
  { name: 'FOLDED string', folded: true, bytes: false },
];
const quoteReason = 'SECRET_QUOTE_WINDOW_EXCEEDED';
const detect = (input, inputRef, options) => detectNormalizedCandidates({ input, inputRef, scope, ...options });
const compose = (detection, inputRef) => composeClassificationUnits({ detection, inputRef, scope, context });
const direct = (text, options) => detectSecrets({ text, inputRef: 'direct-synthetic.invalid', ...options });
const rootSecrets = (result) => result.candidates.filter((item) => item.source === 'SECRET' && item.view.viewId === 0 && !item.field);
const asInput = (text, form) => form.bytes ? new TextEncoder().encode(text) : text;
const prefixFor = (caller, form) => `${form.bytes ? 'é ' : ''}host=host.example.invalid\n${form.folded ? caller.folded : caller.prefix}`;
const originalFor = (text, form) => form.bytes ?
  { kind: 'UTF8_TEXT', span: { start: 0, end: text.length }, coverage: 'EXACT' } :
  { kind: 'ORIGINAL_EXACT', span: { start: 0, end: text.length } };

function fingerprintFacts(candidate, keyed) {
  assert.equal(Object.hasOwn(candidate, 'fingerprint'), keyed);
  if (keyed) assert.equal(/^[0-9a-f]{32}$/u.test(candidate.fingerprint), true);
}
function privateFacts(result, values) {
  const serialized = JSON.stringify(result);
  for (const value of values) assert.equal(serialized.includes(value), false);
}
function partialFacts(result, text, form) {
  assert.equal(result.status, 'PARTIAL');
  assert.equal(result.reasons.includes(quoteReason), true);
  // A normalization run/depth/work limit cannot masquerade as quote-specific evidence.
  assert.equal(result.reasons.some((reason) => reason.startsWith('NORMALIZATION_')), false);
  const opaque = result.uninspected.filter((item) => item.reason === quoteReason && item.viewId === 0);
  assert.equal(opaque.length > 0, true);
  for (const item of opaque) {
    assert.deepEqual(item.viewSpan, { start: 0, end: text.length });
    assert.deepEqual(item.original, originalFor(text, form));
  }
  // Only the failed root SECRET pass is empty. Legitimate parsed FULL fields and other sources may survive.
  assert.equal(rootSecrets(result).length, 0);
  assert.equal(rootSecrets(result).some((item) => Object.hasOwn(item, 'fingerprint')), false);
  assert.equal(result.candidates.some((item) => item.source === 'INFRASTRUCTURE' && item.view.viewId === 0), true);
  privateFacts(result, ['synthetic-uninspected-tail.invalid', 'host.example.invalid']);
}
function composedPartialFacts(detection, inputRef) {
  const result = compose(detection, inputRef);
  assert.equal(result.status, 'PARTIAL');
  assert.equal(result.reasons.includes(quoteReason), true);
  assert.equal(result.reasons.includes('DETECTION_UNREADABLE_REASON'), false);
  assert.equal(result.uninspected.some((item) => item.reason === 'UNREADABLE_OPAQUE_REASON'), false);
  // All actual opaque locations, including code-shaped quote reason and original provenance, persist.
  assert.equal(JSON.stringify(result.uninspected) === JSON.stringify(detection.uninspected), true);
  assert.equal(result.units.flatMap((unit) => unit.detectorEvidence).length, detection.candidates.length);
  privateFacts(result, ['synthetic-uninspected-tail.invalid', 'host.example.invalid']);
}

for (const key of keys) {
  for (const caller of callers) {
    test(`#8 discard earlier candidates: ${caller.name}/${key.name}`, () => {
      const token = ['gh', 'p_', 'Synthetic0'.repeat(4).slice(0, 36)].join('');
      const earlier = `password=synthetic-earlier.invalid\n${token}\n`;
      const positive = direct(earlier, key.options);
      assert.equal(positive.status, 'COMPLETE');
      assert.equal(positive.reasons.length, 0);
      assert.equal(positive.candidates.length, 2);
      assert.equal(positive.candidates.some((item) => item.rule === 'context.key-assignment'), true);
      assert.equal(positive.candidates.some((item) => item.rule === 'format.github-token'), true);
      for (const candidate of positive.candidates) fingerprintFacts(candidate, key.keyed);
      const earlierFingerprints = positive.candidates.flatMap((item) => item.fingerprint ? [item.fingerprint] : []);
      assert.equal(earlierFingerprints.length, key.keyed ? 2 : 0);
      const result = direct(`${earlier}${caller.prefix}"${filler(QWIN)}synthetic-uninspected-tail.invalid"`, key.options);
      assert.equal(result.status, 'FAILURE');
      assert.deepEqual(result.reasons, ['QUOTE_WINDOW_EXCEEDED']);
      assert.equal(result.candidates.length, 0);
      assert.equal(JSON.stringify(result).includes('fingerprint'), false);
      privateFacts(result, ['synthetic-earlier.invalid', token, 'synthetic-uninspected-tail.invalid', ...earlierFingerprints]);
    });

    for (const form of inputs) {
      const label = `${caller.name}/${key.name}/${form.name}`;
      test(`#8 normalized full-coverage controls: ${label}`, () => {
        const prefix = prefixFor(caller, form);
        // TEXT root inputs avoid asking a line parser to accept true-EOF unterminated syntax.
        // Even escapes at the boundary are exercised on their full source span, not decoded field spans.
        const contents = [
          { name: 'bounded', content: 'synthetic-bounded.invalid', ending: '"' },
          { name: 'true-EOF', content: filler(QWIN - 1), ending: '' },
          { name: 'even-boundary', content: `${filler(QWIN - 3)}\\\\`, ending: '"' },
        ];
        for (const control of contents) {
          const text = `${prefix}"${control.content}${control.ending}`;
          const ref = `positive-${caller.name}-${key.name}-${form.name}-${control.name}.invalid`;
          const result = detect(asInput(text, form), ref, key.options);
          assert.equal(result.status, 'COMPLETE');
          assert.equal(result.reasons.length, 0);
          assert.equal(result.uninspected.length, 0);
          const secrets = rootSecrets(result);
          assert.equal(secrets.length, 1);
          const candidate = secrets[0];
          const at = { start: prefix.length + 1, end: prefix.length + 1 + control.content.length };
          assert.deepEqual(candidate.view.span, at);
          assert.equal(candidate.view.representation, form.folded ? 'FOLDED' : 'RAW');
          assert.equal(candidate.rule, caller.rule);
          assert.equal(candidate.subtype, 'PASSWORD');
          assert.equal(candidate.evidence.claim.sensitivity, 'SECRET');
          assert.equal(candidate.evidence.claim.reversible, false);
          assert.deepEqual(candidate.original, form.bytes ? { kind: 'UTF8_TEXT', span: at, coverage: 'EXACT' } :
            { kind: form.folded ? 'ORIGINAL_COVER' : 'ORIGINAL_EXACT', span: at });
          if (form.bytes) assert.equal(new TextEncoder().encode(text).length > text.length, true);
          fingerprintFacts(candidate, key.keyed);
          const composed = compose(result, ref);
          assert.equal(composed.status, 'COMPLETE');
          assert.equal(composed.uninspected.length, 0);
          assert.equal(composed.units.some((unit) => unit.sources.includes('SECRET') &&
            unit.classification.sensitivity === 'SECRET' && unit.classification.reversible === false), true);
          privateFacts(result, [control.content, 'host.example.invalid']);
          privateFacts(composed, [control.content, 'host.example.invalid']);
        }
      });

      for (const ending of ['closed', 'eof']) {
        test(`#8 quote-specific opaque composition: ${label}/${ending}`, () => {
          for (const length of [QWIN, QWIN + 1]) {
            const text = `${prefixFor(caller, form)}"${filler(length)}synthetic-uninspected-tail.invalid${ending === 'closed' ? '"' : ''}`;
            const ref = `partial-${caller.name}-${key.name}-${form.name}-${ending}-${length}.invalid`;
            const result = detect(asInput(text, form), ref, key.options);
            partialFacts(result, text, form);
            composedPartialFacts(result, ref);
          }
        });
      }
    }
  }

  test(`#8 legitimate FULL parsed credential field survives failed root scan: ${key.name}`, () => {
    const content = `${filler(QWIN + 1)}synthetic-uninspected-tail.invalid`;
    const prefix = 'password="';
    const text = `${prefix}${content}"\nhost=host.example.invalid`;
    const ref = `full-field-${key.name}.invalid`;
    const result = detect(text, ref, key.options);
    partialFacts(result, text, inputs[0]);
    const fields = result.candidates.filter((item) => item.source === 'SECRET' && item.field);
    assert.equal(fields.length, 1);
    const field = fields[0];
    assert.equal(field.rule, 'context.field-key');
    assert.equal(field.basis, 'FIELD_KEY');
    assert.equal(field.field.format, 'DOTENV');
    assert.equal(field.field.verbatim, true);
    assert.equal(field.field.hintSource, 'PATH');
    assert.deepEqual(field.field.valueSpan, { start: 0, end: content.length });
    assert.deepEqual(field.view.span, { start: prefix.length, end: prefix.length + content.length });
    assert.deepEqual(field.original, { kind: 'ORIGINAL_EXACT', span: field.view.span });
    fingerprintFacts(field, key.keyed);
    composedPartialFacts(result, ref);
    const composed = compose(result, ref);
    assert.equal(composed.units.some((unit) => unit.sources.includes('SECRET') && unit.location.field &&
      unit.classification.status === 'RESOLVED' && unit.classification.sensitivity === 'SECRET' &&
      unit.classification.reversible === false && unit.location.span.end - unit.location.span.start === content.length), true);
    privateFacts(result, [content]);
    privateFacts(composed, [content]);
  });
}
