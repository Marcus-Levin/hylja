import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { DEFAULT_SUBTYPES, SEMANTIC_CLASSES } from '../dist/classification.js';
import {
  TAXONOMY_DRAFT, DRAFT_SEMANTIC_TYPES, DRAFT_DOMAINS, FORMS, EVIDENCE_KINDS, PERSONAL_DATA_PRIORS,
  taxonomyEntryDraft, draftEntriesForV1,
} from '../dist/taxonomy-draft.js';

const byType = (type) => TAXONOMY_DRAFT.filter((entry) => entry.semanticType === type);

test('entries are well-formed, frozen and globally unique by subtype', () => {
  const seen = new Set();
  for (const entry of TAXONOMY_DRAFT) {
    assert.ok(Object.isFrozen(entry) && Object.isFrozen(entry.evidence));
    assert.match(entry.subtype, /^[A-Z][A-Z0-9_]{0,63}$/);
    assert.ok(DRAFT_SEMANTIC_TYPES.includes(entry.semanticType));
    assert.ok(DRAFT_DOMAINS.includes(entry.domain));
    assert.ok(FORMS.includes(entry.form));
    assert.ok(PERSONAL_DATA_PRIORS.includes(entry.personalDataPrior));
    assert.ok(entry.evidence.length > 0 && entry.evidence.every((kind) => EVIDENCE_KINDS.includes(kind)));
    assert.equal(new Set(entry.evidence).size, entry.evidence.length);
    assert.ok(!seen.has(entry.subtype), entry.subtype);
    seen.add(entry.subtype);
  }
  for (const type of DRAFT_SEMANTIC_TYPES) assert.ok(byType(type).length > 0, type);
});

test('taxonomy describes what information is: no sensitivity, treatment or trust field', () => {
  for (const entry of TAXONOMY_DRAFT) {
    for (const forbidden of ['sensitivity', 'treatment', 'trust', 'decision', 'reversible']) {
      assert.ok(!(forbidden in entry), `${entry.subtype}.${forbidden}`);
    }
  }
});

test('identifiers, content and credentials live under the matching semantic types', () => {
  for (const entry of TAXONOMY_DRAFT) {
    if (entry.semanticType === 'CREDENTIAL_OR_SECRET') assert.equal(entry.form, 'CREDENTIAL', entry.subtype);
    else assert.notEqual(entry.form, 'CREDENTIAL', entry.subtype);
    if (entry.semanticType.endsWith('_IDENTIFIER')) assert.equal(entry.form, 'IDENTIFIER', entry.subtype);
    if (['ENGINEERING_INFORMATION', 'PERSONAL_ATTRIBUTE', 'BUSINESS_CONFIDENTIAL'].includes(entry.semanticType)) {
      assert.equal(entry.form, 'CONTENT', entry.subtype);
    }
  }
});

test('#65 engineering domains each have both identifier and content coverage where they apply', () => {
  const required = ['PLM', 'CAD', 'CAE', 'CAM', 'PROCESS_PLANT', 'ASSET', 'OT', 'QUALITY', 'IM', 'IT'];
  for (const domain of required) {
    assert.ok(TAXONOMY_DRAFT.some((e) => e.domain === domain && e.semanticType === 'ENGINEERING_INFORMATION'), domain);
  }
  for (const domain of ['PLM', 'PROCESS_PLANT', 'ASSET', 'OT', 'QUALITY', 'IM']) {
    assert.ok(TAXONOMY_DRAFT.some((e) => e.domain === domain && e.semanticType === 'ENGINEERING_IDENTIFIER'), domain);
  }
});

test('PERSON is not all personal data: contact and national IDs are personal identifiers', () => {
  assert.deepEqual(byType('PERSON').map((e) => e.subtype), ['PERSON_NAME', 'PERSON_ALIAS']);
  for (const subtype of ['EMAIL_ADDRESS', 'PHONE_NUMBER', 'SE_PERSONNUMMER', 'SE_SAMORDNINGSNUMMER']) {
    assert.equal(taxonomyEntryDraft(subtype).semanticType, 'PERSONAL_IDENTIFIER', subtype);
  }
  // Personal data status can attach to non-person types without renaming them.
  const ip = taxonomyEntryDraft('IP');
  assert.equal(ip.semanticType, 'NETWORK_IDENTIFIER');
  assert.equal(ip.personalDataPrior, 'CONTEXTUAL');
  assert.equal(taxonomyEntryDraft('PORT').personalDataPrior, 'NOT_BY_ITSELF');
});

test('Swedish national identifiers are distinct, SE-scoped and not modelled as special-category', () => {
  for (const subtype of ['SE_PERSONNUMMER', 'SE_SAMORDNINGSNUMMER']) {
    const entry = taxonomyEntryDraft(subtype);
    assert.equal(entry.domain, 'NATIONAL_ID');
    assert.deepEqual(entry.jurisdictions, ['SE']);
    assert.equal(entry.personalDataPrior, 'ALWAYS');
    assert.ok(entry.evidence.includes('FORMAT'));
    assert.deepEqual({ ...entry.v1 }, { semanticType: 'PERSON' });
  }
  assert.ok(TAXONOMY_DRAFT.filter((e) => e.jurisdictions).every((e) => e.jurisdictions.every((c) => c === 'SE')));
  // A sole trader's organisationsnummer is a personnummer: never NOT_BY_ITSELF.
  assert.equal(taxonomyEntryDraft('SE_ORGANISATIONSNUMMER').personalDataPrior, 'CONTEXTUAL');
});

test('every v1 default subtype maps to exactly one draft entry and every v1 class has a home', () => {
  for (const type of SEMANTIC_CLASSES) {
    assert.ok(draftEntriesForV1(type).length > 0, type);
    for (const subtype of DEFAULT_SUBTYPES[type]) {
      assert.equal(draftEntriesForV1(type, subtype).length, 1, `${type}/${subtype}`);
    }
  }
  assert.deepEqual(draftEntriesForV1('PERSON', 'EMAIL').map((e) => e.subtype), ['EMAIL_ADDRESS']);
  // Replay of tenant-extended v1 subtypes and class-only homes.
  assert.deepEqual(draftEntriesForV1('ENGINEERING_IDENTIFIER', 'EQUIPMENT_TAG').map((e) => e.subtype), ['EQUIPMENT_TAG']);
  assert.deepEqual(draftEntriesForV1('USER_ACCOUNT', 'USERNAME').map((e) => e.subtype), ['USERNAME']);
  assert.ok(draftEntriesForV1('ENGINEERING_IDENTIFIER').every((e) => e.semanticType === 'ENGINEERING_IDENTIFIER'));
  assert.equal(draftEntriesForV1('ENGINEERING_IDENTIFIER').length, byType('ENGINEERING_IDENTIFIER').length);
  // Only content without any v1 class stays unmapped.
  for (const entry of TAXONOMY_DRAFT.filter((e) => e.v1 === null)) assert.equal(entry.semanticType, 'ENGINEERING_INFORMATION');
  for (const entry of TAXONOMY_DRAFT) {
    if (!entry.v1) continue;
    assert.ok(SEMANTIC_CLASSES.includes(entry.v1.semanticType));
    if (entry.v1.subtype !== undefined) assert.ok(DEFAULT_SUBTYPES[entry.v1.semanticType].includes(entry.v1.subtype));
  }
});

test('lookups reject unknown or non-string input', () => {
  assert.equal(taxonomyEntryDraft('NOT_A_SUBTYPE'), undefined);
  assert.equal(taxonomyEntryDraft({ toString: () => 'IP' }), undefined);
  assert.deepEqual(draftEntriesForV1('ENGINEERING_INFORMATION'), []);
  assert.deepEqual(draftEntriesForV1('__proto__'), []);
  assert.deepEqual(draftEntriesForV1('PERSON', 7), []);
  assert.deepEqual(draftEntriesForV1('PERSON', 'NOT_A_SUBTYPE'), []);
});

test('FORMAT is not claimed for subtypes whose syntax is shared with unrelated values', () => {
  for (const subtype of ['TENANT_ID', 'SUBSCRIPTION_ID', 'ACCOUNT_ID', 'BUCKET', 'HOSTNAME', 'PORT', 'PART_NUMBER']) {
    assert.ok(!taxonomyEntryDraft(subtype).evidence.includes('FORMAT'), subtype);
  }
  for (const entry of byType('ENGINEERING_IDENTIFIER')) assert.ok(entry.evidence.includes('TENANT_DICTIONARY'), entry.subtype);
});

test('research record documents every draft subtype and contains no national-ID-shaped digits', () => {
  const doc = readFileSync(new URL('../docs/research/issue-65-taxonomy-draft-p0.1.md', import.meta.url), 'utf8');
  for (const entry of TAXONOMY_DRAFT) assert.ok(doc.includes(`\`${entry.subtype}\``), entry.subtype);
  for (const type of DRAFT_SEMANTIC_TYPES) assert.ok(doc.includes(`\`${type}\``), type);
  const texts = ['../src/taxonomy-draft.ts', './taxonomy-draft.test.mjs']
    .map((path) => readFileSync(new URL(path, import.meta.url), 'utf8'));
  for (const text of [doc, ...texts]) assert.doesNotMatch(text, /\b\d{6,8}[-+ ]?\d{4}\b/);
});
