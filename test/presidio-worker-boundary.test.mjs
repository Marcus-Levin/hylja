#!/usr/bin/env node
// Boundary regression for the real Presidio worker's OWN bounded work.
//
// Why this exists: an earlier revision of the worker deleted its result cap so that "two named bounds
// own this", which was true of what the *parent* retains and false of what the child does before its
// first stdout byte. A stubbed engine measured that a 1 MiB adversarial input can produce 400 000
// findings, 83 MiB of child RSS and a ~10 MB reply. This test pins the restored child-side bound: the
// worker's own post-processing stops, and it stops with a NAMED status the adapter turns into
// `WORKER_REPORTED_FAILURE`, never a truncation that could read as a complete answer.
//
// The engine here is a synthetic stdlib-only stub injected on `PYTHONPATH`. No third-party package is
// installed, imported or executed, no model is loaded, no socket is opened, and the analysed text is a
// synthetic non-routable string. The worker's real `main()` runs unmodified.
//
// The worker is invoked directly rather than through `runPresidioWorker` on purpose: the transport
// fixes the child environment and offers no `PYTHONPATH`, and this test is about the child's own
// behaviour, not the parent's. The adapter half of the assertion still uses the real validator.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { PRESIDIO_MAX_RESULTS, preparePresidioAnalysis, completePresidioAnalysis }
  from '../dist/presidio-candidate-source.js';
import { normalizeInput } from '../dist/normalization.js';

const WORKER = new URL('../evaluations/presidio-worker/presidio_worker.py', import.meta.url).pathname;
const MANIFEST = new URL('../evaluations/presidio-worker/manifest.json', import.meta.url).pathname;
const PYTHON = process.env.HYLJA_TEST_PYTHON ?? 'python3';
const skip = spawnSync(PYTHON, ['-c', 'import sys'], { timeout: 20_000 }).status === 0
  ? false : 'no usable python3 interpreter for the worker boundary test';
const SCOPE = Object.freeze({ requestId: 'req-boundary-0001', inputRef: 'n6-boundary-v0-raw',
  tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
  // A synthetic stub has no installed distribution, so the worker's version lookup cannot succeed and
  // it reports the fixed `unknown` token. The pin follows it, which keeps the pin equality check real
  // instead of bypassed, and a version this adapter cannot establish is refused by design.
  expectedProducerVersion: 'unknown', expectedLanguage: 'en', expectedNerAvailable: false });
/**
 * Sampling points around the worker's fixed result bound. The bound itself is *derived* from the
 * observed OK -> FAILURE transition in the last group, so these are inputs to the search rather than
 * a restatement of the answer.
 */
const BOUND_SAMPLES = [1, 64, 1024, 2048, 3072, 4095, 4096, 4097, 8192];

let root;
function stubEngine() {
  // A synthetic `presidio_analyzer` with exactly the surface the worker touches. It is deliberately
  // trivial: the point is the worker's loop and its refusal, not recognizer behaviour.
  if (!root) root = mkdtempSync(join(tmpdir(), 'hylja-presidio-stub-'));
  const pkg = join(root, 'presidio_analyzer');
  mkdirSync(join(pkg, 'nlp_engine'), { recursive: true });
  mkdirSync(join(pkg, 'recognizer_registry'), { recursive: true });
  mkdirSync(join(pkg, 'predefined_recognizers', 'country_specific', 'us'), { recursive: true });
  const write = (relative, body) => writeFileSync(join(pkg, relative), body, 'utf8');
  write('__init__.py', `
class RecognizerResult:
    def __init__(self, entity_type, start, end, score):
        self.entity_type, self.start, self.end, self.score = entity_type, start, end, score
        self.analysis_explanation = None
        self.recognition_metadata = {}
ANALYZER = None


class AnalyzerEngine:
    """Answers a fixed number of synthetic findings read from STUB_FINDINGS."""
    def __init__(self, registry=None, nlp_engine=None, supported_languages=None,
                 default_score_threshold=0, context_aware_enhancer=None, log_decision_process=False,
                 app_tracer=None):
        import os, json
        global ANALYZER
        count = int(os.environ.get("STUB_FINDINGS", "0"))
        self.nlp_engine = nlp_engine
        self.context_aware_enhancer = context_aware_enhancer
        self.default_score_threshold = default_score_threshold
        ANALYZER = count

    def get_supported_entities(self, language=None):
        return []

    def analyze(self, text, language, entities=None, score_threshold=None, return_decision_process=False,
                context=None, allow_list=None, **kwargs):
        out = []
        for index in range(ANALYZER):
            at = (index * 8) % max(1, len(text) - 8)
            out.append(RecognizerResult("EMAIL_ADDRESS", at, at + 8, 0.5))
        return out


class PatternRecognizer:
    pass
`);
  write('nlp_engine/__init__.py', `
class NlpEngine:
    pass


class NoOpNlpEngine(NlpEngine):
    """Returns no artifacts and no supported entities, exactly like the real engine's stub role."""
    def __init__(self, models):
        self.models = models
        self.nlp = None

    def load(self):
        self.nlp = {model["lang_code"]: None for model in self.models}

    def is_loaded(self):
        return self.nlp is not None

    def process_text(self, text, language):
        from .. import NlpArtifactsStub
        return NlpArtifactsStub()

    def get_supported_entities(self):
        return []

    def get_supported_languages(self):
        return list(self.nlp or [])
`);
  write('recognizer_registry/__init__.py', `
class RecognizerRegistry:
    def __init__(self, supported_languages=None, **kwargs):
        self.supported_languages = supported_languages
        self.recognizers = []

    def add_recognizer(self, recognizer):
        self.recognizers.append(recognizer)
`);
  // The worker re-binds `tldextract` to an offline instance before importing Presidio, so the synthetic
  // package must provide one. Stdlib only, and it raises if anything tries to reach the network.
  writeFileSync(join(root, 'tldextract.py'), `
class TLDExtract:
    """Offline stand-in: raises if anything asks for a fetchable suffix list."""

    def __init__(self, suffix_list_urls=(), fallback_to_snapshot=True, cache_dir=None):
        if suffix_list_urls:
            raise AssertionError("stub tldextract must never be configured with fetchable URLs")

    def __call__(self, text):
        raise AssertionError("stub tldextract is only here so the import and rebinding succeed")


TLD_EXTRACTOR = TLDExtract()


def extract(text):
    return TLD_EXTRACTOR(text)
`, 'utf8');
  write('predefined_recognizers/__init__.py', `
from presidio_analyzer import PatternRecognizer


class Recognizer(PatternRecognizer):
    """The worker validates every enabled recognizer against PatternRecognizer, so the stub is one."""

    def __init__(self, supported_language="en"):
        self.supported_language = supported_language
        self.id = type(self).__name__


EmailRecognizer = Recognizer
IpRecognizer = Recognizer
MacAddressRecognizer = Recognizer
PhoneRecognizer = Recognizer
UrlRecognizer = Recognizer
`);
  write('predefined_recognizers/country_specific/__init__.py',
    'from .. import Recognizer  # noqa: F401  re-exported for the country-specific stub\n');
  write('predefined_recognizers/country_specific/us/__init__.py', `
from .. import Recognizer
UsSsnRecognizer = Recognizer
`);
  return root;
}
process.on('exit', () => { if (root) rmSync(root, { recursive: true, force: true }); });

const SYNTHETIC_TEXT = `${'synthetic-boundary '.repeat(40)}demo@example.invalid`;
/** The exact line the transport would write for this text: a real plan, so the digest really binds. */
function planFor(text = SYNTHETIC_TEXT) {
  const prepared = preparePresidioAnalysis(normalizeInput(text),
    { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } }, SCOPE);
  assert.equal(prepared.ok, true);
  return prepared.plan;
}

function runWorker(findings, line) {
  const stub = stubEngine();
  const result = spawnSync(PYTHON, [WORKER, MANIFEST], {
    input: line,
    env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PYTHONHASHSEED: '0',
      PYTHONDONTWRITEBYTECODE: '1', PYTHONNOUSERSITE: '1', PYTHONUNBUFFERED: '1',
      PYTHONPATH: stub, STUB_FINDINGS: String(findings),
    },
    encoding: 'utf8', timeout: 120_000, maxBuffer: 64 * 1024 * 1024,
  });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/**
 * The bound is *derived* by observing where the worker stops answering `OK`, then both sides of that
 * transition are asserted. Reading the worker's source for a constant would prove two numbers match,
 * not that the bound works.
 */
test('the worker answers with every finding up to a bound, then refuses by name with none', { skip }, () => {
  const plan = planFor();
  const probe = (findings) => {
    const run = runWorker(findings, plan.line);
    assert.equal(run.status, 0, `worker exited ${run.status} at ${findings} findings`);
    const reply = JSON.parse(run.stdout);
    return { findings, reply, bytes: run.stdout.length };
  };
  const transitions = BOUND_SAMPLES.map(probe);
  const answering = transitions.filter((row) => row.reply.status === 'OK');
  const refusing = transitions.filter((row) => row.reply.status === 'FAILURE');
  assert.ok(answering.length >= 1 && refusing.length >= 1, JSON.stringify(transitions.map((r) => r.reply.status)));
  // Contiguous and monotone: it never refuses and then answers again.
  assert.deepEqual(transitions.map((row) => row.reply.status),
    [...transitions.map((row) => row.reply.status)].sort((a, b) => (a === 'OK' ? 0 : 1) - (b === 'OK' ? 0 : 1)));
  // Every answered finding is reported; none is silently dropped.
  for (const row of answering) {
    assert.equal(row.reply.results.length, row.findings, `dropped findings at ${row.findings}`);
    // Above the adapter's own array bound (256) the tighter parent bound names the overflow; below it
    // the findings are inside the contract and the run is simply the no-NER `PARTIAL` it should be.
    const reasons = completePresidioAnalysis(plan, JSON.stringify(row.reply) + '\n').reasons;
    if (row.findings > PRESIDIO_MAX_RESULTS) assert.deepEqual(reasons, ['REPLY_RESULT_LIMIT']);
    else assert.deepEqual(reasons, ['NO_NER_CAPABILITY']);
  }
  // A refusal is a named failure with no partial list and a small frame, so a reader can tell
  // "the worker stopped working" from "the worker found nothing".
  const last = answering.at(-1);
  const first = refusing[0];
  assert.ok(first.findings > last.findings, 'the transition is between two sampled counts');
  assert.equal(last.reply.results.length, last.findings);
  assert.deepEqual(first.reply.results, []);
  assert.ok(first.bytes < 4096, `refusal frame is ${first.bytes} bytes, expected a small frame`);
  assert.equal(first.reply.requestId, SCOPE.requestId, 'the binding is echoed so the adapter can name it');
  const named = completePresidioAnalysis(plan, JSON.stringify(first.reply) + '\n');
  assert.deepEqual(named.reasons, ['NO_NER_CAPABILITY', 'WORKER_REPORTED_FAILURE']);
  assert.deepEqual(named.candidates, []);
});

test('a manifest that is valid JSON but not an object still answers a frame', { skip }, () => {
  const stub = stubEngine();
  const request = planFor().line;
  for (const manifest of ['[]', '"a string"', '3', 'null', 'true',
    '{"protocol":"hylja.presidio.worker","version":1,"configuration":[]}',
    '{"protocol":"hylja.presidio.worker","version":1,"configuration":{"filtering":7}}']) {
    const path = join(root, `bad-${Buffer.from(manifest).toString('hex').slice(0, 40)}.json`);
    writeFileSync(path, manifest, 'utf8');
    const result = spawnSync(PYTHON, [WORKER, path], {
      input: request, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', PYTHONHASHSEED: '0',
        PYTHONNOUSERSITE: '1', PYTHONUNBUFFERED: '1', PYTHONPATH: stub, STUB_FINDINGS: '0' },
      encoding: 'utf8', timeout: 60_000,
    });
    assert.equal(result.status, 0, `${manifest} exited ${result.status}`);
    const reply = JSON.parse(result.stdout);
    assert.equal(reply.status, 'FAILURE', manifest);
    assert.deepEqual(reply.results, [], manifest);
    assert.equal(reply.requestId, SCOPE.requestId, 'the binding is echoed so the refusal is nameable');
    rmSync(path, { force: true });
  }
});

test('a request line with trailing bytes after a complete JSON value is refused', { skip }, () => {
  const stub = stubEngine();
  const one = planFor().line.trimEnd();
  for (const line of [`${one}${one}\n`, `${one} trailing\n`, `${one} {}\n`]) {
    const result = spawnSync(PYTHON, [WORKER, MANIFEST], {
      input: line, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', PYTHONHASHSEED: '0',
        PYTHONNOUSERSITE: '1', PYTHONUNBUFFERED: '1', PYTHONPATH: stub, STUB_FINDINGS: '0' },
      encoding: 'utf8', timeout: 60_000,
    });
    assert.equal(result.status, 0);
    const reply = JSON.parse(result.stdout);
    assert.equal(reply.status, 'FAILURE', `accepted a smuggled frame: ${line.slice(0, 40)}`);
    assert.deepEqual(reply.results, []);
  }
});

test('the pinned manifest identity this test binds against is intact', () => {
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
  assert.equal(manifest.protocol, 'hylja.presidio.worker');
  assert.equal(manifest.version, 1);
  assert.equal(manifest.configuration.nlpEngine.nerAvailable, false);
  assert.equal(manifest.artifacts.some((item) => item.name === 'presidio_analyzer'), true);
});
