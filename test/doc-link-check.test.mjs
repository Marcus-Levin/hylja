import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const checker = resolve(root, 'scripts', 'check-doc-links.mjs');
const planted = 'synthetic-planted-example.invalid';

/**
 * Loaded into every checked run through NODE_OPTIONS so that a socket, DNS or fetch attempt throws
 * instead of leaving the machine. A documentation link check must stay offline even when a document
 * names a remote target; this makes an accidental fetch a visible failure rather than a silent pass.
 */
const denyNetwork = `
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
const deny = () => { throw new Error('synthetic network denial'); };
net.Socket.prototype.connect = deny;
net.connect = deny;
net.createConnection = deny;
dns.lookup = deny;
dns.resolve = deny;
dns.resolve4 = deny;
dns.resolve6 = deny;
dns.promises.lookup = deny;
dns.promises.resolve = deny;
dns.promises.resolve4 = deny;
dns.promises.resolve6 = deny;
http.request = deny;
http.get = deny;
https.request = deny;
https.get = deny;
globalThis.fetch = deny;
`;

function git(cwd, ...args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, 'test Git operation should succeed');
}

/** Every fixture lives inside one disposable directory: `repo/` is the checkout, its sibling is outside its root. */
function withRepository(run) {
  const base = mkdtempSync(join(tmpdir(), 'hylja-doc-links-'));
  const repo = join(base, 'repo');
  try {
    mkdirSync(repo);
    git(repo, 'init', '-q');
    cpSync(join(root, '.gitignore'), join(repo, '.gitignore'));
    writeFileSync(join(base, 'deny-network.mjs'), denyNetwork);
    run({ base, repo });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

function write(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function stage(repo, ...paths) {
  git(repo, 'add', '-f', '--', ...paths);
}

function check({ base, repo }, options = {}) {
  const preload = pathToFileURL(join(base, 'deny-network.mjs')).href;
  const result = spawnSync(process.execPath, [checker, ...(options.args ?? [])], {
    cwd: options.cwd ?? repo,
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: `--import ${preload}`, ...options.env },
  });
  assert.equal(result.error, undefined, 'the documentation link check should launch');
  const output = `${result.stdout}\n${result.stderr}`;
  assert.ok(!output.includes(planted), 'diagnostics must never echo planted document content or a link target');
  return { status: result.status, output, stdout: result.stdout };
}

const note = ['# Note', '', '## A section', '', 'Body text.', '', '## Details', '', 'First.', '', '## Details', '', 'Second.', ''].join('\n');

test('valid relative links, anchors and tracked image targets pass', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), note);
    write(join(repo, 'README.md'), [
      '# Root', '',
      '[Note](docs/note.md)', '',
      '[Section](docs/note.md#a-section)', '',
      '[Duplicate](docs/note.md#details-1)', '',
      '[Self](README.md#root)', '',
      '![Concept](docs/assets/concept.png)', '',
      '[Directory](docs)', '',
    ].join('\n'));
    write(join(repo, 'docs', 'assets', 'concept.png'), Buffer.from([137, 80, 78, 71]));
    stage(repo, 'README.md', 'docs/note.md', 'docs/assets/concept.png');
    const result = check({ base, repo }, { cwd: repo });
    assert.equal(result.status, 0, result.output);
    assert.match(result.output, /doc link check: ok/);
  });
});

test('a missing relative target fails with a fixed reason, line and repeated output', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'README.md'), ['# Root', '', '[gone](docs/missing.md)', ''].join('\n'));
    stage(repo, 'README.md');
    const first = check({ base, repo });
    const second = check({ base, repo });
    assert.notEqual(first.status, 0);
    assert.equal(first.status, second.status, 'the exit status must be deterministic');
    assert.equal(first.output, second.output, 'the diagnostic text must be deterministic');
    assert.match(first.output, /README\.md:3: relative-target-missing/);
    assert.doesNotMatch(first.output, /missing\.md/);
  });
});

test('a missing heading anchor in a Markdown target fails', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), note);
    write(join(repo, 'README.md'), ['# Root', '', '[bad](docs/note.md#no-such-heading)', ''].join('\n'));
    stage(repo, 'README.md', 'docs/note.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /README\.md:3: heading-anchor-missing/);
  });
});

test('a bare fragment resolves against the containing document', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'README.md'), ['# Root', '', '[self](#root)', '', '[bad](#root-2)', ''].join('\n'));
    stage(repo, 'README.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /README\.md:5: heading-anchor-missing/);
  });
});

test('setext headings, link titles and angle-bracketed destinations are supported', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), [
      'Setext one', '==========', '',
      'Setext two', '----------', '',
      '## Use `code` and [text](other.md) here', '',
    ].join('\n'));
    write(join(repo, 'docs', 'other.md'), '# Other\n');
    write(join(repo, 'README.md'), [
      '# Root', '',
      '[one](docs/note.md#setext-one)', '',
      '[two](docs/note.md#setext-two "a title")', '',
      '[coded](docs/note.md#use-code-and-text-here)', '',
    ].join('\n'));
    stage(repo, 'README.md', 'docs/note.md', 'docs/other.md');
    const result = check({ base, repo });
    assert.equal(result.status, 0, result.output);

    write(join(repo, 'README.md'), ['# Root', '', '[one](<docs/note.md> "a title")', ''].join('\n'));
    stage(repo, 'README.md');
    const angled = check({ base, repo });
    assert.equal(angled.status, 0, angled.output);
  });
});

test('duplicate headings resolve through GitHub slug suffixes', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), note);
    write(join(repo, 'README.md'), ['# Root', '', '[third](docs/note.md#details-2)', ''].join('\n'));
    stage(repo, 'README.md', 'docs/note.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /README\.md:3: heading-anchor-missing/);
  });
});

test('fenced examples and inline code spans are not checked', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), note);
    write(join(repo, 'README.md'), [
      '# Root', '',
      '```markdown', '[fenced](docs/missing-fence.md)', '[fenced](#nope)', '```', '',
      '~~~', '[tilde](docs/missing-tilde.md)', '~~~', '',
      '`[span](docs/missing-span.md)`', '',
      '[real](docs/note.md)', '',
    ].join('\n'));
    stage(repo, 'README.md', 'docs/note.md');
    const result = check({ base, repo });
    assert.equal(result.status, 0, result.output);
  });
});

test('remote, mailto and protocol-relative targets are skipped without network access', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'README.md'), [
      '# Root', '',
      '[remote](https://192.0.2.1/definitely-not-served)', '',
      '[mail](mailto:synthetic@example.invalid)', '',
      '[protocol-relative](//example.invalid/path)', '',
      '[fragment on remote](https://example.invalid/x#nope)', '',
    ].join('\n'));
    stage(repo, 'README.md');
    const result = check({ base, repo });
    assert.equal(result.status, 0, result.output);
  });
});

test('line anchors and fragments on non-Markdown targets are skipped', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), note);
    write(join(repo, 'src', 'thing.ts'), 'export const example = 1;\n');
    write(join(repo, 'docs', 'index.md'), [
      '# Index', '',
      '[source lines](../src/thing.ts#L2-L9)', '',
      '[source anchor](../src/thing.ts#some-symbol)', '',
      '[markdown line anchor](note.md#L3)', '',
    ].join('\n'));
    stage(repo, 'docs/index.md', 'docs/note.md', 'src/thing.ts');
    const result = check({ base, repo });
    assert.equal(result.status, 0, result.output);
  });
});

test('percent-encoded paths and fragments resolve and a malformed escape is refused', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'enc oded.md'), '# Encoded\n\n## Café\n\nText.\n');
    write(join(repo, 'docs', 'a#b.md'), '# Hash\n\nText.\n');
    write(join(repo, 'README.md'), [
      '# Root', '',
      '[space](docs/enc%20oded.md#caf%C3%A9)', '',
      '[hash](docs/a%23b.md)', '',
      '[malformed](docs/bad%zz.md)', '',
    ].join('\n'));
    stage(repo, 'README.md', 'docs/enc oded.md', 'docs/a#b.md');
    const broken = check({ base, repo });
    assert.notEqual(broken.status, 0);
    assert.match(broken.output, /README\.md:7: malformed-encoded-target/);
    assert.doesNotMatch(broken.output, /enc%20oded|a%23b|bad%zz/);

    write(join(repo, 'README.md'), [
      '# Root', '',
      '[space](docs/enc%20oded.md#caf%C3%A9)', '',
      '[hash](docs/a%23b.md)', '',
    ].join('\n'));
    stage(repo, 'README.md');
    const fixed = check({ base, repo });
    assert.equal(fixed.status, 0, fixed.output);
  });
});

test('untracked documents are not enumerated and untracked targets are reported', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'README.md'), ['# Root', '', '[draft](docs/untracked.md)', ''].join('\n'));
    write(join(repo, 'docs', 'untracked.md'), ['# Draft', '', '[gone](missing.md)', ''].join('\n'));
    stage(repo, 'README.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /README\.md:3: relative-target-not-tracked/);
    assert.doesNotMatch(result.output, /untracked\.md/);
  });
});

test('a target outside the repository root is refused without reading it', () => {
  withRepository(({ base, repo }) => {
    write(join(base, 'outside.md'), `# Outside\n\napi_key=${planted}\n`);
    write(join(repo, 'docs', 'nested', 'page.md'), ['# Page', '', '[escape](../../../outside.md)', ''].join('\n'));
    stage(repo, 'docs/nested/page.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /docs\/nested\/page\.md:3: relative-target-outside-repository/);
  });
});

test('symlinked documents and symlinked targets are refused', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'docs', 'note.md'), note);
    symlinkSync('note.md', join(repo, 'docs', 'linked.md'));
    write(join(repo, 'README.md'), ['# Root', '', '[linked](docs/linked.md)', ''].join('\n'));
    stage(repo, 'README.md', 'docs/note.md', 'docs/linked.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /README\.md:3: relative-target-not-a-regular-path/);
    assert.match(result.output, /docs\/linked\.md:0: document-not-a-regular-path/);
  });
});

test('a document above the read bound is reported instead of silently truncated', () => {
  withRepository(({ base, repo }) => {
    let big = '';
    while (big.length <= 2 << 20) big += '# Heading\n\n';
    write(join(repo, 'docs', 'big.md'), big);
    write(join(repo, 'README.md'), ['# Root', '', '[big](docs/big.md#a-heading)', ''].join('\n'));
    stage(repo, 'README.md', 'docs/big.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /docs\/big\.md:0: document-above-read-bound/);
    assert.match(result.output, /README\.md:3: relative-target-above-read-bound/);
  });
});

test('the fixture guard refuses the tree before any document is read', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'test', 'fixtures', 'private', 'case.env'), `password=${planted}\n`);
    git(repo, 'check-ignore', '-q', '--', 'test/fixtures/private/case.env');
    git(repo, 'add', '-f', '--', 'test/fixtures/private/case.env');
    write(join(repo, 'README.md'), ['# Root', '', '[gone](docs/missing.md)', ''].join('\n'));
    stage(repo, 'README.md');
    const result = check({ base, repo });
    assert.notEqual(result.status, 0);
    assert.match(result.output, /doc link check: refused/);
    assert.match(result.output, /fixture guard: rejected tracked path/);
    assert.doesNotMatch(result.output, /relative-target-missing/);
  });
});

test('a directory that is not a checkout fails as an unusable root', () => {
  withRepository(() => {
    const base = mkdtempSync(join(tmpdir(), 'hylja-doc-links-nogit-'));
    try {
      const result = spawnSync(process.execPath, [checker], { cwd: base, encoding: 'utf8' });
      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /doc link check: unusable/);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});

test('--help prints the supported syntax and limits without inspecting the tree', () => {
  withRepository(({ base, repo }) => {
    write(join(repo, 'README.md'), ['# Root', '', '[gone](docs/missing.md)', ''].join('\n'));
    stage(repo, 'README.md');
    const result = check({ base, repo }, { args: ['--help'] });
    assert.equal(result.status, 0, result.output);
    assert.match(result.stdout, /doc link check: usage/);
    assert.doesNotMatch(result.stdout, /relative-target-missing/);
  });
});

test('the tracked documentation in this checkout passes the supported checks', () => {
  const result = spawnSync(process.execPath, [checker], { cwd: root, encoding: 'utf8' });
  const output = `${result.stdout}\n${result.stderr}`;
  assert.equal(result.status, 0, output);
  assert.match(result.stdout, /doc link check: ok/);
});