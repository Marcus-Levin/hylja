// #137 bounded developer handoff helper.
//
// Every case here is synthetic: the planted values are obviously non-routable `.invalid` names, the
// "GitHub" payloads are hand-written fixtures in this file, and the session inventory is metadata
// with no log behind it. No case reaches the network, reads a real session log, an account file or an
// authentication database, or exports anything to the repository. The one real command the helper
// may spawn is `git`, always with an argv array, a bounded timeout and no shell.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const toolPath = resolve(root, 'scripts', 'development', 'agent-handoff.mjs');
// A dynamic import keeps every case independently red while the helper does not exist yet, instead of
// failing the whole file at load time and proving nothing about any single invariant.
const loadTool = () => import('../scripts/development/agent-handoff.mjs');

const PLANTED = 'synthetic-planted-handoff-7c1d.invalid';
const BODY = `body ${PLANTED} `.repeat(4000);
const MAX_BUFFER = 8 << 20;
// The smallest configurable output cap. It is below the mandatory envelope on purpose: the refusal is
// the result, because a projection that cannot say what it dropped is worse than no projection.
const MIN_OUTPUT_CAP = 256;

/** One disposable directory per case; nothing it creates is ever inside this repository. */
function withTemporaryDirectory(run) {
  const base = mkdtempSync(join(tmpdir(), 'hylja-agent-handoff-'));
  try {
    run(base);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

function git(cwd, ...args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, `test Git operation should succeed: git ${args.join(' ')}`);
  return result.stdout;
}

function writeFile(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
  return path;
}

function run(args, options = {}) {
  const env = options.env === undefined ? { ...process.env } : { ...process.env, ...options.env };
  // An explicit unset: passing `undefined` through spawnSync would stringify it into the child environment.
  for (const name of options.unsetEnvironment ?? []) delete env[name];
  const result = spawnSync(process.execPath, [toolPath, ...args], {
    cwd: options.cwd ?? root,
    input: options.input,
    env: options.env === undefined && options.unsetEnvironment === undefined ? process.env : env,
    timeout: 60_000,
    maxBuffer: MAX_BUFFER,
  });
  const stdout = result.stdout ?? Buffer.alloc(0);
  const stderr = result.stderr ?? Buffer.alloc(0);
  const output = `${stdout.toString('utf8')}\n${stderr.toString('utf8')}`;
  assert.ok(!output.includes(PLANTED), `the helper must never echo planted input values:\n${output}`);
  const parsed = () => JSON.parse(stdout.toString('utf8'));
  return { status: result.status, bytes: stdout.length, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8'), output, json: parsed };
}

function emptyDirectory(base, name) {
  return mkdirSync(join(base, name), { recursive: true }) && join(base, name);
}

/** An executable stub that records its own invocation, so "never executed" is observable rather than asserted. */
function sentinelCommand(directory, name, body) {
  const path = join(directory, name);
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
}

/** Every reported category must account for exactly the input key occurrences it claims. */
function assertSummarised(omitted) {
  const categories = ['projectedKeys', 'derivedKeys', 'groupedKeys', 'rejectedKeys', 'withheldKeys', 'contentKeys', 'credentialKeys', 'otherKeys'];
  const summed = categories.reduce((sum, name) => sum + (omitted[name] ?? 0), 0);
  assert.equal(summed, omitted.inputKeys, `accounting categories must sum to inputKeys: ${JSON.stringify(omitted)}`);
  assert.equal(omitted.valuesReadFromOmittedKeys, false, 'a value behind a class-counted key is never read');
}

function syntheticIssue(overrides = {}, body = BODY) {
  return {
    id: 1000,
    number: 137,
    state: 'open',
    state_reason: null,
    locked: false,
    draft: false,
    title: `synthetic title ${PLANTED}`,
    body,
    user: { login: PLANTED, id: 5 },
    comments: 42,
    labels: [{ name: 'agentic' }, { name: 'developer-tooling' }],
    created_at: '2026-10-01T10:00:00Z',
    updated_at: '2026-10-02T11:00:00Z',
    closed_at: null,
    author_association: 'OWNER',
    api_token: PLANTED,
    ...overrides,
  };
}

function syntheticInventory() {
  return {
    sessions: [
      {
        id: 'chat-0001',
        kind: 'user-chat',
        label: 'hylja planning chat',
        access: 'accessible',
        primaryLog: 'synthetic-log://chat-0001',
        startedAt: '2026-10-03T09:00:00Z',
      },
      {
        id: 'worker-0001',
        kind: 'worker',
        forkedFrom: 'chat-0001',
        access: 'accessible',
        primaryLog: 'synthetic-log://worker-0001',
      },
      {
        id: 'worker-0002',
        kind: 'worker',
        resumedFrom: 'worker-not-in-inventory',
        access: 'inaccessible',
        primaryLog: 'synthetic-log://worker-0002',
      },
      {
        id: 'worker-0003',
        kind: 'unlisted-kind',
        access: 'unknown',
        transcript: PLANTED,
        reasoning: PLANTED,
        auth_token: PLANTED,
        messages: [{ role: 'user', content: PLANTED }],
      },
    ],
  };
}

test('capabilities reports availability from PATH alone and executes none of the listed commands', () => {
  withTemporaryDirectory((base) => {
    const bin = emptyDirectory(base, 'bin');
    const sentinel = join(base, 'gh-was-invoked');
    sentinelCommand(bin, 'gh', `echo invoked > '${sentinel}'`);
    const result = run(['capabilities'], { env: { PATH: bin } });

    assert.equal(result.status, 0, result.output);
    const payload = result.json();
    assert.equal(payload.commands.gh.available, true);
    assert.equal(payload.commands.gh.path, join(bin, 'gh'));
    // git is not on this PATH, so it is reported unavailable and never spawned.
    assert.equal(payload.commands.git.available, false);
    assert.equal(payload.commands.git.path, null);
    assert.equal(payload.runtime.gitWorkTree, false);
    assert.ok(!existsSync(sentinel), 'an available command must still not be executed by a capability report');
  });
});

test('capabilities on an empty PATH reports every probed command unavailable without spawning', () => {
  withTemporaryDirectory((base) => {
    const empty = emptyDirectory(base, 'nothing');
    const result = run(['capabilities'], { env: { PATH: empty } });
    assert.equal(result.status, 0, result.output);
    const payload = result.json();
    for (const [name, entry] of Object.entries(payload.commands)) {
      assert.equal(entry.available, false, `${name} must be reported unavailable`);
      assert.equal(entry.path, null);
    }
  });
});

test('capabilities reports environment presence without reading any environment value', () => {
  const result = run(['capabilities'], { env: { GITHUB_TOKEN: PLANTED, GH_TOKEN: PLANTED } });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.environment.GITHUB_TOKEN.present, true);
  assert.equal(payload.environment.GITHUB_TOKEN.value, null);
  assert.ok(!result.output.includes(PLANTED));
});

test('capabilities output stays inside the configured output cap', async () => {
  const { LIMITS } = await loadTool();
  const cap = LIMITS.outputBytes.min;
  const result = run(['capabilities', '--max-output-bytes', String(cap)]);
  assert.equal(result.status, 0, result.output);
  assert.ok(result.bytes <= cap, `stdout must never exceed the configured cap (${result.bytes} > ${cap})`);
  assert.equal(JSON.parse(result.stdout).command, 'capabilities');
});

test('project-github projects whitelisted metadata and omits bodies, titles, patches and author names', () => {
  const result = run(['project-github', '--input', '-', '--max-output-bytes', '2048'], { input: JSON.stringify(syntheticIssue()) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.kind, 'issue');
  const [item] = payload.items;
  assert.equal(item.number, 137);
  assert.equal(item.state, 'open');
  assert.equal(item.commentCount, 42);
  assert.deepEqual(item.labelNames, ['agentic', 'developer-tooling']);
  assert.equal(item.createdAt, '2026-10-01T10:00:00Z');
  for (const omittedKey of ['body', 'title', 'user', 'api_token']) {
    assert.ok(!(omittedKey in item), `${omittedKey} must never be projected`);
  }
  assert.ok(!('body' in payload.raw) && !('title' in payload.raw));
  assert.ok(payload.omitted.contentKeys >= 2, 'the omitted metadata must count the content-class keys');
  assert.ok(payload.omitted.credentialKeys >= 1, 'the omitted metadata must count the credential-class keys');
  assert.equal(payload.omitted.valuesReadFromOmittedKeys, false);
  assert.equal(payload.raw.printed, false);
});

test('project-github enforces the output cap on the first read of a large response', () => {
  const short = 'synthetic body text';
  const response = { total_count: 200, incomplete_results: false, items: Array.from({ length: 200 }, (_, index) => syntheticIssue({ id: 2000 + index, number: index }, short)) };
  const cap = 1024;
  const result = run(['project-github', '--input', '-', '--max-output-bytes', String(cap)], { input: JSON.stringify(response) });
  assert.equal(result.status, 0, result.output);
  assert.ok(result.bytes <= cap, `stdout must never exceed the configured cap (${result.bytes} > ${cap})`);
  const payload = result.json();
  assert.equal(payload.kind, 'list');
  assert.equal(payload.output.truncated, true);
  assert.equal(payload.output.recordsRead, 200);
  assert.ok(payload.output.recordsOmitted > 0);
  assert.ok(payload.items.length < 200);
  assert.ok(!result.output.includes('body '), 'no response body text may reach the output');
});

test('project-github keeps the whole projection inside the cap even when every record is dropped', () => {
  const response = Array.from({ length: 50 }, (_, index) => syntheticIssue({ id: 3000 + index, number: index }, 'synthetic body text'));
  const cap = 1024;
  const result = run(['project-github', '--input', '-', '--max-output-bytes', String(cap)], { input: JSON.stringify(response) });
  assert.equal(result.status, 0, result.output);
  assert.ok(result.bytes <= cap, `stdout must never exceed the configured cap (${result.bytes} > ${cap})`);
  const payload = result.json();
  assert.equal(payload.output.recordsRead, 50);
  assert.ok(payload.output.recordsOmitted > 0, 'a cap smaller than the records must drop them explicitly');
  assert.equal(payload.items.length + payload.output.recordsOmitted, 50);
  assert.equal(payload.output.truncated, true);
});

test('project-github refuses a cap too small for the mandatory envelope instead of returning an unlabelled result', () => {
  const result = run(['project-github', '--input', '-', '--max-output-bytes', String(MIN_OUTPUT_CAP)], { input: JSON.stringify(syntheticIssue()) });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /agent handoff: refused; output-cap-unrepresentable/);
  assert.equal(result.stdout, '');
});

test('project-github refuses an input above the raw bound without echoing it', () => {
  const result = run(['project-github', '--input', '-', '--max-raw-bytes', '1024'], { input: JSON.stringify(syntheticIssue()) });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /agent handoff: refused; input-above-raw-bound/);
  assert.equal(result.stdout, '');
});

test('project-github refuses malformed and symlinked input with fixed codes', () => {
  withTemporaryDirectory((base) => {
    const malformed = writeFile(join(base, 'malformed.json'), '{"items": [');
    const bad = run(['project-github', '--input', malformed]);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /agent handoff: refused; input-malformed/);

    const secretFile = writeFile(join(base, 'real.json'), JSON.stringify(syntheticIssue()));
    const link = join(base, 'linked.json');
    symlinkSync(secretFile, link);
    const linked = run(['project-github', '--input', link]);
    assert.equal(linked.status, 1);
    assert.match(linked.stderr, /agent handoff: refused; input-not-a-regular-path/);
  });
});

test('project-github projects a comment record without its body, diff or path', () => {
  const comment = {
    id: 77, body: PLANTED, path: PLANTED, diff_hunk: PLANTED, line: 12, user: { login: PLANTED },
    author_association: 'MEMBER', subject_type: 'issue', created_at: '2026-10-03T09:30:00Z', updated_at: '2026-10-03T09:31:00Z',
  };
  const result = run(['project-github', '--input', '-', '--kind', 'comment', '--max-output-bytes', '2048'], { input: JSON.stringify(comment) });
  assert.equal(result.status, 0, result.output);
  const [item] = result.json().items;
  assert.equal(item.id, 77);
  assert.equal(item.authorAssociation, 'MEMBER');
  assert.equal(item.subjectType, 'issue');
  assert.equal(item.createdAt, '2026-10-03T09:30:00Z');
  for (const omittedKey of ['body', 'path', 'diff_hunk', 'user', 'line']) {
    assert.ok(!(omittedKey in item), `${omittedKey} must never be projected`);
  }
});

test('project-github captures the raw response outside the work tree and refuses an overwrite', () => {
  withTemporaryDirectory((base) => {
    const repo = join(base, 'repo');
    mkdirSync(repo);
    git(repo, 'init', '-q');
    const store = mkdirSync(join(base, 'store'), { recursive: true }) && join(base, 'store');
    const raw = JSON.stringify(syntheticIssue());
    const input = writeFile(join(base, 'response.json'), raw);

    const inside = run(['project-github', '--input', input, '--capture', join(repo, 'artifacts')]);
    assert.equal(inside.status, 1);
    assert.match(inside.stderr, /agent handoff: refused; capture-directory-unusable|capture-inside-work-tree/);

    mkdirSync(join(repo, 'artifacts'));
    const refused = run(['project-github', '--input', input, '--capture', join(repo, 'artifacts')]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /agent handoff: refused; capture-inside-work-tree/);
    assert.deepEqual(readdirSync(join(repo, 'artifacts')), [], 'a refused capture must not leave a repository artifact');

    const captured = run(['project-github', '--input', input, '--capture', store]);
    assert.equal(captured.status, 0, captured.output);
    const payload = captured.json();
    assert.equal(payload.raw.printed, false);
    assert.equal(payload.raw.captured, true);
    assert.ok(payload.raw.capturePath.startsWith(store));
    assert.equal(readFileSync(payload.raw.capturePath, 'utf8'), raw);
    assert.equal(statSync(payload.raw.capturePath).mode & 0o077, 0, 'a captured raw response must not be group or world readable');
    assert.ok(!captured.output.includes(PLANTED), 'capturing must not move the raw body into the output');

    const again = run(['project-github', '--input', input, '--capture', store]);
    assert.equal(again.status, 1);
    assert.match(again.stderr, /agent handoff: refused; capture-exists/);
    assert.equal(readdirSync(store).length, 1, 'a refused overwrite must not add a second capture');
  });
});

test('project-github refuses a shared, symlinked or missing capture directory', () => {
  withTemporaryDirectory((base) => {
    const input = writeFile(join(base, 'response.json'), JSON.stringify(syntheticIssue()));
    const shared = mkdirSync(join(base, 'shared'), { recursive: true }) && join(base, 'shared');
    chmodSync(shared, 0o777);
    const permissive = run(['project-github', '--input', input, '--capture', shared]);
    assert.equal(permissive.status, 1);
    assert.match(permissive.stderr, /agent handoff: refused; capture-directory-unusable/);

    const real = mkdirSync(join(base, 'real'), { recursive: true }) && join(base, 'real');
    const link = join(base, 'linked-store');
    symlinkSync(real, link);
    const linked = run(['project-github', '--input', input, '--capture', link]);
    assert.equal(linked.status, 1);
    assert.match(linked.stderr, /agent handoff: refused; capture-directory-unusable/);

    const missing = run(['project-github', '--input', input, '--capture', join(base, 'absent')]);
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /agent handoff: refused; capture-directory-unusable/);
    assert.deepEqual(readdirSync(real), []);
  });
});

test('session-handoff separates user chats from workers and resolves fork and resume relationships', () => {
  const result = run(['session-handoff', '--input', '-', '--max-output-bytes', '4096'], { input: JSON.stringify(syntheticInventory()) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.deepEqual(payload.totals, { records: 4, userChats: 1, workers: 2, unclassified: 1, inaccessible: 1 });
  assert.deepEqual(payload.userChats.map((entry) => entry.id), ['chat-0001']);
  assert.equal(payload.userChats[0].primaryLogLocator, 'synthetic-log://chat-0001');
  assert.deepEqual(payload.workers.map((entry) => entry.id), ['worker-0001', 'worker-0002']);

  const forked = payload.workers.find((entry) => entry.id === 'worker-0001');
  assert.deepEqual(forked.relationships, [{ kind: 'fork', from: 'chat-0001', resolved: true }]);
  const resumed = payload.workers.find((entry) => entry.id === 'worker-0002');
  assert.deepEqual(resumed.relationships, [{ kind: 'resume', from: 'worker-not-in-inventory', resolved: false }]);
  assert.deepEqual(payload.inaccessible, ['worker-0002']);
  assert.deepEqual(payload.unclassified.map((entry) => entry.id), ['worker-0003']);
  assert.equal(payload.output.truncated, false);
  assert.equal(payload.omitted.valuesReadFromOmittedKeys, false);
});

test('session-handoff drops transcript, reasoning and credential keys without reading their values', () => {
  const result = run(['session-handoff', '--input', '-'], { input: JSON.stringify(syntheticInventory()) });
  const payload = result.json();
  const unclassified = payload.unclassified[0];
  for (const key of ['transcript', 'reasoning', 'auth_token', 'messages']) {
    assert.ok(!(key in unclassified), `${key} must never be projected`);
  }
  assert.ok(payload.omitted.contentKeys >= 3, 'transcript, reasoning and messages must be counted as content keys');
  assert.ok(payload.omitted.credentialKeys >= 1, 'auth_token must be counted as a credential key');
  assert.ok(!result.output.includes(PLANTED));
});

test('session-handoff accepts a JSONL inventory and duplicate ids keep the first record', () => {
  const lines = [
    JSON.stringify({ id: 'chat-0001', kind: 'user-chat', access: 'accessible' }),
    '',
    JSON.stringify({ id: 'worker-0001', kind: 'worker', forkedFrom: 'chat-0001', access: 'accessible' }),
    JSON.stringify({ id: 'chat-0001', kind: 'worker', label: 'duplicate record' }),
  ].join('\n');
  const result = run(['session-handoff', '--input', '-'], { input: `${lines}\n` });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(result.status, 0, result.output);
  assert.equal(payload.output.sessionsRead, 3, 'the input record count is reported, not the deduplicated one');
  assert.equal(payload.totals.records, 2);
  assert.equal(payload.output.sessionsDuplicate, 1);
  assert.equal(payload.omitted.duplicateIds, 1);
  assert.equal(payload.totals.userChats, 1);
  assert.ok(!result.output.includes('duplicate record'), 'a dropped duplicate must not be projected');
});

test('session-handoff stays inside the configured cap and reports what it dropped', () => {
  const sessions = Array.from({ length: 300 }, (_, index) => ({
    id: `worker-${String(index).padStart(4, '0')}`,
    kind: 'worker',
    label: `synthetic worker ${index}`,
    access: index % 3 === 0 ? 'inaccessible' : 'accessible',
    forkedFrom: 'chat-0001',
    primaryLog: `synthetic-log://worker-${index}`,
  }));
  const cap = 1024;
  const result = run(['session-handoff', '--input', '-', '--max-output-bytes', String(cap)], { input: JSON.stringify({ sessions }) });
  assert.equal(result.status, 0, result.output);
  assert.ok(result.bytes <= cap, `stdout must never exceed the configured cap (${result.bytes} > ${cap})`);
  const payload = result.json();
  assert.equal(payload.output.truncated, true);
  assert.ok(payload.output.sessionsOmitted > 0);
  assert.equal(payload.output.sessionsRead, 300);
  const projected = payload.userChats.length + payload.workers.length + payload.unclassified.length;
  assert.equal(projected + payload.output.sessionsOmitted, 300);
});

test('session-handoff refuses malformed input and a record without a safe identifier', () => {
  const malformed = run(['session-handoff', '--input', '-'], { input: '{"sessions": [' });
  assert.equal(malformed.status, 1);
  assert.match(malformed.stderr, /agent handoff: refused; input-malformed/);

  const noId = run(['session-handoff', '--input', '-'], { input: JSON.stringify({ sessions: [{ kind: 'worker' }] }) });
  assert.equal(noId.status, 1);
  assert.match(noId.stderr, /agent handoff: refused; session-record-invalid \(index 0\)/);

  const unsafeId = run(['session-handoff', '--input', '-'], { input: JSON.stringify({ sessions: [{ id: `${PLANTED}\nsecond line`, kind: 'worker' }] }) });
  assert.equal(unsafeId.status, 1);
  assert.match(unsafeId.stderr, /agent handoff: refused; session-record-invalid \(index 0\)/);
  assert.ok(!unsafeId.output.includes(PLANTED), 'a refused record must not echo its identifier');
});

test('session-handoff refuses an inventory above the record bound', async () => {
  const { LIMITS } = await loadTool();
  const sessions = Array.from({ length: LIMITS.maxSessions + 1 }, (_, index) => ({ id: `worker-${index}`, kind: 'worker' }));
  const result = run(['session-handoff', '--input', '-'], { input: JSON.stringify({ sessions }) });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /agent handoff: refused; records-above-bound/);
});

test('compare proves identity through Git blob ids without printing any source text', () => {
  withTemporaryDirectory((base) => {
    const repo = join(base, 'repo');
    mkdirSync(join(repo, 'docs'), { recursive: true });
    git(repo, 'init', '-q');
    const document = `line one\nline two ${PLANTED}\nline three\n`;
    writeFile(join(repo, 'docs', 'note.md'), document);
    git(repo, 'add', '--', 'docs/note.md');
    git(repo, '-c', 'user.email=synthetic@example.invalid', '-c', 'user.name=synthetic', 'commit', '-q', '-m', 'synthetic');

    const identity = run(['compare', 'HEAD:docs/note.md', join(repo, 'docs', 'note.md')], { cwd: repo });
    assert.equal(identity.status, 0, identity.output);
    const payload = identity.json();
    assert.equal(payload.identical, true);
    assert.equal(payload.identityOnly, true);
    assert.match(payload.left.identity, /^[0-9a-f]{40}$/);
    assert.equal(payload.left.identity, payload.right.identity);
    assert.ok(!identity.output.includes(PLANTED), 'no source line may reach the comparison output');

    writeFile(join(repo, 'docs', 'note.md'), `line one\nline two ${PLANTED}\nline three\nline four\n`);
    const differing = run(['compare', 'HEAD:docs/note.md', join(repo, 'docs', 'note.md')], { cwd: repo });
    assert.equal(differing.status, 0, differing.output);
    const proof = differing.json();
    assert.equal(proof.identical, false);
    assert.equal(proof.identityOnly, false);
    assert.ok(proof.differingLines >= 1);
    assert.ok(proof.proofs.length >= 1);
    assert.ok(proof.proofs.every((entry) => [entry.left, entry.right].some((digest) => digest?.startsWith('sha256:'))
      && [entry.left, entry.right].every((digest) => digest === null || digest.startsWith('sha256:'))));
    assert.ok(!differing.output.includes(PLANTED));
    assert.ok(!differing.output.includes('line two'), 'a bounded line proof must be a digest, not the line');
  });
});

test('compare scans two files line by line and reports only bounded digest proofs', () => {
  withTemporaryDirectory((base) => {
    const left = writeFile(join(base, 'left.md'), `alpha\nbravo ${PLANTED}\ncharlie\n`);
    const right = writeFile(join(base, 'right.md'), 'alpha\nbravo\ncharlie\ndelta\n');
    const result = run(['compare', left, right]);
    assert.equal(result.status, 0, result.output);
    const payload = result.json();
    assert.equal(payload.identical, false);
    assert.equal(payload.differingLines, 2);
    assert.deepEqual(payload.proofs.map((proof) => proof.line), [2, 4]);
    assert.equal(payload.scan.comparedLines, 4);
    assert.equal(payload.scan.linesLeft, 3);
    assert.equal(payload.scan.linesRight, 4);
    assert.equal(payload.proofs[1].left, null, 'a line missing on one side is reported as absent, not as text');
    assert.ok(!result.output.includes(PLANTED));
    assert.ok(!result.output.includes('bravo'));
  });
});

test('compare refuses a Git operand when git is unavailable and still compares plain files in process', () => {
  withTemporaryDirectory((base) => {
    const empty = emptyDirectory(base, 'nothing');
    const left = writeFile(join(base, 'left.md'), 'one\ntwo\n');
    const right = writeFile(join(base, 'right.md'), 'one\ntwo\n');
    const unavailable = run(['compare', 'HEAD:docs/note.md', left], { env: { PATH: empty } });
    assert.equal(unavailable.status, 1);
    assert.match(unavailable.stderr, /agent handoff: refused; command-unavailable/);

    const inProcess = run(['compare', left, right], { env: { PATH: empty } });
    assert.equal(inProcess.status, 0, inProcess.output);
    const payload = inProcess.json();
    assert.equal(payload.identical, true);
    assert.match(payload.left.identity, /^sha256:[0-9a-f]{16}$/);
  });
});

test('compare enforces the configured timeout on a child process', () => {
  withTemporaryDirectory((base) => {
    const bin = emptyDirectory(base, 'bin');
    // The stub sleeps on an absolute path: PATH holds only this directory, so a bare `sleep` would exit 127
    // instead of exercising the timeout.
    sentinelCommand(bin, 'git', 'exec /bin/sleep 30');
    const left = writeFile(join(base, 'left.md'), 'one\n');
    const right = writeFile(join(base, 'right.md'), 'one\n');
    const result = run(['compare', left, right, '--timeout-ms', '300'], { env: { PATH: bin }, timeout: 60_000 });
    assert.equal(result.status, 3);
    assert.match(result.stderr, /agent handoff: budget; command-budget-exceeded/);
    assert.equal(result.stdout, '', 'a refused comparison must print no partial result');
  });
});

test('compare refuses a symlinked operand and an operand above the scan bound', async () => {
  const { LIMITS } = await loadTool();
  withTemporaryDirectory((base) => {
    const real = writeFile(join(base, 'real.md'), 'one\n');
    const link = join(base, 'link.md');
    symlinkSync(real, link);
    const linked = run(['compare', link, real]);
    assert.equal(linked.status, 1);
    assert.match(linked.stderr, /agent handoff: refused; operand-not-a-regular-path/);

    const big = writeFile(join(base, 'big.md'), Buffer.alloc(LIMITS.scanBytes + 1, 0x61));
    const oversized = run(['compare', big, real]);
    assert.equal(oversized.status, 1);
    assert.match(oversized.stderr, /agent handoff: refused; operand-above-scan-bound/);
  });
});

test('the line scan stops at its deadline instead of running unbounded', async () => {
  const { scanLines } = await loadTool();
  const left = Buffer.from('alpha\nbravo\ncharlie\n');
  const right = Buffer.from('alpha\ndelta\ncharlie\n');
  let ticks = 0;
  const now = () => (ticks += 10_000);
  assert.throws(() => scanLines(left, right, { deadlineMs: 5, now }), (error) => {
    assert.equal(error.code, 'scan-budget-exceeded');
    assert.equal(error.budget, true);
    return true;
  });
  assert.equal(ticks > 0, true);

  const steady = scanLines(left, right, { deadlineMs: 60_000, now: () => 0 });
  assert.equal(steady.identical, false);
  assert.equal(steady.differingLines, 1);
  assert.equal(steady.comparedLines, 3);
  assert.equal(steady.proofs[0].line, 2);
  // Pinned digests: the proof is a content digest of the line, not the line and not an ordinal.
  assert.equal(steady.proofs[0].left, 'sha256:f144a6907dc4');
  assert.equal(steady.proofs[0].right, 'sha256:4f4a9410ffcd');
});

test('--help describes the supported commands and bounds without probing the environment', () => {
  withTemporaryDirectory((base) => {
    const bin = emptyDirectory(base, 'bin');
    const sentinel = join(base, 'gh-was-invoked');
    sentinelCommand(bin, 'gh', `echo invoked > '${sentinel}'`);
    const result = run(['--help'], { env: { PATH: bin } });
    assert.equal(result.status, 0, result.output);
    for (const command of ['capabilities', 'project-github', 'compare', 'session-handoff']) {
      assert.ok(result.stdout.includes(command), `the help text must name ${command}`);
    }
    assert.ok(result.stdout.includes('LIMITS'), 'the help text must state the supported bounds');
    assert.ok(!existsSync(sentinel));
  });
});

test('an unknown command or an out-of-range bound is refused with a fixed code', () => {
  const unknown = run(['not-a-command']);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /agent handoff: refused; usage-invalid/);

  for (const args of [['capabilities', '--max-output-bytes', '0'], ['capabilities', '--max-output-bytes', '99999999'], ['compare', 'a', 'b', '--timeout-ms', '0'], ['session-handoff', '--nope']]) {
    const result = run(args);
    assert.equal(result.status, 1, result.output);
    assert.match(result.stderr, /agent handoff: refused; (option-out-of-range|usage-invalid)/);
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Independent-review remediation (REQUEST_CHANGES at c322). Each case below is a behavior regression for
// one reproduced finding: R1 capture containment, R2 record bound, R3 reduction order, R4 loss accounting,
// R5 one-row JSONL, R6 inspected-key accounting, and the C1 comparison completeness claim.
// ---------------------------------------------------------------------------------------------------------------

/** A small synthetic repository with one commit; nothing outside the disposable base is touched. */
function syntheticRepository(base, name = 'repo') {
  const repo = join(base, name);
  mkdirSync(join(repo, 'docs'), { recursive: true });
  git(repo, 'init', '-q');
  writeFile(join(repo, 'docs', 'note.md'), 'synthetic note\n');
  git(repo, 'add', '--', 'docs/note.md');
  git(repo, '-c', 'user.email=synthetic@example.invalid', '-c', 'user.name=synthetic', 'commit', '-q', '-m', 'synthetic');
  return repo;
}

/** An isolated response file plus a private store directory outside every repository. */
function captureFixture(base) {
  const raw = JSON.stringify(syntheticIssue());
  return { raw, input: writeFile(join(base, 'response.json'), raw), store: mkdirSync(join(base, 'store'), { recursive: true }) && join(base, 'store') };
}

test('raw capture is refused inside a work tree even when Git discovery is overridden', () => {
  withTemporaryDirectory((base) => {
    const repo = syntheticRepository(base);
    const inside = join(repo, 'captures');
    mkdirSync(inside);
    const outside = mkdirSync(join(base, 'outside'), { recursive: true }) && join(base, 'outside');
    const { input } = captureFixture(base);
    const result = run(['project-github', '--input', input, '--capture', inside], {
      env: { GIT_DIR: join(repo, '.git'), GIT_WORK_TREE: outside },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /agent handoff: refused; capture-inside-work-tree/);
    assert.deepEqual(readdirSync(inside), [], 'a refused capture must not write a raw response into the repository');
  });
});

test('raw capture is refused inside Git metadata storage and leaves no file behind', () => {
  withTemporaryDirectory((base) => {
    const repo = syntheticRepository(base);
    const { input } = captureFixture(base);
    const metadata = join(repo, '.git');
    const result = run(['project-github', '--input', input, '--capture', metadata]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /agent handoff: refused; capture-inside-repository/);
    assert.deepEqual(
      readdirSync(metadata).filter((name) => name.startsWith('github-response-')),
      [],
      'a refused capture must not write a raw response into Git metadata storage',
    );

    // A bare metadata layout outside any work tree is refused for the same reason.
    const bare = mkdirSync(join(base, 'bare-repo'), { recursive: true }) && join(base, 'bare-repo');
    for (const marker of ['HEAD', 'config']) mkdirSync(join(bare, marker));
    for (const marker of ['objects', 'refs']) mkdirSync(join(bare, marker));
    const bareResult = run(['project-github', '--input', input, '--capture', bare]);
    assert.equal(bareResult.status, 1);
    assert.match(bareResult.stderr, /agent handoff: refused; capture-inside-repository/);
    assert.deepEqual(readdirSync(bare).filter((name) => name.startsWith('github-response-')), []);
  });
});

test('raw capture fails closed when containment cannot be established', { skip: process.getuid?.() === 0 ? 'root bypasses directory permissions, so the unreadable-ancestor case cannot be established' : false }, () => {
  withTemporaryDirectory((base) => {
    const { input } = captureFixture(base);
    const locked = mkdirSync(join(base, 'locked'), { recursive: true }) && join(base, 'locked');
    const destination = mkdirSync(join(locked, 'store'), { recursive: true }) && join(locked, 'store');
    chmodSync(locked, 0o000);
    try {
      const result = run(['project-github', '--input', input, '--capture', destination]);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /agent handoff: refused; capture-verification-unavailable/);
      chmodSync(locked, 0o700);
      assert.deepEqual(readdirSync(destination), [], 'an unverifiable capture must not write anything');
    } finally {
      chmodSync(locked, 0o700);
    }
  });
});

test('raw capture still succeeds in a private directory outside every repository', () => {
  withTemporaryDirectory((base) => {
    const repo = syntheticRepository(base);
    const { input, store } = captureFixture(base);
    const result = run(['project-github', '--input', input, '--capture', store], {
      env: { GIT_DIR: join(repo, '.git'), GIT_WORK_TREE: repo },
    });
    assert.equal(result.status, 0, result.output);
    const payload = result.json();
    assert.equal(payload.raw.captured, true);
    assert.ok(payload.raw.capturePath.startsWith(store));
    assert.equal(statSync(payload.raw.capturePath).mode & 0o077, 0);
  });
});

test('the GitHub record bound refuses an oversized response instead of dropping a record', async () => {
  const { LIMITS } = await loadTool();
  const record = (id) => ({ id, number: id, state: 'open', body: 'synthetic body text' });
  const withinBound = run(['project-github', '--input', '-', '--max-output-bytes', '262144'], {
    input: JSON.stringify(Array.from({ length: LIMITS.maxItems }, (_, id) => record(id + 1))),
  });
  assert.equal(withinBound.status, 0, withinBound.output);
  assert.equal(withinBound.json().output.recordsRead, LIMITS.maxItems);

  const aboveBound = run(['project-github', '--input', '-', '--max-output-bytes', '262144'], {
    input: JSON.stringify(Array.from({ length: LIMITS.maxItems + 1 }, (_, id) => record(id + 1))),
  });
  assert.equal(aboveBound.status, 1);
  assert.match(aboveBound.stderr, /agent handoff: refused; records-above-bound/);
  assert.equal(aboveBound.stdout, '', 'a refused record bound must print no partial projection');
});

test('the fitter keeps every task identity before giving up a field tier', () => {
  const labelled = (id) => ({
    id: 1000 + id,
    number: id,
    state: 'open',
    labels: Array.from({ length: 32 }, (_, index) => ({ name: `synthetic-label-${id}-${index}-padding-value` })),
  });
  const cap = 1536;
  const withLabels = run(['project-github', '--input', '-', '--max-output-bytes', String(cap)], {
    input: JSON.stringify([labelled(1), labelled(2)]),
  });
  assert.equal(withLabels.status, 0, withLabels.output);
  assert.ok(withLabels.bytes <= cap, `stdout must never exceed the configured cap (${withLabels.bytes} > ${cap})`);
  const payload = withLabels.json();
  assert.equal(payload.output.recordsProjected, 2, 'both records must survive when their identities fit');
  assert.deepEqual(payload.items.map((item) => item.number), [1, 2]);
  assert.equal(payload.output.truncated, true, 'losing the label fields is a loss the flag must report');
  assert.ok(payload.output.fieldsWithheld > 0);

  // Control: the same two identities without the verbose labels fit even at the richest tier.
  const control = run(['project-github', '--input', '-', '--max-output-bytes', String(cap)], {
    input: JSON.stringify([{ id: 1001, number: 1, state: 'open' }, { id: 1002, number: 2, state: 'open' }]),
  });
  assert.equal(control.status, 0, control.output);
  assert.equal(control.json().output.tier, 2);
  assert.equal(control.json().output.recordsProjected, 2);
});

test('field loss is reported as truncation and the key accounting adds up for both commands', () => {
  const cap = 896;
  const github = run(['project-github', '--input', '-', '--max-output-bytes', String(cap)], {
    input: JSON.stringify({ id: 1, number: 1, state: 'open', created_at: '2026-10-03T00:00:00Z', body: 'synthetic body text' }),
  });
  assert.equal(github.status, 0, github.output);
  const projected = github.json();
  assert.ok(github.bytes <= cap);
  assert.equal(projected.output.tier, 0);
  assert.equal('createdAt' in projected.items[0], false);
  assert.equal(projected.output.truncated, true, 'a withheld field is a loss the flag must report');
  assert.equal(projected.output.recordsOmitted, 0, 'no record was dropped in this case');
  assert.ok(projected.output.fieldsWithheld > 0);
  assertSummarised(projected.omitted);

  // The session envelope carries the group lists as well, so its field-only case needs its own cap.
  const sessionCap = 1152;
  const sessions = run(['session-handoff', '--input', '-', '--max-output-bytes', String(sessionCap)], {
    input: JSON.stringify({ sessions: [{ id: 'chat-1', kind: 'user-chat', access: 'accessible', label: 'synthetic label', startedAt: '2026-10-03T09:00:00Z', primaryLog: 'synthetic-log://one' }] }),
  });
  assert.equal(sessions.status, 0, sessions.output);
  const handoff = sessions.json();
  assert.ok(sessions.bytes <= sessionCap);
  assert.equal(handoff.output.truncated, true, 'a withheld session field is a loss the flag must report');
  assert.equal(handoff.output.sessionsOmitted, 0);
  assert.ok(handoff.output.fieldsWithheld > 0);
  assertSummarised(handoff.omitted);
});

test('inspected session metadata is not counted as a never-read key', () => {
  const inventory = [
    { id: 'chat-1', kind: 'user-chat', access: 'accessible', transcript: PLANTED },
    { id: 'worker-1', kind: 'worker', access: 'accessible', forkedFrom: 'chat-1', resumedFrom: 'chat-1' },
  ];
  const result = run(['session-handoff', '--input', '-'], { input: JSON.stringify(inventory) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.omitted.inputKeys, 9, 'four keys on the chat plus five on the worker');
  assert.equal(payload.omitted.otherKeys, 0, 'grouping and relationship keys were read, so they are not unread keys');
  assert.equal(payload.omitted.contentKeys, 1, 'the transcript key is counted and never read');
  assert.equal(payload.omitted.credentialKeys, 0);
  assert.equal(payload.omitted.derivedKeys, 2, 'forkedFrom and resumedFrom are reported through relationships');
  assert.equal(payload.omitted.groupedKeys, 2, 'kind is reported through the emitted group, separately from edges');
  assert.equal(payload.omitted.rejectedKeys, 0);
  assert.equal(payload.omitted.withheldKeys, 0);
  assert.deepEqual(payload.workers[0].relationships, [
    { kind: 'fork', from: 'chat-1', resolved: true },
    { kind: 'resume', from: 'chat-1', resolved: true },
  ]);
  assertSummarised(payload.omitted);
});

test('a one-row JSONL inventory is accepted with and without a trailing newline', () => {
  const row = { id: 'chat-1', kind: 'user-chat', access: 'inaccessible', primaryLog: 'synthetic-log://one', transcript: PLANTED };
  for (const input of [`${JSON.stringify(row)}\n`, JSON.stringify(row)]) {
    const result = run(['session-handoff', '--input', '-'], { input });
    assert.equal(result.status, 0, result.output);
    const payload = result.json();
    assert.equal(payload.totals.records, 1);
    assert.deepEqual(payload.userChats.map((entry) => entry.id), ['chat-1']);
    assert.deepEqual(payload.inaccessible, ['chat-1']);
    assert.equal(payload.omitted.contentKeys, 1);
    assert.equal('transcript' in payload.userChats[0], false);
  }
});

test('a JSON object that is not a session record is still a shape refusal', () => {
  for (const input of ['{"items":[]}', '{"sessions":{}}', '{"notes":"synthetic"}']) {
    const result = run(['session-handoff', '--input', '-'], { input });
    assert.equal(result.status, 1, result.output);
    assert.match(result.stderr, /agent handoff: refused; input-shape-mismatch/);
  }
});

test('an unequal-length comparison reports a complete scan rather than a truncated one', () => {
  withTemporaryDirectory((base) => {
    const left = writeFile(join(base, 'left.md'), 'alpha\nbravo\n');
    const right = writeFile(join(base, 'right.md'), 'alphabet\nbravo charlie\n');
    assert.notEqual(left.length, right.length);
    const result = run(['compare', left, right]);
    assert.equal(result.status, 0, result.output);
    const payload = result.json();
    assert.equal(payload.identical, false);
    assert.equal(payload.scan.complete, true, 'both operands are below the scan bound, so every byte was compared');
    assert.equal(payload.scan.truncated, undefined, 'a length difference is not truncation and must not be labelled as one');
    assert.equal(payload.scan.comparedLines, 2);
    assert.equal(payload.differingLines, 2);
    assert.notEqual(payload.left.bytes, payload.right.bytes);
  });
});

test('environment presence is the name being defined, with no value read into the output', () => {
  const result = run(['capabilities'], { env: { GITHUB_TOKEN: '', GH_TOKEN: PLANTED }, unsetEnvironment: ['GIT_ASKPASS'] });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.environment.GITHUB_TOKEN.present, true, 'a defined but empty name is present by name');
  assert.equal(payload.environment.GITHUB_TOKEN.value, null);
  assert.equal(payload.environment.GH_TOKEN.present, true);
  assert.equal(payload.environment.GH_TOKEN.value, null);
  assert.equal(payload.environment.GIT_ASKPASS.present, false);
  assert.ok(!result.output.includes(PLANTED));
});

test('a coverage environment in the child does not break the sanitized Git probe', () => {
  // The exact failure mode seen only under `node --test --experimental-test-coverage`: the runner sets
  // NODE_V8_COVERAGE in each test file's environment, and Node's child_process copies that variable into a
  // caller-supplied env object. Reproduced here directly, so the case is red on any run rather than only
  // under coverage, and the coverage JSON lands in a disposable directory.
  withTemporaryDirectory((base) => {
    const coverage = mkdirSync(join(base, 'coverage'), { recursive: true }) && join(base, 'coverage');
    const capabilities = run(['capabilities'], { env: { NODE_V8_COVERAGE: coverage } });
    assert.equal(capabilities.status, 0, capabilities.output);
    assert.equal(capabilities.json().command, 'capabilities');
    assert.equal(capabilities.json().runtime.gitWorkTree, true, 'the probe must still report the real work tree');

    const { input, store } = captureFixture(base);
    const captured = run(['project-github', '--input', input, '--capture', store], { env: { NODE_V8_COVERAGE: coverage } });
    assert.equal(captured.status, 0, captured.output);
    assert.equal(captured.json().raw.captured, true);
  });
});

test('the Git probe environment is built per call, mutable, and free of discovery overrides', async () => {
  const { gitProbeEnvironment } = await loadTool();
  const first = gitProbeEnvironment();
  const second = gitProbeEnvironment();
  assert.notEqual(first, second, 'Node adds NODE_V8_COVERAGE to the object it is given, so each call needs its own');
  assert.equal(Object.isFrozen(first), false, 'a frozen object makes that assignment throw');
  assert.equal(Object.isExtensible(first), true);
  assert.equal(first.PATH, process.env.PATH ?? '', 'the probe must exec the same PATH the availability lookup found');
  for (const name of Object.keys(first)) {
    assert.doesNotMatch(name, /^GIT_/, `${name} must not reach the Git probe`);
    assert.doesNotMatch(name, /^(?:HOME|USER|LOGNAME)$/, `${name} must not reach the Git probe`);
    assert.doesNotMatch(name, /TOKEN|SECRET|PASSWORD|CREDENTIAL|COOKIE|AUTH|KEY/i, `${name} must not reach the Git probe`);
  }
});

test('raw capture is refused in a descendant of a bare repository', () => {
  withTemporaryDirectory((base) => {
    // A bare repository has no work tree, so only the metadata markers can catch it, and they apply to
    // every ancestor, not only to the destination itself.
    const bare = join(base, 'bare.git');
    git(base, 'init', '--bare', '-q', bare);
    const cache = mkdirSync(join(bare, 'cache'), { recursive: true }) && join(bare, 'cache');
    const { input } = captureFixture(base);
    const result = run(['project-github', '--input', input, '--capture', cache]);
    assert.equal(result.status, 1, result.output);
    assert.match(result.stderr, /agent handoff: refused; capture-inside-repository/);
    assert.deepEqual(readdirSync(cache).filter((name) => name.startsWith('github-response-')), []);
    assert.deepEqual(readdirSync(bare).filter((name) => name.startsWith('github-response-')), []);
  });
});

test('raw capture is still accepted outside every repository, including beside a bare one', () => {
  withTemporaryDirectory((base) => {
    const bare = join(base, 'bare.git');
    git(base, 'init', '--bare', '-q', bare);
    const store = mkdirSync(join(base, 'store'), { recursive: true }) && join(base, 'store');
    const { input } = captureFixture(base);
    const result = run(['project-github', '--input', input, '--capture', store]);
    assert.equal(result.status, 0, result.output);
    assert.equal(result.json().raw.captured, true);
    assert.equal(statSync(result.json().raw.capturePath).mode & 0o077, 0);
  });
});

test('accounting counts only retained records and only values that were emitted', () => {
  const rows = Array.from({ length: 20 }, (_, index) => ({ id: index, number: index, state: 'open', body: 'synthetic body text' }));
  const cap = 1024;
  const result = run(['project-github', '--input', '-', '--max-output-bytes', String(cap)], { input: JSON.stringify(rows) });
  assert.equal(result.status, 0, result.output);
  assert.ok(result.bytes <= cap, `stdout must never exceed the configured cap (${result.bytes} > ${cap})`);
  const payload = result.json();
  const retained = payload.items.length;
  assert.equal(payload.output.recordsRead, 20);
  assert.equal(payload.output.recordsOmitted, 20 - retained);
  assert.equal(retained, 6, 'the documented capacity at this cap is six rows, which this fix must not change');
  assert.equal(payload.omitted.inputKeys, retained * 4, 'accounting covers the records that were projected');
  assert.equal(payload.omitted.projectedKeys, retained * 3, 'only id, number and state were emitted per retained row');
  assert.equal(payload.omitted.contentKeys, retained);
  assert.equal(payload.omitted.withheldKeys, 0, 'tier 0 excludes no supplied key in these rows');
  assert.equal(payload.omitted.rejectedKeys, 0);
  assertSummarised(payload.omitted);
});

test('a rejected optional value is reported as rejected, not as an emitted field', () => {
  const record = { id: 1, state: 'future-state', created_at: { value: PLANTED }, body: PLANTED };
  const result = run(['project-github', '--input', '-'], { input: JSON.stringify(record) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.deepEqual(payload.items[0], { id: 1 }, 'only the validated identifier is emitted');
  assert.equal(payload.omitted.inputKeys, 4);
  assert.equal(payload.omitted.projectedKeys, 1);
  assert.equal(payload.omitted.rejectedKeys, 2, 'state and created_at were inspected and refused, not emitted and not withheld');
  assert.equal(payload.omitted.withheldKeys, 0);
  assert.equal(payload.omitted.contentKeys, 1);
  assertSummarised(payload.omitted);
});

test('consulted head and base refs are projected rather than called unread', () => {
  const record = { id: 1, head: { ref: 'synthetic-feature' }, base: { ref: 'main' }, body: PLANTED };
  const result = run(['project-github', '--input', '-', '--kind', 'pull'], { input: JSON.stringify(record) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.items[0].headRef, 'synthetic-feature');
  assert.equal(payload.items[0].baseRef, 'main');
  assert.equal(payload.omitted.inputKeys, 4);
  assert.equal(payload.omitted.projectedKeys, 3, 'id, head and base were read and emitted');
  assert.equal(payload.omitted.otherKeys, 0, 'consulted native keys are not unread data');
  assert.equal(payload.omitted.rejectedKeys, 0);
  assertSummarised(payload.omitted);
});

test('absent optional keys produce no occurrence at all', () => {
  const result = run(['project-github', '--input', '-'], { input: JSON.stringify({ id: 1, state: 'open' }) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.omitted.inputKeys, 2, 'fieldsWithheld counts schema names; inputKeys counts supplied keys only');
  assert.equal(payload.omitted.withheldKeys, 0, 'the tier excluded no supplied key, so nothing was budget-withheld');
  assert.equal(payload.omitted.rejectedKeys, 0);
  assert.equal(payload.omitted.projectedKeys, 2);
  assertSummarised(payload.omitted);

  // At a lower tier the same record names excluded schema fields while still withholding no occurrence.
  const tight = run(['project-github', '--input', '-', '--max-output-bytes', '900'], { input: JSON.stringify({ id: 1, state: 'open' }) });
  assert.equal(tight.status, 0, tight.output);
  assert.equal(tight.json().output.tier, 0);
  assert.ok(tight.json().output.fieldsWithheld > 0, 'the tier names the schema fields it excluded');
  assert.equal(tight.json().omitted.withheldKeys, 0, 'no supplied key was dropped, because none of the excluded fields exists');
  assert.equal(tight.json().omitted.inputKeys, 2);
  assertSummarised(tight.json().omitted);
});

test('a grouping key that reached the output is derived, never budget-withheld', () => {
  const inventory = [{ id: 'chat-1', kind: 'user-chat', access: 'accessible', transcript: PLANTED }];
  const result = run(['session-handoff', '--input', '-'], { input: JSON.stringify(inventory) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.equal(payload.output.truncated, false);
  assert.deepEqual(payload.userChats.map((entry) => entry.id), ['chat-1']);
  assert.equal(payload.omitted.withheldKeys, 0, 'kind was used for the emitted group, not removed by a budget');
  assert.equal(payload.omitted.groupedKeys, 1, 'grouping is reported apart from relationship derivation');
  assert.equal(payload.omitted.derivedKeys, 0);
  assert.equal(payload.omitted.projectedKeys, 2);
  assert.equal(payload.omitted.contentKeys, 1);
  assert.equal(payload.omitted.inputKeys, 4);
  assert.deepEqual(payload.output.derivedFrom, ['kind', 'forkedFrom', 'resumedFrom']);
  assertSummarised(payload.omitted);
});

test('a self or unsafe edge is reported as rejected, not as a re-emitted relationship', () => {
  const inventory = [{ id: 'chat-1', kind: 'user-chat', forkedFrom: 'chat-1', resumedFrom: `unsafe${PLANTED}\nvalue` }];
  const result = run(['session-handoff', '--input', '-'], { input: JSON.stringify(inventory) });
  assert.equal(result.status, 0, result.output);
  const payload = result.json();
  assert.deepEqual(payload.userChats[0].relationships, [], 'neither supplied edge can become a relationship');
  assert.equal(payload.omitted.derivedKeys, 0, 'no edge was re-emitted, so nothing is counted as derived');
  assert.equal(payload.omitted.rejectedKeys, 2, 'the self reference and the unsafe value were refused');
  assert.equal(payload.omitted.groupedKeys, 1);
  assert.equal(payload.omitted.projectedKeys, 1);
  assert.equal(payload.omitted.inputKeys, 4);
  assertSummarised(payload.omitted);
});

test('the helper is developer tooling and is not imported by the runtime core', async () => {
  const sources = readdirSync(join(root, 'src')).filter((name) => name.endsWith('.ts'));
  assert.ok(sources.length > 0);
  for (const name of sources) {
    const text = readFileSync(join(root, 'src', name), 'utf8');
    assert.doesNotMatch(text, /agent-handoff|scripts\/development/, `src/${name} must not import the developer handoff helper`);
  }
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.scripts['agent:handoff'], 'node scripts/development/agent-handoff.mjs');
  assert.equal(manifest.exports, undefined, 'the helper must not become a runtime export');
  assert.deepEqual(manifest.dependencies, undefined, 'the helper must add no runtime dependency');
});
