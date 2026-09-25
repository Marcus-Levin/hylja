#!/usr/bin/env node
// CI guard for tracked paths and staged fixture blobs. It is not a secret detector
// or an enforcement boundary: only the repository's synthetic corpus belongs here.
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const excludedFixtureArea = /(?:^|\/)fixtures\/(?:private|restricted|local|raw|real|production)(?:\/|$)/i;
const excludedDirectory = /(?:^|\/)(?:node_modules|dist|coverage|artifacts|test-results|\.hylja-state|\.nyc_output)(?:\/|$)/i;
const excludedName = /^(?:\.env(?:\..*)?|\.npmrc|\.netrc|\.pypirc|id_rsa(?:\..*)?|id_ed25519(?:\..*)?)$/i;
const excludedExtension = /\.(?:pem|key|p12|pfx|log|sqlite3?|db)$/i;
const fixtureArea = /(?:^|\/)(?:fixtures|__fixtures__|artifacts|snapshots|__snapshots__)(?:\/|$)/i;
const goldenArea = /(?:^|\/)fixtures\/synthetic-golden\//;
const exampleFile = /(?:^|\/)\.env\.example$/;
const credentialAssignment = /(?:^|[\s,{])["']?(?:password|passwd|api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|authorization|cookie)["']?\s*[:=]\s*["']?([^\s"',;}]+)/gim;
const obviouslySynthetic = /^synthetic-[a-z0-9-]+\.invalid$/;
const credentialMarker = /-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b/;
const decoder = new TextDecoder('utf-8', { fatal: true });

function reject(reason) {
  throw new Error(`fixture guard: ${reason}`);
}

function git(args, maxBuffer) {
  const result = spawnSync('git', args, { encoding: 'buffer', maxBuffer, windowsHide: true });
  if (result.error || result.status !== 0) reject('unable to inspect Git index');
  return result.stdout;
}

function inspect() {
  // ls-files is relative to the current directory; never scan only a subtree.
  const top = decoder.decode(git(['rev-parse', '--show-toplevel'], 4096)).trimEnd();
  if (resolve(top) !== resolve(process.cwd())) reject('must run from repository root');
  const index = git(['ls-files', '--stage', '-z'], 16 * 1024 * 1024);
  let records;
  try {
    records = decoder.decode(index).split('\0');
  } catch {
    reject('unable to inspect Git index');
  }

  for (const record of records) {
    if (!record) continue;
    const match = /^(\d{6}) ([0-9a-f]{40,64}) ([0-3])\t(.+)$/s.exec(record);
    if (!match || match[3] !== '0') reject('unable to inspect Git index');
    const [, mode, objectId, , path] = match;
    if (excludedDirectory.test(path) || excludedFixtureArea.test(path)
        || (excludedName.test(path.split('/').at(-1)) && !exampleFile.test(path))
        || excludedExtension.test(path)) {
      reject('rejected tracked path (excluded path)');
    }

    if (!fixtureArea.test(path) && !exampleFile.test(path)) continue;
    if (mode !== '100644' && mode !== '100755') reject('rejected tracked path (non-regular fixture)');
    const blob = git(['cat-file', 'blob', objectId], 1024 * 1024);
    let text;
    try {
      text = decoder.decode(blob);
    } catch {
      reject('rejected fixture content (non-text or oversized)');
    }
    if (text.includes('\0')) reject('rejected fixture content (non-text or oversized)');
    if (credentialMarker.test(text)) reject('rejected credential-like content');
    for (const match of text.matchAll(credentialAssignment)) {
      if (!goldenArea.test(path) || !obviouslySynthetic.test(match[1])) {
        reject('rejected credential-like content');
      }
    }
  }
  process.stdout.write('fixture guard: tracked paths and synthetic fixtures checked\n');
}

try {
  inspect();
} catch (error) {
  // Never print a filename, Git's stderr, a blob, or an exception stack: even a
  // malicious filename can contain a planted value.
  process.stderr.write(error instanceof Error && error.message.startsWith('fixture guard:')
    ? `${error.message}\n` : 'fixture guard: unable to inspect Git index\n');
  process.exitCode = 1;
}
