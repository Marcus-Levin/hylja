#!/usr/bin/env node
/**
 * #136 bounded offline documentation link check.
 *
 *   npm run check:docs
 *   node scripts/check-doc-links.mjs [--help]
 *
 * This is a regression guardrail for broken documentation links. It enumerates tracked Markdown files
 * from the Git index, resolves relative link targets inside the repository, and resolves supported local
 * heading anchors. It authenticates nothing, sends no bytes and is not a security boundary.
 *
 * Supported syntax
 * - inline links and images: `[text](target)`, `![alt](target)`, one optional link title, and an
 *   angle-bracketed destination.
 * - a destination is checked when it is a bare fragment (`#anchor`), or a repository-relative path that
 *   resolves inside the repository root, is an existing regular file or a tracked directory.
 * - a fragment on a Markdown target (`.md`, `.markdown`) is resolved against that file's ATX and
 *   Setext headings with GitHub text slugs; duplicate headings take the `-1`, `-2` suffix form.
 * - percent-encoded path and fragment components are decoded after the fragment separator is split, so
 *   `%23` in a path is a literal `#` and never a fragment separator.
 * - inline code spans and fenced code blocks are excluded; a link example inside one is not a link.
 *
 * Skipped, never fetched
 * - any destination with a URI scheme (`https:`, `mailto:`, ...) and any protocol-relative `//host` one.
 * - a fragment on a non-Markdown target, including GitHub line anchors such as `src/x.ts#L1-L9`.
 * - an empty destination.
 *
 * Limitations
 * - reference links (`[text][id]`), shortcut references and raw HTML links are not parsed.
 * - a code span that continues over a line break is not tracked; a link inside one is still checked.
 * - heading text is slugged from the raw heading, with code span contents kept and inline link targets
 *   dropped. Explicit HTML anchors and other rendered-text differences are not modelled, and indented
 *   code blocks are not excluded.
 * - a heading whose rendered slug differs from this model is reported rather than silently accepted, so
 *   a documentation migration cannot pass by weakening the rule that is in force now.
 * - the `*.md` document enumeration is the Git pathspec of that name, so it is case-sensitive.
 *
 * Bounds: 4096 documents, 2 MiB per file, 8192 headings per document, 64 KiB per parsed line, 8 MiB of
 * Git output, and 200 printed findings with the remainder counted. Exceeding a bound is a fixed refusal,
 * never a silent pass.
 *
 * Privacy and bounds
 * - the existing fixture guard (`scripts/check-fixtures.mjs`) runs first and must pass before any
 *   document is read. This script never re-implements its path or fixture policy.
 * - only tracked paths are enumerated; documents and Markdown targets are read as regular files inside
 *   the repository root, bounded per file, never through a symbolic link, and never from outside the root.
 * - non-Markdown targets are checked for existence and tracking only, and are never read.
 * - diagnostics name a repository-relative document path, a line (`0` for the whole document) and a
 *   fixed reason code. They never print a link target, a heading or any document content.
 */
import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HELP = `doc link check: usage
  node scripts/check-doc-links.mjs [--help]

Checks tracked Markdown files for broken relative link targets and unsupported heading anchors, using
the syntax and limits documented at the top of scripts/check-doc-links.mjs. Runs offline, runs the
existing fixture guard first, reads only tracked paths inside the repository, and prints only a
document path, a line number and a fixed reason code.`;

const GUARD = resolve(dirname(fileURLToPath(import.meta.url)), 'check-fixtures.mjs');
const MAX_DOCUMENT_BYTES = 2 << 20;
const MAX_DOCUMENTS = 4096;
const MAX_GIT_OUTPUT = 8 << 20;
const MAX_FINDINGS = 200;
const MAX_HEADINGS = 8192;
const MAX_LINE_LENGTH = 1 << 16;
const decoder = new TextDecoder('utf-8', { fatal: true });

class Unusable extends Error {}
class Refused extends Error {}

function unusable(message) {
  throw new Unusable(message);
}

function git(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'buffer', maxBuffer: MAX_GIT_OUTPUT, windowsHide: true });
  if (result.error || result.status !== 0) unusable('unable to inspect the Git index');
  try {
    return decoder.decode(result.stdout);
  } catch {
    return unusable('unable to inspect the Git index');
  }
}

function repositoryRoot() {
  const result = spawnSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8', windowsHide: true });
  if (result.error || result.status !== 0 || result.stdout.trim() === '') unusable('not inside a Git work tree');
  return realpathSync(resolve(result.stdout.trim()));
}

function trackedPaths(root, pathspec) {
  const args = pathspec === undefined ? ['ls-files', '-z'] : ['ls-files', '-z', '--', pathspec];
  return git(root, args).split('\0').filter(Boolean);
}

function runFixtureGuard(root) {
  const result = spawnSync(process.execPath, [GUARD], { cwd: root, stdio: 'inherit', windowsHide: true });
  if (result.error || result.status !== 0) throw new Refused('the fixture guard rejected this tree');
}

/** A fence opener or closer: a ``` or ~~~ run of three or more, indented by at most three spaces. */
function fenceMarker(line) {
  const match = /^ {0,3}(`{3,}|~{3,})/.exec(line);
  return match === null ? null : match[1];
}

/**
 * Replaces the content of single-line code spans with spaces of the same length, so a Markdown example
 * inside a code span is not mistaken for a link. A run with no closer on the same line is left alone:
 * tracking a code span across lines would let one stray backtick mask the rest of a document.
 */
function maskCodeSpans(line) {
  if (!line.includes('`')) return line;
  const characters = [...line];
  let index = 0;
  while (index < characters.length) {
    if (characters[index] !== '`') {
      index += 1;
      continue;
    }
    let run = 0;
    while (characters[index + run] === '`') run += 1;
    let scan = index + run;
    let closer = -1;
    while (scan < characters.length) {
      if (characters[scan] !== '`') {
        scan += 1;
        continue;
      }
      let width = 0;
      while (characters[scan + width] === '`') width += 1;
      if (width === run) {
        closer = scan;
        break;
      }
      scan += width;
    }
    if (closer === -1) break;
    for (let masked = index; masked < closer + run; masked += 1) characters[masked] = ' ';
    index = closer + run;
  }
  return characters.join('');
}

/** Inline links and images: link text with one nested bracket level, a destination, an optional title. */
const INLINE_LINK = /!?\[(?:[^\[\]\\]|\\.|\[[^\[\]\n]*\])*\]\(\s*(<[^<>\n]*>|[^\s()]*(?:\([^\s()\n]*\)[^\s()]*)*)(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?\s*\)/g;

/** Splits a destination into path and fragment before any percent-decoding, so `%23` is not a split. */
function splitDestination(raw) {
  const trimmed = raw.trim();
  const destination = trimmed.startsWith('<') && trimmed.endsWith('>')
    ? trimmed.slice(1, -1)
    : (/\s/.test(trimmed) ? trimmed.slice(0, trimmed.search(/\s/)) : trimmed);
  const hash = destination.indexOf('#');
  return hash === -1
    ? { path: destination, fragment: '' }
    : { path: destination.slice(0, hash), fragment: destination.slice(hash + 1) };
}

/** Every inline link and image of one document, with its 1-based line, outside fences and code spans. */
function* documentLinks(text) {
  let fence = null;
  const lines = text.split('\n');
  for (const [index, raw] of lines.entries()) {
    const marker = fenceMarker(raw);
    if (marker !== null) {
      if (fence === null) fence = marker;
      else if (marker[0] === fence[0] && marker.length >= fence.length) fence = null;
      continue;
    }
    if (fence !== null) continue;
    const line = raw.length > MAX_LINE_LENGTH ? raw.slice(0, MAX_LINE_LENGTH) : raw;
    for (const match of maskCodeSpans(line).matchAll(INLINE_LINK)) {
      yield { line: index + 1, destination: match[1] };
    }
  }
}

/**
 * GitHub-style heading slugs: lower case, punctuation removed, each ASCII space becomes one hyphen.
 * The stripped set is GitHub's: ASCII punctuation except `-` and `_`, plus the general-punctuation,
 * supplemental-punctuation-B, non-breaking space, ogham, ideographic and zero-width ranges. The
 * en dash and em dash are punctuation here, so `CAE – finite` yields `cae--finite` as GitHub renders it.
 */
const SLUG_STRIP = /[\u00A0\u1680\u2000-\u206F\u2E00-\u2E7F\u3000\uFEFF\\'!"#$%&()*+,./:;<=>?@[\]^`{|}~]/g;

function slug(text) {
  return text.toLowerCase().replace(SLUG_STRIP, '').replace(/ /g, '-');
}

/** Heading text as a reader sees it: code span contents kept, inline link targets dropped. */
function headingText(raw) {
  return raw.replace(/`([^`]*)`/g, '$1').replace(/!?\[([^\[\]]*)\]\([^)]*\)/g, '$1');
}

/** Every heading anchor of one document, including the `-1`, `-2` suffix form for duplicates. */
function headingAnchors(text) {
  const anchors = new Set();
  const occurrences = new Map();
  const add = (raw) => {
    if (anchors.size >= MAX_HEADINGS) return;
    const base = slug(headingText(raw));
    let candidate = base;
    let seen = occurrences.get(base) ?? 0;
    while (anchors.has(candidate)) {
      seen += 1;
      candidate = `${base}-${seen}`;
    }
    occurrences.set(base, seen);
    anchors.add(candidate);
  };
  let fence = null;
  let paragraph = null;
  for (const line of text.split('\n')) {
    const marker = fenceMarker(line);
    if (marker !== null) {
      if (fence === null) fence = marker;
      else if (marker[0] === fence[0] && marker.length >= fence.length) fence = null;
      paragraph = null;
      continue;
    }
    if (fence !== null) continue;
    const atx = /^ {0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$/.exec(line);
    if (atx !== null) {
      add(atx[1]);
      paragraph = null;
      continue;
    }
    const setext = /^ {0,3}(?:=+|-+)[ \t]*$/.exec(line);
    if (setext !== null && paragraph !== null) {
      add(paragraph);
      paragraph = null;
      continue;
    }
    paragraph = line.trim() === '' || line.startsWith('    ') ? null : line;
  }
  return anchors;
}

/** Decodes one percent-encoded path or fragment component, or reports a malformed escape. */
function decodeComponent(value) {
  if (!value.includes('%')) return value;
  try {
    const decoded = decodeURIComponent(value);
    return decoded.includes('\0') ? null : decoded;
  } catch {
    return null;
  }
}

function isMarkdown(relative) {
  return /\.(?:md|markdown)$/i.test(relative);
}

/**
 * Reads one tracked Markdown file as text. On refusal it returns a role-less cause instead of content:
 * the caller composes the role, so one oversized file is reported under both the document and the
 * relative-target code it actually failed as.
 */
function readDocument(root, relative) {
  try {
    const absolute = join(root, relative);
    const stats = lstatSync(absolute);
    if (stats.isSymbolicLink() || !stats.isFile()) return { cause: 'not-a-regular-path' };
    if (stats.size > MAX_DOCUMENT_BYTES) return { cause: 'above-read-bound' };
    return { text: decoder.decode(readFileSync(absolute)) };
  } catch (error) {
    return { cause: error?.code === 'ENOENT' ? 'missing-from-work-tree' : 'unreadable' };
  }
}

/** One check pass over the enumerated documents, its tracked targets and their heading anchors. */
function inspect(root, documents, tracked) {
  const findings = [];
  const texts = new Map();
  const anchors = new Map();

  /** Text of a Markdown document or target, read once, with a fixed reason code on refusal. */
  const textOf = (host, target, role) => {
    const known = texts.get(target);
    if (known !== undefined) {
      if (known.cause !== undefined) findings.push({ ...host, reason: `${role}-${known.cause}` });
      return known;
    }
    const record = readDocument(root, target);
    texts.set(target, record);
    if (record.cause !== undefined) findings.push({ ...host, reason: `${role}-${record.cause}` });
    return record;
  };

  const anchorsOf = (host, target) => {
    const known = anchors.get(target);
    if (known !== undefined) return known;
    const record = textOf(host, target, 'relative-target');
    const computed = record.text === undefined ? null : headingAnchors(record.text);
    anchors.set(target, computed);
    return computed;
  };

  const anchorIn = (host, target, fragment) => {
    const decoded = decodeComponent(fragment);
    if (decoded === null) {
      findings.push({ ...host, reason: 'malformed-encoded-target' });
      return;
    }
    const wanted = decoded.replace(/^user-content-/, '');
    if (wanted === '' || /^L\d+/i.test(wanted)) return;
    const found = anchorsOf(host, target);
    if (found !== null && !found.has(wanted)) findings.push({ ...host, reason: 'heading-anchor-missing' });
  };

  const checkLink = (relative, link) => {
    const host = { document: relative, line: link.line };
    const { path, fragment } = splitDestination(link.destination);
    if (path === '' && fragment === '') return;
    if (path.startsWith('//') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(path)) return;
    if (path === '') {
      anchorIn(host, relative, fragment);
      return;
    }
    const decodedPath = decodeComponent(path);
    if (decodedPath === null) {
      findings.push({ ...host, reason: 'malformed-encoded-target' });
      return;
    }
    const resolved = posix.normalize(posix.join(posix.dirname(relative), decodedPath)).replace(/\/+$/, '');
    if (resolved === '.' || resolved === '..' || resolved.startsWith('../') || posix.isAbsolute(resolved)) {
      findings.push({ ...host, reason: 'relative-target-outside-repository' });
      return;
    }
    let stats;
    try {
      stats = lstatSync(join(root, resolved));
    } catch (error) {
      findings.push({ ...host, reason: error?.code === 'ENOENT' ? 'relative-target-missing' : 'relative-target-unreadable' });
      return;
    }
    if (stats.isSymbolicLink() || (!stats.isFile() && !stats.isDirectory())) {
      findings.push({ ...host, reason: 'relative-target-not-a-regular-path' });
      return;
    }
    if (stats.isDirectory() ? !containsTrackedPath(resolved, tracked) : !tracked.has(resolved)) {
      findings.push({ ...host, reason: 'relative-target-not-tracked' });
      return;
    }
    if (fragment !== '' && isMarkdown(resolved)) anchorIn(host, resolved, fragment);
  };

  let links = 0;
  for (const relative of documents) {
    const record = textOf({ document: relative, line: 0 }, relative, 'document');
    if (record.text === undefined) continue;
    for (const link of documentLinks(record.text)) {
      links += 1;
      checkLink(relative, link);
    }
  }

  findings.sort((a, b) => (a.document === b.document ? a.line - b.line : a.document < b.document ? -1 : 1));
  for (const finding of findings.slice(0, MAX_FINDINGS)) {
    process.stderr.write(`${finding.document}:${finding.line}: ${finding.reason}\n`);
  }
  if (findings.length > 0) {
    const hidden = findings.length - Math.min(findings.length, MAX_FINDINGS);
    process.stderr.write(`doc link check: ${findings.length} finding(s) across ${documents.length} documents`);
    process.stderr.write(hidden > 0 ? ` (${hidden} not printed)\n` : '\n');
    return 1;
  }
  process.stdout.write(`doc link check: ok; ${documents.length} documents, ${links} links\n`);
  return 0;
}

function run() {
  if (process.argv.includes('--help')) {
    process.stdout.write(`${HELP}\n`);
    return;
  }
  const root = repositoryRoot();
  runFixtureGuard(root);
  const tracked = new Set(trackedPaths(root));
  const documents = trackedPaths(root, '*.md');
  if (documents.length > MAX_DOCUMENTS) unusable('too many tracked documents');
  process.exitCode = inspect(root, documents, tracked);
}

/** A directory is only a usable link target when the index holds at least one path inside it. */
function containsTrackedPath(directory, tracked) {
  const prefix = `${directory}/`;
  for (const path of tracked) {
    if (path.startsWith(prefix)) return true;
  }
  return false;
}

try {
  run();
} catch (error) {
  if (error instanceof Refused) process.stderr.write(`doc link check: refused; ${error.message}\n`);
  else if (error instanceof Unusable) process.stderr.write(`doc link check: unusable; ${error.message}\n`);
  else process.stderr.write('doc link check: unusable; the check could not complete\n');
  process.exitCode = 1;
}