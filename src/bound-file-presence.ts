/**
 * One construction-bound, read-only **file presence** effect for an opaque mapped engineering
 * identifier (issue #245).
 *
 * `createBoundFilePresence(hostValue, targetValue)` returns `{ handle, dispose }`. The handle is the
 * shipped `BoundMappingUse` from [`mapping-use.ts`](./mapping-use.ts) and is the only object a
 * caller ever receives: `use()` takes no argument, names no path, carries no selector and returns
 * one fixed code. The filesystem backend is **private**: it is supplied here, internally, as the one
 * `MappingUseBackend` the executor already binds at construction, and it is never exported, never
 * reachable from the handle and never consulted without the complete authority path behind it.
 *
 * The authority path is not re-implemented here. `createBoundFilePresence` snapshots the host shape,
 * injects the private backend and hands the whole record to `createBoundMappingUse`, which owns the
 * grant parser, the Policy Engine call, the registry read, the authorization seam, the audit appends
 * and the material load, in its own order and with its own refusal vocabulary. There is no second
 * parser and no second executor here, so a rule cannot hold in this module and be absent from the
 * executor.
 *
 * The target record is closed and version 1: `{ version, identifier, root, leaf }`. `identifier` is
 * the private identifier bytes the resource was provisioned with out of band, copied once into an
 * owned buffer. `root` is one absolute trusted directory; `leaf` is exactly one component. Traversal
 * (`..`), an absolute leaf, a multi-component leaf, an empty or control-character leaf, a relative or
 * traversing root and an inherited or accessor-carrying record are all refused before any native
 * function runs, so a malformed record costs no metadata stat and no effect. A root that is *linked*
 * is the one shape-valid record that costs a native call: its own trusted setup `lstat` runs first,
 * the root is refused as a link, and nothing is canonicalized, bound, opened or spent.
 *
 * Trusted-directory limit, stated plainly: standard Node 22 `fs` has no portable ancestor-relative
 * `openat` boundary, so this module requires the root's own ancestors to be trusted and stable. The
 * root itself is required not to be a symbolic link, is canonicalized with `realpathSync`, and the
 * canonical path is re-stat'ed as a directory. That bounds **path syntax and the linked path**, and
 * it is *not* hostile-race confinement: an ancestor directory replaced between construction and the
 * effect is not detected here. A checked path is not a confinement claim, and no `openat`-equivalent
 * guarantee is made or implied.
 *
 * The bound identity is established at construction: the leaf is `lstat`ed once and, if it is a
 * regular file, its `(dev, ino)` is kept. The per-call effect first compares the recovered bytes with
 * the private identifier, byte by byte, with no decoding, no retention, no logging and no forwarding -
 * a mismatch is therefore a reached effect that could not be completed, never an absence - and only
 * then opens that one construction-bound path with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, `fstat`s
 * the descriptor, requires a regular file, and requires the observed identity to be the one bound at
 * construction, so a link, a directory, a device, a socket or a **substituted** inode at the same
 * name is refused rather than reported. `ENOENT` is the one native answer that is an honest absence
 * (`NOT_FOUND`); a nonregular or substituted target, an identifier that is not the private one, and
 * every other fault are a reached effect that could not be completed, which the executor already
 * reports as `FAILED`.
 *
 * The private backend is never reachable from anything a host callback can see. The executor applies
 * every host callback method with its own copy of the host as the receiver, so this module captures
 * the caller's own `authority` and `material` methods and hands the executor synchronous forwarders
 * that invoke those captured methods on the caller's own host object. The object carrying the backend
 * is the executor's internal copy; it is never passed as an argument and never applied as a receiver.
 * Each forwarder returns the answer exactly as the method returned it, a value or a promise alike, so
 * no extra await and no second normalization sits between the host and the executor.
 *
 * The native functions are captured **at module load**, before any guard runs, so a property
 * replaced on `node:fs` later - or a host that re-points its own callbacks after construction - can
 * never retarget the effect. Inside the backend there is no `await`, no host property read and no
 * dynamic function lookup: the executor's sealed continuation is the only caller, and this module
 * reads only its own state there.
 *
 * Disposal is trusted construction control and not caller input. It clears the owned identifier
 * copy, drops the bound path and refuses every later call before any native function is reached. It
 * is idempotent. Overwriting a JavaScript buffer is hygiene, not zeroization: copies held by the
 * engine, by garbage-collected buffers or by swapped pages are not covered, and nothing observable
 * from outside this module proves a particular allocation was erased.
 *
 * What this is not
 * - **Not an export, a mapping API or a resolution service.** No original is returned to any caller,
 *   there is no reference argument, no enumeration, no scan and no bulk path, so no direct mapping
 *   lookup API exists here (decision 004). `USE` never implies `DISPLAY` or `EXPORT`.
 * - **Not a bypass of the Policy Engine or of authorization.** Every effect is behind
 *   `createBoundMappingUse`, and a refusal anywhere on that path opens nothing.
 * - **Not a content reader.** No byte of any file is read, no file is written, no shell runs, no
 *   socket opens and nothing is persisted.
 * - **Not a managed filesystem interception and not a sandbox.** The host is trusted, not
 *   authenticated; the backend's nonretention duty and the trusted-directory precondition above are
 *   obligations, not proofs.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { createBoundMappingUse } from './mapping-use.js';
import type { BoundMappingUse, MappingUseAudit, MappingUsePolicy, MappingUseResult,
  MappingUseScope } from './mapping-use.js';
import type { MappingUseBackend } from './mapping-use.js';
import type { MappingMetadataRegistry } from './mapping-metadata-registry.js';
import { MAPPING_AEAD_LIMITS } from './mapping-aead.js';

/**
 * Narrow, module-local widening of the shipped `node:fs` declaration. This file needs exactly two
 * facts the shared release-gate shim does not declare - that a stat is a directory, and the device
 * and inode an observed identity is built from - so they are declared here rather than added to a
 * shared surface other modules read.
 */
declare module 'node:fs' {
  interface Stats {
    readonly dev: number;
    readonly ino: number;
    isDirectory(): boolean;
  }
}

/** The one construction target. Closed record, four fields, nothing optional. */
export interface BoundFileTarget {
  version: 1;
  /** The private identifier bytes, compared without decoding and never returned or forwarded. */
  identifier: Uint8Array;
  /** One absolute trusted directory. Traversal and a linked root are refused. */
  root: string;
  /** Exactly one component: no separator, no traversal, no absolute name. */
  leaf: string;
}

/** Trusted construction control. The caller receives `handle` only; `dispose` stays with the owner. */
export interface BoundFilePresence {
  handle: BoundMappingUse;
  dispose(): void;
}

/* ---------------------------------------------------------------------------------------------
 * Native surface, captured once at module load. A property replaced on `node:fs` after this point
 * is a replacement of something this module no longer reads; the flags are composed once too, so
 * no effect is ever opened under a flag read at effect time.
 * ------------------------------------------------------------------------------------------- */
const OPEN = openSync;
const FSTAT = fstatSync;
const CLOSE = closeSync;
const STAT = lstatSync;
const CANONICALIZE = realpathSync;
const READ_ONLY = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
/**
 * One captured `Reflect.apply`, read once at module load. `fn.call(recv)` and `fn.apply(recv, xs)`
 * resolve a mutable property of the function object at the moment they run; this reference cannot be
 * re-pointed afterwards, so the forwarding below invokes the captured host method directly.
 */
const REFLECT_APPLY = Reflect.apply;

const PATH_LIMIT = 4096;
const LEAF_LIMIT = 255;
/** The same ceiling the AEAD seam already bounds a mapping payload to. */
const IDENTIFIER_LIMIT = MAPPING_AEAD_LIMITS.plaintextBytes;
/** The host record carries nine mandatory fields and the target record four; both are capped. */
const MAX_KEYS = 16;
const CONTROL = /[\u0000-\u001f\u007f]/u;

const WITHHELD: MappingUseResult = Object.freeze({ version: 1, code: 'WITHHELD' } as const);

function refuse(): never { throw new TypeError('Invalid bound file presence configuration'); }

/* ---------------------------------------------------------------------------------------------
 * Defensive readers for the two values crossing this boundary. Own data descriptors only, bounded
 * keys, no getters and no inherited properties, so one snapshot is what every later check reads.
 * This decides **shape** and nothing else: the authority parser is the executor's, not this file's.
 * ------------------------------------------------------------------------------------------- */
type Fields = Record<string, unknown>;

function snapshot(value: unknown, required: readonly string[]): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse();
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== 'string')) refuse();
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key)) refuse();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) refuse();
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) refuse();
  return result;
}
function text(value: unknown, limit: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > limit ||
    CONTROL.test(value) || value.trim() !== value) refuse();
  return value;
}
/** One leaf component. The single rule that also refuses traversal and multi-component names. */
function leaf(value: unknown): string {
  const name = text(value, LEAF_LIMIT);
  if (name === '.' || name === '..' || name.includes('/') || isAbsolute(name)) refuse();
  return name;
}
/** One owned copy of the identifier. The declared length is validated before any allocation. */
function identifier(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) refuse();
  const declared: unknown = value.byteLength;
  if (typeof declared !== 'number' || !Number.isSafeInteger(declared) || declared < 1 ||
    declared > IDENTIFIER_LIMIT) refuse();
  const copy = new Uint8Array(declared);
  try {
    for (let index = 0; index < declared; index += 1) {
      const byte: unknown = value[index];
      if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 0xff) {
        copy.fill(0);
        refuse();
      }
      copy[index] = byte;
    }
  } catch (error) {
    // A byte source that throws mid-copy leaves a partial owned copy behind; it is overwritten here
    // rather than abandoned, so a hostile source never keeps an uncleaned identifier buffer.
    copy.fill(0);
    throw error;
  }
  return copy;
}

/* ---------------------------------------------------------------------------------------------
 * The bound target, established once by the trusted constructor.
 * ------------------------------------------------------------------------------------------- */
/** The construction-bound identity of the leaf. `null` when it was not a regular file back then. */
interface BoundIdentity { readonly dev: number; readonly ino: number }

/**
 * The trusted root. Absolute, free of traversal, not a symbolic link, canonicalized and then
 * re-stat'ed as a real directory. Every native call in this function is trusted setup metadata, not
 * a per-call effect, and a refusal here happens before any file at this root is opened.
 */
function trustedRoot(value: unknown): string {
  const root = text(value, PATH_LIMIT);
  if (!isAbsolute(root)) refuse();
  const parts = root.split('/');
  for (let index = 1; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === undefined || part.length === 0 || part === '.' || part === '..') refuse();
  }
  const stats = STAT(root);
  if (stats.isSymbolicLink() || !stats.isDirectory()) refuse();
  const canonical = CANONICALIZE(root);
  const resolved = text(canonical, PATH_LIMIT);
  // The canonical path is re-checked as a real directory rather than trusted: `realpathSync`
  // resolved a path, and this module binds a directory it has itself observed.
  const canonicalStats = STAT(resolved);
  if (canonicalStats.isSymbolicLink() || !canonicalStats.isDirectory()) refuse();
  return resolved;
}

/**
 * The bound leaf's observed identity. A leaf that is absent, a link or not a regular file at
 * construction binds no identity: the effect may then still report an honest absence, but any
 * regular file that exists at that name later is a substitution and is refused.
 */
function boundIdentity(path: string): BoundIdentity | null {
  let stats;
  try {
    stats = STAT(path);
  } catch (error) {
    if (absent(error)) return null;
    refuse();
  }
  if (stats.isSymbolicLink() || !stats.isFile()) return null;
  return Object.freeze({ dev: stats.dev, ino: stats.ino });
}

/* ---------------------------------------------------------------------------------------------
 * The private backend. One primitive boolean in, nothing out, and no bytes retained.
 * ------------------------------------------------------------------------------------------- */
/** Whole-buffer equality, as one boolean: no byte and no length ever crosses an assertion here. */
function matches(recovered: Uint8Array, provisioned: Uint8Array): boolean {
  if (recovered.byteLength !== provisioned.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < provisioned.byteLength; index += 1) {
    difference |= (recovered[index] ?? 0) ^ (provisioned[index] ?? 0);
  }
  return difference === 0;
}
/** `ENOENT` is the one native answer that is an honest absence. Everything else is a fault. */
function absent(error: unknown): boolean {
  try {
    return error !== null && typeof error === 'object' &&
      (error as { readonly code?: unknown }).code === 'ENOENT';
  } catch { return false; }
}

/**
 * The whole per-call native effect, in one synchronous continuation with no `await`, no host
 * property read and no dynamic function lookup. The order is fixed and it is the honest one: compare
 * the recovered bytes with the private identifier **before** the first native function runs, so a
 * recovered identifier that is not the private one is a reached effect that could not be completed -
 * never an `ENOENT` and never the `NOT_FOUND` this module reserves for one. Only then open with
 * `O_NOFOLLOW` so a link is refused by the kernel, `fstat` the descriptor that was actually opened,
 * require a regular file, require the construction-bound identity, and close in a `finally`. The
 * recovered bytes are read once and dropped; nothing here decodes, stores, logs or forwards them.
 *
 * A nonregular or substituted target, an identifier that is not the private one, and every fault
 * other than `ENOENT`, throw. The backend has no vocabulary of its own: the executor already reports a
 * throwing backend inside its sealed segment as a reached effect that could not be completed, which is
 * exactly the honest code, and never a `USE`. Every message below is a fixed literal: no path, no
 * identifier, no byte and no native text is ever carried out of this function.
 */
function probe(path: string, identity: BoundIdentity | null, provisioned: Uint8Array,
  recovered: Uint8Array): boolean {
  if (!matches(recovered, provisioned)) {
    throw new Error('recovered identifier is not the provisioned one');
  }
  let descriptor: number;
  try {
    descriptor = OPEN(path, READ_ONLY);
  } catch (error) {
    if (absent(error)) return false;
    throw error;
  }
  try {
    const observed = FSTAT(descriptor);
    if (observed.isSymbolicLink() || !observed.isFile()) throw new Error('not a regular file');
    if (identity === null || observed.dev !== identity.dev || observed.ino !== identity.ino) {
      throw new Error('not the bound target');
    }
    return true;
  } finally {
    CLOSE(descriptor);
  }
}

/* ---------------------------------------------------------------------------------------------
 * The private host. Shape is checked here so a caller cannot smuggle a key past the executor; the
 * values themselves are the host's own, and `createBoundMappingUse` re-reads and re-validates all of
 * them, in full, before any effect can exist.
 *
 * The executor applies every host callback method with **its own** copy of the host as the receiver,
 * so the object that reaches an external callback would be this decorated copy - backend and all. The
 * two callbacks are therefore captured here as the caller's own methods and handed over as
 * synchronous forwarders over the captured `Reflect.apply`: each one invokes its captured method on
 * the caller's own host object and returns that answer unchanged, a value or a promise alike. No
 * extra await and no re-normalization is introduced, and the decorated copy - the only object that
 * carries the private backend - is never an argument and never a receiver.
 * ------------------------------------------------------------------------------------------- */
const HOST_KEYS = ['version', 'mappingRef', 'scope', 'entityId', 'registry', 'audit', 'policy',
  'authority', 'material'] as const;

function privateHost(value: unknown, backend: MappingUseBackend) {
  const v = snapshot(value, HOST_KEYS);
  if (v.version !== 1) refuse();
  const authority = v.authority;
  const material = v.material;
  if (typeof authority !== 'function' || typeof material !== 'function') refuse();
  const receiver = value as object;
  return Object.freeze({
    version: 1 as const,
    mappingRef: v.mappingRef as string,
    scope: v.scope as MappingUseScope,
    entityId: v.entityId as string,
    registry: v.registry as MappingMetadataRegistry,
    audit: v.audit as MappingUseAudit,
    policy: v.policy as MappingUsePolicy,
    backend,
    authority: (): unknown => REFLECT_APPLY(authority as () => unknown, receiver, []),
    material: (): unknown => REFLECT_APPLY(material as () => unknown, receiver, []),
  });
}

/* ---------------------------------------------------------------------------------------------
 * Construction. One owned identifier copy, one bound path, one bound identity, one private backend,
 * one delegated executor. Missing or malformed configuration is not an exception and carries no
 * native error text: it yields a handle that refuses every call before any native function is reached.
 * ------------------------------------------------------------------------------------------- */
export function createBoundFilePresence(hostValue: unknown,
  targetValue: unknown): BoundFilePresence {
  /** Owned, mutable state. Every field here belongs to this module, never to the caller. */
  let owned: Uint8Array | null = null;
  let path: string | null = null;
  let identity: BoundIdentity | null = null;
  let executor: BoundMappingUse | null = null;
  let disposed = false;

  try {
    const record = snapshot(targetValue, ['version', 'identifier', 'root', 'leaf']);
    if (record.version !== 1) refuse();
    owned = identifier(record.identifier);
    // Every shape check, including the leaf, is settled before the first native function runs, so a
    // malformed record costs no metadata stat and no effect.
    const name = leaf(record.leaf);
    const bound = trustedRoot(record.root);
    path = `${bound}/${name}`;
    identity = boundIdentity(path);
    const provisioned = owned;
    const backend: MappingUseBackend = Object.freeze({
      lookup(recovered: Uint8Array): boolean {
        // Read from this module's own state only. A disposed or unbound target refuses before the
        // first native call, and the throw is the executor's `FAILED`, never a claim of presence.
        if (disposed || path === null || provisioned === null) {
          throw new Error('bound file presence target is unavailable');
        }
        return probe(path, identity, provisioned, recovered);
      },
    });
    executor = createBoundMappingUse(privateHost(hostValue, backend));
  } catch {
    // Configuration is usable or it is not: one restrictive handle, no supplied value, no native
    // error text, and the partial identifier copy this module already owned is cleared.
    if (owned !== null) owned.fill(0);
    owned = null;
    path = null;
    identity = null;
    executor = null;
  }

  const use = async (): Promise<MappingUseResult> => {
    if (disposed || executor === null) return WITHHELD;
    return executor.use();
  };
  const dispose = (): void => {
    disposed = true;
    executor = null;
    path = null;
    identity = null;
    if (owned !== null) {
      owned.fill(0);
      owned = null;
    }
  };
  return Object.freeze({ handle: Object.freeze({ use }), dispose });
}