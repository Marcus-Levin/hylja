# Bound file-presence effect

Status: contract for [`src/bound-file-presence.ts`](../../src/bound-file-presence.ts) ([#245](https://github.com/Marcus-Levin/hylja/issues/245)), a child of [#24](https://github.com/Marcus-Levin/hylja/issues/24). It adds one real read-only filesystem effect **behind** the existing bound `USE` executor and adds nothing to it. The seams it delegates to own their own contracts and are not restated: [mapping-use.md](mapping-use.md), [mapping-authorization.md](mapping-authorization.md), [policy-contract.md](policy-contract.md), [audit-ledger-contract.md](audit-ledger-contract.md), [mapping-metadata-registry.md](mapping-metadata-registry.md), [mapping-aead.md](mapping-aead.md). Implementation status lives only in [capabilities.md](../capabilities.md); [`test/bound-file-presence.e2e.test.mjs`](../../test/bound-file-presence.e2e.test.mjs) is the authoritative record of every assertion.

## The one operation

`createBoundFilePresence(hostValue, targetValue)` returns `{ handle, dispose }`.

- `handle` is the shipped `BoundMappingUse`. `use()` takes **no argument** and returns one fixed code - `USED`, `NOT_FOUND`, `WITHHELD` or `FAILED` - and nothing else. The caller supplies no path, no leaf, no selector, no operation, no grant and no key, and receives no identifier, no byte, no reason and no file metadata.
- `dispose()` is **trusted construction control**, not caller input. It clears the owned identifier copy, drops the bound path and refuses every later call before any native function is reached. It is idempotent.
- The filesystem backend is **private**. It is supplied internally as the single `MappingUseBackend` the executor binds at construction, and it is not exported, not reachable from the handle and never consulted without the complete authority path behind it. There is no filesystem lookup that can bypass the Policy Engine or authorization, no reference argument, no enumeration and no bulk path, so no direct mapping lookup API exists here ([decision 004](../decisions/004-brokered-vault-no-direct-mapping-api.md)). `USE` never implies `DISPLAY` or `EXPORT`.
- Missing or malformed configuration is **not** an exception and carries no native error text, no supplied value and no errno string: it yields a handle whose `use()` answers `WITHHELD` before any native function runs.

## The closed target record

`{ version: 1, identifier, root, leaf }`, all four fields mandatory, own data descriptors only, no extra, symbol, hidden or accessor field and no inherited prototype.

| Field | Rule |
| --- | --- |
| `identifier` | the private identifier bytes the resource was provisioned with out of band, copied once into an owned buffer; a `Uint8Array` of 1 to the AEAD payload ceiling, read byte by byte, never decoded, retained, logged or forwarded |
| `root` | one absolute directory, 1 to 4096 characters, no control character, no `.` or `..` component, not a symbolic link, canonicalized with `realpathSync`, and the canonical path re-observed as a real directory |
| `leaf` | exactly one component, 1 to 255 characters: no separator, no `.`, no `..`, no leading separator, no control character |

Traversal, an absolute or multi-component leaf, a relative or traversing root, a linked root and a malformed record are all decided **before the first native call**: a refused record costs zero metadata stats, zero opens and zero effects.

## The effect, and what decides it

1. Construction copies the identifier, canonicalizes the trusted root, binds one path and **observes the leaf's identity once**: a regular file binds its `(dev, ino)`, and an absent leaf, a link, a directory or any other nonregular target binds none.
2. Every `use()` runs the shipped executor unchanged. Its grant parser, Policy Engine call, registry read, authorization seam, audit appends, material load, recheck-after-every-callback rule and sealed final continuation are this module's only route to an effect, and it re-implements none of them.
3. After the executor's final guards, in its one sealed continuation, the private backend performs one synchronous `openSync` with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, one `fstatSync` on **the descriptor that was opened**, requires a regular file, requires the observed `(dev, ino)` to be the one bound at construction, and closes in a `finally`.
4. Only then are the recovered bytes compared with the private identifier, byte by byte, as one boolean.
5. The native functions are captured **at module load**, before any guard runs, so a property replaced on `node:fs` afterwards - and a host callback re-pointed after construction - cannot retarget the effect. Inside the backend there is no `await`, no host property read and no dynamic function lookup.

| Outcome | Exactly when |
| --- | --- |
| `USED` | the bound regular file was opened, confirmed against its construction-bound identity, and the recovered bytes equal the private identifier |
| `NOT_FOUND` | the real open returned `ENOENT`; absence is the one native answer this module treats as an answer |
| `WITHHELD` | any executor guard refused - scope, policy, lifecycle, authorization, audit, revision, key, clock or an overlapping call - or the construction was unusable. No open, no `fstat`, no `close` happens on that path |
| `FAILED` | the sealed segment reached the effect and could not complete it: a link (`ELOOP` from `O_NOFOLLOW`), a directory or other nonregular target, a **substituted** inode at the same name, a disposal between the last guard and the backend, or any other native fault |

A target that was not a regular file at construction binds no identity, so it can still report an honest `NOT_FOUND` while it stays absent; any regular file that appears at that name later is a substitution and is refused rather than reported.

## Trusted-directory limit, stated as a limit

Standard Node 22 `fs` has **no portable ancestor-relative `openat` boundary**. This module therefore requires the root's ancestors to be trusted and stable, and requires the root itself not to be a symbolic link. What is enforced here is path syntax, the linked-path case at the leaf, nonregular targets and inode substitution. What is **not** enforced, and is not claimed: an ancestor directory replaced between construction and the effect, a hostile filesystem mutating the path while the effect runs, or confinement against an attacker who controls the directory tree. A checked path is not a confinement claim.

## Other limits

- **Not a bypass of enforcement.** Every effect is behind `createBoundMappingUse`. A refusal anywhere on that path opens nothing, and no effect exists before the sealed continuation.
- **Not a content reader, a writer or a transport.** No file byte is read, no file is written or truncated, no shell runs, no socket opens, nothing is persisted and nothing leaves the process.
- **Not authentication and not a fresh-authority authority.** The host is trusted, not authenticated; the executor's own limits in [mapping-use.md](mapping-use.md) apply unchanged, and the frozen shallow copy of the host configuration handed to the executor means a host callback that mutates its own configuration receives a read-only object.
- **The backend's nonretention duty is a host-class obligation, restated unchanged.** This module reads the recovered bytes once, keeps no reference to them and forwards them nowhere; overwriting its own owned buffers is hygiene, **not** zeroization - engine-held copies, garbage-collected buffers and swapped pages are not covered, and nothing observable from outside proves a particular allocation was erased.
- **Not acceptance.** [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) stays a draft and [decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) stays **proposed**; nothing here adopts a proposal, changes classification v1, policy or any adapter. This child does not complete [#24](https://github.com/Marcus-Levin/hylja/issues/24), deployment authentication, managed filesystem interception, hostile-directory confinement or held-out utility.

## Verification

```text
npm run build && npm run typecheck && node --test test/bound-file-presence.e2e.test.mjs
```

Ten cases over one explicitly ephemeral `mkdtemp` tree with obviously synthetic, non-routable content. **The counters are real native calls, not self-reported module state**: the test wraps the real `node:fs` exports before it dynamically imports the shipped module, every wrapper delegates to the original implementation, and `node:fs` is reached through `createRequire` rather than a static import because a built-in's ESM facade snapshots its exports on first import. Trusted setup metadata operations (`lstatSync`, `realpathSync`) are counted separately from the per-call effect triple (`openSync`, `fstatSync`, `closeSync`).

- A genuine synthetic temporary file yields `USED` from exactly one open, one fstat and one close over three construction-time stats and one canonicalization, with the target byte-for-byte unchanged and no descriptor left open; a genuinely absent target yields `NOT_FOUND` from one open that returned `ENOENT` and no fstat at all.
- Revoked mapping, blocked policy, `DISPLAY` grant, malformed grant, unusable host and expired grant each yield `WITHHELD` with **zero** opens, fstats and closes - and each ships a same-target control that spends the effect, so a zero count cannot be a broken instrument. The expired grant records exactly one attributable `RESOLUTION_DENIED` through the real append and loads no material.
- Fifteen malformed, traversing, absolute, multi-component, NUL, relative, oversized and prototype-carrying target records each yield `WITHHELD` with zero native calls of any kind, no host callback, no material load and an empty ledger; a symbolic-link root is refused at construction after exactly one root stat and with no canonicalization.
- A symlink target, a directory and a substituted inode each refuse with the real open, fstat and close observed and no descriptor leaked; a genuine bound file at its bound identity still spends the effect.
- Caller mutation of the target record and of the identifier buffer, replacement of the host's own callbacks and replacement of `fs.openSync`, `fs.fstatSync` and `fs.closeSync` after construction all fail to retarget the handle: the effect is spent on the construction-bound path.
- Disposal blocks every later call with zero native calls, leaves the caller's own buffer intact, and a disposal raised from inside a host callback refuses the in-flight call before any open, while the identical hook sequence without the disposal spends it.

No assertion receives a recovered identifier, a file body, a protected path or a native error as an operand: codes, counters, booleans and whole-buffer comparisons only.