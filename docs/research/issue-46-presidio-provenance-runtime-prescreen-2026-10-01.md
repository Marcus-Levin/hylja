# Presidio provenance verification and anonymizer runtime prescreen — 2026-10-01

**AI-prepared follow-up research for [#46](https://github.com/Marcus-Levin/hylja/issues/46), not independently reviewed and not an adoption, comparative or #39 scoring result.** It continues, and does not edit, the dated [2026-10-01 artifact dossier](issue-46-presidio-artifact-prescreen-2026-10-01.md); current capabilities and limits live only in [docs/capabilities.md](../capabilities.md), live campaign status only in the GitHub issues, and the dated campaign record is the retired plan's [frozen snapshot](https://github.com/Marcus-Levin/hylja/blob/f838fc2dc8da0402338d4dfd1c028392a9f4b9ee/docs/plan.md#current-state), not current state.

Two things changed since that dossier. First, the PEP 740 / Sigstore attestation bundles it recorded as *parsed but not cryptographically verified* have now been **verified**, check by check, against a trust anchor corroborated from two independent public sources, with the certificate's workflow/run/source claims compared against independently fetched GitHub records. Second, the **minimum** runtime dependency set for a Presidio *anonymizer* smoke has been screened, pinned and executed inside an ephemeral, network-less, unprivileged sandbox on obviously synthetic in-memory values. No analyzer, NLP engine, model weight or hosted service was downloaded or run; no scored comparison, candidate tuning, pre-tuning lock, blind custody, mapping state or production effect is claimed.

## What was selected, and what was not

| Role | Artifact | SHA-256 (downloaded bytes) | Origin |
| --- | --- | --- | --- |
| attested candidate (already selected) | `presidio_analyzer-2.2.364-py3-none-any.whl` | `0a9eeb60ccc416c505367b4989d056becb84ef082703ee3361c046fb75941739` | [PyPI integrity/provenance](https://pypi.org/integrity/presidio-analyzer/2.2.364/presidio_analyzer-2.2.364-py3-none-any.whl/provenance) |
| attested candidate (already selected) | `presidio_anonymizer-2.2.364-py3-none-any.whl` | `f3edfe80b5e83a22976439727e9d449c796b12efdf6cd70a6db860d4942a6b72` | [PyPI integrity/provenance](https://pypi.org/integrity/presidio-anonymizer/2.2.364/presidio_anonymizer-2.2.364-py3-none-any.whl/provenance) |
| trial runtime dependency | `cryptography-48.0.1-cp311-abi3-manylinux_2_34_x86_64.whl` | `0ee6ea481db1ab889cba043ec1eda17bb9c1ea79db6722f779c3667f9f70322f` | [PyPI](https://pypi.org/project/cryptography/48.0.1/) |
| trial runtime dependency | `cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96` | [PyPI](https://pypi.org/project/cffi/2.1.1/) |
| trial runtime dependency | `pycparser-3.0-py3-none-any.whl` | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` | [PyPI](https://pypi.org/project/pycparser/3.0/) |

`presidio-anonymizer==2.2.364` declares exactly one mandatory dependency, `cryptography>=48.0.1,<49.0.0`, which in turn requires `cffi` and `pycparser`; that is the whole pinned set for this smoke. `presidio_analyzer` was **not installed or executed**: installing it would pull `spacy`, `numpy`, `pydantic`, `regex`, `tldextract`, `phonenumbers`, `click`, `pyyaml` and, at analyzer construction, a downloaded spaCy model. Those remain unselected, unscreened and undownloaded, and the analyzer's own runtime prescreen is still incomplete.

The two provenance objects used here were fetched fresh from PyPI's Integrity API and are **canonically identical** (same key-sorted JSON bytes) to the copies in the dossier directory; only their whitespace differs. Each attestation's in-toto subject digest equals the SHA-256 of the wheel bytes on disk, so the signature is bound to exactly the artifacts screened by the earlier dossier.

## Specification and trust anchor actually used

* [PEP 740](https://peps.python.org/pep-0740/) is now historical; the canonical, current specification is the PyPA [Index hosted attestations](https://packaging.python.org/en/latest/specifications/index-hosted-attestations/) document, whose *Attestation verification* section requires: `version` is 1; the certificate is valid under an a priori trusted authority and identifies an appropriate signing subject; the statement is a valid in-toto v1 statement whose subject name and digest match the distribution filename and contents; the signature is a valid v1 **DSSE** signature for the statement under that certificate; and, when transparency entries are verified, each entry's inclusion time must lie inside the signing certificate's validity period. PyPI's own pages ([guide](https://docs.pypi.org/attestations/), [publish predicate v1](https://docs.pypi.org/attestations/publish/v1/), [security model](https://docs.pypi.org/attestations/security-model/)) add that the publish predicate conveys the Trusted Publisher through the *signing identity*, with a null predicate body.
* Verification used **no trust store on this host and no global configuration**. A single trust-anchor file was pinned by digest and cross-checked from two independent public sources before use:
  1. the resource `trusted_root.json` shipped inside the PyPI-published `sigstore` 4.5.0 wheel (`sha256 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`, whose wheel digest is recorded below);
  2. the Sigstore TUF repository's signed `targets` metadata, version 14, at `https://tuf-repo-cdn.sigstore.dev/14.targets.json` (`sha256 6a697f7f8908c8ab26c11786ecb490b54acec97fa8c802e399f065f8a0cc1acd`), which lists `trusted_root.json` with **exactly that SHA-256**.
* The TUF metadata itself was checked offline rather than trusted for its transport: `15.root.json` (`sha256 73747011d0857ada15479a16c4cae0f3ed03aac698b523b97e1de314ac9d9ca8`, version 15, expires 2026-11-20) carries 5 valid signatures from its own 6 keys against a threshold of 3, and `14.targets.json` carries 5 valid signatures from those same root keys against a threshold of 3. Signature verification used `securesystemslib`'s canonical TUF serialization; root and targets metadata were fetched over HTTPS from the canonical CDN but their **key history was not walked**, so this is "the current root signs these roles", not a full TUF update path.
* Treating the Sigstore public-good Fulcio roots and the Rekor/CT log keys as anchors is a **research assumption for this screen**, not a Hylja trust policy, pinning decision or `approved` gate. The Fulcio roots carried in the pinned trust anchor are `CN=sigstore,O=sigstore.dev` with SHA-256 `03a38ffb1f450100c2596d1d10b900ac4d504058006dda58199576bbeb9c73d0` (valid 2021-03-07→2031-02-23) and `3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1` (valid 2021-10-07→2031-10-05), plus intermediate `CN=sigstore-intermediate,O=sigstore.dev` `15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47`.

## Per-check verification results

Both wheels produced the same outcome set: **31 PASS, 0 FAIL, 0 UNVERIFIED** each (62 checks total). Checks are reported separately rather than collapsed into one verdict, and every check that a library performed is named. The count was 62 for the run described here; the follow-up commit that corrected this document's accuracy defects added one further counted check per artifact (the transparency-log-key comparison above, now `transparency_log_id_is_in_pinned_anchor`), so the corrected verifier reports **32 PASS per artifact, 64 in total**, with every other verdict unchanged — see [the plan](https://github.com/Marcus-Levin/hylja/blob/f838fc2dc8da0402338d4dfd1c028392a9f4b9ee/docs/plan.md#current-state) for the head that carries the correction.

| Check | Verdict | How it was established |
| --- | --- | --- |
| PEP 740 object version is 1 | PASS | parsed field |
| attestation `version` is 1 | PASS | parsed field |
| one bundle, one attestation, one transparency entry | PASS | structure |
| leaf is an end-entity code-signing certificate | PASS | no `BasicConstraints` CA flag, `KeyUsage.digitalSignature`, EKU `codeSigning` (no `BasicConstraints` extension present at all, recorded) |
| leaf signed by a Fulcio issuer present in the pinned trust anchor | PASS | `cryptography` ECDSA verification of leaf over issuer public key |
| that intermediate is signed by a self-signed Fulcio root in the same anchor | PASS | `cryptography` verification, both candidates tried (two roots share one subject DN) |
| **DSSE v1 signature over the PAE of the statement** | PASS | recomputed locally (`DSSEv1 <len> application/vnd.in-toto+json <len> <statement>`) and verified with `cryptography` ECDSA/SHA-256 under the leaf public key |
| same PAE, computed by `sigstore-python`'s own envelope parser | PASS | second, independent code path over the same wire JSON |
| in-toto subject: exactly one subject, name equals the wheel filename, SHA-256 equals the wheel bytes | PASS | recomputed |
| **RFC 6962 inclusion proof** against the checkpoint root hash | PASS | Merkle proof recomputed here (leaf hash, index/tree-size decomposition, node chaining), not taken from a library |
| **Rekor v2 signed entry timestamp (inclusion promise)** | PASS | `sigstore-python` 4.5.0 `log_entry._verify(trusted rekor keyring)` |
| **signed checkpoint** (tree size and root hash, checkpoint signature) | PASS | same call; checkpoint declares tree size `2094891788` (anonymizer) / `2094891879` (analyzer), matching the entry's `treeSize` |
| transparency log key is one of the pinned anchor's log keys | PASS | the entry's `logId.keyId` `wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=` is base64 of `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d`, the key of the anchor's `rekor.sigstore.dev` entry (the other anchor key, `log2025-1.rekor.sigstore.dev`, is `zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=`) |
| inclusion time inside the certificate's validity window | PASS | integrated times 2026-07-22T07:54:31Z / 07:54:32Z inside 10-minute leaf windows |
| embedded precertificate SCT | PASS | `sigstore-python` `verify_sct` against the anchor's CT keyring |
| certificate key-usage / EKU profile | PASS | as above |
| **end-to-end reference verification** with `pypi-attestations` 0.0.30 `GitHubPublisher(repository="data-privacy-stack/presidio", workflow="release.yml")`, `offline=True` | PASS | official PyPA library; returned predicate `https://docs.pypi.org/attestations/publish/v1`, predicate body `null` |
| SAN URI equals the expected Trusted Publisher identity | PASS | `https://github.com/data-privacy-stack/presidio/.github/workflows/release.yml@refs/heads/main`, built from independently fetched GitHub records, not from the certificate |
| OIDC issuer extension | PASS | `https://token.actions.githubusercontent.com` |
| source repository URI / digest / ref | PASS | match the fetched repo `html_url`, run `head_sha`, run `head_branch` |
| build config URI | PASS | equals the expected identity above |
| build trigger, run invocation URI, repository visibility | PASS | `workflow_dispatch`; `…/actions/runs/29901897108/attempts/1`; `public` |
| build config digest claim | PASS (with correction) | the claim `1.3.6.1.4.1.57264.1.19` is the **commit SHA**, not a digest of the workflow file; it equals the fetched run `head_sha`. The independently fetched workflow file at that commit is 7,340 bytes, `sha256 65d4e9adb71f6bc478de1ca56a0748a1701c0a1b435e70b3e8b870a952d92ac3`, and its computed git blob SHA-1 `373ca6ce2c0f4b835224a233ccc450d2f76d01b0` equals the blob SHA GitHub's contents API reports for that path at that commit |
| publisher metadata in the provenance object | PASS | repository/workflow equal the independently fetched repository and active workflow `182052767` (path `.github/workflows/release.yml`) |

Independently fetched public records used as the expected identity (GitHub REST, no credentials, no auth API): repository `data-privacy-stack/presidio` (`full_name`, `html_url`, `default_branch=main`, `visibility=public`); workflow `release.yml` → id `182052767`, path `.github/workflows/release.yml`, state `active`; run `29901897108` → `head_sha 636cadd91675c61c71923d8d68eaa9511073826a`, `head_branch main`, `event workflow_dispatch`, `conclusion success`, created `2026-07-22T07:53:51Z`, attempt 1; commit `636cadd…` exists; the workflow file exists at that commit; tag `2.2.364` → `779dbd286d5ef4d1fbe2514275fb1bce358f2417`.

### What the verification does and does not establish

Established: the bytes of these two files were signed by a short-lived Fulcio certificate that chains to the pinned Sigstore roots; the signature covers an in-toto v1 statement whose subject is exactly these filenames and SHA-256 values; the statement was logged in the Rekor v2 public-good instance whose key is in the same pinned anchor, with a verifiable inclusion proof, checkpoint and signed entry timestamp, at a time inside the certificate's validity; and the certificate's identity matches the PyPI Trusted Publisher for `data-privacy-stack/presidio` / `release.yml`, whose GitHub-side claims agree with GitHub's own public records.

**Not established, and not to be read as established:**

* **Build provenance.** The only published attestation is the *publish* predicate with a null body. There is **no SLSA provenance attestation** for either file, so nothing here binds the wheel *contents* to a source tree, build recipe or builder. The certificate says a workflow ran from commit `636cadd…`; it does not attest what that workflow produced byte-for-byte, and no reproducible-build comparison was performed.
* **Signature ≠ honest publisher.** A valid signature proves who signed, not that the build was clean. A compromised workflow at that commit would produce an equally valid signature.
* **Trust-anchor independence.** Both anchor sources ultimately descend from Sigstore infrastructure; a compromise of Sigstore's root signing, the TUF CDN or the wheel distribution channel would not be detected here.
* Fulcio's legacy extensions `1.3.6.1.4.1.57264.1.1`–`.6` are present but encode their values as `OtherName`; they were recorded as undecodable rather than guessed.
* The two attestations cover only these two wheels. The sdists remain unselected, unsigned and uninspected, no PGP signature exists for either wheel, the wheels still package **no** LICENSE/NOTICE file (40 members, `.dist-info` holds only `METADATA`, `WHEEL`, `RECORD`), and the MIT permission grant for synthetic local evaluation therefore still rests on the source LICENSE plus the metadata declaration rather than on a redistributed notice.
* Verification ran **offline** against a pinned trust root. A rotated trust root would fail these checks rather than silently pass; equally, this run did not observe what the current live trust root says today.

## Screened trial runtime: dependency and advisory findings

`cryptography` was resolved to **48.0.1**, which is both the floor declared by `presidio-anonymizer` and the newest release in the 48.x line. Every downloaded artifact's SHA-256 was compared with an independently fetched PyPI metadata record, its **actual wheel** `METADATA` was read for the license expression and Python requirement, and an OSV PyPI version query was run for it.

The helper that produced this screen has since been hardened for bounded, pin-first work (see `scripts/research/prescreen_pypi_artifacts.py`): local bytes are streamed through a fixed size ceiling and digested **before** the archive is opened, an absent or mismatched index pin is refused before any member is parsed, member count, per-member size, metadata size and metadata compression ratio are bounded, and every failure is a fixed code that never echoes a file name, member name, request URL or response body. Re-running the hardened helper over the same 38 downloaded artifacts (4 runtime + 34 verifier wheels) and the same independent index records reproduced, for every one of them, the SHA-256, byte size, license expression, Python requirement, native-code flag, archive-entry count and advisory identifiers recorded in that run's inspection JSON — the `<output-json>` file the helper writes, which is **not** committed here; neither artifact table below carries an archive-entry column, so the entry count comes from that JSON and not from these tables. Two field definitions changed in that hardening, and neither of them changes the enumerated list above. (1) The helper now reports archive **entries** (every `infolist()` record, so directory entries are included) separately from **file members**; the count its earlier record called `zip_members` was the whole `namelist()`, i.e. that same entry count, and the 40/40 member figure in the observations below is a **file-member** count. (2) Package identity is now read from the artifact's **own `METADATA: Name:` field**, so for the 38 recorded artifacts it carries that artifact's declared spelling — for example `presidio_anonymizer` for the anonymizer wheel, whose file name also spells the package with underscores and whose recorded artifact JSON and every table here use the normalized hyphenated index key `presidio-anonymizer` that the index request itself still sends. Where that field is absent or fails the helper's grammar, `package_name` falls back to the file-name-derived spelling instead. Package identity is therefore not one of the fields enumerated as reproduced above, and the earlier record's normalized spelling differs from the re-run value in that field alone. **That is a supply-chain hygiene check, not a provenance check:** it re-establishes byte agreement with the index and the recorded metadata, and it does not re-verify the signed attestation bundles, which remain exactly as verified above.

| Artifact | License expression (from the wheel) | Native code | OSV records for the pinned version |
| --- | --- | --- | --- |
| `presidio-anonymizer` 2.2.364 | MIT | no | none |
| `cryptography` 48.0.1 | Apache-2.0 OR BSD-3-Clause | yes (`cryptography/hazmat/bindings/_rust.abi3.so`) | **6 records → 3 distinct advisories** |
| `cffi` 2.1.1 | MIT-0 | yes | none |
| `pycparser` 3.0 | BSD-3-Clause | no | none |

The three `cryptography` advisories (all published 2026-08-03/04, GitHub-reviewed) are:

| Advisory | Severity | Range | Fixed in | Reachable from the exercised anonymizer path? |
| --- | --- | --- | --- | --- |
| `GHSA-g6cj-pr64-35w5` (PKCS#7 `EnvelopedData` decryption Bleichenbacher oracle, CWE-208/209) | HIGH | ≥44.0.0 | 50.0.0 | no — the anonymizer imports only `Cipher`, `algorithms`, `modes` and `padding` from `cryptography.hazmat.primitives` |
| `GHSA-jwv3-5hgf-82ww` (duplicate self-signed intermediates cause exponential path building, CWE-400) | HIGH | ≥42.0.0 | 49.0.0 | no — X.509 path building is not used |
| `GHSA-m2h6-j472-rp4c` (verifier accepts wildcard DNS names vs `permittedSubtrees`, CWE-295) | MODERATE | ≥45.0.0 | 49.0.0 | no — no name verification is used |

This is a real and unfavourable finding, stated plainly: **`presidio-anonymizer` 2.2.364 declares `cryptography<49.0.0`, and no version inside that declared range is free of these three advisories.** The two HIGH items are not reachable through the anonymizer's own cryptography usage, but that is a statement about this one code path, not a clearance, and it is an adoption blocker candidate for any wider use of the stack. Moving to `cryptography` 49/50 would violate the upstream declared range and was not done.

## Isolated anonymizer smoke

Isolation (root-verified unprivileged `bwrap`, `--unshare-all` = user, PID, network, IPC, UTS and cgroup namespaces): cleared environment; no host home, repository, agent, credential or data mount; read-only access to the system runtime (`/usr`, `/bin`, `/lib`, `/lib64`) and to the screened work directory; private tmpfs `/tmp`; **no network at execution time**; `RLIMIT_AS` 2 GiB, `RLIMIT_CPU` 240 s, `RLIMIT_FSIZE` 16 MiB, `RLIMIT_NPROC` 64, `RLIMIT_NOFILE` 1024, `RLIMIT_CORE` 0, plus a 300 s whole-run wall-clock kill and a 120 s per-step deadline enforced by the driver. Nothing in the run was privileged and nothing ran on the host outside this sandbox. The isolation was **not** relaxed to work around any error.

**What those bounds are, precisely.** `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE` and `RLIMIT_CORE` are **per process**, and `RLIMIT_NPROC` is **per real UID**; none of them is an aggregate bound over a process tree, and `--unshare-cgroup` only namespaces the hierarchy — it sets no `memory.max`, `cpu.max` or `pids.max`. bubblewrap 0.11.1 offers no `--rlimit` option, which is why the limits are applied by a prelude inside the sandbox. The process cap was lowered from 512 to 64 to suit a one-process smoke, and the per-step output ceiling is enforced separately from the rlimits: `RLIMIT_FSIZE` bounds regular files but **not** pipes, so child stdout/stderr are read one 64 KiB chunk at a time, counted and **dropped** — nothing accumulates across reads and no child byte is carried into any report, though each chunk is transiently materialised in the reader before it is counted, and because the ceiling is tested after a chunk is counted the reported total can overshoot the cap by at most one chunk — and the child's process group is killed with `OUTPUT_LIMIT_EXCEEDED` once the ceiling is crossed. **Runtime-execution gate:** an aggregate memory/CPU/process bound is not available to this screen without privileges, so concurrent amplification inside the sandbox remains bounded only by per-process limits and the fixed number of steps; treat any workload that forks as outside what this screen measured.

Two sandbox-specific facts worth recording: this host's Python ships no `ensurepip` wheels, so `python -m venv` cannot bootstrap pip offline; the trial therefore used `venv --without-pip` plus a strict, reviewable offline installer that unpacks exactly the four screened wheels, refuses absolute/traversal/symlink/oversize members, and re-reads every written file to confirm its digest.

Candidate output was treated as untrusted. In the run recorded here the child's stdout and stderr were read over pipes in bounded chunks, counted and dropped with no accumulation and nothing carried into the report (`retained_bytes` 0; the child's own streams were empty apart from the trusted-side installer's 254-byte summary), the child's result file was accepted only through the fixed schema, and no candidate byte, traceback or exception text entered this document. **That is a statement about this recorded run, not a general property of the tooling:** the correction commit for this document's accuracy defects also replaced the schema's key/type allowlist (which bounded slots but not values) with booleans, range-checked integers and fixed codes only, and the driver now emits one complete report with fixed step outcomes for floods, timeouts and spawn failures — see [the plan](https://github.com/Marcus-Levin/hylja/blob/f838fc2dc8da0402338d4dfd1c028392a9f4b9ee/docs/plan.md#current-state).

Narrow observations (booleans, counts and versions only — no planted value, no mapping, no raw output):

| Observation | Result |
| --- | --- |
| offline install of the 4 pinned wheels | exit 0 |
| installed tree vs screened wheel members | 40/40 members byte-identical, `installed_tree_check_completed=true` and, only because that is true, `installed_tree_matches_screened_wheel=true` |
| `presidio-anonymizer` installed version | equals the recorded pin `2.2.364` (compared by the **driver**, on the trusted side, reading installed `METADATA` with a strict grammar; the child supplies no string) |
| `cryptography` installed version | equals the recorded pin `48.0.1` (same trusted-side comparison) |
| Python (driver's own interpreter) | 3.14 |
| declared API symbols | importable, 6 of the 6 declared symbols present |
| `AnonymizerEngine()` constructed | yes |
| `mask` operator on a synthetic in-memory value | output length 92, `differs_from_input=true`, `planted_value_absent_from_output=true`, 1 engine item, reported entity type matches the expected `PERSON` (boolean, not the string) |
| `hash` operator (`hash_type=sha256`) on the same synthetic value | output length 131, `differs_from_input=true`, `planted_value_absent_from_output=true`, length stable across calls, values differ across calls (this version salts each entity with fresh `os.urandom`) |
| reversible operators exercised | **no** — `encrypt`/`decrypt`/`deanonymize` were deliberately not run, so no mapping state exists anywhere in this trial |
| NLP engine, model weights or hosted calls | none downloaded or used |

The plant is a literal placeholder string plus an RFC 2606 `.invalid` address held in that process' memory during the run. It is **also** the tracked source constant `PLANTED` in [`scripts/research/smoke_child.py`](../../scripts/research/smoke_child.py), i.e. public obviously-synthetic source-fixture ground truth committed on purpose, not a runtime secret. What is accurate for this trial is narrower: no raw candidate **result** and no mapping was committed, the value was not written into a fixture, a log or this document, and no transformed output text was recorded anywhere. The `mask`/`hash` runs are **unscored development evidence**: they show that the declared API wires up and transforms an obviously synthetic span inside the isolation described. They are not a comparative result, not evidence about detection quality, not a protected-egress boundary demonstration, and not a substitute for Hylja's own #19 final-byte check.

## Explicit gaps carried forward

* **No analyzer runtime at all**: `presidio_analyzer` and its eight mandatory dependencies (including `spacy`) are unscreened and undownloaded, and no recognizer, NLP configuration, language model or weight file has been selected. Detector quality, `spacy` model supply and the analyzer's own advisory and license posture are unknown.
* **Transitive depth**: only the anonymizer's three non-anonymizer dependencies are pinned. Any wider stack, image, hosted service (Azure/OpenAI/Jev extras) or the sdists remain unprescreened.
* **Provenance scope**: publish-only attestations for two wheels; no build attestation, no reproducible build, no signature on the sdists, no packaged license notice in either wheel.
* **`cryptography` 48.0.1** carries two HIGH and one MODERATE advisory with no in-range fix; only this narrow code path avoids the affected APIs.
* **Maintenance, SBOM, exit/replacement path and full legal/commercial review** remain the later adoption gate, untouched by this screen.
* Nothing here decides [#48](https://github.com/Marcus-Levin/hylja/issues/48), scores [#40](https://github.com/Marcus-Levin/hylja/issues/40)/[#43](https://github.com/Marcus-Levin/hylja/issues/43), freezes any part of [#39](https://github.com/Marcus-Levin/hylja/issues/39), or establishes any production privacy boundary.

## Reproducing this screen

The pinned inputs are the four digests above, the pinned trust-anchor digest `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`, the TUF metadata digests in the specification section, and the verifier tools in the table below, which were installed into a private virtualenv from PyPI-published wheels only (`--only-binary=:all:`, digests independently compared, licenses and OSV records recorded) and used with `offline=True`/no network:

| Artifact | Version | SHA-256 | Bytes | License (wheel) | Native | OSV |
| --- | --- | --- | --- | --- | --- | --- |
| `annotated-types` | 0.8.0 | `f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0` | 13427 | MIT | no | 0 |
| `certifi` | 2026.7.22 | `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775` | 136983 | MPL-2.0 | no | 0 |
| `cffi` | 2.1.1 | `b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96` | 221525 | MIT-0 | yes | 0 |
| `charset-normalizer` | 3.5.2 | `34276fd796040bf0993ab33a369aa572e6979c7aab225a88893667ad8eac8f7a` | 255056 | MIT | yes | 0 |
| `cryptography` | 50.0.2 | `9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079` | 4752576 | Apache-2.0 OR BSD-3-Clause | yes | 0 |
| `dnspython` | 2.8.0 | `01d9bbc4a2d76bf0db7c1f729812ded6d912bd318d3b1cf81d30c0f845dbf3af` | 331094 | ISC | no | 0 |
| `email-validator` | 2.3.0 | `80f13f623413e6b197ae73bb10bf4eb0908faf509ad8362c5edeb0be7fd450b4` | 35604 | Unlicense | no | 0 |
| `id` | 1.6.1 | `f5ec41ed2629a508f5d0988eda142e190c9c6da971100612c4de9ad9f9b237ca` | 14689 | (no License field) | no | 0 |
| `idna` | 3.20 | `ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c` | 69583 | BSD-3-Clause | no | 0 |
| `markdown-it-py` | 4.2.0 | `9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a` | 91687 | (no License field) | no | 0 |
| `mdurl` | 0.1.2 | `84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8` | 9979 | (no License field) | no | 0 |
| `packaging` | 26.3 | `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` | 129956 | Apache-2.0 OR BSD-2-Clause | no | 0 |
| `platformdirs` | 4.12.2 | `29dbf06d96c500bc6bdbce75fb0a14d63279c93b1842f97e72a135b33e856983` | 32457 | MIT | no | 0 |
| `pyasn1` | 0.6.4 | `deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b` | 84410 | BSD-2-Clause | no | 0 |
| `pycparser` | 3.0 | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` | 48172 | BSD-3-Clause | no | 0 |
| `pydantic` | 2.13.5 | `346a034f080da3755d8e9cb5e00e8b07de1d39e4f6e2c87d8ab7cafa0b269a73` | 472589 | MIT | no | 0 |
| `pydantic-core` | 2.46.5 | `54d510bac3ee52247af28ed4bb18a1e799f040ac60fd2bf5ccd4c92f1fbe786f` | 2068352 | MIT | yes | 0 |
| `pygments` | 2.21.0 | `2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9` | 1250147 | BSD-2-Clause | no | 0 |
| `pyjwt` | 2.15.1 | `42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193` | 33860 | MIT | no | 0 |
| `pyopenssl` | 26.4.0 | `f0eb0cb2d581d3ad2b9c489468485e7f2ab6727d08401bcf9d824c3caddf3c1c` | 56026 | Apache License, Version 2.0 | no | 0 |
| `pypi-attestations` | 0.0.30 | `b3a9c53f6cb89e5e7b5b70e6cfca97cfc66008c1ed54087355e06e40071cef21` | 23015 | Apache-2.0 | no | 0 |
| `requests` | 2.34.2 | `2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0` | 73075 | Apache-2.0 | no | 0 |
| `rfc3161-client` | 1.0.9 | `fac3f440a507555e684dc5daba75e33dc08f0f45fdefa48448f19001233a6b21` | 2415566 | (no License field) | yes | 0 |
| `rfc3986` | 2.0.0 | `50b1502b60e289cb37883f3dfd34532b8873c7de9f49bb546641ce9cbd256ebd` | 31326 | Apache 2.0 | no | 0 |
| `rfc8785` | 0.1.4 | `520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48` | 9240 | (no License field) | no | 0 |
| `rich` | 15.0.0 | `33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb` | 310654 | MIT | no | 0 |
| `securesystemslib` | 1.5.1 | `ada8bdf817da29ece4ba91654f6a162ce7cfbadbc3ae3f840f7313f9d22675de` | 876390 | MIT | no | 0 |
| `sigstore` | 4.5.0 | `f045b207f2e12605cf775ec38e89c5eda625d71ffa7830477db65e47ec2bc8b2` | 111724 | (no License field) | no | 0 |
| `sigstore-models` | 0.0.6 | `5201a68f4d7d0f8bec1e2f4378eb646b084c52609a4e31db8c385095fff68b2e` | 13213 | (no License field) | no | 0 |
| `sigstore-rekor-types` | 0.0.18 | `b62bf38c5b1a62bc0d7fe0ee51a0709e49311d137c7880c329882a8f4b2d1d78` | 20610 | (no License field) | no | 0 |
| `tuf` | 7.0.1 | `d30434bda6e079ab303fb30d1b3006d939a10ca34783b1573d61cd9b802fa45c` | 56253 | Apache-2.0 OR MIT | no | 0 |
| `typing-extensions` | 4.16.0 | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` | 45571 | PSF-2.0 | no | 0 |
| `typing-inspection` | 0.4.4 | `65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147` | 14750 | MIT | no | 0 |
| `urllib3` | 2.8.0 | `0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3` | 135717 | MIT | no | 0 |

The research-only helper scripts used for the offline install, the untrusted-output boundary and the sandbox are in [`scripts/research/`](../../scripts/research/README.md). They were written **after** this screen; the committed copies were then used to re-run both the verification (62 checks, identical verdicts) and the smoke (identical booleans, counts and versions), so the code in the repository is the code that produced the results above. They are not part of `npm test`, CI, the Hylja core or any adapter, must be reviewed as security-sensitive before reuse, and are the route for an independent reviewer to repeat or challenge these results. `selftest.py` is their deterministic, offline self-test: no candidate code, no network and no sandbox. The dated fact from the screen run described above is that it used the earlier 30-test revision of that self-test; its scope, count and pass state are recorded as a dated record, not current state, in the retired plan's [frozen snapshot](https://github.com/Marcus-Levin/hylja/blob/f838fc2dc8da0402338d4dfd1c028392a9f4b9ee/docs/plan.md#current-state), while live task status is in the GitHub issues, so this dossier stays a record of what that one dated run observed.
