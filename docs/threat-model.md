# Threat model

Status: foundation threat model. Revisit for each deployment profile and implementation slice.

## Assets

- plaintext originals and reversible mappings;
- encryption/HMAC keys and KMS capabilities;
- policy and authorization configuration;
- provider/harness credentials;
- audit evidence and provenance;
- tenant boundaries and destination profiles;
- evaluation corpora containing restricted incident cases;
- availability of the enforcement path.

## Adversaries and failures

- malicious external model/provider;
- prompt-injected or goal-hijacked agent;
- poisoned MCP/tool/resource/skill content;
- compromised harness or provider adapter;
- malicious or compromised user/workload identity;
- malicious administrator or key operator;
- compromised database/backup/storage;
- compromised application host;
- supply-chain compromise of parser, model, SDK, or dependency;
- accidental developer logging or telemetry leakage;
- classifier false negative or policy misconfiguration;
- denial-of-service/resource-exhaustion input;
- cross-tenant confusion or stale-cache reuse.

## Priority abuse cases

### Exfiltration through non-model sinks

An agent may attempt to leak protected data through HTTP, GitHub, email, Slack, shell/network commands, MCP, memory, logs, or tool arguments rather than the model API. Source-to-sink flow control must cover supported sinks.

### Prompt injection and tool poisoning

Untrusted data may instruct an agent to reveal secrets, alter policy, call privileged tools, or persist malicious instructions. Sensitivity and trust are separate axes. External data never becomes control-plane authority simply because the model repeats it.

### Mapping forgery

An attacker supplies a synthetic-looking token and claims it maps to a privileged identity. Only authenticated Hylja metadata creates resolvable entity references.

### Bulk enumeration

A caller attempts sequential/random token resolution or wide search. Tokens are high entropy; brokered operations are purpose-bound, rate-limited, tenant-scoped, and audited. No bulk plaintext lookup API exists.

### Contextual re-identification

A direct name is replaced, but rare combinations of customer type, site, geography, dates, product versions, and project descriptions reveal the identity. Re-identification risk is independently evaluated and may trigger generalization.

### Encoded/obfuscated values

Secrets may be Base64, URL encoded, hex, escaped, fragmented, Unicode-confused, nested in archives, or placed in unusual fields/keys. Normalization is bounded and resource-limited to avoid turning decoding itself into a denial-of-service vector.

### Mapping swap/integrity attack

An attacker replaces ciphertext or mapping metadata so synthetic entity A resolves to original B. AEAD associated data and monotonic mapping versions bind ciphertext to tenant/entity/type/version.

### Admin compromise

A privileged account attempts tenant-wide export, policy disablement, backup restoration, or root-key use. High-risk actions require short-lived elevation, strong authentication, explicit reason, immutable audit, and where justified dual control.

### Backup compromise

Backups contain durable ciphertext and metadata. Backup identities, encryption, access, and restore processes are separate. Production mapping data is never restored into development environments.

### Semantic-service privacy paradox

If a hosted semantic judge receives raw secrets, cloaking has only shifted the third-party exposure. Hylja minimizes/locally substitutes candidates before external semantic judgment whenever possible and supports deployments where semantic judgment is local or disabled.

### Streaming leak

Protected content can be released token-by-token before a late detector recognizes it. High-risk streams use a holdback/buffer policy; some classes require complete-message inspection before release.

### Supply-chain bypass

A compromised parser/adapter intentionally skips enforcement. Builds require dependency pinning, SBOM/provenance, signed release artifacts where practical, scanning, and adapter conformance tests.

## Threat-model outputs

Each implementation issue should state which threats it addresses, which new attack surfaces it introduces, and how its acceptance tests prove the claimed boundary.
