/**
 * KEEP-only complete-response OpenAI-compatible inbound receiver (#212). One call owns the whole
 * runtime effect for an inbound provider reply: the strict complete-text translation, the exact
 * private canonical body image of that response, snapshot-bound per-unit classification evidence over
 * every variable field of the image, one real deterministic `SEND` policy decision per unit, the real
 * fixed-worker egress sentinel child process over those exact bytes, and exactly one trusted release
 * of the sentinel's own private `ALLOW` copy.
 *
 * What this is NOT. It is not a gateway, a listener, a server, a provider client, an authentication
 * implementation, a credential or vault path, a transformation engine, a streaming design or a hosted
 * tool interceptor. The trusted host supplies an already authenticated boundary, the pinned policy
 * commit, the snapshot-bound inspection handoff and the exact-byte release point; **nothing here
 * authenticates any of them**, and this unit cannot prove that an arbitrary injected release point
 * honors its contract. Routing, identity, classification provenance and the control plane remain
 * integration-host obligations, exactly as the policy, sentinel and envelope contracts already state.
 *
 * The trust boundary is deliberately narrow:
 *
 * - The caller supplies `endpoint` and `body` and nothing else. Authority, classification, destination,
 *   profile, keys, policy and treatment cannot travel in a payload field: the strict codec refuses any
 *   extra own key, and provider, model, id, created, usage and finish reason are non-authority protocol
 *   metadata that is re-serialized but never interpreted.
 * - **Provider source trust is always `UNTRUSTED`** and is not a host or caller input at all. The
 *   envelope's own source record has no trust member, so no host can attach one, and the policy boundary
 *   here pins `UNTRUSTED` as the observed trust: a classification that elevated its own trust is a
 *   context mismatch in real policy, not a negotiated value. Protected model output is untrusted text;
 *   a token-shaped string, an instruction or a claim inside it grants no authority, selects no route
 *   and triggers no restoration.
 * - There is no public "prepared" or "ready" handle and no replayable `releasePrepared`. A `RELEASED`
 *   result carries no bytes and no digest, so nothing a caller holds can be released twice, mutated
 *   after a check, or re-released after routing changed. Cancellation is receiver-owned and never a
 *   caller signal.
 * - Only `KEEP` releases. `MASK`, `REMOVE`, every other treatment and `REQUIRE_REVIEW` all withhold,
 *   because this unit implements no transformation semantics and no review authority.
 * - `coverage: 'COMPLETE'` alone never authorizes. Authorization is the conjunction of exact whole-image
 *   unit coverage, a classification digest that matches the record actually used, a real `RESOLVED`
 *   classification carrying detector evidence, a real `SELECTED`/`KEEP` policy decision **for every
 *   declared unit**, and a real `ALLOW` from the sentinel child over these exact bytes. Detector
 *   absence is never clearance: this module never turns an absent or partial finding into a `PUBLIC`
 *   assumption of its own, it fabricates no evidence, and an unresolved remainder refuses.
 * - Authorization does not outlive its evidence. Sticky cancellation is re-read after the last host
 *   observation, and the snapshotted boundary proof intervals are re-read for freshness at the release
 *   point, immediately before the release call. That is freshness, never authenticity: authenticating
 *   those proofs remains the host's obligation, and an unchanged digest is not a current proof.
 * - Every accepted method is captured once, on the receiver it was validated on, and is never looked up
 *   on the host object again. `inspect`, `observe` and `releaseExact` run as the function references the
 *   validated data properties held, so reading a method back off the host at the release point - a
 *   Proxy `get` trap away from running after the last guard - never happens, and a host that replaces
 *   its own method later does not retarget a receiver that already exists. Invoking the captured
 *   release point is still host code: its honesty, and anything it does with its receiver, remain host
 *   obligations.
 * - Nothing outside the accepted subset is narrowed: streaming objects and fragments, tools, multiple
 *   choices, multimodal or opaque content, duplicate keys and unknown fields are refused by the strict
 *   codec before any image, evidence, decision or child exists.
 *
 * The checked image is private and is **body bytes only**: no transport header, no status line, no
 * provider credential and no host framing is built here, so there is nothing in the image a hostile
 * label could inject into. The trusted inspection callback receives its own copy, which it may scribble
 * on; the released bytes are the sentinel's own private `ALLOW` copy. The only representation that may
 * reach the release point is that copy, handed over once.
 */
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical-json.js';
import { createInteractionEnvelope } from './interaction-envelope.js';
import type { BoundaryContext, InteractionDraft, InteractionEnvelope } from './interaction-envelope.js';
import type { Classification, Trust } from './classification.js';
import { decidePolicy, digestClassification, KNOWN_POLICY_BUNDLE } from './policy.js';
import type { PolicyBoundary, PolicyBundle, PolicyRequest } from './policy.js';
import { createSentinelProcessRunner } from './egress-sentinel-process.js';
import type {
  SentinelProcessKnownRegistration,
  SentinelProcessRunnerConfig,
  SentinelProcessScope,
} from './egress-sentinel-process.js';
import type { SentinelProcessDestination } from './egress-sentinel-process-protocol.js';
import { translateOpenAiTextResponse } from './openai-text-response.js';
import type { OpenAiTextResponseProtocol, OpenAiTextResponseRefusal } from './openai-text-response.js';

/**
 * Every refusal is one of these fixed codes, or one of the strict codec's own fixed codes. No code
 * carries a field name, byte offset, parser excerpt, exception message, release error, sentinel reason
 * or any part of the input, so a refusal is safe to log and a planted value never reappears in a result.
 */
export const OPENAI_KEEP_RECEIVER_REFUSALS = Object.freeze([
  /** The trusted host object is not the exact declared shape; this receiver can never release. */
  'HOST_INVALID',
  /** One receive is already in flight. There is no queue, no pool and no replay. */
  'RECEIVER_BUSY',
  /** `cancel()` was observed first, or this receiver was already cancelled. */
  'CANCELLED',
  /** The accepted response cannot be serialized as one canonical image under the fixed bounds. */
  'IMAGE_REFUSED',
  /** The independently authenticated boundary could not be bound to this interaction. */
  'INTERACTION_REFUSED',
  /** The observed route, profile digest or commit is not a usable destination label. */
  'ROUTE_REFUSED',
  /** The sentinel scope does not belong to this authenticated tenant/project. */
  'SCOPE_REFUSED',
  /** Empty, partial, foreign, unresolved or unbound inspection evidence. Never an exception echo. */
  'INSPECTION_REFUSED',
  /** The real policy seam denied: unknown or stale policy, foreign context, profile or rule mismatch. */
  'POLICY_DENIED',
  /** The real policy seam held the decision for review. A held state is never a transformation. */
  'POLICY_HELD',
  /** A real, selected treatment that is not `KEEP`. This unit implements no other treatment. */
  'POLICY_NOT_KEEP',
  /** The sentinel child did not return `ALLOW` over these bytes, or the check could not run at all. */
  'SENTINEL_BLOCKED',
  /** The release point reported a different route or profile than the one the check was made against. */
  'ROUTE_CHANGED',
  /** The committed policy identity changed between the decision and the release. */
  'POLICY_STALE',
  /** The trusted release point failed or did not confirm. The effect may be partial; nothing is retried. */
  'RELEASE_FAILED',
  /** Fail-closed catch-all for an unexpected internal failure; carries no detail either. */
  'RECEIVER_FAILED',
] as const);

export type KeepReceiveRefusal = (typeof OPENAI_KEEP_RECEIVER_REFUSALS)[number] | OpenAiTextResponseRefusal;
export type KeepReceiveResult =
  | Readonly<{ status: 'RELEASED' }>
  | Readonly<{ status: 'REFUSED'; code: KeepReceiveRefusal }>;
export type KeepReceiverState = 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';

/** One inspectable unit of the exact private image, in wire order: choice envelope, content, metadata. */
export type KeepReleaseUnitKind = 'PROTOCOL' | 'MESSAGE';
export interface KeepReleaseUnit {
  /** Opaque reference chosen by the receiver. It names a position, never a value or a raw span. */
  readonly unitRef: string;
  readonly kind: KeepReleaseUnitKind;
  /** SHA-256 of this unit's exact bytes inside the image. A binding token, never a permission. */
  readonly digest: string;
}

/** What the receiver hands the trusted inspector: which image, which interaction, which units. */
export interface KeepReleaseBinding {
  readonly version: 1;
  readonly interactionRef: string;
  /** SHA-256 of the receiver's own private snapshot of the exact canonical body image. */
  readonly imageDigest: string;
  readonly units: readonly KeepReleaseUnit[];
}

export interface KeepReleaseFinding {
  readonly unitRef: string;
  /** Digest the trusted producer pinned for this exact record. Congruence is checked, not trusted. */
  readonly classificationDigest: string;
  readonly classification: Classification;
}

/** The shape a trusted inspector returns. It is validated here; the declared type grants no authority. */
export interface KeepReleaseResult {
  readonly version: 1;
  readonly interactionRef: string;
  readonly imageDigest: string;
  /** A completeness statement, never a safety one. Necessary and nowhere near sufficient. */
  readonly coverage: 'COMPLETE';
  /** Explicit: no part of the image is left unclassified. Anything else refuses. */
  readonly remainder: 'NONE';
  readonly units: readonly KeepReleaseFinding[];
}

export interface KeepReceiverObservation {
  /** Destination id and profile digest observed at the release point, right now. */
  readonly destination: SentinelProcessDestination;
  /** The currently committed policy identity and content digest. */
  readonly commit: Readonly<{ id: string; version: string; digest: string }>;
}

export interface KeepReceiverReleasePoint {
  /**
   * Re-observes the actual route and the committed policy. Called once for the check and again in the
   * same synchronous turn as the release, so no await separates the last check from the effect.
   * Redirects are prohibited: a different route is a refusal, never a followed location.
   */
  observe(): KeepReceiverObservation;
  /** Releases exactly these bytes, once. A resolved promise is the only confirmation of the effect. */
  releaseExact(image: Uint8Array): Promise<void>;
}

/**
 * The trusted integration host. Every member arrives from an already authenticated adapter or broker;
 * none of them arrives from a request header, body, model text or launcher flag, and none of them
 * authenticates itself here. `sourceTrust` is deliberately absent: provider source trust is not a host
 * input for this unit.
 */
export interface KeepReceiverHost {
  /** Independently authenticated subject/context plus the observed source and destination with proofs. */
  readonly boundary: BoundaryContext;
  /** The committed policy snapshot; its content digest comes from `releasePoint.observe()`. */
  readonly policyBundle: PolicyBundle;
  /** Tenant/project the sentinel checks under. Must belong to the authenticated context. */
  readonly scope: SentinelProcessScope;
  /** Known originals registration, or an explicit `null` when this egress has none to protect. */
  readonly known: SentinelProcessKnownRegistration | null;
  /** Host-owned sentinel runner configuration. The child is the module's fixed compiled worker. */
  readonly sentinel: SentinelProcessRunnerConfig;
  /** Whole-image, snapshot-bound classification handoff. The only classification source. */
  inspect(image: Uint8Array, binding: KeepReleaseBinding): unknown;
  /** Independently observed route/profile and the exact-byte release point. */
  readonly releasePoint: KeepReceiverReleasePoint;
}

export interface OpenAiKeepReceiver {
  /** One receive per call. A second concurrent call is refused rather than queued or duplicated. */
  receive(input: unknown): Promise<KeepReceiveResult>;
  /** Receiver-owned, sticky cancellation. After it, this receiver can never release again. */
  cancel(): void;
  readonly state: KeepReceiverState;
}

/* ---------- Fixed, closed vocabularies and strict structural readers ---------- */

const HOST_KEYS: readonly string[] =
  ['boundary', 'policyBundle', 'scope', 'known', 'sentinel', 'inspect', 'releasePoint'];
const RELEASE_POINT_KEYS: readonly string[] = ['observe', 'releaseExact'];
const OBSERVATION_KEYS: readonly string[] = ['destination', 'commit'];
const DESTINATION_KEYS: readonly string[] = ['id', 'profileDigest'];
const COMMIT_KEYS: readonly string[] = ['id', 'version', 'digest'];
const RESULT_KEYS: readonly string[] = ['version', 'interactionRef', 'imageDigest', 'coverage', 'remainder', 'units'];
const FINDING_KEYS: readonly string[] = ['unitRef', 'classificationDigest', 'classification'];
const CONTROL = /[\u0000-\u001f\u007f]/u;
const HEX_DIGEST = /^[0-9a-f]{64}$/u;
const MAX_DESTINATION_LABEL = 256;
const encoder = new TextEncoder();
/**
 * Provider source trust is not negotiable and not supplied. Protected model output is untrusted text
 * at its own source, and nothing a response says can raise it ([decision 003](../docs/decisions/
 * 003-semantic-judgment-does-not-own-effects.md), [007](../docs/decisions/007-fail-closed-for-
 * protected-egress.md)).
 */
const PROVIDER_SOURCE_TRUST: Trust = 'UNTRUSTED';
const COMPLETE_OBJECT = 'chat.completion';
/** The three fixed structural spans of the image, in wire order. No header, no framing, no credential. */
const CHOICE_PREFIX = '{"choices":[{"finish_reason":';
const CHOICE_MIDDLE = ',"index":0,"message":{"content":';
const CHOICE_SUFFIX = ',"role":"assistant"}}],';
const DOCUMENT_SUFFIX = '}';

type Fields = Record<string, unknown>;
type ObserveMethod = () => KeepReceiverObservation;
type ReleaseExactMethod = (image: Uint8Array) => Promise<void>;
type InspectMethod = (image: Uint8Array, binding: KeepReleaseBinding) => unknown;

/**
 * Bind one already-accepted method to the receiver it was validated on, once. The wrapper calls that
 * captured function through the trusted `Reflect.apply`, which performs the call directly: it reads no
 * property of the host object and never looks up `.call`, `.bind` or `.apply` on it. Calling the captured
 * function is therefore the only host code that runs, the receiver is preserved, and reading a method
 * back off the host later - the one way a Proxy `get` trap could run after the release-point guards -
 * never happens.
 */
function captured<A extends unknown[], R>(method: (...args: A) => R, receiver: unknown): (...args: A) => R {
  return (...args: A): R => Reflect.apply(method, receiver, args) as R;
}

/**
 * Own enumerable DATA properties only, and exactly the declared set. A getter, a symbol key, an
 * unknown key or a hostile trap is refused without being invoked, and a refused value is never read.
 */
function exact(value: unknown, names: readonly string[]): Fields | null {
  if (value === null || typeof value !== 'object') return null;
  // A revoked Proxy throws from every trap, the array check included, so the whole structural refusal
  // is inside one containment. Nothing here is read before it has been proved to be a plain value.
  let keys: (string | symbol)[];
  try { if (Array.isArray(value)) return null; keys = Reflect.ownKeys(value); } catch { return null; }
  if (keys.length !== names.length) return null;
  const out: Fields = Object.create(null) as Fields;
  for (const key of keys) {
    if (typeof key !== 'string' || !names.includes(key)) return null;
    let descriptor: PropertyDescriptor | undefined;
    try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { return null; }
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) return null;
    out[key] = descriptor.value;
  }
  return out;
}

/** One own data property, or `undefined`. Never invokes an accessor. */
function ownData(value: unknown, name: string): unknown {
  if (value === null || typeof value !== 'object') return undefined;
  let descriptor: PropertyDescriptor | undefined;
  try { descriptor = Object.getOwnPropertyDescriptor(value, name); } catch { return undefined; }
  return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
}

function digestOf(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * A destination label is framed into the sentinel request, so it is validated here before the child
 * can see it: non-empty, bounded, and free of control characters. This unit builds no header, so an
 * ordinary space is legal here; this is a structural bound, not authentication of the route.
 */
function usableDestination(destination: unknown): SentinelProcessDestination | null {
  const fields = exact(destination, DESTINATION_KEYS);
  if (fields === null) return null;
  const id = fields['id'];
  const profileDigest = fields['profileDigest'];
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_DESTINATION_LABEL ||
    CONTROL.test(id) || typeof profileDigest !== 'string' || !HEX_DIGEST.test(profileDigest)) return null;
  return { id, profileDigest };
}

function observationOf(value: unknown): KeepReceiverObservation | null {
  const fields = exact(value, OBSERVATION_KEYS);
  if (fields === null) return null;
  const destination = usableDestination(fields['destination']);
  const commit = exact(fields['commit'], COMMIT_KEYS);
  if (destination === null || commit === null) return null;
  const { id, version, digest } = commit as { id: unknown; version: unknown; digest: unknown };
  if (typeof id !== 'string' || id.length === 0 || CONTROL.test(id) ||
    typeof version !== 'string' || version.length === 0 || CONTROL.test(version) ||
    typeof digest !== 'string' || !HEX_DIGEST.test(digest)) return null;
  return Object.freeze({ destination, commit: Object.freeze({ id, version, digest }) });
}

function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function refused(code: KeepReceiveRefusal): KeepReceiveResult {
  return Object.freeze({ status: 'REFUSED' as const, code });
}

/**
 * The exact trusted-host shape. Only what this seam structurally relies on is checked here; the
 * envelope, the policy seam and the sentinel runner remain the authority for everything they own, and
 * this never duplicates them. Note what is not here: no source trust, no destination, no profile, no
 * treatment and no credential is accepted from this object beyond what its declared members carry.
 */
function trustedHost(value: unknown): KeepReceiverHost | null {
  const fields = exact(value, HOST_KEYS);
  if (fields === null) return null;
  const releasePoint = exact(fields['releasePoint'], RELEASE_POINT_KEYS);
  if (releasePoint === null) return null;
  const inspect = fields['inspect'];
  const observe = releasePoint['observe'];
  const releaseExact = releasePoint['releaseExact'];
  if (typeof inspect !== 'function' || typeof observe !== 'function' || typeof releaseExact !== 'function') return null;
  const recordish = fields['boundary'];
  const bundle = fields['policyBundle'];
  const scope = fields['scope'];
  const sentinel = fields['sentinel'];
  if (recordish === null || typeof recordish !== 'object' || bundle === null || typeof bundle !== 'object' ||
    scope === null || typeof scope !== 'object' || sentinel === null || typeof sentinel !== 'object') return null;
  const known = fields['known'];
  if (known !== null && (known === null || typeof known !== 'object')) return null;
  // The validated data-property snapshot is authoritative for the callables: each one is captured on the
  // receiver it was found on and is never read off the host again. The release point keeps its own object
  // as its receiver, so a host method that reads its own state still sees it, while a later host-side
  // replacement of `observe` or `releaseExact` cannot retarget a receiver that already exists.
  const snapshot = Object.freeze({ ...fields });
  return Object.freeze({
    ...snapshot,
    inspect: captured(inspect as InspectMethod, snapshot),
    releasePoint: Object.freeze({
      observe: captured(observe as ObserveMethod, fields['releasePoint']),
      releaseExact: captured(releaseExact as ReleaseExactMethod, fields['releasePoint']),
    }),
  }) as unknown as KeepReceiverHost;
}

/* ---------- The exact private canonical image and its unit decomposition ---------- */

interface ReleaseImage {
  readonly bytes: Uint8Array;
  /** Exact byte range of each declared unit inside `bytes`, in wire order. */
  readonly ranges: readonly Readonly<{ start: number; length: number }>[];
}

/** The single assistant text of an accepted complete response, read structurally once. */
function assistantContent(draft: InteractionDraft): string {
  const payload = draft.payload;
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new TypeError('payload');
  const messages = (payload as { messages?: unknown }).messages;
  if (!Array.isArray(messages) || messages.length !== 1) throw new TypeError('messages');
  const message = messages[0] as { role?: unknown; content?: unknown } | undefined;
  if (message === null || typeof message !== 'object' || Array.isArray(message)) throw new TypeError('message');
  if (message.role !== 'assistant' || typeof message.content !== 'string') throw new TypeError('content');
  return message.content;
}

/**
 * Serialize the accepted translation into the exact canonical body image. The canonical serializer is
 * the existing core seam: no whitespace, members in canonical order and minimal string escaping, so
 * one accepted response has exactly one image and the image digest cannot mean two documents. The
 * image is **body bytes only** - no status line, no header, no provider field beyond the accepted
 * subset - and the assistant text is preserved exactly as the codec decoded it.
 *
 * The image is assembled from the three declared spans so each unit digest binds a real byte range of
 * it: the choice envelope prefix (which carries the finish reason), the assistant content literal, and
 * the suffix that carries the role plus every remaining protocol member (`created`, `id`, `model`,
 * `object` and optional `usage`). Together they are the whole image with no gap and no overlap.
 */
function buildImage(draft: InteractionDraft, protocol: OpenAiTextResponseProtocol): ReleaseImage {
  const content = assistantContent(draft);
  // The reported model is protocol metadata the codec already bounded and validated; it is carried
  // into the image as data and never read as a route, a profile or an authority.
  const model = draft.metadata?.model;
  if (typeof model !== 'string') throw new TypeError('model');
  const metadata: Record<string, unknown> = {
    created: protocol.created, id: protocol.id, model, object: COMPLETE_OBJECT,
    ...(protocol.usage === undefined ? {} : {
      usage: {
        completion_tokens: protocol.usage.completion_tokens,
        prompt_tokens: protocol.usage.prompt_tokens,
        total_tokens: protocol.usage.total_tokens,
      },
    }),
  };
  const finish = canonicalJson(protocol.finish_reason);
  const literal = canonicalJson(content);
  const members = canonicalJson(metadata).slice(1, -1);
  const prefix = encoder.encode(CHOICE_PREFIX);
  const middle = encoder.encode(CHOICE_MIDDLE);
  const suffix = encoder.encode(CHOICE_SUFFIX);
  const close = encoder.encode(DOCUMENT_SUFFIX);
  const first = prefix.byteLength + finish.byteLength + middle.byteLength;
  const second = literal.byteLength;
  const total = first + second + suffix.byteLength + members.byteLength + close.byteLength;
  const bytes = new Uint8Array(total);
  let at = 0;
  const place = (part: Uint8Array): void => { bytes.set(part, at); at += part.byteLength; };
  place(prefix); place(finish); place(middle);
  place(literal);
  place(suffix); place(members); place(close);
  return Object.freeze({
    bytes,
    ranges: Object.freeze([
      Object.freeze({ start: 0, length: first }),
      Object.freeze({ start: first, length: second }),
      Object.freeze({ start: first + second, length: total - first - second }),
    ]),
  });
}

/** One unit per declared span of the whole image, each bound to its exact bytes inside it. */
function unitsOf(image: ReleaseImage, interactionRef: string): readonly KeepReleaseUnit[] {
  const kinds: readonly KeepReleaseUnitKind[] = ['PROTOCOL', 'MESSAGE', 'PROTOCOL'];
  return Object.freeze(image.ranges.map((range, index) => Object.freeze({
    unitRef: `${interactionRef}-u${index}`,
    kind: kinds[index] as KeepReleaseUnitKind,
    digest: digestOf(image.bytes.subarray(range.start, range.start + range.length)),
  })));
}

/* ---------- The trusted inspection handoff ---------- */

/**
 * Validate the inspector's answer as a structure, never as an authority. Returns the finding list only
 * when every declared unit is present exactly once; the caller then binds each record by digest and
 * decides policy over it.
 */
function findingsOf(value: unknown, binding: KeepReleaseBinding): readonly KeepReleaseFinding[] | null {
  const fields = exact(value, RESULT_KEYS);
  if (fields === null) return null;
  if (fields['version'] !== 1 || fields['interactionRef'] !== binding.interactionRef ||
    fields['imageDigest'] !== binding.imageDigest || fields['coverage'] !== 'COMPLETE' ||
    fields['remainder'] !== 'NONE') return null;
  const units = fields['units'];
  if (!Array.isArray(units) || units.length !== binding.units.length) return null;
  const seen = new Set<string>();
  const findings: KeepReleaseFinding[] = [];
  for (const entry of units) {
    const finding = exact(entry, FINDING_KEYS);
    if (finding === null) return null;
    const { unitRef, classificationDigest, classification } = finding as {
      unitRef: unknown; classificationDigest: unknown; classification: unknown;
    };
    if (typeof unitRef !== 'string' || !binding.units.some((unit) => unit.unitRef === unitRef) ||
      seen.has(unitRef) || typeof classificationDigest !== 'string' || !HEX_DIGEST.test(classificationDigest) ||
      classification === null || typeof classification !== 'object') return null;
    seen.add(unitRef);
    findings.push({ unitRef, classificationDigest, classification: classification as Classification });
  }
  return Object.freeze(findings);
}

/**
 * A finding is usable only when it is a `RESOLVED` classification carrying detector evidence and when
 * the pinned digest matches the record the receiver will actually decide over. A substituted record, an
 * unresolved remainder, or a semantic-only `PUBLIC` judgment that no detector corroborated all refuse:
 * detector absence is never clearance, and this module supplies no absence-to-PUBLIC default of its own.
 */
function usableClassification(finding: KeepReleaseFinding): Classification | null {
  if (ownData(finding.classification, 'status') !== 'RESOLVED') return null;
  const evidence = ownData(finding.classification, 'evidence');
  if (!Array.isArray(evidence)) return null;
  const detector = evidence.some((record) => ownData(record, 'source') === 'detector' &&
    ownData(record, 'status') === 'FOUND');
  if (!detector) return null;
  let pinned: string;
  try { pinned = digestClassification(finding.classification); } catch { return null; }
  return pinned === finding.classificationDigest ? finding.classification : null;
}

/** The envelope contract's own five-minute window, re-declared so the release-point re-read uses it. */
const MAX_PROOF_AGE_MS = 5 * 60 * 1000;

/**
 * Are the proof intervals this interaction was actually bound under still current? This re-reads the
 * envelope's own snapshots against the clock at the release point, exactly as
 * `parseInteractionEnvelope` requires a wire timestamp to be inside every proof interval, and it
 * changes nothing about which proofs these are: an identical digest is not a current proof, a closed
 * window grants nothing back, and a boundary that went stale mid-receive cannot be bound to this
 * release. Freshness only; authenticating a proof stays the host's obligation.
 */
function currentEvidence(envelope: InteractionEnvelope, now: number): boolean {
  for (const claim of envelope.provenance) {
    const issued = Date.parse(claim.issuedAt);
    const expires = Date.parse(claim.expiresAt);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now || expires <= now ||
      expires - issued > MAX_PROOF_AGE_MS) return false;
  }
  const occurred = Date.parse(envelope.occurredAt);
  return Number.isFinite(occurred) && occurred <= now && occurred >= now - MAX_PROOF_AGE_MS;
}

/* ---------- The receiver ---------- */

/**
 * Create a KEEP-only receiver bound to one trusted host. Construction never throws and never releases:
 * an unusable host yields a permanently restrictive receiver instead of an echo of a caller value.
 */
export function createOpenAiKeepReceiver(host: unknown): OpenAiKeepReceiver {
  const trusted = trustedHost(host);
  if (trusted === null) {
    return Object.freeze({
      receive: (): Promise<KeepReceiveResult> => Promise.resolve(refused('HOST_INVALID')),
      cancel: (): void => { /* an unusable receiver owns nothing to cancel */ },
      get state(): KeepReceiverState { return 'FAILED'; },
    });
  }
  const runner = createSentinelProcessRunner(trusted.sentinel);
  let busy = false;
  let cancelled = false;

  /** One receive, start to finish. Every stage that is not an authorization withholds. */
  const run = async (input: unknown): Promise<KeepReceiveResult> => {
    const translated = translateOpenAiTextResponse(input);
    if (translated.status === 'REFUSED') return refused(translated.reason);

    const observed = observationOf(trusted.releasePoint.observe());
    if (observed === null) return refused('ROUTE_REFUSED');

    // Binding the independently authenticated boundary to this interaction is the envelope's own
    // refusal point, so it is caught here and nowhere else: evidence that cannot be bound at all
    // (an expired, malformed or foreign-boundary window) is INTERACTION_REFUSED, exactly like
    // evidence that was bound and is no longer current at the release point below.
    let envelope: InteractionEnvelope;
    try { envelope = createInteractionEnvelope(translated.draft, trusted.boundary); }
    catch { return refused('INTERACTION_REFUSED'); }
    const interactionRef = envelope.id;
    if (trusted.scope.tenantRef !== envelope.context.tenantId ||
      (envelope.context.projectId !== undefined && trusted.scope.projectRef !== envelope.context.projectId)) {
      return refused('SCOPE_REFUSED');
    }

    let image: ReleaseImage;
    try { image = buildImage(translated.draft, translated.protocol); }
    catch { return refused('IMAGE_REFUSED'); }
    const imageDigest = digestOf(image.bytes);
    const units = unitsOf(image, interactionRef);
    const binding: KeepReleaseBinding = Object.freeze({
      version: 1, interactionRef, imageDigest, units,
    });

    // The inspector gets its own copy. It can answer, mutate or throw; none of it reaches the bytes,
    // and a thrown value is never inspected: its text, class and stack are all caller-controlled.
    let findings: readonly KeepReleaseFinding[] | null;
    try { findings = findingsOf(trusted.inspect(image.bytes.slice(), binding), binding); }
    catch { findings = null; }
    if (findings === null) return refused('INSPECTION_REFUSED');
    const byUnit = new Map(findings.map((finding) => [finding.unitRef, finding] as const));

    for (const unit of units) {
      const finding = byUnit.get(unit.unitRef);
      if (finding === undefined) return refused('INSPECTION_REFUSED');
      const classification = usableClassification(finding);
      if (classification === null) return refused('INSPECTION_REFUSED');
      const request: PolicyRequest = {
        version: 1, interactionRef, candidateRef: unit.unitRef,
        subject: envelope.subject, context: envelope.context, source: envelope.source,
        destination: envelope.destination, classification, operation: 'SEND',
        policy: KNOWN_POLICY_BUNDLE,
      };
      // The observed source trust is pinned here and is not a host or caller value: protected model
      // output is untrusted at its own source, so a record that claims another trust is a real
      // context mismatch in `decidePolicy` below.
      const boundary: PolicyBoundary = {
        interactionRef, candidateRef: unit.unitRef,
        classificationDigest: finding.classificationDigest,
        authenticated: { subject: envelope.subject, context: envelope.context },
        observed: {
          source: { ...envelope.source, trust: PROVIDER_SOURCE_TRUST },
          destination: envelope.destination,
        },
        policy: { ...observed.commit },
      };
      const decision = decidePolicy(request, boundary, trusted.policyBundle);
      if (decision.state === 'DENIED') return refused('POLICY_DENIED');
      if (decision.state === 'HELD') return refused('POLICY_HELD');
      if (decision.treatment !== 'KEEP') return refused('POLICY_NOT_KEEP');
    }

    const outcome = await runner.check({
      bytes: image.bytes, scope: trusted.scope, destination: observed.destination,
      // What the decision authorized: the route in the authenticated boundary, not the observed one.
      // A swapped boundary or a changed route is therefore a real mismatch for the child to find.
      authorized: { id: envelope.destination.ref, profileDigest: observed.destination.profileDigest },
      known: trusted.known,
    });
    // A cancellation this receiver asked for is reported as one; every other non-`ALLOW` outcome,
    // including a check that never ran, collapses into one fixed sentinel refusal.
    if (outcome.status !== 'ALLOW') return refused(outcome.code === 'CANCELLED' ? 'CANCELLED' : 'SENTINEL_BLOCKED');
    const release = outcome.release;

    // The release point, deliberately ordered. The release and observation callables were captured
    // during validation, so this is the last point at which any host property is read at all: the final
    // host observation and every structural and freshness check it can invalidate happen first; sticky
    // cancellation is then re-read with nothing between that read and the release call but this frame,
    // so a cancel raised by that last callback can no longer reach a release. The early read below only
    // spares the host a second observation.
    if (cancelled) return refused('CANCELLED');
    const current = observationOf(trusted.releasePoint.observe());
    if (current === null) return refused('ROUTE_REFUSED');
    if (!same(current.destination, observed.destination)) return refused('ROUTE_CHANGED');
    if (!same(current.commit, observed.commit)) return refused('POLICY_STALE');
    // The finite trusted callback and the fixed-worker child both took real time. Re-read the boundary
    // evidence this interaction was bound under: a proof window that closed during the receive is not a
    // still-current context, and the identity, context and observed route it authorized are no longer
    // usable for this release. Recreating the envelope instead would mint a new interaction identity and
    // invalidate every digest, unit reference and policy decision already pinned over it.
    if (!currentEvidence(envelope, Date.now())) return refused('INTERACTION_REFUSED');
    // No callback and no await separates this read from the effect it guards.
    if (cancelled) return refused('CANCELLED');
    try { await trusted.releasePoint.releaseExact(release); }
    catch { return refused('RELEASE_FAILED'); }
    // The effect already happened once. It is never retried, repeated or replayed from a returned handle.
    return Object.freeze({ status: 'RELEASED' as const });
  };

  return Object.freeze({
    /**
     * Receive one complete text response, or refuse it with a fixed code. The admission claim is taken
     * synchronously, before any stage runs, so a concurrent call is refused rather than queued and can
     * never produce a second release.
     */
    receive: (input: unknown): Promise<KeepReceiveResult> => {
      if (busy) return Promise.resolve(refused('RECEIVER_BUSY'));
      if (cancelled) return Promise.resolve(refused('CANCELLED'));
      busy = true;
      return run(input).catch(() => refused('RECEIVER_FAILED')).finally(() => { busy = false; });
    },
    cancel: (): void => {
      if (cancelled) return;
      cancelled = true;
      runner.cancel();
    },
    get state(): KeepReceiverState {
      if (cancelled) return 'CANCELLED';
      if (runner.state === 'QUARANTINED') return 'FAILED';
      return busy ? 'BUSY' : 'IDLE';
    },
  });
}
