/**
 * KEEP-only complete-text OpenAI-compatible request sender (#201). One call owns the whole runtime
 * effect: translation, the exact private serialized request image, snapshot-bound whole-image
 * classification evidence, the real deterministic SEND policy decision, the real fixed-worker egress
 * sentinel child process, and exactly one trusted transport dispatch.
 *
 * What this is NOT. It is not a gateway, a listener, a provider client, an authentication
 * implementation, a credential or vault path, a transformation engine or a response release. The
 * trusted host supplies an already authenticated boundary, the pinned policy commit, the
 * snapshot-bound inspection handoff and the exact-byte transport; **nothing here authenticates any of
 * them**, and this unit cannot prove that an arbitrary injected transport honors its contract.
 * Routing, identity, classification provenance and the control plane remain integration-host
 * obligations, exactly as the policy, sentinel and envelope contracts already state.
 *
 * The trust boundary is deliberately narrow:
 *
 * - The caller supplies `endpoint` and `body` and nothing else. Authority, classification, destination,
 *   profile, keys, policy and treatment cannot travel in a payload field: the codec refuses any extra
 *   own key, and provider/model are non-authority protocol metadata.
 * - There is no public "prepared" or "ready" handle and no replayable `sendPrepared`. A `SENT` result
 *   carries no bytes and no digest, so nothing a caller holds can be sent twice, mutated after a
 *   check, or re-sent after routing changed. Cancellation is sender-owned, never a caller signal.
 * - Only `KEEP` releases. `MASK`, `REMOVE`, every other treatment and `REQUIRE_REVIEW` all withhold,
 *   because this unit implements no transformation semantics and no review authority.
 * - `coverage: 'COMPLETE'` alone never authorizes. Authorization is the conjunction of exact whole-image
 *   unit coverage, a classification digest that matches the record actually used, a real `RESOLVED`
 *   classification carrying detector evidence, a real `SELECTED`/`KEEP` policy decision, and a real
 *   `ALLOW` from the sentinel child over these exact bytes.
 * - Authorization does not outlive its evidence. Sticky cancellation is re-read after the last host
 *   observation, and the snapshotted boundary proof intervals are re-read for freshness at the dispatch
 *   point, immediately before the transport call. That is freshness, never authenticity: authenticating
 *   those proofs remains the host's obligation, and an unchanged digest is not a current proof.
 * - Every accepted method is captured once, on the receiver it was validated on, and is never looked up
 *   on the host object again. `inspect`, `observe` and `sendExact` run as the function references the
 *   validated data properties held, so reading a method back off the host at the dispatch point - a
 *   Proxy `get` trap away from running after the last guard - never happens, and a host that replaces
 *   its own method later does not retarget a sender that already exists. Invoking the captured transport
 *   is still host code: its honesty, and anything it does with its receiver, remain host obligations.
 * - Detector absence is never clearance: an empty or partial finding set, an unclassified remainder, a
 *   caller-supplied digest or an `UNRESOLVED` record all refuse.
 *
 * The checked image is private. The trusted inspection callback receives its own copy, which it may
 * scribble on; the released bytes are the sentinel's own private ALLOW copy. The only representation
 * that may reach the transport is that copy, handed over once.
 */
import { createHash } from 'node:crypto';
import { createInteractionEnvelope } from './interaction-envelope.js';
import type { BoundaryContext, InteractionDraft, InteractionEnvelope } from './interaction-envelope.js';
import { TRUST_LEVELS } from './classification.js';
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
import { OPENAI_TEXT_REQUEST_ENDPOINT, translateOpenAiTextRequest } from './openai-text-request.js';
import type { OpenAiTextRequestRefusal } from './openai-text-request.js';

/**
 * Every refusal is one of these fixed codes, or one of the codec's own fixed codes. No code carries a
 * field name, byte offset, parser excerpt, exception message, transport error or any part of the
 * input, so a refusal is safe to log and a planted value never reappears in a result.
 */
export const OPENAI_KEEP_SENDER_REFUSALS = Object.freeze([
  /** The trusted host object is not the exact declared shape; this sender can never dispatch. */
  'HOST_INVALID',
  /** One send is already in flight. There is no queue, no pool and no replay. */
  'SENDER_BUSY',
  /** `cancel()` was observed first, or this sender was already cancelled. */
  'CANCELLED',
  /** The independently authenticated boundary could not be bound to this interaction. */
  'INTERACTION_REFUSED',
  /** The observed route or profile is not a usable destination label. */
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
  /** The send point reported a different route or profile than the one the check was made against. */
  'ROUTE_CHANGED',
  /** The committed policy identity changed between the decision and the dispatch. */
  'POLICY_STALE',
  /** The trusted transport failed or did not confirm. The effect may be partial; nothing is retried. */
  'DISPATCH_FAILED',
  /** Fail-closed catch-all for an unexpected internal failure; carries no detail either. */
  'SENDER_FAILED',
] as const);

export type KeepSendRefusal = (typeof OPENAI_KEEP_SENDER_REFUSALS)[number] | OpenAiTextRequestRefusal;
export type KeepSendResult =
  | Readonly<{ status: 'SENT' }>
  | Readonly<{ status: 'REFUSED'; code: KeepSendRefusal }>;
export type KeepSenderState = 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';

/** One inspected unit of the exact private image, in wire order: the header block, then the model, then each message. */
export type KeepInspectionUnitKind = 'METADATA' | 'MODEL' | 'MESSAGE';
export interface KeepInspectionUnit {
  /** Opaque reference chosen by the sender. It names a position, never a value or a raw span. */
  readonly unitRef: string;
  readonly kind: KeepInspectionUnitKind;
  /** SHA-256 of this unit's exact bytes inside the image. A binding token, never a permission. */
  readonly digest: string;
}

/** What the sender hands the trusted inspector: which image, which interaction, which units. */
export interface KeepInspectionBinding {
  readonly version: 1;
  readonly interactionRef: string;
  /** SHA-256 of the sender's own private snapshot of the exact wire image. */
  readonly imageDigest: string;
  readonly units: readonly KeepInspectionUnit[];
}

export interface KeepInspectionFinding {
  readonly unitRef: string;
  /** Digest the trusted producer pinned for this exact record. Congruence is checked, not trusted. */
  readonly classificationDigest: string;
  readonly classification: Classification;
}

/** The shape a trusted inspector returns. It is validated here; the declared type grants no authority. */
export interface KeepInspectionResult {
  readonly version: 1;
  readonly interactionRef: string;
  readonly imageDigest: string;
  /** A completeness statement, never a safety one. Necessary and nowhere near sufficient. */
  readonly coverage: 'COMPLETE';
  /** Explicit: no part of the image is left unclassified. Anything else refuses. */
  readonly remainder: 'NONE';
  readonly units: readonly KeepInspectionFinding[];
}

export interface KeepSenderObservation {
  /** Destination id and profile digest observed at the send point, right now. */
  readonly destination: SentinelProcessDestination;
  /** The currently committed policy identity and content digest. */
  readonly commit: Readonly<{ id: string; version: string; digest: string }>;
}

export interface KeepSenderSendPoint {
  /**
   * Re-observes the actual route and the committed policy. Called once for the check and again in the
   * same synchronous turn as the dispatch, so no await separates the last check from the effect.
   * Redirects are prohibited: a different route is a refusal, never a followed location.
   */
  observe(): KeepSenderObservation;
  /** Sends exactly these bytes, once. A resolved promise is the only confirmation of the effect. */
  sendExact(image: Uint8Array): Promise<void>;
}

/**
 * The trusted integration host. Every member arrives from an already authenticated adapter or broker;
 * none of them arrives from a request header, body, model text or launcher flag, and none of them
 * authenticates itself here.
 */
export interface KeepSenderHost {
  /** Independently authenticated subject/context plus the observed source and destination with proofs. */
  readonly boundary: BoundaryContext;
  /** Source trust observed for this interaction. Never a payload or model claim. */
  readonly sourceTrust: Trust;
  /** The committed policy snapshot; its content digest comes from `sendPoint.observe()`. */
  readonly policyBundle: PolicyBundle;
  /** Tenant/project the sentinel checks under. Must belong to the authenticated context. */
  readonly scope: SentinelProcessScope;
  /** Known originals registration, or an explicit `null` when this egress has none to protect. */
  readonly known: SentinelProcessKnownRegistration | null;
  /** Host-owned sentinel runner configuration. The child is the module's fixed compiled worker. */
  readonly sentinel: SentinelProcessRunnerConfig;
  /** Whole-image, snapshot-bound classification handoff. The only classification source. */
  inspect(image: Uint8Array, binding: KeepInspectionBinding): unknown;
  /** Independently observed route/profile and the exact-byte transport. */
  readonly sendPoint: KeepSenderSendPoint;
}

export interface OpenAiKeepSender {
  /** One send per call. A second concurrent call is refused rather than queued or duplicated. */
  send(input: unknown): Promise<KeepSendResult>;
  /** Sender-owned, sticky cancellation. After it, this sender can never dispatch again. */
  cancel(): void;
  readonly state: KeepSenderState;
}

/* ---------- Fixed, closed vocabularies and strict structural readers ---------- */

const HOST_KEYS: readonly string[] = ['boundary', 'sourceTrust', 'policyBundle', 'scope', 'known', 'sentinel', 'inspect', 'sendPoint'];
const SEND_POINT_KEYS: readonly string[] = ['observe', 'sendExact'];
const OBSERVATION_KEYS: readonly string[] = ['destination', 'commit'];
const DESTINATION_KEYS: readonly string[] = ['id', 'profileDigest'];
const COMMIT_KEYS: readonly string[] = ['id', 'version', 'digest'];
const RESULT_KEYS: readonly string[] = ['version', 'interactionRef', 'imageDigest', 'coverage', 'remainder', 'units'];
const FINDING_KEYS: readonly string[] = ['unitRef', 'classificationDigest', 'classification'];
const CONTROL = /[\u0000-\u001f\u007f]/u;
const HEX_DIGEST = /^[0-9a-f]{64}$/u;
const MAX_DESTINATION_LABEL = 256;
const CONTENT_TYPE = 'application/json; charset=utf-8';
const encoder = new TextEncoder();

type Fields = Record<string, unknown>;
type ObserveMethod = () => KeepSenderObservation;
type SendExactMethod = (image: Uint8Array) => Promise<void>;
type InspectMethod = (image: Uint8Array, binding: KeepInspectionBinding) => unknown;

/**
 * Bind one already-accepted method to the receiver it was validated on, once. The wrapper calls that
 * captured function through the trusted `Reflect.apply`, which performs the call directly: it reads no
 * property of the host object and never looks up `.call`, `.bind` or `.apply` on it. Calling the captured
 * function is therefore the only host code that runs, the receiver is preserved, and reading a method
 * back off the host later - the one way a Proxy `get` trap could run after the dispatch-point guards -
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
 * A destination label is interpolated into the image's `Host` header, so it is validated here before
 * it can reach the image. This is a structural bound, not authentication of the route.
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

function observationOf(value: unknown): KeepSenderObservation | null {
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

function refused(code: KeepSendRefusal): KeepSendResult {
  return Object.freeze({ status: 'REFUSED' as const, code });
}

/**
 * The exact trusted-host shape. Only what this seam structurally relies on is checked here; the
 * envelope, the policy seam and the sentinel runner remain the authority for everything they own, and
 * this never duplicates them.
 */
function trustedHost(value: unknown): KeepSenderHost | null {
  const fields = exact(value, HOST_KEYS);
  if (fields === null) return null;
  const sendPoint = exact(fields['sendPoint'], SEND_POINT_KEYS);
  if (sendPoint === null) return null;
  const inspect = fields['inspect'];
  const observe = sendPoint['observe'];
  const sendExact = sendPoint['sendExact'];
  if (typeof inspect !== 'function' || typeof observe !== 'function' || typeof sendExact !== 'function') return null;
  if (!(TRUST_LEVELS as readonly string[]).includes(fields['sourceTrust'] as string)) return null;
  const recordish = fields['boundary'];
  const bundle = fields['policyBundle'];
  const scope = fields['scope'];
  const sentinel = fields['sentinel'];
  if (recordish === null || typeof recordish !== 'object' || bundle === null || typeof bundle !== 'object' ||
    scope === null || typeof scope !== 'object' || sentinel === null || typeof sentinel !== 'object') return null;
  const known = fields['known'];
  if (known !== null && (known === null || typeof known !== 'object')) return null;
  // The validated data-property snapshot is authoritative for the callables: each one is captured on the
  // receiver it was found on and is never read off the host again. The send point keeps its own object
  // as its receiver, so a host method that reads its own state still sees it, while a later host-side
  // replacement of `observe` or `sendExact` cannot retarget a sender that already exists.
  const snapshot = Object.freeze({ ...fields });
  return Object.freeze({
    ...snapshot,
    inspect: captured(inspect as InspectMethod, snapshot),
    sendPoint: Object.freeze({
      observe: captured(observe as ObserveMethod, fields['sendPoint']),
      sendExact: captured(sendExact as SendExactMethod, fields['sendPoint']),
    }),
  }) as unknown as KeepSenderHost;
}

/* ---------- The exact private image and its unit decomposition ---------- */

interface SendImage {
  readonly bytes: Uint8Array;
  /** Byte length of the header section, including the blank line that ends it. */
  readonly metadataLength: number;
  /** The exact JSON literal bytes the model occupies in the image. */
  readonly modelLiteral: string;
  /** The exact JSON literal bytes each message content occupies, in wire order. */
  readonly messageLiterals: readonly string[];
}

interface DraftMessage { readonly role: string; readonly literal: string }

function draftMessages(draft: InteractionDraft): readonly DraftMessage[] {
  const payload = draft.payload;
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new TypeError('payload');
  const messages = (payload as { messages?: unknown }).messages;
  if (!Array.isArray(messages)) throw new TypeError('messages');
  return messages.map((message) => {
    if (message === null || typeof message !== 'object' || Array.isArray(message)) throw new TypeError('message');
    const { role, content } = message as { role?: unknown; content?: unknown };
    if (typeof role !== 'string' || typeof content !== 'string') throw new TypeError('content');
    return { role, literal: JSON.stringify(content) };
  });
}

/**
 * Serialize the translated draft into the exact wire image. The header set is fixed and allowlisted:
 * the caller contributes the endpoint (matched literally by the codec), the model and the message
 * texts, and nothing else. There is no treatment here, so the checked image is the sent image.
 */
function buildImage(draft: InteractionDraft, hostLabel: string): SendImage {
  const model = draft.metadata?.model;
  if (typeof model !== 'string') throw new TypeError('model');
  const messages = draftMessages(draft);
  const modelLiteral = JSON.stringify(model);
  const body = `{"model":${modelLiteral},"messages":[${messages
    .map((message) => `{"role":${JSON.stringify(message.role)},"content":${message.literal}}`).join(',')}]}`;
  const head = [
    `POST ${OPENAI_TEXT_REQUEST_ENDPOINT} HTTP/1.1`,
    `Host: ${hostLabel}`,
    `Content-Type: ${CONTENT_TYPE}`,
    `Content-Length: ${encoder.encode(body).byteLength}`,
    '', '',
  ].join('\r\n');
  const headBytes = encoder.encode(head);
  const bodyBytes = encoder.encode(body);
  const bytes = new Uint8Array(headBytes.byteLength + bodyBytes.byteLength);
  bytes.set(headBytes, 0);
  bytes.set(bodyBytes, headBytes.byteLength);
  return Object.freeze({
    bytes, metadataLength: headBytes.byteLength, modelLiteral,
    messageLiterals: Object.freeze(messages.map((message) => message.literal)),
  });
}

/** One unit per inspectable position of the whole image, each bound to its exact bytes inside it. */
function unitsOf(image: SendImage, interactionRef: string): readonly KeepInspectionUnit[] {
  const units: KeepInspectionUnit[] = [
    { unitRef: `${interactionRef}-u0`, kind: 'METADATA', digest: digestOf(image.bytes.subarray(0, image.metadataLength)) },
    { unitRef: `${interactionRef}-u1`, kind: 'MODEL', digest: digestOf(encoder.encode(image.modelLiteral)) },
  ];
  image.messageLiterals.forEach((literal, index) => {
    units.push({ unitRef: `${interactionRef}-u${index + 2}`, kind: 'MESSAGE', digest: digestOf(encoder.encode(literal)) });
  });
  return Object.freeze(units);
}

/* ---------- The trusted inspection handoff ---------- */

/**
 * Validate the inspector's answer as a structure, never as an authority. Returns the finding list only
 * when every declared unit is present exactly once; the caller then binds each record by digest and
 * decides policy over it.
 */
function findingsOf(value: unknown, binding: KeepInspectionBinding): readonly KeepInspectionFinding[] | null {
  const fields = exact(value, RESULT_KEYS);
  if (fields === null) return null;
  if (fields['version'] !== 1 || fields['interactionRef'] !== binding.interactionRef ||
    fields['imageDigest'] !== binding.imageDigest || fields['coverage'] !== 'COMPLETE' ||
    fields['remainder'] !== 'NONE') return null;
  const units = fields['units'];
  if (!Array.isArray(units) || units.length !== binding.units.length) return null;
  const seen = new Set<string>();
  const findings: KeepInspectionFinding[] = [];
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
 * the pinned digest matches the record the sender will actually decide over. A substituted record, an
 * unresolved remainder, or a semantic-only PUBLIC judgment that no detector corroborated all refuse:
 * detector absence is never clearance.
 */
function usableClassification(finding: KeepInspectionFinding): Classification | null {
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

/** The envelope contract's own five-minute window, re-declared so the dispatch-point re-read uses it. */
const MAX_PROOF_AGE_MS = 5 * 60 * 1000;

/**
 * Are the proof intervals this interaction was actually bound under still current? This re-reads the
 * envelope's own snapshots against the clock at the dispatch point, exactly as
 * `parseInteractionEnvelope` requires a wire timestamp to be inside every proof interval, and it
 * changes nothing about which proofs these are: an identical digest is not a current proof, a closed
 * window grants nothing back, and a boundary that went stale mid-send cannot be bound to this
 * dispatch. Freshness only; authenticating a proof stays the host's obligation.
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

/* ---------- The sender ---------- */

/**
 * Create a KEEP-only sender bound to one trusted host. Construction never throws and never sends: an
 * unusable host yields a permanently restrictive sender instead of an echo of a caller value.
 */
export function createOpenAiKeepSender(host: unknown): OpenAiKeepSender {
  const trusted = trustedHost(host);
  if (trusted === null) {
    return Object.freeze({
      send: (): Promise<KeepSendResult> => Promise.resolve(refused('HOST_INVALID')),
      cancel: (): void => { /* an unusable sender owns nothing to cancel */ },
      get state(): KeepSenderState { return 'FAILED'; },
    });
  }
  const runner = createSentinelProcessRunner(trusted.sentinel);
  let busy = false;
  let cancelled = false;

  /** One send, start to finish. Every stage that is not an authorization withholds. */
  const run = async (input: unknown): Promise<KeepSendResult> => {
    const translated = translateOpenAiTextRequest(input);
    if (translated.status === 'REFUSED') return refused(translated.reason);

    const observed = observationOf(trusted.sendPoint.observe());
    if (observed === null) return refused('ROUTE_REFUSED');

    const envelope = createInteractionEnvelope(translated.draft, trusted.boundary);
    const interactionRef = envelope.id;
    if (trusted.scope.tenantRef !== envelope.context.tenantId ||
      (envelope.context.projectId !== undefined && trusted.scope.projectRef !== envelope.context.projectId)) {
      return refused('SCOPE_REFUSED');
    }

    let image: SendImage;
    try { image = buildImage(translated.draft, observed.destination.id); } catch { return refused('SENDER_FAILED'); }
    const imageDigest = digestOf(image.bytes);
    const units = unitsOf(image, interactionRef);
    const binding: KeepInspectionBinding = Object.freeze({
      version: 1, interactionRef, imageDigest, units,
    });

    // The inspector gets its own copy. It can answer, mutate or throw; none of it reaches the bytes,
    // and a thrown value is never inspected: its text, class and stack are all caller-controlled.
    let findings: readonly KeepInspectionFinding[] | null;
    try { findings = findingsOf(trusted.inspect(image.bytes.slice(), binding), binding); } catch { findings = null; }
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
      const boundary: PolicyBoundary = {
        interactionRef, candidateRef: unit.unitRef,
        classificationDigest: finding.classificationDigest,
        authenticated: { subject: envelope.subject, context: envelope.context },
        observed: { source: { ...envelope.source, trust: trusted.sourceTrust }, destination: envelope.destination },
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
    // A cancellation this sender asked for is reported as one; every other non-`ALLOW` outcome,
    // including a check that never ran, collapses into one fixed sentinel refusal.
    if (outcome.status !== 'ALLOW') return refused(outcome.code === 'CANCELLED' ? 'CANCELLED' : 'SENTINEL_BLOCKED');
    const release = outcome.release;

    // The dispatch point, deliberately ordered. The transport and observation callables were captured
    // during validation, so this is the last point at which any host property is read at all: the final
    // host observation and every structural and freshness check it can invalidate happen first; sticky
    // cancellation is then re-read with nothing between that read and the transport call but this frame,
    // so a cancel raised by that last callback can no longer reach a dispatch. The early read below only
    // spares the host a second observation.
    if (cancelled) return refused('CANCELLED');
    const current = observationOf(trusted.sendPoint.observe());
    if (current === null) return refused('ROUTE_REFUSED');
    if (!same(current.destination, observed.destination)) return refused('ROUTE_CHANGED');
    if (!same(current.commit, observed.commit)) return refused('POLICY_STALE');
    // The finite trusted callback and the fixed-worker child both took real time. Re-read the boundary
    // evidence this interaction was bound under: a proof window that closed during the send is not a
    // still-current context, and the identity, context and observed route it authorized are no longer
    // usable for this dispatch. Recreating the envelope instead would mint a new interaction identity
    // and invalidate every digest, unit reference and policy decision already pinned over it.
    if (!currentEvidence(envelope, Date.now())) return refused('INTERACTION_REFUSED');
    // No callback and no await separates this read from the effect it guards.
    if (cancelled) return refused('CANCELLED');
    try { await trusted.sendPoint.sendExact(release); }
    catch { return refused('DISPATCH_FAILED'); }
    // The effect already happened once. It is never retried, repeated or replayed from a returned handle.
    return Object.freeze({ status: 'SENT' as const });
  };

  return Object.freeze({
    /**
     * Send one complete text request, or refuse it with a fixed code. The admission claim is taken
     * synchronously, before any stage runs, so a concurrent call is refused rather than queued and can
     * never produce a second dispatch.
     */
    send: (input: unknown): Promise<KeepSendResult> => {
      if (busy) return Promise.resolve(refused('SENDER_BUSY'));
      if (cancelled) return Promise.resolve(refused('CANCELLED'));
      busy = true;
      return run(input).catch(() => refused('SENDER_FAILED')).finally(() => { busy = false; });
    },
    cancel: (): void => {
      if (cancelled) return;
      cancelled = true;
      runner.cancel();
    },
    get state(): KeepSenderState {
      if (cancelled) return 'CANCELLED';
      if (runner.state === 'QUARANTINED') return 'FAILED';
      return busy ? 'BUSY' : 'IDLE';
    },
  });
}