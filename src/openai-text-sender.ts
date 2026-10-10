/**
 * Complete-text OpenAI-compatible request sender (#201, whole-message MASK #218). One call owns the
 * whole runtime effect: translation, the exact private serialized ORIGINAL request image,
 * snapshot-bound whole-image classification evidence over that original, the real deterministic SEND
 * policy decision per unit, a private per-unit plan, the rebuilt final image when real policy selected
 * `MASK` for a message, the real fixed-worker egress sentinel child process over those exact final
 * bytes, and exactly one trusted transport dispatch.
 * Normative expansion: docs/contracts/openai-text-sender.md - the contract owns the normative order, codes and
 * limits; this header is the working summary.
 *
 * What this is NOT. It is not a gateway, a listener, a provider client, an authentication
 * implementation, a credential or vault path, a general transformation engine or a response release.
 * The one transformation it owns is the narrow, irreversible, generic whole-message mask below. The
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
 * - `KEEP` releases as before. A `MESSAGE` unit whose real policy decision is `SELECTED` with
 *   treatment `MASK` releases as the fixed generic literal `[hylja:masked]`
 *   (decision 011), irreversibly and with
 *   nothing original in the released representation. That literal is original-independent and carries
 *   no kind, format, fidelity or other derived fact; it is not a typed placeholder, not a field-level
 *   or span-level rewrite, not a mapping and not reversible. `METADATA` and `MODEL` units still
 *   require `KEEP`; `REMOVE` and every other treatment, and `REQUIRE_REVIEW`, all withhold, because
 *   this unit implements no other treatment and no review authority.
 * - `coverage: 'COMPLETE'` alone never authorizes. Authorization is the conjunction of exact whole-image
 *   unit coverage, a classification digest that matches the record actually used, a real `RESOLVED`
 *   classification carrying detector evidence, a real `SELECTED` policy decision that is `KEEP` for
 *   every unit or `MASK` for a `MESSAGE` unit, a derivation that reproduces the plan over the final
 *   bytes, and a real `ALLOW` from the sentinel child over exactly those final bytes.
 * - Authorization does not outlive its evidence. Sticky cancellation is re-read after the last host
 *   observation, and the snapshotted boundary proof intervals are re-read for freshness at the dispatch
 *   point, immediately before the transport call. That is freshness, never authenticity: authenticating
 *   those proofs remains the host's obligation, and an unchanged digest is not a current proof.
 * - The scope and the known-original registration the child is asked to check under are captured into
 *   **private copies before the trusted inspection callback runs**, and those copies - not the host's own
 *   mutable objects - are what the child receives. `scope` and `known` are host-owned and mutable: read
 *   only at check time, a host that rewrites either during the inspection would decide which scope the
 *   real child runs under, and the dispatch would then happen under a scope this sender never bound to
 *   this interaction. The existing sentinel snapshot seam owns that validation and copying, so it is
 *   reused rather than duplicated, and its request id is this send's own generated interaction identity.
 *   It is not a rule that revokes on host-side mutation: a host that rewrites its own members to the same
 *   values is checked under exactly the captured ones.
 * - Every accepted method is captured once, on the receiver it was validated on, and is never looked up
 *   on the host object again. `inspectOriginal`, `observe` and `sendExact` run as the function references the
 *   validated data properties held, so reading a method back off the host at the dispatch point - a
 *   Proxy `get` trap away from running after the last guard - never happens, and a host that replaces
 *   its own method later does not retarget a sender that already exists. Invoking the captured transport
 *   is still host code: its honesty, and anything it does with its receiver, remain host obligations.
 * - Detector absence is never clearance: an empty or partial finding set, an unclassified remainder, a
 *   caller-supplied digest or an `UNRESOLVED` record all refuse.
 *
 * Both images are private. The trusted inspection callback is bound to the ORIGINAL image and receives
 * its own copy, which it may scribble on; the rebuilt final image exists only inside this unit. The
 * released bytes are the sentinel's own private ALLOW copy over the FINAL image. The only
 * representation that may reach the transport is that copy, handed over once.
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
import { snapshotSentinelRequest } from './egress-sentinel-process-protocol.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT, translateOpenAiTextRequest } from './openai-text-request.js';
import type { OpenAiTextRequestRefusal } from './openai-text-request.js';

/**
 * Every refusal is one of these fixed codes, or one of the codec's own fixed codes. No code carries a
 * field name, byte offset, parser excerpt, exception message, transport error or any part of the
 * input, so a refusal is safe to log and a planted value never reappears in a result.
 */
export const OPENAI_TEXT_SENDER_REFUSALS = Object.freeze([
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

export type TextSendRefusal = (typeof OPENAI_TEXT_SENDER_REFUSALS)[number] | OpenAiTextRequestRefusal;
export type TextSendResult =
  | Readonly<{ status: 'SENT' }>
  | Readonly<{ status: 'REFUSED'; code: TextSendRefusal }>;
export type TextSenderState = 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';

/** One inspected unit of the exact private image, in wire order: the header block, then the model, then each message. */
export type TextInspectionUnitKind = 'METADATA' | 'MODEL' | 'MESSAGE';
export interface TextInspectionUnit {
  /** Opaque reference chosen by the sender. It names a position, never a value or a raw span. */
  readonly unitRef: string;
  readonly kind: TextInspectionUnitKind;
  /** SHA-256 of this unit's exact bytes inside the image. A binding token, never a permission. */
  readonly digest: string;
}

/** What the sender hands the trusted inspector: which image, which interaction, which units. */
export interface TextInspectionBinding {
  readonly version: 1;
  readonly interactionRef: string;
  /** SHA-256 of the sender's own private snapshot of the exact wire image. */
  readonly imageDigest: string;
  readonly units: readonly TextInspectionUnit[];
}

export interface TextInspectionFinding {
  readonly unitRef: string;
  /** Digest the trusted producer pinned for this exact record. Congruence is checked, not trusted. */
  readonly classificationDigest: string;
  readonly classification: Classification;
}

/** The shape a trusted inspector returns. It is validated here; the declared type grants no authority. */
export interface TextInspectionResult {
  readonly version: 1;
  readonly interactionRef: string;
  readonly imageDigest: string;
  /** A completeness statement, never a safety one. Necessary and nowhere near sufficient. */
  readonly coverage: 'COMPLETE';
  /** Explicit: no part of the image is left unclassified. Anything else refuses. */
  readonly remainder: 'NONE';
  readonly units: readonly TextInspectionFinding[];
}

export interface TextSenderObservation {
  /** Destination id and profile digest observed at the send point, right now. */
  readonly destination: SentinelProcessDestination;
  /** The currently committed policy identity and content digest. */
  readonly commit: Readonly<{ id: string; version: string; digest: string }>;
}

export interface TextSenderSendPoint {
  /**
   * Re-observes the actual route and the committed policy. Called once for the check and again in the
   * same synchronous turn as the dispatch, so no await separates the last check from the effect.
   * Redirects are prohibited: a different route is a refusal, never a followed location.
   */
  observe(): TextSenderObservation;
  /**
   * REQUIRED, and awaited only after the inspection, the policy decisions, the derivation and the real
   * fixed-worker child have all completed. It prepares the transport without sending: it carries no
   * byte, returns no approval, decides nothing, and cannot grant a route, a commit or a freshness.
   * It exists because a transport may defer its native write until after the connection completes, so
   * the dispatch-point guards must be read **after** the transport is ready, not before. A rejected or
   * failed readiness is `DISPATCH_FAILED`, exactly as a failed transport is, and it withholds the bytes.
   */
  waitUntilReady(): Promise<void>;
  /** Sends exactly these bytes, once. A resolved promise is the only confirmation of the effect. */
  sendExact(image: Uint8Array): Promise<void>;
}

/**
 * The trusted integration host. Every member arrives from an already authenticated adapter or broker;
 * none of them arrives from a request header, body, model text or launcher flag, and none of them
 * authenticates itself here.
 */
export interface TextSenderHost {
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
  inspectOriginal(image: Uint8Array, binding: TextInspectionBinding): unknown;
  /** Independently observed route/profile and the exact-byte transport. */
  readonly sendPoint: TextSenderSendPoint;
}

export interface OpenAiTextSender {
  /** One send per call. A second concurrent call is refused rather than queued or duplicated. */
  send(input: unknown): Promise<TextSendResult>;
  /** Sender-owned, sticky cancellation. After it, this sender can never dispatch again. */
  cancel(): void;
  readonly state: TextSenderState;
}

/* ---------- Fixed, closed vocabularies and strict structural readers ---------- */

const HOST_KEYS: readonly string[] = ['boundary', 'sourceTrust', 'policyBundle', 'scope', 'known', 'sentinel', 'inspectOriginal', 'sendPoint'];
const SEND_POINT_KEYS: readonly string[] = ['observe', 'waitUntilReady', 'sendExact'];
const OBSERVATION_KEYS: readonly string[] = ['destination', 'commit'];
const DESTINATION_KEYS: readonly string[] = ['id', 'profileDigest'];
const COMMIT_KEYS: readonly string[] = ['id', 'version', 'digest'];
const RESULT_KEYS: readonly string[] = ['version', 'interactionRef', 'imageDigest', 'coverage', 'remainder', 'units'];
const FINDING_KEYS: readonly string[] = ['unitRef', 'classificationDigest', 'classification'];
const CONTROL = /[\u0000-\u001f\u007f]/u;
/**
 * The destination label is interpolated into the image's `Host` header, so an ordinary space is
 * refused there exactly as a control character is. It is the label bound only: every other string
 * this module reads keeps the narrower control-character rule above.
 */
const LABEL_UNSAFE = /[\u0000-\u0020\u007f]/u;
const HEX_DIGEST = /^[0-9a-f]{64}$/u;
const MAX_DESTINATION_LABEL = 256;
const CONTENT_TYPE = 'application/json; charset=utf-8';
const encoder = new TextEncoder();

type Fields = Record<string, unknown>;
type ObserveMethod = () => TextSenderObservation;
type WaitUntilReadyMethod = () => Promise<void>;
type SendExactMethod = (image: Uint8Array) => Promise<void>;
type InspectOriginalMethod = (image: Uint8Array, binding: TextInspectionBinding) => unknown;

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
 * A unit digest over encoded text. The encode buffer is this caller's own temporary - it exists to be
 * hashed and nothing else - so it is zeroed here rather than left for the garbage collector. The JS
 * string it was encoded from is immutable and is not, and cannot be, erased by this module.
 */
function digestOfText(text: string): string {
  const encoded = encoder.encode(text);
  try { return digestOf(encoded); } finally { encoded.fill(0); }
}

/**
 * A destination label is interpolated into the image's `Host` header, so it is validated here before
 * it can reach the image: non-empty, bounded, and free of control characters and of ordinary spaces,
 * because a space would already make the emitted header value ambiguous. This is a structural bound,
 * not authentication of the route.
 */
function usableDestination(destination: unknown): SentinelProcessDestination | null {
  const fields = exact(destination, DESTINATION_KEYS);
  if (fields === null) return null;
  const id = fields['id'];
  const profileDigest = fields['profileDigest'];
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_DESTINATION_LABEL ||
    LABEL_UNSAFE.test(id) || typeof profileDigest !== 'string' || !HEX_DIGEST.test(profileDigest)) return null;
  return { id, profileDigest };
}

function observationOf(value: unknown): TextSenderObservation | null {
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

function refused(code: TextSendRefusal): TextSendResult {
  return Object.freeze({ status: 'REFUSED' as const, code });
}

/**
 * The exact trusted-host shape. Only what this seam structurally relies on is checked here; the
 * envelope, the policy seam and the sentinel runner remain the authority for everything they own, and
 * this never duplicates them.
 */
function trustedHost(value: unknown): TextSenderHost | null {
  const fields = exact(value, HOST_KEYS);
  if (fields === null) return null;
  const sendPoint = exact(fields['sendPoint'], SEND_POINT_KEYS);
  if (sendPoint === null) return null;
  const inspect = fields['inspectOriginal'];
  const observe = sendPoint['observe'];
  const waitUntilReady = sendPoint['waitUntilReady'];
  const sendExact = sendPoint['sendExact'];
  // Readiness is a required member, never an optional legacy path: a send point that cannot be prepared
  // cannot be dispatched through, so there is exactly one shape and no fallback.
  if (typeof inspect !== 'function' || typeof observe !== 'function' ||
    typeof waitUntilReady !== 'function' || typeof sendExact !== 'function') return null;
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
  // replacement of `observe` or `sendExact` cannot retarget a sender that already exists. The inspection
  // member is installed under the name the host declares it, so the call site reads THIS captured
  // function - and never the raw function the spread above carried over - and the receiver it runs on is
  // that same accepted snapshot, carrying the host's own accepted members and not the wrappers below.
  const snapshot = Object.freeze({ ...fields });
  return Object.freeze({
    ...snapshot,
    inspectOriginal: captured(inspect as InspectOriginalMethod, snapshot),
    sendPoint: Object.freeze({
      observe: captured(observe as ObserveMethod, fields['sendPoint']),
      waitUntilReady: captured(waitUntilReady as WaitUntilReadyMethod, fields['sendPoint']),
      sendExact: captured(sendExact as SendExactMethod, fields['sendPoint']),
    }),
  }) as unknown as TextSenderHost;
}

/* ---------- The exact private image and its unit decomposition ---------- */

interface SendImage {
  readonly bytes: Uint8Array;
  /** Byte length of the header section, including the blank line that ends it. */
  readonly metadataLength: number;
  /** The observed destination label this image was framed with. */
  readonly hostLabel: string;
  /** The exact JSON body the image carries, as text. Never a parsed value. */
  readonly body: string;
  /** The exact JSON literal bytes the model occupies in the image. */
  readonly modelLiteral: string;
  /** The model text itself, as the codec decoded it. A masked rebuild never changes it. */
  readonly model: string;
  /** The roles, in wire order. A masked rebuild never changes one. */
  readonly messages: readonly DraftMessage[];
  /** The exact JSON literal bytes each message content occupies, in wire order. */
  readonly messageLiterals: readonly string[];
}

interface DraftMessage { readonly role: string; readonly literal: string }

/**
 * The one generic irreversible literal this unit can emit. It is original-independent: it carries no
 * kind, format, fidelity or other derived fact, it is not a typed placeholder, and nothing resolves it
 * back. Its only visibility is the minimal irreversible presence and structure a masked unit has.
 */
const MASK_LITERAL = '[hylja:masked]';
/** The exact JSON literal those bytes occupy as a message `content` value in the rebuilt body. */
const MASK_JSON_LITERAL = JSON.stringify(MASK_LITERAL);
/** Recorded in every plan entry, so a final image is bound to the rule version that produced it. */
const TRANSFORMATION_VERSION = 1;

/**
 * One private derivation commitment, shared by both arms of the plan. It binds the ORIGINAL
 * interaction's unit reference and digest to the classification, the observed policy commit, the
 * decision fingerprint and the transformation version that were actually used. It is congruence
 * evidence about one change and nothing else: not clearance, not authorization, not an identity and
 * not a bearer capability.
 */
interface PlanBinding {
  readonly unitRef: string;
  readonly originalDigest: string;
  readonly classificationDigest: string;
  readonly policy: Readonly<{ id: string; version: string; digest: string }>;
  readonly decisionRef: string | null;
  readonly version: number;
}

/**
 * The private, discriminated per-unit plan. Only the real Policy Engine writes an entry, only for a
 * real `SELECTED` decision: `KEEP` for every unit kind, and `MASK` for a `MESSAGE` unit only. There is
 * no caller-selected treatment, no substitute text and no per-span or per-field rewrite anywhere here.
 */
type UnitPlan =
  | Readonly<PlanBinding & { treatment: 'KEEP'; unitKind: TextInspectionUnitKind }>
  | Readonly<PlanBinding & { treatment: 'MASK'; unitKind: 'MESSAGE' }>;

/** A rebuilt image plus the unit digests the plan has to reproduce exactly. */
interface DerivedImage {
  readonly bytes: Uint8Array;
  readonly imageDigest: string;
  readonly units: readonly TextInspectionUnit[];
}

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
 * Frame the given message literals into the exact wire image. The header set is fixed and
 * allowlisted: the caller contributes the endpoint (matched literally by the codec), the model and the
 * message texts, and nothing else. `Content-Length` is the only field derived from the body, so a
 * rebuilt body is the only thing that can change a header, and the trusted codec owns that bound.
 *
 * The body is encoded exactly once. That single buffer is both the body half of the framed image and
 * the source of the `Content-Length` field, so no second copy of the wire bytes is ever allocated here
 * for a length alone.
 */
function frameImage(messages: readonly DraftMessage[], model: string, hostLabel: string): SendImage {
  const modelLiteral = JSON.stringify(model);
  const body = `{"model":${modelLiteral},"messages":[${messages
    .map((message) => `{"role":${JSON.stringify(message.role)},"content":${message.literal}}`).join(',')}]}`;
  // The body buffer is allocated first and is this function's own, so its own `finally` covers every
  // step after it: encoding the head, allocating the framed image, and returning. The head buffer has
  // the same status and is zeroed inside that window. The framed `bytes` itself is owned by whoever
  // built this image - the ORIGINAL image or the derivation - and is enrolled there instead.
  const bodyBytes = encoder.encode(body);
  try {
    const head = [
      `POST ${OPENAI_TEXT_REQUEST_ENDPOINT} HTTP/1.1`,
      `Host: ${hostLabel}`,
      `Content-Type: ${CONTENT_TYPE}`,
      `Content-Length: ${bodyBytes.byteLength}`,
      '', '',
    ].join('\r\n');
    const headBytes = encoder.encode(head);
    try {
      const bytes = new Uint8Array(headBytes.byteLength + bodyBytes.byteLength);
      bytes.set(headBytes, 0);
      bytes.set(bodyBytes, headBytes.byteLength);
      return Object.freeze({
        bytes, metadataLength: headBytes.byteLength, hostLabel, body, model, modelLiteral, messages,
        messageLiterals: Object.freeze(messages.map((message) => message.literal)),
      });
    } finally { headBytes.fill(0); }
  } finally { bodyBytes.fill(0); }
}

/** The ORIGINAL image: what the caller's body says, with no treatment applied anywhere. */
function buildImage(draft: InteractionDraft, hostLabel: string): SendImage {
  const model = draft.metadata?.model;
  if (typeof model !== 'string') throw new TypeError('model');
  return frameImage(draftMessages(draft), model, hostLabel);
}

/**
 * Rebuild the final image from the private plan and prove the rebuild is congruent with the original.
 *
 * A `KEEP` message keeps its exact original literal bytes, a `KEEP` model keeps its exact original
 * literal bytes, and roles, order and count never change: the same text in two messages is two
 * separate units, so one selected unit can never rewrite a byte in another. A `MASK` message unit is
 * replaced whole by the fixed literal. Only `Content-Length` is recomputed, as the UTF-8 byte length
 * of the rebuilt body.
 *
 * Every step is deterministic and fail-closed: the rebuilt body is re-parsed by the same strict codec
 * the caller's original had to pass and is compared against the plan, so a representation the codec
 * refuses, a digest that does not reproduce or a message that does not decode back to the plan throws
 * and the send withholds. Masked text is never relabelled, never reclassified and never re-bound to a
 * clearance: no `PUBLIC` relabelling happens here, and a final unit digest is recomputed rather than
 * reused from the original.
 */
function deriveFinal(image: SendImage, units: readonly TextInspectionUnit[],
  plan: readonly UnitPlan[], interactionRef: string): DerivedImage {
  if (plan.length !== units.length || plan.length !== image.messageLiterals.length + 2) {
    throw new TypeError('plan');
  }
  // METADATA and MODEL occupy the first two plan slots, so message i is plan[i + 2].
  const messages = image.messages.map((message, index) => {
    const entry = plan[index + 2];
    return { role: message.role, literal: entry === undefined || entry.treatment === 'KEEP'
      ? message.literal : MASK_JSON_LITERAL };
  });
  const final = frameImage(messages, image.model, image.hostLabel);
  // Every refusal below abandons this final image, and an abandoned image is still an allocated copy of
  // the wire bytes. So the one buffer allocated for the rebuild is this function's own: it is returned
  // to the caller only if the whole derivation holds, and zeroed here if anything in it fails.
  try {
    const finalUnits = unitsOf(final, interactionRef);
    const maskedDigest = digestOfText(MASK_JSON_LITERAL);
    for (let index = 0; index < plan.length; index += 1) {
      const entry = plan[index] as UnitPlan;
      const original = units[index] as TextInspectionUnit;
      const derived = finalUnits[index] as TextInspectionUnit;
      if (entry.unitRef !== original.unitRef || entry.unitRef !== derived.unitRef ||
        entry.unitKind !== original.kind || entry.unitKind !== derived.kind ||
        entry.originalDigest !== original.digest) throw new TypeError('binding');
      if (entry.treatment === 'MASK') {
        if (entry.unitKind !== 'MESSAGE' || derived.digest !== maskedDigest) throw new TypeError('mask');
      } else if (entry.unitKind !== 'METADATA' && derived.digest !== original.digest) {
        // A KEEP model or message unit must still carry its own original bytes. The METADATA unit is the
        // one exception decision 011 authorizes: its header block covers the recomputed Content-Length.
        throw new TypeError('keep');
      }
    }
    const reparsed = translateOpenAiTextRequest({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: final.body });
    if (reparsed.status !== 'TRANSLATED') throw new TypeError('codec');
    const decoded = draftMessages(reparsed.draft);
    if (reparsed.draft.metadata?.model !== image.model || decoded.length !== messages.length) {
      throw new TypeError('codec');
    }
    for (let index = 0; index < messages.length; index += 1) {
      if (decoded[index]?.role !== messages[index]?.role || decoded[index]?.literal !== messages[index]?.literal) {
        throw new TypeError('codec');
      }
    }
    return Object.freeze({ bytes: final.bytes, imageDigest: digestOf(final.bytes), units: finalUnits });
  } catch (failure) {
    final.bytes.fill(0);
    throw failure;
  }
}

/**
 * The fail-closed entry to the derivation. A deterministic failure - a codec refusal, a digest that
 * does not reproduce, a message that does not decode back - withholds the whole send and carries no
 * detail; no partial image, no substitute literal and no original ever comes back out of here.
 */
function derivationOf(image: SendImage, units: readonly TextInspectionUnit[],
  plan: readonly UnitPlan[], interactionRef: string): DerivedImage | null {
  try { return deriveFinal(image, units, plan, interactionRef); } catch { return null; }
}

/** One unit per inspectable position of the whole image, each bound to its exact bytes inside it. */
function unitsOf(image: SendImage, interactionRef: string): readonly TextInspectionUnit[] {
  const units: TextInspectionUnit[] = [
    { unitRef: `${interactionRef}-u0`, kind: 'METADATA', digest: digestOf(image.bytes.subarray(0, image.metadataLength)) },
    { unitRef: `${interactionRef}-u1`, kind: 'MODEL', digest: digestOfText(image.modelLiteral) },
  ];
  image.messageLiterals.forEach((literal, index) => {
    units.push({ unitRef: `${interactionRef}-u${index + 2}`, kind: 'MESSAGE', digest: digestOfText(literal) });
  });
  return Object.freeze(units);
}

/* ---------- The trusted inspection handoff ---------- */

/**
 * Validate the inspector's answer as a structure, never as an authority. Returns the finding list only
 * when every declared unit is present exactly once; the caller then binds each record by digest and
 * decides policy over it.
 */
function findingsOf(value: unknown, binding: TextInspectionBinding): readonly TextInspectionFinding[] | null {
  const fields = exact(value, RESULT_KEYS);
  if (fields === null) return null;
  if (fields['version'] !== 1 || fields['interactionRef'] !== binding.interactionRef ||
    fields['imageDigest'] !== binding.imageDigest || fields['coverage'] !== 'COMPLETE' ||
    fields['remainder'] !== 'NONE') return null;
  const units = fields['units'];
  if (!Array.isArray(units) || units.length !== binding.units.length) return null;
  const seen = new Set<string>();
  const findings: TextInspectionFinding[] = [];
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
function usableClassification(finding: TextInspectionFinding): Classification | null {
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
export function createOpenAiTextSender(host: unknown): OpenAiTextSender {
  const trusted = trustedHost(host);
  if (trusted === null) {
    return Object.freeze({
      send: (): Promise<TextSendResult> => Promise.resolve(refused('HOST_INVALID')),
      cancel: (): void => { /* an unusable sender owns nothing to cancel */ },
      get state(): TextSenderState { return 'FAILED'; },
    });
  }
  const runner = createSentinelProcessRunner(trusted.sentinel);
  let busy = false;
  let cancelled = false;

  /** One send, start to finish. Every stage that is not an authorization withholds. */
  const run = async (input: unknown): Promise<TextSendResult> => {
    const translated = translateOpenAiTextRequest(input);
    if (translated.status === 'REFUSED') return refused(translated.reason);

    const observed = observationOf(trusted.sendPoint.observe());
    if (observed === null) return refused('ROUTE_REFUSED');

    // Binding the independently authenticated boundary to this interaction is the envelope's own
    // refusal point, so it is caught here and nowhere else: evidence that cannot be bound at all
    // (an expired, malformed or foreign-boundary window) is INTERACTION_REFUSED, exactly like
    // evidence that was bound and is no longer current at the dispatch point below. Letting it reach
    // the outer catch-all would report an internal failure for a boundary the host simply could not
    // prove, and would carry no detail either way.
    let envelope: InteractionEnvelope;
    try { envelope = createInteractionEnvelope(translated.draft, trusted.boundary); }
    catch { return refused('INTERACTION_REFUSED'); }
    const interactionRef = envelope.id;

    let image: SendImage;
    try { image = buildImage(translated.draft, observed.destination.id); } catch { return refused('SENDER_FAILED'); }
    // Every byte buffer this send allocates is enrolled here the instant it is allocated, and every
    // enrolled buffer is zeroed when this send ends: on the accepted path, and on every refusal alike,
    // including the refusals taken before the inspection ever runs. A buffer this module allocated is
    // its own to clear; caller-supplied text, immutable JS strings and anything the trusted inspector
    // copies out for itself are not this module's to erase. This is a statement about the buffers this
    // module owns, not about the runtime's memory, a heap dump or any other process's copies.
    const owned: Uint8Array[] = [];
    const own = (buffer: Uint8Array): Uint8Array => { owned.push(buffer); return buffer; };
    const wipeOwned = (): void => { for (const buffer of owned) buffer.fill(0); };
    own(image.bytes);
    const imageDigest = digestOf(image.bytes);
    const units = unitsOf(image, interactionRef);
    const binding: TextInspectionBinding = Object.freeze({
      version: 1, interactionRef, imageDigest, units,
    });

    // The scope, registration and destinations the child is asked to check under are captured into
    // private, capped copies BEFORE the host inspector runs, and those copies - not the host's own
    // aliases - are what the child is later handed. The request this send owns and checks is the
    // FINAL image; it does not exist yet, so this pre-capture binds only what cannot wait for the
    // policy decisions. The existing sentinel
    // snapshot seam owns that validation and copying, so this reuses it instead of adding a second
    // context validator: an unknown own key, an oversized registration, a registration scope that is not
    // the check scope, an unsupported value or a hostile trap refuses here exactly as the runner's own
    // check refuses, before any child exists. The per-operation binding token is this send's own generated
    // interaction identity - never a fixed global id - and the runner still mints the real per-child
    // request id when it spawns.
    const taken = snapshotSentinelRequest({
      bytes: image.bytes,
      scope: trusted.scope,
      destination: observed.destination,
      // What the decision authorized: the route in the authenticated boundary, not the observed one.
      // A swapped boundary or a changed route is therefore a real mismatch for the child to find.
      authorized: { id: envelope.destination.ref, profileDigest: observed.destination.profileDigest },
      known: trusted.known,
    }, `${interactionRef}.sentinel`);
    if (!taken.ok) {
      // Nothing on this branch reaches a child, so both outcomes withhold. A scope that does not belong
      // to the authenticated context keeps the refusal it has always reported; it is read through own
      // data descriptors, never an accessor, and it decides nothing that could authorize an effect. The
      // ORIGINAL image built above is this send's own buffer, so it is cleared on this path too.
      wipeOwned();
      const tenantRef = ownData(trusted.scope, 'tenantRef');
      const projectRef = ownData(trusted.scope, 'projectRef');
      if (tenantRef !== envelope.context.tenantId ||
        (envelope.context.projectId !== undefined && projectRef !== envelope.context.projectId)) {
        return refused('SCOPE_REFUSED');
      }
      return refused('SENTINEL_BLOCKED');
    }
    const capturedRequest = taken.value;
    try {
      // The captured scope is compared against the BOUND ENVELOPE, not against an earlier mutable alias
      // of the host object: this is the scope the child is about to run under, so it is the one that
      // must belong to this authenticated tenant/project.
      if (capturedRequest.scope.tenantRef !== envelope.context.tenantId ||
        (envelope.context.projectId !== undefined &&
          capturedRequest.scope.projectRef !== envelope.context.projectId)) {
        return refused('SCOPE_REFUSED');
      }

      // The inspector gets its own copy. It can answer, mutate or throw; none of it reaches the bytes,
      // and a thrown value is never inspected: its text, class and stack are all caller-controlled. The
      // copy is enrolled before the call, so it is cleared whether the callback answers or throws.
      let findings: readonly TextInspectionFinding[] | null;
      const inspected = own(image.bytes.slice());
      try { findings = findingsOf(trusted.inspectOriginal(inspected, binding), binding); }
      catch { findings = null; }
      if (findings === null) return refused('INSPECTION_REFUSED');
      const byUnit = new Map(findings.map((finding) => [finding.unitRef, finding] as const));
      const plan: UnitPlan[] = [];

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
        const commitment: PlanBinding = {
          unitRef: unit.unitRef, originalDigest: unit.digest,
          classificationDigest: finding.classificationDigest, policy: { ...observed.commit },
          decisionRef: decision.decisionRef ?? null, version: TRANSFORMATION_VERSION,
        };
        // The one treatment this unit implements, for the one unit kind that may carry it. The
        // decision is real policy's alone: nothing here can select it, and the METADATA and MODEL
        // units are never masked, so a MASK decision over either still refuses below.
        if (unit.kind === 'MESSAGE' && decision.treatment === 'MASK') {
          plan.push(Object.freeze({ ...commitment, treatment: 'MASK', unitKind: 'MESSAGE' }));
          continue;
        }
        if (decision.treatment !== 'KEEP') return refused('POLICY_NOT_KEEP');
        plan.push(Object.freeze({ ...commitment, treatment: 'KEEP', unitKind: unit.kind }));
      }

      // The rebuild is deterministic and fail-closed. Anything the trusted codec refuses, any digest
      // the plan does not reproduce and any message that does not decode back withholds the send, and
      // a derived image never becomes a handle: it exists only here, is checked below and is dropped
      // with this frame.
      const derived = derivationOf(image, units, plan, interactionRef);
      if (derived === null) return refused('SENDER_FAILED');
      // The rebuilt image the derivation allocated and this sender's private copy of it are both this
      // send's own buffers. A refused derivation never reaches this line - it clears its own final image
      // where it abandoned it - and here both copies are enrolled and cleared when the send ends.
      own(derived.bytes);
      const checked = own(derived.bytes.slice());

      const outcome = await runner.check({
        // The private FINAL bytes, under the scope and registration captured before the inspection. A
        // host alias mutated during the inspection cannot retarget the check, and the child is asked
        // about exactly the bytes that will be dispatched - never the original ones.
        bytes: checked,
        scope: capturedRequest.scope,
        destination: capturedRequest.observed,
        authorized: capturedRequest.authorized,
        known: capturedRequest.known,
      });
      // A cancellation this sender asked for is reported as one; every other non-`ALLOW` outcome,
      // including a check that never ran, collapses into one fixed sentinel refusal.
      if (outcome.status !== 'ALLOW') {
        return refused(outcome.code === 'CANCELLED' ? 'CANCELLED' : 'SENTINEL_BLOCKED');
      }
      const release = outcome.release;

      // Readiness comes next, and only here. Everything that could authorize a dispatch has already
      // happened - the inspection, the real policy decision per unit, the derivation and the real
      // fixed-worker child ALLOW - and none of it is redone after this await. Readiness prepares the
      // transport and carries no byte: it returns no approval, grants no route, no commit and no
      // freshness, and it is not itself a re-check. It is here because a transport may buffer the write
      // until its connection completes, so the dispatch-point guards below must be read AFTER the
      // transport is ready, never before. A rejection, a failure or a cancellation raised while it runs
      // withholds the dispatch entirely.
      if (cancelled) return refused('CANCELLED');
      try { await trusted.sendPoint.waitUntilReady(); }
      catch { return refused('DISPATCH_FAILED'); }

      // The dispatch point, deliberately ordered. The transport and observation callables were captured
      // during validation, so this is the last point at which any host property is read at all: the final
      // host observation and every structural and freshness check it can invalidate happen first; sticky
      // cancellation is then re-read with nothing between that read and the transport call but this frame,
      // so a cancel raised by that last callback can no longer reach a dispatch. The early read below only
      // spares the host a second observation.
      if (cancelled) return refused('CANCELLED');
      // The released bytes are still the private plan-derived image the child ALLOWed. Readiness is a
      // transport event, so it cannot be allowed to substitute a different buffer for them.
      if (digestOf(release) !== derived.imageDigest) return refused('DISPATCH_FAILED');
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
    } finally {
      // These provisional copies are this sender's own and exist only for this send. They are zeroed when
      // it ends - including on an inspection, policy, derivation or sentinel refusal - and they are never
      // reachable from a result, a binding, a finding or the sent bytes.
      wipeOwned();
      capturedRequest.payload.fill(0);
      capturedRequest.known?.key.fill(0);
    }
  };

  return Object.freeze({
    /**
     * Send one complete text request, or refuse it with a fixed code. The admission claim is taken
     * synchronously, before any stage runs, so a concurrent call is refused rather than queued and can
     * never produce a second dispatch.
     */
    send: (input: unknown): Promise<TextSendResult> => {
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
    get state(): TextSenderState {
      if (cancelled) return 'CANCELLED';
      if (runner.state === 'QUARANTINED') return 'FAILED';
      return busy ? 'BUSY' : 'IDLE';
    },
  });
}