// #250 focused tests for the pure reply-binding projection the demo evidence observes replies through.
//
// What this proves: the projection `projectSentinelReplyBinding` returns is exactly the binding a reply
// is validated against - the request id, the scope, the observed and authorized destination, the
// payload digest and the registered refs, and nothing else. No payload byte, no key and no registration
// value survives it, so a consumer that only needs to check a reply can be handed this object instead of
// the parent's whole snapshot. The accepted runner keeps passing its full `SentinelProcessSnapshot`,
// which remains a valid caller of the narrowed `decodeResponseFrame` because the snapshot IS that
// binding plus the bytes.
//
// The bounds are checked here on the authoritative decoder itself: a foreign binding, an unknown reason
// code, a ref this parent never registered and 257 rules are each a separate restrictive failure, and a
// truncated or duplicated reply never reaches the decoder at all.
//
// Pure and offline: no provider, no credential, no network, no child process. Every value below is
// obviously synthetic and non-routable (`.invalid`, `tenant-synthetic-*`).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  EGRESS_SENTINEL_PROCESS_LIMITS,
  classifyReplyFraming,
  decodeRequestFrame,
  decodeResponseFrame,
  encodeRequestFrame,
  encodeResponseFrame,
  projectSentinelReplyBinding,
  snapshotSentinelRequest,
} from '../dist/egress-sentinel-process-protocol.js';

const SCOPE = Object.freeze({ tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01' });
const DESTINATION = Object.freeze({ id: 'DEST-SYNTHETIC-LOCAL', profileDigest: 'sha256:0f1e2d3c4b5a6978' });
const KEY = Uint8Array.from(Array.from({ length: 32 }, (unused, index) => (index * 7 + 3) & 0xff));
const PLANTED_ORIGINAL = 'orla.vance@synthetic-planted.invalid';
const PLANTED_REF = 'planted.person.demo';
const REQUEST_ID = 'rsynthetic00000000deadbeef';

/** The one synthetic request this file builds: a real payload, a real registration, a real key. */
function request() {
  return {
    bytes: new TextEncoder().encode('synthetic payload bytes for one bounded check'),
    scope: SCOPE,
    destination: DESTINATION,
    authorized: DESTINATION,
    known: {
      scope: SCOPE, key: KEY,
      entries: [{ kind: 'ORIGINAL', ref: PLANTED_REF, value: PLANTED_ORIGINAL }],
    },
  };
}

/** A decoded request frame's binding, exactly as the demo observation derives it. */
function bindingOf(frame) {
  const decoded = decodeRequestFrame(frame);
  assert.equal(decoded.ok, true, 'the request frame this parent really wrote decodes');
  return projectSentinelReplyBinding(decoded.value);
}

/** A genuine BLOCK over the registered original, bound to `binding`. */
function knownOriginalBlock(binding) {
  return encodeResponseFrame({
    requestId: binding.requestId,
    tenantRef: binding.scope.tenantRef,
    projectRef: binding.scope.projectRef,
    observedId: binding.observed.id,
    observedProfileDigest: binding.observed.profileDigest,
    authorizedId: binding.authorized.id,
    authorizedProfileDigest: binding.authorized.profileDigest,
    payloadDigest: binding.payloadDigest,
    response: { decision: 'BLOCK', reasonCodes: ['KNOWN_ORIGINAL_DETECTED'], rules: [PLANTED_REF] },
  });
}

test('the reply binding is exactly the fields a reply is validated against, and no protected bytes', () => {
  const snapshot = snapshotSentinelRequest(request(), REQUEST_ID);
  assert.equal(snapshot.ok, true, 'the synthetic request snapshots');
  const binding = projectSentinelReplyBinding(snapshot.value);
  assert.deepEqual(Object.keys(binding).sort(), [
    'authorized', 'observed', 'payloadDigest', 'registeredRefs', 'requestId', 'scope',
  ], 'the projection carries the binding fields and nothing else');
  assert.deepEqual(Object.keys(binding.scope).sort(), ['projectRef', 'tenantRef']);
  assert.deepEqual(Object.keys(binding.observed).sort(), ['id', 'profileDigest']);
  assert.deepEqual(Object.keys(binding.authorized).sort(), ['id', 'profileDigest']);
  // No payload byte, no key and no registration value survives the projection: a consumer holding only
  // this object holds labels and a digest.
  assert.equal(Object.values(binding).some((value) => value instanceof Uint8Array), false,
    'no byte array survives in the projection');
  assert.equal(JSON.stringify(binding).includes(PLANTED_ORIGINAL), false,
    'the projection carries no registered original value');
  assert.deepEqual(binding.registeredRefs, [PLANTED_REF], 'the registered refs are the labels themselves');
  assert.equal(binding.payloadDigest, snapshot.value.payloadDigest, 'the digest is the snapshot own');
  assert.equal(Object.isFrozen(binding), true, 'the projection is frozen');
});

test('a binding recomputed from the real request frame equals the parent snapshot own binding', () => {
  const snapshot = snapshotSentinelRequest(request(), REQUEST_ID);
  const frame = encodeRequestFrame(snapshot.value);
  const fromFrame = bindingOf(frame);
  const direct = projectSentinelReplyBinding(snapshot.value);
  assert.equal(fromFrame.requestId, direct.requestId);
  assert.equal(fromFrame.scope.tenantRef, direct.scope.tenantRef);
  assert.equal(fromFrame.scope.projectRef, direct.scope.projectRef);
  assert.equal(fromFrame.observed.id, direct.observed.id);
  assert.equal(fromFrame.observed.profileDigest, direct.observed.profileDigest);
  assert.equal(fromFrame.authorized.id, direct.authorized.id);
  assert.equal(fromFrame.authorized.profileDigest, direct.authorized.profileDigest);
  assert.equal(fromFrame.payloadDigest, direct.payloadDigest,
    'the digest is recomputed from the frame bytes, never taken from the parent side');
  assert.deepEqual(fromFrame.registeredRefs, direct.registeredRefs);
});

test('a genuine known-original BLOCK validates against the projected binding', () => {
  const frame = encodeRequestFrame(snapshotSentinelRequest(request(), REQUEST_ID).value);
  const binding = bindingOf(frame);
  const decoded = decodeResponseFrame(knownOriginalBlock(binding), binding);
  assert.equal(decoded.ok, true, 'the genuine block decodes');
  assert.equal(decoded.value.decision, 'BLOCK');
  assert.deepEqual(decoded.value.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(decoded.value.rules, [PLANTED_REF]);
});

test('the full request snapshot is still a valid caller of the narrowed decoder', () => {
  const snapshotted = snapshotSentinelRequest(request(), REQUEST_ID);
  const frame = encodeRequestFrame(snapshotted.value);
  const decoded = decodeResponseFrame(knownOriginalBlock(projectSentinelReplyBinding(snapshotted.value)),
    snapshotted.value);
  assert.equal(decoded.ok, true, 'the accepted runner keeps passing its own snapshot unchanged');
  assert.equal(decoded.value.decision, 'BLOCK');
  assert.equal(classifyReplyFraming(knownOriginalBlock(bindingOf(frame))), 'OK');
});

test('a foreign binding is a mismatch, not a decision', () => {
  const frame = encodeRequestFrame(snapshotSentinelRequest(request(), REQUEST_ID).value);
  const binding = bindingOf(frame);
  const foreign = encodeResponseFrame({
    requestId: binding.requestId,
    tenantRef: binding.scope.tenantRef,
    projectRef: binding.scope.projectRef,
    observedId: binding.observed.id,
    observedProfileDigest: binding.observed.profileDigest,
    authorizedId: binding.authorized.id,
    authorizedProfileDigest: binding.authorized.profileDigest,
    // A digest this parent never computed for this payload.
    payloadDigest: 'f'.repeat(64),
    response: { decision: 'BLOCK', reasonCodes: ['KNOWN_ORIGINAL_DETECTED'], rules: [PLANTED_REF] },
  });
  const decoded = decodeResponseFrame(foreign, binding);
  assert.equal(decoded.ok, false, 'a foreign digest never decodes');
  assert.equal(decoded.code, 'REPLY_BINDING_MISMATCH');
});

test('an unknown reason code and an unregistered ref are malformed, not a decision', () => {
  const frame = encodeRequestFrame(snapshotSentinelRequest(request(), REQUEST_ID).value);
  const binding = bindingOf(frame);
  const base = {
    requestId: binding.requestId,
    tenantRef: binding.scope.tenantRef,
    projectRef: binding.scope.projectRef,
    observedId: binding.observed.id,
    observedProfileDigest: binding.observed.profileDigest,
    authorizedId: binding.authorized.id,
    authorizedProfileDigest: binding.authorized.profileDigest,
    payloadDigest: binding.payloadDigest,
  };
  const unknownReason = decodeResponseFrame(encodeResponseFrame({
    ...base, response: { decision: 'BLOCK', reasonCodes: ['KNOWN_ORIGINAL_DETECTED', 'SOME_OTHER_TEXT'], rules: [PLANTED_REF] },
  }), binding);
  assert.equal(unknownReason.ok, false, 'a free-text reason never decodes');
  assert.equal(unknownReason.code, 'REPLY_MALFORMED');
  const foreignRef = decodeResponseFrame(encodeResponseFrame({
    ...base, response: { decision: 'BLOCK', reasonCodes: ['KNOWN_ORIGINAL_DETECTED'], rules: ['ref.this.parent.never.registered'] },
  }), binding);
  assert.equal(foreignRef.ok, false, 'a ref this parent never registered never decodes');
  assert.equal(foreignRef.code, 'REPLY_MALFORMED');
});

test('more rules than the protocol bounds allow is malformed', () => {
  const frame = encodeRequestFrame(snapshotSentinelRequest(request(), REQUEST_ID).value);
  const binding = bindingOf(frame);
  const overLimit = decodeResponseFrame(encodeResponseFrame({
    requestId: binding.requestId,
    tenantRef: binding.scope.tenantRef,
    projectRef: binding.scope.projectRef,
    observedId: binding.observed.id,
    observedProfileDigest: binding.observed.profileDigest,
    authorizedId: binding.authorized.id,
    authorizedProfileDigest: binding.authorized.profileDigest,
    payloadDigest: binding.payloadDigest,
    response: {
      decision: 'BLOCK',
      reasonCodes: ['KNOWN_ORIGINAL_DETECTED'],
      // One over `maxRules`, all of them refs this parent really registered.
      rules: Array.from({ length: EGRESS_SENTINEL_PROCESS_LIMITS.maxRules + 1 }, () => PLANTED_REF),
    },
  }), binding);
  assert.equal(overLimit.ok, false, 'a rule count over the bound never decodes');
  assert.equal(overLimit.code, 'REPLY_MALFORMED');
  const atLimit = decodeResponseFrame(encodeResponseFrame({
    requestId: binding.requestId,
    tenantRef: binding.scope.tenantRef,
    projectRef: binding.scope.projectRef,
    observedId: binding.observed.id,
    observedProfileDigest: binding.observed.profileDigest,
    authorizedId: binding.authorized.id,
    authorizedProfileDigest: binding.authorized.profileDigest,
    payloadDigest: binding.payloadDigest,
    response: {
      decision: 'BLOCK',
      reasonCodes: ['KNOWN_ORIGINAL_DETECTED'],
      rules: Array.from({ length: EGRESS_SENTINEL_PROCESS_LIMITS.maxRules }, () => PLANTED_REF),
    },
  }), binding);
  assert.equal(atLimit.ok, true, 'the bound itself still decodes');
});

test('a truncated, duplicated or trailing reply is refused before it is decoded', () => {
  const frame = encodeRequestFrame(snapshotSentinelRequest(request(), REQUEST_ID).value);
  const binding = bindingOf(frame);
  const reply = knownOriginalBlock(binding);
  assert.equal(classifyReplyFraming(reply.subarray(0, reply.byteLength - 1)), 'REPLY_MALFORMED',
    'a missing trailing newline is truncation');
  assert.equal(classifyReplyFraming(reply.subarray(0, reply.byteLength - 2)), 'REPLY_MALFORMED',
    'a short body is truncation');
  const joined = new Uint8Array(reply.byteLength * 2);
  joined.set(reply, 0);
  joined.set(reply, reply.byteLength);
  assert.equal(classifyReplyFraming(joined), 'REPLY_DUPLICATE', 'a second complete frame is a duplicate reply');
  assert.equal(decodeResponseFrame(reply.subarray(0, reply.byteLength - 1), binding).ok, false,
    'a truncated frame never decodes');
});
