/**
 * PROPOSED / PUBLIC_DRAFT_ONLY / NON-ENFORCING. One public synthetic pair only.
 * Hypothetical fixture checks, NOT accepted CREATE/DISPLAY, authentication, policy,
 * broker/custody/audit, trusted time, private data protection or secure erasure.
 * Synchronous: no callbacks, clocks/timers, IO, provider, keys or accepted core imports.
 */
import { transformDraft } from './transform.mjs';

const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'OWNER_REFUSED' });
const REVOKED = Object.freeze({ status: 'REVOKED', revision: 2 });
const ASSET = /^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$/u;
const REFERENCE = /^DRAFT-REF-[a-f0-9]{64}$/u;
const DISPLAY_DESTINATION = /^SYNTHETIC-DISPLAY-[A-Z0-9]{1,32}$/u;
const ADMIN_DESTINATION = /^SYNTHETIC-ADMIN-[A-Z0-9]{1,32}$/u;
const PURPOSE = 'SYNTHETIC-LOG-SUMMARY';
const ADMIN_PURPOSE = 'SYNTHETIC-OWNER-LIFECYCLE';

function closed(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

// Only JSON-created records are inspected, never caller-owned descriptors/getters.
function parse(text, keys) {
  if (typeof text !== 'string' || text.length < 1 || text.length > 512 || !/^[\x20-\x7e]+$/u.test(text)) return null;
  try {
    const value = JSON.parse(text);
    if (!closed(value, keys) || JSON.stringify(value) !== text) return null;
    return value;
  } catch {
    return null;
  }
}

function time(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 1000000;
}

function tupleMatches(value, context) {
  return value !== null && value.version === 1 && value.scope === context.scope &&
    value.session === context.session && value.context === context.context;
}

export function createDraftOwner(configJson, contextJson, original) {
  try {
    const config = parse(configJson, ['version', 'purpose', 'operation', 'destination', 'adminDestination', 'createdAt', 'expiresAt', 'revision']);
    const context = parse(contextJson, ['version', 'scope', 'session', 'context']);
    if (config === null || context === null || config.version !== 1 || config.purpose !== PURPOSE ||
      config.operation !== 'DISPLAY' || config.revision !== 1 ||
      typeof config.destination !== 'string' || !DISPLAY_DESTINATION.test(config.destination) ||
      typeof config.adminDestination !== 'string' || !ADMIN_DESTINATION.test(config.adminDestination) ||
      !time(config.createdAt) || !time(config.expiresAt) || config.createdAt >= config.expiresAt ||
      typeof original !== 'string' || original.length > 80 || !ASSET.test(original)) return REFUSAL;

    // S1 owns context validation and reference derivation. No separate hash grammar here.
    const transformed = transformDraft(contextJson,
      JSON.stringify({ version: 1, task: 'SUMMARIZE_FAILURES', asset: original }),
      JSON.stringify({ version: 1, events: [{ asset: original, tick: 0, level: 'INFO', code: 'START' }] }));
    if (transformed.status !== 'TRANSFORMED' || transformed.references.length !== 1) return REFUSAL;
    const reference = transformed.references[0];
    const image = JSON.parse(transformed.cloakedJson);
    if (image.message.asset !== reference || image.log.events.length !== 1 || image.log.events[0].asset !== reference) return REFUSAL;

    let retained = original;
    let state = 'ACTIVE';
    let revision = 1;
    let lastNow = config.createdAt;
    function terminate(next) {
      state = next;
      revision = 2;
      retained = null; // Drop this retained reference only; no heap/caller-copy erasure claim.
    }
    function observe(now) {
      if (!time(now) || now < lastNow) {
        if (state === 'ACTIVE') terminate('DELETED');
        return false;
      }
      lastNow = now;
      if (state === 'ACTIVE' && now >= config.expiresAt) terminate('EXPIRED');
      return true;
    }
    const owner = Object.freeze({
      displayOne(candidate, requestJson, now) {
        if (!observe(now) || state !== 'ACTIVE') return REFUSAL;
        const request = parse(requestJson, ['version', 'scope', 'session', 'context', 'purpose', 'operation', 'destination', 'revision']);
        if (!tupleMatches(request, context) || request.purpose !== PURPOSE || request.operation !== 'DISPLAY' ||
          request.destination !== config.destination || request.revision !== revision ||
          typeof candidate !== 'string' || candidate.length !== 74 || !REFERENCE.test(candidate) || candidate !== reference) return REFUSAL;
        return Object.freeze({ status: 'DISPLAYED', value: retained });
      },
      revoke(adminRequestJson, now) {
        if (!observe(now) || (state !== 'ACTIVE' && state !== 'REVOKED')) return REFUSAL;
        const request = parse(adminRequestJson, ['version', 'scope', 'session', 'context', 'administrativePurpose', 'operation', 'destination', 'revision']);
        if (!tupleMatches(request, context) || request.administrativePurpose !== ADMIN_PURPOSE ||
          request.operation !== 'REVOKE' || request.destination !== config.adminDestination || request.revision !== revision) return REFUSAL;
        if (state === 'ACTIVE') terminate('REVOKED');
        return REVOKED;
      },
    });
    return Object.freeze({ status: 'OWNED', owner });
  } catch {
    // Construction failures never expose exception text or a partially usable handle.
    return REFUSAL;
  }
}
