/**
 * PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY.
 * One public synthetic pair, independent fixture DISPLAY/admin predicates only.
 * No accepted CREATE/policy/authentication/custody/audit, I/O, model or trusted clock.
 * See docs/specs/synthetic-pilot-owner-draft.md; no private erasure claim.
 */
import { derivePilotReference } from './transform.mjs';

const REFUSAL = Object.freeze({ status: 'REFUSED', reason: 'PILOT_OWNER_REFUSED' });
const REVOKED = Object.freeze({ status: 'REVOKED', mode: 'PUBLIC_DRAFT_ONLY', revision: 2 });
const DISPLAY_DESTINATION = /^SYNTHETIC-DISPLAY-[A-Z0-9]{1,32}(?![\s\S])/u;
const ADMIN_DESTINATION = /^SYNTHETIC-ADMIN-[A-Z0-9]{1,32}(?![\s\S])/u;
const REFERENCE = /^DRAFT-PILOT-REF-[a-f0-9]{64}(?![\s\S])/u;
const CONFIG_KEYS = ['version', 'displayPurpose', 'displayDestination', 'adminPurpose', 'adminDestination', 'createdAt', 'expiresAt', 'revision'];
const REQUEST_KEYS = ['version', 'scope', 'session', 'context', 'purpose', 'operation', 'destination', 'revision'];

function parseOrdered(text, keys) {
  // Primitive/bounds checks BEFORE parsing; no caller-object reflection/coercion.
  if (typeof text !== 'string' || text.length < 1 || text.length > 1024 || /[^\x20-\x7e]/u.test(text)) return null;
  try {
    const value = JSON.parse(text);
    // Only JSON-created records reach reflection. Exact order is part of P2,
    // unlike P1 context: canonical JSON alone does not enforce member order.
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const actual = Object.keys(value);
    if (actual.length !== keys.length || !keys.every((key, i) => actual[i] === key) ||
      JSON.stringify(value) !== text) return null;
    return value;
  } catch {
    return null;
  }
}

function time(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 1000000;
}

export function createPilotOwner(configJson, contextJson, original) {
  try {
    const config = parseOrdered(configJson, CONFIG_KEYS);
    if (config === null || config.version !== 1 || config.revision !== 1 ||
      config.displayPurpose !== 'SYNTHETIC-PILOT-RESULT' || config.adminPurpose !== 'SYNTHETIC-OWNER-LIFECYCLE' ||
      typeof config.displayDestination !== 'string' || !DISPLAY_DESTINATION.test(config.displayDestination) ||
      typeof config.adminDestination !== 'string' || !ADMIN_DESTINATION.test(config.adminDestination) ||
      !time(config.createdAt) || !time(config.expiresAt) || config.createdAt >= config.expiresAt) return REFUSAL;

    // Reviewed P1 is the SOLE context/original validation and reference derivation.
    // No copied hash/asset/context grammar, fabricated log, or Gate1 domain reuse.
    const derived = derivePilotReference(contextJson, original);
    if (derived.status !== 'DERIVED') return REFUSAL;
    const context = JSON.parse(contextJson);
    const reference = derived.reference;
    let highWater = config.createdAt;
    let closed = false;
    let revision = 1;

    function observe(now) {
      // Always first, including malformed/denied calls. Closing never reopens;
      // closure alone does NOT change revision or prevent valid admin acknowledgment.
      if (!time(now) || now < highWater) {
        closed = true;
        return false;
      }
      highWater = now;
      if (now >= config.expiresAt) closed = true;
      return true;
    }
    function matches(request, purpose, operation, destination) {
      return request !== null && request.version === 1 && request.scope === context.scope &&
        request.session === context.session && request.context === context.context &&
        request.purpose === purpose && request.operation === operation &&
        request.destination === destination && request.revision === revision;
    }

    return Object.freeze({
      status: 'OWNED', mode: 'PUBLIC_DRAFT_ONLY',
      displayOne(candidate, requestJson, now) {
        if (!observe(now) || closed || revision !== 1) return REFUSAL;
        if (typeof candidate !== 'string' || candidate.length !== 80 || !REFERENCE.test(candidate) || candidate !== reference) return REFUSAL;
        const request = parseOrdered(requestJson, REQUEST_KEYS);
        if (!matches(request, config.displayPurpose, 'DISPLAY', config.displayDestination)) return REFUSAL;
        return Object.freeze({ status: 'DISPLAYED', mode: 'PUBLIC_DRAFT_ONLY', original, revision: 1 });
      },
      revoke(adminJson, now) {
        if (!observe(now)) return REFUSAL;
        const request = parseOrdered(adminJson, REQUEST_KEYS);
        if (!matches(request, config.adminPurpose, 'REVOKE', config.adminDestination)) return REFUSAL;
        closed = true;
        revision = 2;
        return REVOKED;
      },
    });
  } catch {
    // No original/reference/partial handle or exception detail accompanies failure.
    return REFUSAL;
  }
}
