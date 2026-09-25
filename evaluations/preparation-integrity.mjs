#!/usr/bin/env node
// Compileable RED checkpoint. Preparation integrity is not approval or scored eligibility.
import { pathToFileURL } from 'node:url';

export function verifyPreparation(...args) {
  if (args.length) return { status: 'PREPARATION_INVALID', reason: 'INPUT_REJECTED' };
  return { status: 'PREPARATION_INVALID', reason: 'CHECK_UNAVAILABLE' };
}

// Intentionally deny-only; this module has no authority to unlock a scored protocol.
export function requireScoredV0() {
  return { status: 'SCORED_V0_DENIED', reason: 'EXTERNAL_APPROVAL_BOUNDARY_ABSENT' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = process.argv.length === 2 ? verifyPreparation() : verifyPreparation({});
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.status !== 'PREPARATION_VALID_BUT_NOT_ELIGIBLE') process.exitCode = 1;
}
