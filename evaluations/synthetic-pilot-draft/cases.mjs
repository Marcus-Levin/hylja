// PROPOSED / PUBLIC_DRAFT_ONLY. Frozen public preparation inputs, NO answers or I/O.
const encode = JSON.stringify;
// Handwritten tuples: asset suffix, tick, level, code; frozen contract before runs.
const definitions = [
  ['C01', 'ERROR_COUNTS', [['A', 1, 'INFO', 'FAILURE']]],
  ['C02', 'ERROR_COUNTS', [['A', 1, 'ERROR', 'START'], ['A', 2, 'ERROR', 'STOP'], ['A', 3, 'INFO', 'FAILURE']]],
  ['C03', 'ERROR_COUNTS', [['A', 9, 'ERROR', 'STOP'], ['A', 2, 'ERROR', 'STOP']]],
  ['C04', 'ERROR_COUNTS', [['A', 4, 'INFO', 'FAILURE'], ['B', 2, 'ERROR', 'STOP']]],
  ['C05', 'ERROR_COUNTS', [['A', 8, 'INFO', 'START'], ['B', 7, 'ERROR', 'STOP'], ['C', 6, 'INFO', 'FAILURE'], ['D', 5, 'ERROR', 'START'], ['E', 4, 'INFO', 'STOP'], ['F', 3, 'ERROR', 'FAILURE'], ['G', 2, 'INFO', 'START'], ['H', 1, 'ERROR', 'STOP']]],
  ['C06', 'ERROR_COUNTS', [['A', 3, 'ERROR', 'START'], ['A', 2, 'INFO', 'FAILURE'], ['B', 1, 'INFO', 'FAILURE']]],
  ['C07', 'FIRST_ERRORS', [['A', 1, 'INFO', 'FAILURE']]],
  ['C08', 'FIRST_ERRORS', [['A', 9, 'ERROR', 'STOP'], ['A', 2, 'ERROR', 'FAILURE']]],
  ['C09', 'FIRST_ERRORS', [['A', 5, 'ERROR', 'START'], ['A', 5, 'ERROR', 'FAILURE']]],
  ['C10', 'FIRST_ERRORS', [['A', 8, 'INFO', 'FAILURE'], ['B', 2, 'ERROR', 'STOP'], ['B', 2, 'ERROR', 'FAILURE']]],
  ['C11', 'FIRST_ERRORS', [['A', 1000000, 'ERROR', 'STOP'], ['A', 0, 'ERROR', 'START']]],
  ['C12', 'FIRST_ERRORS', [['A', 1, 'INFO', 'START']]],
];
export const pilotCases = Object.freeze(definitions.map(([id, task, tuples]) => {
  const context = { version: 1, scope: 'SYNTHETIC-SCOPE-' + id, session: 'SYNTHETIC-SESSION-' + id, context: 'SYNTHETIC-CONTEXT-' + id };
  const labels = [...new Set(tuples.map(([suffix]) => suffix))];
  const assets = labels.map((suffix) => 'SYNTHETIC-ASSET-' + id + suffix);
  const events = tuples.map(([suffix, tick, level, code]) => ({ asset: 'SYNTHETIC-ASSET-' + id + suffix, tick, level, code }));
  const inputJson = encode({ version: 1, context, message: { version: 1, task, assets }, log: { version: 1, events } });
  const controlsJson = encode(assets.map((asset, i) => {
    const config = { version: 1, displayPurpose: 'SYNTHETIC-PILOT-RESULT', displayDestination: 'SYNTHETIC-DISPLAY-' + id + labels[i], adminPurpose: 'SYNTHETIC-OWNER-LIFECYCLE', adminDestination: 'SYNTHETIC-ADMIN-' + id + labels[i], createdAt: 10, expiresAt: 100, revision: 1 };
    const display = { ...context, purpose: config.displayPurpose, operation: 'DISPLAY', destination: config.displayDestination, revision: 1 };
    return { asset, configJson: encode(config), displayJson: encode(display), now: 20, revokeJson: null };
  }));
  return Object.freeze({ id, inputJson, controlsJson });
}));
