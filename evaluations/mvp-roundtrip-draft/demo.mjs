// PROPOSED / PUBLIC_DRAFT_ONLY. Fixed public file, in-process deterministic responder.
// No command-line path, provider/model, private input, callback or retry support.
import { runFixedDraft } from './integration.mjs';
const result = runFixedDraft();
if (result.status !== 'DISPLAYED') {
  console.log('PUBLIC_DRAFT_ONLY / INTEGRATION_REFUSED');
  process.exitCode = 1;
} else {
  // Captures are owned public synthetic bytes only, not reconstructed traffic.
  console.log(JSON.stringify(result));
}
