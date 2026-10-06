// Fixed diagnostic probe: deliberate planted host exceptions never reach listener results or output.
import { createOpenAiLocalListener } from '../../dist/openai-local-listener.js';
const token = ('synthetic_listener_fixture_' + 'A'.repeat(43)).slice(0, 43);
let called = false;
const host = { listenPort: 0, callerToken: token,
  get conversation() { called = true; throw new Error(token); } };
try {
  const owner = createOpenAiLocalListener(host);
  const result = await owner.start();
  await owner.close();
  const refused = result.status === 'REFUSED' && result.code === 'HOST_INVALID' && !called;
  process.stdout.write(refused ? 'HOST_REFUSED\n' : 'PROBE_FAILED\n');
  process.exitCode = refused ? 0 : 1;
} catch { process.stdout.write('PROBE_FAILED\n'); process.exitCode = 1; }
