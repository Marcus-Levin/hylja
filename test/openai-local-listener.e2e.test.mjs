// Synthetic loopback wire evidence only; host fixture labels are not generic classification.
// Assertions reduce captured bytes to booleans. Never print native errors or protected material.
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';
import { createDemoHost, DEMO_REQUEST, DEMO_REPLY, DEMO_LEAKY_REPLY,
  PLANTED_ORIGINAL, PLANTED_SECRET } from '../scripts/lib/synthetic-conversation-fixture.mjs';

import { installWorkerObservation, workerObservation, noteRegisteredOriginal } from '../scripts/lib/synthetic-conversation-worker-observation.mjs';
installWorkerObservation();
noteRegisteredOriginal('planted.person.demo');
let api;
try { api = await import('../dist/openai-local-listener.js'); } catch { /* fixed assertion below */ }
// Synthetic, deterministic non-secret capabilities; syntax is no evidence of random entropy.
const capability = (variant = 'A') => ('synthetic_listener_fixture_' + variant.repeat(43)).slice(0, 43);
const expectedBody = '{"model":"fixture-model-demo","messages":[{"role":"system","content":"You are a synthetic fixture assistant."},{"role":"user","content":"[hylja:masked]"},{"role":"user","content":"Reply with the rotation window only."}]}';
const expectedRequest = 'POST /v1/chat/completions HTTP/1.1\r\nHost: model-sink-demo.example.invalid\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: '
  + Buffer.byteLength(expectedBody) + '\r\n\r\n' + expectedBody;
const expectedReply = '{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"Rotation window 02:00 UTC. Nothing is restored and no original is returned.","role":"assistant"}}],"created":1762000101,"id":"chatcmpl-fixture-demo-0001","model":"fixture-model-demo","object":"chat.completion","usage":{"completion_tokens":18,"prompt_tokens":40,"total_tokens":58}}';
const children = [];
const originalSpawn = childProcess.spawn;
childProcess.spawn = function (...args) {
  const child = Reflect.apply(originalSpawn, this, args);
  if (String(args[1]?.[0]).endsWith('egress-sentinel-process-worker.js')) children.push(child);
  return child;
};
syncBuiltinESMExports();

function bounded(promise) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('fixture deadline')), 25_000);
  })]).finally(() => clearTimeout(timer));
}
async function peer(t, answer = DEMO_REPLY) {
  const state = { connections: 0, bytes: 0, images: [], sockets: new Set(), answer };
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    state.connections++;
    state.sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => state.sockets.delete(socket));
    const chunks = [];
    socket.on('data', chunk => { state.bytes += chunk.length; chunks.push(chunk); });
    socket.on('end', () => {
      state.images.push(Buffer.concat(chunks).toString('utf8'));
      state.onRequest?.(socket);
      if (state.answer === null || socket.destroyed) return;
      const body = state.answer;
      const frame = state.raw ?? ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
        + Buffer.byteLength(body) + '\r\n\r\n' + body);
      socket.end(frame);
    });
  });
  await bounded(new Promise(resolve => server.listen(0, '127.0.0.1', resolve)));
  state.port = server.address().port;
  t.after(async () => {
    for (const socket of state.sockets) socket.destroy();
    await bounded(new Promise(resolve => server.close(resolve)));
  });
  return state;
}
function host(port, options = {}) {
  const runs = [];
  const supplied = createDemoHost({ port, timeoutMs: 10_000, releases: [], runs });
  delete supplied.onReply;
  for (const side of ['sender', 'receiver']) {
    supplied[side].boundary = structuredClone(supplied[side].boundary);
    for (const group of ['authenticated', 'observed']) {
      for (const key of Object.keys(supplied[side].boundary[group]).filter(key => key.endsWith('Proof'))) {
        const now = Date.now();
        supplied[side].boundary[group][key] = {
          ref: 'proof-listener-synthetic.invalid',
          issuedAt: new Date(now - 1000).toISOString(),
          expiresAt: new Date(now + 120_000).toISOString(),
        };
      }
    }
  }
  options.change?.(supplied);
  return { listenPort: 0, callerToken: capability(), conversation: supplied, runs };
}
async function listener(t, upstream, options = {}) {
  assert.equal(typeof api?.createOpenAiLocalListener === 'function', true, 'listener API exists');
  const fixture = host(upstream.port, options);
  const { runs, ...input } = fixture;
  const owner = api.createOpenAiLocalListener(input);
  const started = await bounded(owner.start());
  assert.equal(started.status === 'LISTENING', true, 'listener bound');
  t.after(() => bounded(owner.close()));
  return { owner, port: started.port, runs, input };
}
function request(port, options = {}) {
  const body = options.body ?? DEMO_REQUEST;
  const headers = options.headers ?? [
    'Host: 127.0.0.1:' + port, 'Authorization: Bearer ' + capability(),
    'Content-Type: application/json; charset=utf-8', 'Content-Length: ' + Buffer.byteLength(body),
    'X-Synthetic-Harmless: fixture.invalid',
  ];
  return Buffer.concat([Buffer.from((options.line ?? 'POST /v1/chat/completions HTTP/1.1')
    + '\r\n' + headers.join('\r\n') + '\r\n\r\n'), Buffer.from(body)]);
}
async function raw(port, bytes, options = {}) {
  const socket = net.createConnection({ port, host: '127.0.0.1' });
  const chunks = [];
  socket.on('error', () => {});
  const closed = new Promise(resolve => socket.on('close', resolve));
  socket.on('data', chunk => chunks.push(chunk));
  await bounded(new Promise(resolve => socket.on('connect', resolve)));
  if (bytes) socket.write(bytes);
  if (options.end) socket.end();
  options.connected?.(socket);
  await bounded(closed);
  return Buffer.concat(chunks).toString('utf8');
}
function status(wire, expected) { assert.equal(wire.startsWith('HTTP/1.1 ' + expected + ' '), true); }
function refusal(wire, code, http) {
  status(wire, http);
  const body = JSON.stringify({ error: { message: code, type: 'hylja_refusal', param: null, code } });
  assert.equal(wire.split('\r\n\r\n')[1] === body, true, 'fixed public body');
  for (const value of [capability(), PLANTED_ORIGINAL, PLANTED_SECRET]) assert.equal(wire.includes(value), false);
}
function noUpstream(upstream, before) {
  assert.equal(upstream.connections, before.connections);
  assert.equal(upstream.bytes, before.bytes);
}
async function positive(local, upstream) {
  const before = upstream.images.length;
  const wire = await raw(local.port, request(local.port));
  status(wire, 200);
  assert.equal(wire.split('\r\n\r\n')[1] === expectedReply, true, 'canonical client reply');
  assert.equal(upstream.images.length, before + 1);
  assert.equal(upstream.images.at(-1) === expectedRequest, true, 'independently declared masked wire');
  for (const value of [capability(), PLANTED_ORIGINAL, PLANTED_SECRET, 'X-Synthetic-Harmless']) {
    assert.equal(upstream.images.at(-1).includes(value), false);
  }
}
test('listener real guarded synthetic wire control', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  await positive(local, upstream);
  assert.equal(workerObservation().allow >= 2, true, 'both fixed children returned actual bound ALLOW frames');
  assert.equal(local.runs.some(run => run.side === 'request' && run.findings > 0), true);
  assert.equal(children.length >= 2, true);
  for (const child of children) {
    assert.equal(child.exitCode === 0, true);
    let live = false;
    try { process.kill(child.pid, 0); live = true; } catch { /* actual process absence */ }
    assert.equal(live, false, 'fixed worker is not live');
  }
});

function baseHeaders(port, body = DEMO_REQUEST) {
  return ['Host: 127.0.0.1:' + port, 'Authorization: Bearer ' + capability(),
    'Content-Type: application/json', 'Content-Length: ' + Buffer.byteLength(body)];
}
test('auth, context and route negatives make zero upstream contact, then control', { timeout: 60_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  const cases = [
    { code: 'ACCESS_DENIED', http: 401, headers: h => h.filter(x => !x.startsWith('Authorization:')) },
    { code: 'ACCESS_DENIED', http: 401, headers: h => h.map(x => x.startsWith('Authorization:') ? 'Authorization: Bearer ' + capability('B') : x) },
    { code: 'ACCESS_DENIED', http: 401, headers: h => h.map(x => x.startsWith('Authorization:') ? 'Authorization: Bearer synthetic.invalid' : x) },
    { code: 'ACCESS_DENIED', http: 401, headers: h => [...h, h[1]] },
    ...['X-Hylja-Context: override.invalid', 'OpenAI-Project: override.invalid',
      'OpenAI-Organization: override.invalid', 'Forwarded: for=192.0.2.1',
      'X-Forwarded-Host: decoy.invalid'].map(header => ({ headers: h => [...h, header] })),
    { headers: h => h.map(x => x.startsWith('Host:') ? 'Host: alternate.invalid' : x) },
    ...['GET /v1/chat/completions HTTP/1.1', 'POST /v1/chat/completions?x=1 HTTP/1.1',
      'POST /v1/chat/completions/ HTTP/1.1', 'POST /v1/responses HTTP/1.1',
      'POST /v1/completions HTTP/1.1', 'POST http://decoy.invalid/v1/chat/completions HTTP/1.1',
      'POST /v1/chat/completions HTTP/1.0'].map(line => ({ line })),
  ];
  for (const entry of cases) {
    const before = { connections: upstream.connections, bytes: upstream.bytes };
    const wire = await raw(local.port, request(local.port, { headers: entry.headers?.(baseHeaders(local.port)) ?? baseHeaders(local.port), line: entry.line }));
    refusal(wire, entry.code ?? 'REQUEST_REFUSED', entry.http ?? 400);
    noUpstream(upstream, before);
  }
  await positive(local, upstream);
  const secondHost = host(upstream.port);
  const { runs, ...secondInput } = secondHost;
  secondInput.callerToken = capability('B');
  const second = api.createOpenAiLocalListener(secondInput);
  t.after(() => second.close());
  const started = await second.start();
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  refusal(await raw(started.port, request(started.port)), 'ACCESS_DENIED', 401);
  noUpstream(upstream, before);
  await positive(local, upstream);
});

test('strict framing, unsupported fields and bounds refuse before upstream', { timeout: 60_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  const bodies = [
    { ...JSON.parse(DEMO_REQUEST), tools: [] }, { ...JSON.parse(DEMO_REQUEST), stream: true },
    { ...JSON.parse(DEMO_REQUEST), unknown: 'synthetic.invalid' },
    { model: 'fixture.invalid', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: 'https://image.invalid/' }] }] },
    { model: 'fixture.invalid', messages: [{ role: 'user', content: 'synthetic', unknown: true }] },
  ];
  for (const body of bodies) {
    const before = { connections: upstream.connections, bytes: upstream.bytes };
    refusal(await raw(local.port, request(local.port, { body: JSON.stringify(body) })), 'REQUEST_REFUSED', 400);
    noUpstream(upstream, before);
  }
  for (const extra of ['Transfer-Encoding: chunked', 'Content-Encoding: gzip', 'Content-Encoding: identity',
    'Expect: 100-continue', 'Origin: https://origin.invalid', 'Upgrade: websocket',
    'Proxy-Authorization: synthetic.invalid', 'Content-Length: ' + Buffer.byteLength(DEMO_REQUEST),
    'Folded: fixture\r\n continuation', 'Invalid Value: x', 'X-Harmless: \x01']) {
    const before = { connections: upstream.connections, bytes: upstream.bytes };
    refusal(await raw(local.port, request(local.port, { headers: [...baseHeaders(local.port), extra] })), 'REQUEST_REFUSED', 400);
    noUpstream(upstream, before);
  }
  for (const headers of [
    [...baseHeaders(local.port), 'X-Bound: ' + 'x'.repeat(8192)],
    [...baseHeaders(local.port), ...Array.from({ length: 61 }, (_, i) => 'X-Field-' + i + ': fixture')],
    baseHeaders(local.port).map(x => x.startsWith('Content-Length:') ? 'Content-Length: 65537' : x),
  ]) {
    const before = { connections: upstream.connections, bytes: upstream.bytes };
    refusal(await raw(local.port, request(local.port, { headers })), 'REQUEST_TOO_LARGE', 413);
    noUpstream(upstream, before);
  }
  for (const value of ['0', '01', '+1', '1,1']) {
    refusal(await raw(local.port, request(local.port, { headers: baseHeaders(local.port).map(x => x.startsWith('Content-Length:') ? 'Content-Length: ' + value : x) })), 'REQUEST_REFUSED', 400);
  }
  const invalid = Buffer.concat([request(local.port, { body: 'x' }).subarray(0, -1), Buffer.from([0xff])]);
  refusal(await raw(local.port, invalid), 'REQUEST_REFUSED', 400);
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  refusal(await raw(local.port, request(local.port).subarray(0, -10), { end: true }), 'REQUEST_REFUSED', 400);
  noUpstream(upstream, before);
  // Coalesced pipeline/surplus is refused, never parsed as a second request.
  refusal(await raw(local.port, Buffer.concat([request(local.port), request(local.port)])), 'REQUEST_REFUSED', 400);
  await positive(local, upstream);
});

test('absolute slowloris deadline and four-socket admission cap', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  const holding = [];
  for (let i = 0; i < 4; i++) {
    const socket = net.createConnection({ host: '127.0.0.1', port: local.port });
    socket.on('error', () => {});
    t.after(() => socket.destroy());
    await new Promise(resolve => socket.on('connect', resolve));
    socket.write('POST /v1/chat/completions HTTP/1.1\r\n');
    holding.push(socket);
  }
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  refusal(await raw(local.port, request(local.port)), 'BUSY', 429);
  noUpstream(upstream, before);
  for (const socket of holding) socket.destroy();
  await new Promise(resolve => setImmediate(resolve));
  const wire = await raw(local.port, Buffer.from('POST /v1/chat/completions HTTP/1.1\r\n'), {
    connected(socket) { const interval = setInterval(() => socket.write('X'), 200); socket.on('close', () => clearInterval(interval)); },
  });
  refusal(wire, 'REQUEST_TIMEOUT', 408);
  noUpstream(upstream, before);
  await positive(local, upstream);
});

test('real outbound sentinel block and protected inbound coarse refusal', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const suppress = await listener(t, upstream, { change(c) {
    const inspect = c.sender.inspectOriginal;
    c.sender.inspectOriginal = function (image, binding) {
      const result = inspect(image, binding);
      const fixture = result.units[0].classification;
      return { ...result, units: result.units.map(unit => ({ ...unit, classification: fixture,
        classificationDigest: result.units[0].classificationDigest })) };
    };
  } });
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  const childBefore = children.length;
  const blockBefore = workerObservation().block;
  refusal(await raw(suppress.port, request(suppress.port)), 'RELEASE_REFUSED', 403);
  noUpstream(upstream, before);
  assert.equal(children.length, childBefore + 1, 'actual outbound child ran');
  assert.equal(workerObservation().block, blockBefore + 1, 'actual complete BLOCK, not a crash');
  const local = await listener(t, upstream);
  await positive(local, upstream);
  upstream.answer = DEMO_LEAKY_REPLY;
  const knownBefore = workerObservation().namedKnownOriginal;
  refusal(await raw(local.port, request(local.port)), 'RELEASE_REFUSED', 403);
  assert.equal(workerObservation().namedKnownOriginal, knownBefore + 1, 'registered original really blocked inbound');
  upstream.answer = DEMO_REPLY;
  await positive(local, upstream);
});

test('upstream redirect never follows decoy; framing and timeout are availability only', { timeout: 60_000 }, async t => {
  const decoy = await peer(t);
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  upstream.raw = 'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:' + decoy.port + '/v1/chat/completions\r\nContent-Length: 1\r\n\r\nx';
  refusal(await raw(local.port, request(local.port)), 'UPSTREAM_UNAVAILABLE', 502);
  assert.equal(decoy.connections, 0);
  assert.equal(decoy.bytes, 0);
  for (const frame of ['HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nx',
    'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n']) {
    upstream.raw = frame;
    refusal(await raw(local.port, request(local.port)), 'UPSTREAM_UNAVAILABLE', 502);
  }
  upstream.raw = undefined;
  await positive(local, upstream);
  upstream.answer = JSON.stringify({ ...JSON.parse(DEMO_REPLY), choices: [] });
  refusal(await raw(local.port, request(local.port)), 'RELEASE_REFUSED', 403);
  upstream.answer = null;
  refusal(await raw(local.port, request(local.port)), 'UPSTREAM_TIMEOUT', 504);
  upstream.answer = DEMO_REPLY;
  await positive(local, upstream);
});

function setWindow(c, side, group, key, issued, expires) {
  c[side].boundary[group][key] = { ref: 'synthetic-window.invalid',
    issuedAt: new Date(issued).toISOString(), expiresAt: new Date(expires).toISOString() };
}
test('each pinned proof independently caps admission, without refreshing evidence', { timeout: 60_000 }, async t => {
  const upstream = await peer(t);
  for (const side of ['sender', 'receiver']) {
    for (const [group, key] of [['authenticated', 'identityProof'], ['authenticated', 'requestProof'],
      ['observed', 'sourceProof'], ['observed', 'routeProof']]) {
      const stale = await listener(t, upstream, { change(c) {
        setWindow(c, side, group, key, Date.now() - 2000, Date.now() - 1000);
      } });
      const before = { connections: upstream.connections, bytes: upstream.bytes };
      refusal(await raw(stale.port, request(stale.port)), 'RELEASE_REFUSED', 403);
      noUpstream(upstream, before);
      await stale.owner.close();
    }
  }
  for (const [issued, expires] of [[Date.now() - 301_000, Date.now() + 1000],
    [Date.now() - 1000, Date.now() + 301_000], [Date.now() + 1000, Date.now() + 2000]]) {
    const stale = await listener(t, upstream, { change(c) { setWindow(c, 'receiver', 'observed', 'routeProof', issued, expires); } });
    const before = { connections: upstream.connections, bytes: upstream.bytes };
    refusal(await raw(stale.port, request(stale.port)), 'RELEASE_REFUSED', 403);
    noUpstream(upstream, before);
  }
  await positive(await listener(t, upstream), upstream);
});

function spinUntil(time) { while (Date.now() <= time) { /* finite real clock race, no override */ } }
test('whole intersection expires at admission, outbound dispatch and inbound release', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  let end;
  const admission = await listener(t, upstream, { change(c) {
    end = Date.now() + 80;
    setWindow(c, 'receiver', 'authenticated', 'requestProof', Date.now() - 1000, end);
  } });
  await new Promise(resolve => setTimeout(resolve, 100));
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  refusal(await raw(admission.port, request(admission.port)), 'RELEASE_REFUSED', 403);
  noUpstream(upstream, before);
  let observations = 0;
  const dispatch = await listener(t, upstream, { change(c) {
    end = Date.now() + 500;
    setWindow(c, 'receiver', 'observed', 'routeProof', Date.now() - 1000, end);
    const observe = c.observe;
    c.observe = function () { const result = Reflect.apply(observe, this, []); if (++observations === 2) spinUntil(end); return result; };
  } });
  const bytesBefore = upstream.bytes;
  refusal(await raw(dispatch.port, request(dispatch.port)), 'RELEASE_REFUSED', 403);
  assert.equal(upstream.bytes, bytesBefore, 'readiness may connect but expiry sends no late bytes');
  const release = await listener(t, upstream, { change(c) {
    end = Date.now() + 700;
    setWindow(c, 'sender', 'authenticated', 'identityProof', Date.now() - 1000, end);
    const inspect = c.receiver.inspect;
    c.receiver.inspect = function (...args) { const result = Reflect.apply(inspect, this, args); spinUntil(end); return result; };
  } });
  const imagesBefore = upstream.images.length;
  refusal(await raw(release.port, request(release.port)), 'RELEASE_REFUSED', 403);
  assert.equal(upstream.images.length, imagesBefore + 1, 'earlier guarded upstream request is not rolled back');
  await positive(await listener(t, upstream), upstream);
});

async function workersGone(since) {
  for (const child of children.slice(since)) {
    let live = false;
    try { process.kill(child.pid, 0); live = true; } catch { /* actual liveness */ }
    assert.equal(live, false, 'no live fixed worker after close');
  }
}
test('abort before dispatch, after request, and concurrent busy exchange', { timeout: 30_000 }, async t => {
  const upstream = await peer(t, null);
  const local = await listener(t, upstream);
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  await raw(local.port, request(local.port).subarray(0, 50), { connected: socket => socket.destroy() });
  noUpstream(upstream, before);
  let firstSocket;
  let reached;
  const arrived = new Promise(resolve => { reached = resolve; });
  upstream.onRequest = () => reached();
  const first = raw(local.port, request(local.port), { connected: socket => { firstSocket = socket; } });
  await bounded(arrived);
  refusal(await raw(local.port, request(local.port)), 'BUSY', 429);
  firstSocket.destroy();
  assert.equal(await first === '', true, 'abort has no client release');
  await local.owner.close();
  await workersGone(0);
  upstream.answer = DEMO_REPLY;
  await positive(await listener(t, upstream), upstream);
});

test('close during inspection, child, upstream and guarded response write drains actual workers', { timeout: 60_000 }, async t => {
  const upstream = await peer(t);
  const ownedTransports = [];
  const connect = net.createConnection;
  net.createConnection = function (...args) {
    const socket = Reflect.apply(connect, this, args);
    if (args[0]?.localAddress === '127.0.0.1') ownedTransports.push(socket);
    return socket;
  };
  syncBuiltinESMExports();
  t.after(() => { net.createConnection = connect; syncBuiltinESMExports(); });
  let local;
  let closePromise;
  const before = { connections: upstream.connections, bytes: upstream.bytes };
  const inspection = await listener(t, upstream, { change(c) {
    const inspect = c.sender.inspectOriginal;
    c.sender.inspectOriginal = function (...args) { closePromise = local.owner.close(); return Reflect.apply(inspect, this, args); };
  } });
  local = inspection;
  let childAt = children.length;
  assert.equal(await raw(local.port, request(local.port)) === '', true);
  await bounded(closePromise);
  noUpstream(upstream, before);
  await workersGone(childAt);

  local = await listener(t, upstream);
  const spawn = childProcess.spawn;
  childProcess.spawn = function (...args) {
    const child = Reflect.apply(spawn, this, args);
    if (String(args[1]?.[0]).endsWith('egress-sentinel-process-worker.js')) queueMicrotask(() => { closePromise = local.owner.close(); });
    return child;
  };
  syncBuiltinESMExports();
  childAt = children.length;
  try {
    assert.equal(await raw(local.port, request(local.port)) === '', true);
    await bounded(closePromise);
    await workersGone(childAt);
  } finally { childProcess.spawn = spawn; syncBuiltinESMExports(); }

  upstream.answer = null;
  local = await listener(t, upstream);
  upstream.onRequest = () => { closePromise = local.owner.close(); };
  assert.equal(await raw(local.port, request(local.port)) === '', true);
  await bounded(closePromise);
  await workersGone(childAt);
  upstream.onRequest = undefined;
  upstream.answer = DEMO_REPLY;

  local = await listener(t, upstream);
  const write = net.Socket.prototype.write;
  let guardedWrites = 0;
  net.Socket.prototype.write = function (chunk, ...args) {
    const isReply = chunk instanceof Uint8Array && Buffer.from(chunk).subarray(0, 16).toString() === 'HTTP/1.1 200 OK\r';
    const result = Reflect.apply(write, this, [chunk, ...args]);
    if (isReply) { guardedWrites++; queueMicrotask(() => { closePromise = local.owner.close(); }); }
    return result;
  };
  childAt = children.length;
  let wire;
  try { wire = await raw(local.port, request(local.port)); await bounded(closePromise); }
  finally { net.Socket.prototype.write = write; }
  assert.equal(guardedWrites, 1, 'one guarded native write began before queued close');
  assert.equal(wire.includes(PLANTED_ORIGINAL) || wire.includes(PLANTED_SECRET), false);
  // A guarded write already handed to the kernel can reach the client; no rollback is asserted.
  await workersGone(childAt);
  // The fixture's silent allowHalfOpen peer owns its remote half; inspect the actual owned transports.
  assert.equal(ownedTransports.length > 0, true, 'non-vacuous native transport capture');
  for (const socket of ownedTransports) {
    assert.equal(socket.destroyed, true, 'actual upstream transport destroyed');
    await bounded(new Promise(resolve => { if (socket.closed) resolve(); else socket.once('close', resolve); }));
  }
  await positive(await listener(t, upstream), upstream);
});

test('own-data invalidity and sink injection never bind; callback snapshots cannot retarget', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const valid = host(upstream.port);
  delete valid.runs;
  let getterCalls = 0;
  const badHosts = [null, {}, { ...valid, extra: true }, { ...valid, listenPort: 1 },
    { ...valid, listenPort: upstream.port }, { ...valid, listenPort: -1 },
    { ...valid, callerToken: 'synthetic.invalid' },
    { ...valid, conversation: { ...valid.conversation, onReply: async () => {} } },
    { ...valid, conversation: { ...valid.conversation, sender: { ...valid.conversation.sender, sendPoint: {} } } },
    { ...valid, conversation: { ...valid.conversation, receiver: { ...valid.conversation.receiver, releasePoint: {} } } },
    { ...valid, get conversation() { getterCalls++; throw new Error(capability()); } },
    { ...valid, conversation: { ...valid.conversation, sender: { ...valid.conversation.sender,
      boundary: { get authenticated() { getterCalls++; throw new Error(PLANTED_SECRET); }, observed: {} } } } },
  ];
  for (const input of badHosts) {
    const owner = api.createOpenAiLocalListener(input);
    const result = await owner.start();
    assert.equal(result.status === 'REFUSED' && result.code === 'HOST_INVALID', true);
    assert.equal(owner.state === 'FAILED', true);
    await owner.close();
  }
  assert.equal(getterCalls, 0);
  const local = await listener(t, upstream);
  local.input.conversation.observe = () => { throw new Error(capability()); };
  local.input.conversation.sender.inspectOriginal = () => { throw new Error(PLANTED_SECRET); };
  local.input.conversation.receiver.inspect = () => { throw new Error(PLANTED_SECRET); };
  await positive(local, upstream);
  await positive(local, upstream); // distinct fresh owners and sockets, same privately pinned evidence.
});

test('diagnostic subprocess reports only fixed label, never planted host exception', { timeout: 30_000 }, async () => {
  const captured = childProcess.spawnSync(process.execPath, ['test/support/openai-local-listener-diagnostic-probe.mjs'], { encoding: 'utf8', timeout: 20_000 });
  assert.equal(captured.status, 0);
  assert.equal(captured.stdout === 'HOST_REFUSED\n', true);
  assert.equal(captured.stderr === '', true);
  assert.equal(captured.stdout.includes(capability()) || captured.stderr.includes(capability()), false);
});

test('native non-streamed OpenAI-shaped HTTP client receives one canonical guarded reply', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  const chunks = [];
  const captures = [];
  const completed = new Promise((resolve, reject) => {
    const client = http.request({ host: '127.0.0.1', port: local.port, path: '/v1/chat/completions',
      method: 'POST', headers: { Authorization: 'Bearer ' + capability(),
        'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(DEMO_REQUEST),
        'X-Synthetic-SDK-Shape': 'fixture.invalid', Connection: 'close' } }, response => {
      assert.equal(response.statusCode, 200);
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', resolve);
      response.on('error', () => reject(new Error('client refused')));
    });
    client.on('socket', socket => socket.on('data', chunk => captures.push(chunk)));
    client.on('error', () => reject(new Error('client refused')));
    client.end(DEMO_REQUEST);
  });
  await bounded(completed);
  assert.equal(Buffer.concat(chunks).toString() === expectedReply, true);
  assert.equal(Buffer.concat(captures).toString().split('\r\n\r\n')[1] === expectedReply, true);
  assert.equal(upstream.images.at(-1) === expectedRequest, true);
});

test('full-request client abort cancels before any late inbound inspection or release', { timeout: 30_000 }, async t => {
  const upstream = await peer(t, null);
  const local = await listener(t, upstream);
  let client;
  let observed;
  const arrived = new Promise(resolve => { observed = resolve; });
  upstream.onRequest = socket => { observed(socket); };
  const receiving = raw(local.port, request(local.port), { connected: socket => { client = socket; } });
  const upstreamSocket = await bounded(arrived);
  client.destroy();
  await receiving;
  await new Promise(resolve => setTimeout(resolve, 50));
  upstreamSocket.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
    + Buffer.byteLength(DEMO_REPLY) + '\r\n\r\n' + DEMO_REPLY);
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(local.runs.filter(run => run.side === 'reply').length, 0, 'abort admits no later receiver');
  await local.owner.close();
  await workersGone(0);
  upstream.onRequest = undefined;
  upstream.answer = DEMO_REPLY;
  await positive(await listener(t, upstream), upstream);
});

test('expiry during finite client framing still maps to coarse 403 without a 200 write', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  let end;
  const local = await listener(t, upstream, { change(c) {
    end = Date.now() + 800;
    setWindow(c, 'sender', 'observed', 'sourceProof', Date.now() - 1000, end);
  } });
  const encode = TextEncoder.prototype.encode;
  let delayed = 0;
  TextEncoder.prototype.encode = function (value) {
    if (value === expectedReply) { delayed++; spinUntil(end); }
    return Reflect.apply(encode, this, [value]);
  };
  let wire;
  try { wire = await raw(local.port, request(local.port)); }
  finally { TextEncoder.prototype.encode = encode; }
  assert.equal(delayed, 1, 'finite real-time framing delay was observed');
  refusal(wire, 'RELEASE_REFUSED', 403);
  await positive(await listener(t, upstream), upstream);
});

test('closed listener cannot return a stale listening handle or bind again', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  await local.owner.close();
  const result = await local.owner.start();
  assert.equal(result.status === 'REFUSED' && result.code === 'CLOSED', true);
  assert.equal(local.owner.state === 'CLOSED', true);
});

test('close during actual inbound child check leaves no release or live worker', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  const spawn = childProcess.spawn;
  let ordinal = 0;
  let closed;
  childProcess.spawn = function (...args) {
    const child = Reflect.apply(spawn, this, args);
    if (String(args[1]?.[0]).endsWith('egress-sentinel-process-worker.js') && ++ordinal === 2) {
      queueMicrotask(() => { closed = local.owner.close(); });
    }
    return child;
  };
  syncBuiltinESMExports();
  const since = children.length;
  try {
    const wire = await raw(local.port, request(local.port));
    assert.equal(wire === '', true);
    assert.equal(ordinal, 2, 'inbound fixed child really started');
    await bounded(closed);
    await workersGone(since);
  } finally { childProcess.spawn = spawn; syncBuiltinESMExports(); }
  assert.equal(upstream.images.length, 1, 'already guarded outbound request remains observable');
  await positive(await listener(t, upstream), upstream);
});

test('private response writer has an absolute five-second completion bound', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  const local = await listener(t, upstream);
  const write = net.Socket.prototype.write;
  let withheld = 0;
  net.Socket.prototype.write = function (chunk, ...args) {
    if (chunk instanceof Uint8Array && Buffer.from(chunk).subarray(0, 16).toString() === 'HTTP/1.1 200 OK\r') {
      withheld++;
      // Real native write still runs. Only its completion notification is withheld to exercise the bound.
      const forwarded = args.map(arg => typeof arg === 'function' ? () => {} : arg);
      return Reflect.apply(write, this, [chunk, ...forwarded]);
    }
    return Reflect.apply(write, this, [chunk, ...args]);
  };
  const now = Date.now();
  let wire;
  try { wire = await raw(local.port, request(local.port)); }
  finally { net.Socket.prototype.write = write; }
  assert.equal(withheld, 1);
  assert.equal(Date.now() - now >= 4800, true, 'writer deadline actually elapsed');
  assert.equal(wire.includes(PLANTED_ORIGINAL) || wire.includes(PLANTED_SECRET), false);
  await local.owner.close();
  await workersGone(0);
  // The guarded write may already have reached the kernel/client; no rollback is claimed.
  await positive(await listener(t, upstream), upstream);
});

test('captured callbacks receive their validated snapshots, never caller token or reply sink', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  let observations = 0;
  let inspections = 0;
  let valid = true;
  const local = await listener(t, upstream, { change(c) {
    const observe = c.observe;
    c.observe = function () {
      observations++;
      valid &&= this.port === upstream.port && this.timeoutMs === 10_000 && !Object.hasOwn(this, 'callerToken') && !Object.hasOwn(this, 'onReply');
      return Reflect.apply(observe, this, []);
    };
    for (const [side, key] of [['sender', 'inspectOriginal'], ['receiver', 'inspect']]) {
      const inspect = c[side][key];
      c[side][key] = function (...args) {
        inspections++;
        valid &&= this.boundary.authenticated.subject.principalId === 'principal-demo.invalid'
          && !Object.hasOwn(this, 'onReply') && !Object.hasOwn(this, 'callerToken');
        return Reflect.apply(inspect, this, args);
      };
    }
  } });
  await positive(local, upstream);
  assert.equal(valid, true);
  assert.equal(observations, 4);
  assert.equal(inspections, 2);
});

test('one listener cannot bind different sender and receiver authenticated contexts', { timeout: 30_000 }, async t => {
  const upstream = await peer(t);
  for (const change of [
    c => { c.receiver.boundary.authenticated.context.sessionId = 'different-session.synthetic.invalid'; },
    c => { c.receiver.boundary.authenticated.subject.principalId = 'different-principal.synthetic.invalid'; },
  ]) {
    const fixture = host(upstream.port, { change });
    const { runs, ...input } = fixture;
    const owner = api.createOpenAiLocalListener(input);
    const result = await owner.start();
    t.after(() => owner.close());
    assert.equal(result.status === 'REFUSED' && result.code === 'HOST_INVALID', true);
  }
  assert.equal(upstream.connections, 0);
  assert.equal(upstream.bytes, 0);
  await positive(await listener(t, upstream), upstream);
});
