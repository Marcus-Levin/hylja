import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { detectInfrastructure, MAX_TEXT_UNITS, INFRA_PRODUCER } from '../dist/infrastructure-identifiers.js';

// Synthetic only: documentation address ranges, reserved names (.invalid/.example) and fake cloud IDs.
const run = (text) => detectInfrastructure({ text, inputRef: 'field-a.invalid' });
const found = (text, result = run(text)) => result.candidates.map((c) => [c.semanticType, c.subtype ?? '', text.slice(c.start, c.end)]);
const has = (text, type, subtype, value) =>
  assert.ok(found(text).some(([t, s, v]) => t === type && s === subtype && v === value), `${type}/${subtype} ${value} in ${text}`);

test('#9 negative: a host inside a URL query keeps its own candidate, offset and fidelity', () => {
  const text = 'GET https://proxy.example.com:8443/fetch?target=build.tenant-a.invalid&x=1';
  const result = run(text);
  const host = result.candidates.find((c) => text.slice(c.start, c.end) === 'build.tenant-a.invalid');
  assert.ok(host);
  assert.equal(host.semanticType, 'HOST_OR_SERVICE');
  assert.equal(host.start, text.indexOf('build.tenant-a.invalid'));
  assert.equal(host.fidelity.scope, 'RESERVED_NAME');
  // The URL, its host and its port are separate candidates too.
  has(text, 'NETWORK_IDENTIFIER', 'URL', 'https://proxy.example.com:8443/fetch?target=build.tenant-a.invalid&x=1');
  has(text, 'HOST_OR_SERVICE', '', 'proxy.example.com');
  const port = result.candidates.find((c) => c.subtype === 'PORT');
  assert.equal(text.slice(port.start, port.end), '8443');
  assert.equal(port.fidelity.wellKnownService, 'https-alt');
});

test('IP addresses, subnets and MACs carry version and scope; documentation ranges are recognized', () => {
  for (const [text, subtype, scope, version] of [
    ['from 192.0.2.10 ok', 'IP', 'DOCUMENTATION', 4], ['198.51.100.7', 'IP', 'DOCUMENTATION', 4], ['203.0.113.255', 'IP', 'DOCUMENTATION', 4],
    ['10.4.0.0/16', 'SUBNET', 'PRIVATE', 4], ['172.20.1.1', 'IP', 'PRIVATE', 4], ['192.168.0.1', 'IP', 'PRIVATE', 4],
    ['127.0.0.1', 'IP', 'LOOPBACK', 4], ['169.254.1.1', 'IP', 'LINK_LOCAL', 4], ['100.64.0.1', 'IP', 'SHARED', 4],
    ['2001:db8::1', 'IP', 'DOCUMENTATION', 6], ['2001:db8:0:0:0:0:0:1', 'IP', 'DOCUMENTATION', 6], ['fe80::1%eth0', 'IP', 'LINK_LOCAL', 6],
    ['fd00::/8', 'SUBNET', 'PRIVATE', 6], ['::1', 'IP', 'LOOPBACK', 6],
  ]) {
    const [candidate] = run(text).candidates.filter((c) => c.semanticType === 'NETWORK_IDENTIFIER');
    assert.ok(candidate, text);
    assert.deepEqual([candidate.subtype, candidate.fidelity.scope, candidate.fidelity.ipVersion], [subtype, scope, version], text);
  }
  has('mac 00:1B:44:11:3A:B7 end', 'NETWORK_IDENTIFIER', 'MAC', '00:1B:44:11:3A:B7');
  has('mac 00-1b-44-11-3a-b7', 'NETWORK_IDENTIFIER', 'MAC', '00-1b-44-11-3a-b7');
});

test('technical look-alikes are not network identifiers', () => {
  for (const text of ['version v1.2.3.4', 'build 1.2.3.4.5', 'at 12:30:45', '2026-09-26T10:00:00Z', '999.1.1.1', 'a::b::c',
    'ratio 3:4', 'uuid 123e4567-e89b-12d3-a456-426614174000']) {
    assert.deepEqual(found(text).filter(([t]) => t === 'NETWORK_IDENTIFIER'), [], text);
  }
});

test('DNS names: hosts are candidates, file names are not, and reserved names are classed', () => {
  has('connect to plc-gateway-07.internal now', 'HOST_OR_SERVICE', '', 'plc-gateway-07.internal');
  has('db.tenant-a.invalid:5432', 'HOST_OR_SERVICE', '', 'db.tenant-a.invalid');
  has('db.tenant-a.invalid:5432', 'NETWORK_IDENTIFIER', 'PORT', '5432');
  for (const text of ['see package.json and index.html', 'run build.sh', 'open drawing.dwg', 'photo.jpg']) {
    assert.deepEqual(found(text).filter(([t]) => t === 'HOST_OR_SERVICE'), [], text);
  }
  const internal = run('api.corp').candidates[0];
  assert.equal(internal.fidelity.scope, 'PRIVATE');
});

test('URLs of any scheme; single-label URL hosts; userinfo does not become the host', () => {
  has('jdbc:postgresql://db01:5432/app', 'HOST_OR_SERVICE', '', 'db01');
  has('http://db01:5432/app', 'NETWORK_IDENTIFIER', 'PORT', '5432');
  const text = 'mqtt://svc:synthetic@broker.example.invalid:8883/t';
  has(text, 'HOST_OR_SERVICE', '', 'broker.example.invalid');
  assert.equal(run(text).candidates.find((c) => c.subtype === 'PORT').fidelity.wellKnownService, 'mqtt-tls');
});

test('POSIX, Windows and UNC paths carry their style', () => {
  for (const [text, value, style] of [
    ['file /var/log/app/server.log here', '/var/log/app/server.log', 'POSIX'], ['~/projects/synthetic/notes.md', '~/projects/synthetic/notes.md', 'POSIX'],
    ['C:\\Users\\synthetic\\file.txt', 'C:\\Users\\synthetic\\file.txt', 'WINDOWS'],
    ['\\\\fileserver.invalid\\share\\dir', '\\\\fileserver.invalid\\share\\dir', 'UNC'],
  ]) {
    const candidate = run(text).candidates.find((c) => c.semanticType === 'FILE_OR_RESOURCE_PATH');
    assert.ok(candidate, text);
    assert.equal(text.slice(candidate.start, candidate.end), value);
    assert.equal(candidate.fidelity.pathStyle, style);
  }
  assert.deepEqual(found('a / b and 1/2').filter(([t]) => t === 'FILE_OR_RESOURCE_PATH'), []);
});

test('cloud identifiers: ARN, account, Azure subscription and resource group, GCP project, buckets, keyed IDs', () => {
  const guid = '00000000-0000-4000-8000-000000000000';
  has('arn:aws:iam::123456789012:role/synthetic', 'CLOUD_RESOURCE', 'ARN', 'arn:aws:iam::123456789012:role/synthetic');
  has('arn:aws:iam::123456789012:role/synthetic', 'CLOUD_RESOURCE', 'ACCOUNT_ID', '123456789012');
  has(`/subscriptions/${guid}/resourceGroups/rg-synthetic/providers/x`, 'CLOUD_RESOURCE', 'SUBSCRIPTION_ID', guid);
  has(`/subscriptions/${guid}/resourceGroups/rg-synthetic/providers/x`, 'CLOUD_RESOURCE', 'RESOURCE_GROUP', 'rg-synthetic');
  has('projects/synthetic-project/zones/x', 'CLOUD_RESOURCE', 'PROJECT_ID', 'synthetic-project');
  has('s3://synthetic-bucket/key', 'CLOUD_RESOURCE', 'BUCKET', 'synthetic-bucket');
  has('gs://synthetic-bucket/key', 'CLOUD_RESOURCE', 'BUCKET', 'synthetic-bucket');
  has('synthetic-bucket.s3.amazonaws.com', 'CLOUD_RESOURCE', 'BUCKET', 'synthetic-bucket');
  has('synthacct.blob.core.windows.net', 'CLOUD_RESOURCE', 'BUCKET', 'synthacct');
  has('deploy-bot@synthetic-proj.iam.gserviceaccount.com', 'CLOUD_RESOURCE', 'SERVICE_ACCOUNT',
    'deploy-bot@synthetic-proj.iam.gserviceaccount.com');
  has(`"tenantId": "${guid}"`, 'CLOUD_RESOURCE', 'TENANT_ID', guid);
  has(`subscription_id = ${guid}`, 'CLOUD_RESOURCE', 'SUBSCRIPTION_ID', guid);
  has('aws_account_id=123456789012', 'CLOUD_RESOURCE', 'ACCOUNT_ID', '123456789012');
  assert.deepEqual(found('order_id=123456789012').filter(([t]) => t === 'CLOUD_RESOURCE'), []);
});

test('keyed single-label hosts and environments', () => {
  has('host=db01 port=5432', 'HOST_OR_SERVICE', '', 'db01');
  has('"hostname": "historian-02"', 'HOST_OR_SERVICE', '', 'historian-02');
  has('Server=sql-synthetic;Database=app', 'HOST_OR_SERVICE', '', 'sql-synthetic');
  has('env=staging', 'APPLICATION_OR_ENVIRONMENT', '', 'staging');
  has('DEPLOY_ENV: production', 'APPLICATION_OR_ENVIRONMENT', '', 'production');
  assert.deepEqual(found('host=true env=1').filter(([t]) => t !== 'NETWORK_IDENTIFIER'), []);
});

test('results never contain matched values; evidence composes conservatively without sensitivity', () => {
  const text = 'https://plc-gateway-07.internal:502 from 192.0.2.10 host=historian-02';
  const result = run(text);
  const serialized = JSON.stringify(result);
  for (const value of ['plc-gateway-07', '192.0.2.10', 'historian-02']) assert.ok(!serialized.includes(value), value);
  const ip = result.candidates.find((c) => c.subtype === 'IP');
  assert.equal(ip.evidence.provenance.producerId, INFRA_PRODUCER.id);
  const composed = composeClassification({ detectorEvidence: [ip.evidence] },
    { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.equal(composed.status, 'UNRESOLVED');
  assert.deepEqual(composed.reasons, ['MISSING_SENSITIVITY']);
  const configured = composeClassification({ detectorEvidence: [{ ...ip.evidence, claim: { ...ip.evidence.claim, sensitivity: 'CONFIDENTIAL' } }] },
    { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.deepEqual([configured.status, configured.semanticType, configured.subtype], ['RESOLVED', 'NETWORK_IDENTIFIER', 'IP']);
  // Every candidate's evidence is valid v1 input with a unique id.
  const all = composeClassification({ detectorEvidence: result.candidates.map((c) => c.evidence) },
    { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.ok(!all.reasons.includes('INVALID_EVIDENCE') && !all.reasons.includes('DUPLICATE_EVIDENCE_ID'));
});

test('failures are explicit and report nothing', () => {
  for (const [request, reason] of [
    [{ text: 1, inputRef: 'x' }, 'INVALID_REQUEST'], [{ text: 'a', inputRef: '' }, 'INVALID_REQUEST'],
    [{ text: 'x'.repeat(MAX_TEXT_UNITS + 1), inputRef: 'x' }, 'INPUT_TOO_LARGE'], [{ text: '\uD800', inputRef: 'x' }, 'INVALID_TEXT'],
    [{ text: Array.from({ length: 300 }, (_, i) => `10.0.${i >> 8}.${i & 255}`).join(' '), inputRef: 'x' }, 'TOO_MANY_CANDIDATES'],
  ]) {
    const result = detectInfrastructure(request);
    assert.deepEqual([result.status, result.reasons, result.candidates], ['FAILURE', [reason], []], reason);
  }
});

test('adversarial inputs stay within a bounded-work budget', () => {
  for (const text of ['1.'.repeat(500_000), 'a.'.repeat(500_000), ':'.repeat(1 << 20), 'a:'.repeat(500_000), '/a'.repeat(500_000),
    'C:\\'.repeat(300_000), '\\\\a'.repeat(300_000), 'x://'.repeat(250_000), 'arn:aws:'.repeat(120_000), 'host='.repeat(200_000),
    `${'a-'.repeat(400_000)}.com`, 'projects/'.repeat(100_000), '/subscriptions/'.repeat(60_000), 'ff:'.repeat(300_000)]) {
    const started = process.hrtime.bigint();
    const result = run(text.slice(0, MAX_TEXT_UNITS));
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'FAILURE'].includes(result.status));
    // Catches super-linear matching; not a performance SLA.
    assert.ok(elapsedMs < 3000, `${text.slice(0, 8)} ${elapsedMs}ms`);
  }
});

test('synthetic golden set: false-positive and false-negative counts by subtype (development measurement)', (t) => {
  const guid = '00000000-0000-4000-8000-000000000000';
  const golden = [
    ['GET https://api.example.com/v1/ping 200 from 192.0.2.10:443', [['NETWORK_IDENTIFIER', 'URL', 'https://api.example.com/v1/ping'],
      ['HOST_OR_SERVICE', '', 'api.example.com'], ['NETWORK_IDENTIFIER', 'IP', '192.0.2.10'], ['NETWORK_IDENTIFIER', 'PORT', '443']]],
    [`{"server":"plc-gateway-07.internal","port":443,"subscriptionId":"${guid}"}`, [['HOST_OR_SERVICE', '', 'plc-gateway-07.internal'],
      ['CLOUD_RESOURCE', 'SUBSCRIPTION_ID', guid]]],
    ['wrote /srv/app/output.json in 12:30:45 build v1.2.3.4', [['FILE_OR_RESOURCE_PATH', '', '/srv/app/output.json']]],
    ['see package.json and README.md for version 2.0.1', []],
  ];
  const stats = {};
  for (const [text, expected] of golden) {
    const got = found(text).map((row) => row.join('|'));
    const want = expected.map((row) => row.join('|'));
    for (const item of new Set([...got, ...want])) {
      const key = item.split('|').slice(0, 2).join('/');
      stats[key] ??= { tp: 0, fp: 0, fn: 0 };
      stats[key][got.includes(item) && want.includes(item) ? 'tp' : got.includes(item) ? 'fp' : 'fn']++;
    }
  }
  for (const [subtype, { tp, fp, fn }] of Object.entries(stats)) {
    t.diagnostic(`${subtype}: recall ${tp}/${tp + fn}, false positives ${fp}`);
    assert.equal(fn, 0, `${subtype} false negatives`);
    assert.equal(fp, 0, `${subtype} false positives`);
  }
});

test('review: hosts in nested URLs, URL paths and user@host get their own candidates', () => {
  for (const [text, host] of [['https://proxy.invalid/f?url=https://build.tenant-a.invalid/x', 'build.tenant-a.invalid'],
    ['https://a.invalid/?next=//b.tenant-a.invalid/x', 'b.tenant-a.invalid'], ['https://a.invalid/path/c.tenant-a.invalid/x', 'c.tenant-a.invalid'],
    ['ssh admin@bastion.tenant-a.invalid', 'bastion.tenant-a.invalid'], ['git@git.example.com:org/repo.git', 'git.example.com'],
    ['host ärende.tenant.invalid ok', 'ärende.tenant.invalid']]) has(text, 'HOST_OR_SERVICE', '', host);
});

test('review: IPv4/IPv6 edge forms and scopes', () => {
  for (const [text, value] of [['at fd00::1.', 'fd00::1'], ['addr 2001:db8::1.', '2001:db8::1'], ['range 10.0.0.1-10.0.0.5', '10.0.0.1'],
    ['range 10.0.0.1-10.0.0.5', '10.0.0.5'], ['ip-10.0.0.1', '10.0.0.1'], ['10.0.0.1_eth0', '10.0.0.1'], ['10.001.002.003', '10.001.002.003'],
    ['fd12:3456:789a::10.0.0.1', 'fd12:3456:789a::10.0.0.1'], ['[2001:db8::1]:443', '2001:db8::1'], ['::ffff:192.0.2.1', '::ffff:192.0.2.1']]) {
    assert.ok(found(text).some(([t, s, v]) => t === 'NETWORK_IDENTIFIER' && (s === 'IP' || s === 'SUBNET') && v === value), `${text} -> ${value}`);
  }
  has('fd00::1/64.', 'NETWORK_IDENTIFIER', 'SUBNET', 'fd00::1/64');
  has('192.0.2.10:8443', 'NETWORK_IDENTIFIER', 'PORT', '8443');
  has('[2001:db8::1]:443', 'NETWORK_IDENTIFIER', 'PORT', '443');
  const scope = (text) => run(text).candidates.find((c) => c.semanticType === 'NETWORK_IDENTIFIER').fidelity.scope;
  assert.equal(scope('192.0.2.0/8'), 'PUBLIC');
  assert.equal(scope('2001:db8::/16'), 'PUBLIC');
  assert.equal(scope('3fff::1'), 'DOCUMENTATION');
  assert.equal(scope('198.18.0.1'), 'RESERVED');
  assert.equal(scope('::ffff:192.0.2.1'), 'DOCUMENTATION');
  for (const text of ['dead::beef', 'add::', 'a::b']) assert.deepEqual(found(text).filter(([t]) => t === 'NETWORK_IDENTIFIER'), [], text);
});

test('review: file URLs, forward-slash and long Windows paths, colon lists and quoted paths with spaces', () => {
  for (const [text, value] of [['file:///home/synthetic/secret.txt', '/home/synthetic/secret.txt'], ['file:///C:/Users/synthetic/x.txt', '/C:/Users/synthetic/x.txt'],
    ['C:/Users/synthetic/file.txt', 'C:/Users/synthetic/file.txt'], ['PATH=/usr/bin:/home/synthetic/bin', '/home/synthetic/bin'],
    ['-v /srv/data:/var/lib/data', '/var/lib/data'], ['open "/Users/John Smith/Documents/x.pdf" now', '/Users/John Smith/Documents/x.pdf'],
    ['"C:\\Users\\John Smith\\x.txt"', 'C:\\Users\\John Smith\\x.txt']]) {
    assert.ok(found(text).some(([t, , v]) => t === 'FILE_OR_RESOURCE_PATH' && v === value), `${text} -> ${value}`);
  }
});

test('review: code, prose and local paths are not hosts or cloud projects; custom schemes are OTHER', () => {
  for (const text of ['obj.method.call()', 'np.array', 'e.target.value', 'process.env.HOST', 'java.util.List', 'com.example.app.Main',
    'e.g. this', 'i.e. that', 'U.S.A', 'Mr.Smith', 'v1.2.3-beta.rc1']) {
    assert.deepEqual(found(text).filter(([t]) => t === 'HOST_OR_SERVICE'), [], text);
  }
  assert.deepEqual(found('~/projects/synthetic/notes.md').filter(([t]) => t === 'CLOUD_RESOURCE'), []);
  has('projects/synthetic-project/zones/x', 'CLOUD_RESOURCE', 'PROJECT_ID', 'synthetic-project');
  has('project_id: synthetic-proj-1', 'CLOUD_RESOURCE', 'PROJECT_ID', 'synthetic-proj-1');
  has('storage.googleapis.com/synthetic-bucket/o', 'CLOUD_RESOURCE', 'BUCKET', 'synthetic-bucket');
  has('s3a://synthetic-bucket/key', 'CLOUD_RESOURCE', 'BUCKET', 'synthetic-bucket');
  has('arn:aws-iso-b:iam::123456789012:role/x', 'CLOUD_RESOURCE', 'ACCOUNT_ID', '123456789012');
  assert.equal(run('tenantacmeerp://open/x').candidates.find((c) => c.subtype === 'URL').fidelity.scheme, 'OTHER');
  has('(see https://a.invalid/x).', 'NETWORK_IDENTIFIER', 'URL', 'https://a.invalid/x');
});

test('review: keyed-name rule skips schemes, emails, versions and prose; finds server_name and Data Source', () => {
  for (const text of ['endpoint=https://x.invalid', 'email_address=a@b.invalid', 'address=Main Street', 'node=v18.1.0']) {
    assert.deepEqual(found(text).filter(([, , v]) => ['https', 'a', 'Main', 'v18.1.0'].includes(v)), [], text);
  }
  has('Server=tcp:sql01,1433', 'HOST_OR_SERVICE', '', 'sql01');
  has('server_name = web01', 'HOST_OR_SERVICE', '', 'web01');
  has('Data Source=sql01;', 'HOST_OR_SERVICE', '', 'sql01');
});

test('review: URLs ending in long punctuation runs are trimmed in linear time', () => {
  const started = process.hrtime.bigint();
  run(`https://a.invalid/${')'.repeat(8000)} `.repeat(130).slice(0, MAX_TEXT_UNITS));
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 3000);
});

test('rereview: private suffixes, newer gTLDs and host context are hosts; code chains still are not', () => {
  for (const [text, host] of [['db.default.svc', 'db.default.svc'], ['vault.service.consul:8200', 'vault.service.consul'],
    ['ssh admin@db.default.svc', 'db.default.svc'], ['api.prod', 'api.prod'], ['nas.lab', 'nas.lab'], ['web.dmz', 'web.dmz'], ['app.k8s', 'app.k8s'],
    ['build-07.tenant-a.host', 'build-07.tenant-a.host'], ['ops.team', 'ops.team'], ['acme.consulting', 'acme.consulting'],
    ['?u=https://vault.service.consul/x', 'vault.service.consul'], ['//weird.customtld/x', 'weird.customtld'], ['portal.example.se', 'portal.example.se']]) {
    has(text, 'HOST_OR_SERVICE', '', host);
  }
  for (const text of ['user.id', 'self.id', 'Object.is', 'this.me', 'main.cc', 'script.pl', 'module.pm', 'fig.ps', 'app.mk']) {
    assert.deepEqual(found(text).filter(([t]) => t === 'HOST_OR_SERVICE'), [], text);
  }
  has('host=web', 'HOST_OR_SERVICE', '', 'web');
  has('server: jenkins', 'HOST_OR_SERVICE', '', 'jenkins');
  has('Server=sqlprod;', 'HOST_OR_SERVICE', '', 'sqlprod');
  has('net 1.2.3.4/33', 'NETWORK_IDENTIFIER', 'IP', '1.2.3.4');
  has('fd00::1/129', 'NETWORK_IDENTIFIER', 'IP', 'fd00::1');
});

test('second rereview: upper-case FQDNs, two-letter apex domains and version-like first labels are hosts; code members are not', () => {
  for (const [text, host] of [['DC01.CORP.LOCAL', 'DC01.CORP.LOCAL'], ['login from DC01.ACME.LOCAL', 'DC01.ACME.LOCAL'],
    ['SERVER.TENANT.COM', 'SERVER.TENANT.COM'], ['ACME.CORP', 'ACME.CORP'], ['tenant.io', 'tenant.io'], ['acme.co', 'acme.co'],
    ['v2.api.tenant.com', 'v2.api.tenant.com'], ['1.pool.ntp.org', '1.pool.ntp.org'], ['api-2.prod', 'api-2.prod'],
    ['vault.service.consul', 'vault.service.consul']]) has(text, 'HOST_OR_SERVICE', '', host);
  for (const text of ['self.host', 'args.host', 'window.location.host', 'response.data', 'config.data', 'user.domain', 'app.server',
    'job.run', 'task.build', 'self.site', 'a.prod', 'app.stage', 'console.info', 'data.no']) {
    assert.deepEqual(found(text).filter(([t]) => t === 'HOST_OR_SERVICE'), [], text);
  }
});

test('third rereview: popular gTLD apex and subdomains, mixed-case TLDs and other ccTLDs are hosts', () => {
  for (const host of ['tenant.dev', 'acme.app', 'acme.info', 'acme.network', 'acme.group', 'acme.host', 'app.tenant.dev', 'my.tenant.site',
    'data.tenant.network', 'e.tenant.app', 'db01.Tenant.COM', 'mail.Tenant.COM', 'acme.ru', 'acme.it', 'tenant.br', 'x.com', 't.co']) {
    has(`see ${host} now`, 'HOST_OR_SERVICE', '', host);
  }
  for (const text of ['this.props.data', 'process.env.HOST', 'window.location.host', 'myObject.someField.value']) {
    assert.deepEqual(found(text).filter(([t]) => t === 'HOST_OR_SERVICE'), [], text);
  }
});
