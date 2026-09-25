import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runReferenceCandidate } from "./reference.mjs";

// Public development inputs only. No planted oracle, expectedAnswer or blind material.
const development = JSON.parse(readFileSync(
  new URL("../../docs/research/issue-39-public-development-fixtures-p0.1.json", import.meta.url),
  "utf8",
));
const fixture = (id) => development.fixtures.find((entry) => entry.fixtureId === id);
const sinkId = "CAPTURE-DEMO-MODEL"; // A proposed local capture ID, NOT a trusted route.
const run = (fields, taskPrompt) => runReferenceCandidate({ sinkId, fields, taskPrompt });

function assertByteSpan(text, event, spelling) {
  const start = text.indexOf(spelling);
  assert.ok(start >= 0, "test input has a synthetic example");
  assert.equal(event.startByte, Buffer.byteLength(text.slice(0, start), "utf8"));
  assert.equal(event.endByte, Buffer.byteLength(text.slice(0, start + spelling.length), "utf8"));
}

test("D01 proposed text: basic identities and roles survive irreversible masking", () => {
  const sample = fixture("D01-DEV-001");
  const { disposition, events, transformedFields, taskResponse } = run(
    [{ id: "body", text: sample.input.text }],
    sample.taskControl.prompt,
  );
  assert.equal(disposition, "TRANSFORMED");
  assert.ok(events.some((event) => event.semanticType === "PERSON" && event.subtype === "NAME"));
  assert.ok(events.some((event) => event.semanticType === "PERSON" && event.subtype === "EMAIL"));
  assert.ok(events.some((event) => event.semanticType === "PERSON" && event.subtype === "PHONE"));
  assert.ok(events.some((event) => event.semanticType === "CUSTOMER_OR_PARTNER"));
  assert.ok(events.some((event) => event.semanticType === "PROJECT_OR_CONTRACT"));
  assert.ok(events.every((event) => event.fieldId === "body" && event.endByte > event.startByte));
  const visible = transformedFields[0].text;
  assert.ok(!visible.includes("person.alpha@example.invalid"), "no original email in transformed field");
  assert.ok(!visible.includes("202-555-0101"), "no original phone in transformed field");
  assert.ok(visible.includes("primary on-call") && visible.includes("backup"));
  assert.ok(visible.includes("approved internal channel"));
  assert.equal(taskResponse, undefined);
});

test("UTF-8 byte spans point into their own field, not UTF-16 offsets", () => {
  const text = "🌐 customer=Customer Demo-South contact=unit@example.invalid callback=+1 202-555-0102";
  const result = run([{ id: "message", text }]);
  assert.equal(result.disposition, "TRANSFORMED");
  const email = result.events.find((event) => event.subtype === "EMAIL");
  const phone = result.events.find((event) => event.subtype === "PHONE");
  assert.ok(email && phone);
  assertByteSpan(text, email, "unit@example.invalid");
  assertByteSpan(text, phone, "+1 202-555-0102");
});

test("D02 proposed log: even obviously nonlive token means BLOCK and no field text", () => {
  const sample = fixture("D02-DEV-001");
  const result = run(sample.input.lines.map((text, index) => ({ id: `line:${index}`, text })));
  assert.equal(result.disposition, "BLOCK");
  assert.equal(result.transformedFields, undefined);
  assert.equal(result.taskResponse, undefined);
  const secret = result.events.find((event) => event.semanticType === "CREDENTIAL_OR_SECRET");
  assert.ok(secret, "candidate reports secret detector event independently of blocking");
  assert.equal(secret.fieldId, "line:0");
  assert.ok(secret.endByte > secret.startByte);
});

test("D02 non-secret log keeps HTTPS /health, attempted 443 and expected 8443", () => {
  const sample = fixture("D02-DEV-001");
  const result = run(sample.input.lines.slice(1).map((text, index) => ({ id: `line:${index + 1}`, text })));
  assert.equal(result.disposition, "TRANSFORMED");
  const visible = result.transformedFields.map((field) => field.text).join("\n");
  assert.ok(visible.includes("https://") && visible.includes(":443/health"));
  assert.ok(visible.includes("expected_service_port=8443"));
  assert.ok(visible.includes('"port":443') && visible.includes('"port":8443'));
  assert.ok(!visible.includes("diag-node.example.invalid"));
  assert.ok(!result.events.some((event) => event.subtype === "PHONE"));
});

test("D05 JSON remains valid and response edits effective HTTPS port with visible relations", () => {
  const sample = fixture("D05-DEV-001");
  const result = run([{ id: "config", hint: "json", text: JSON.stringify(sample.input.value) }], sample.taskControl.prompt);
  assert.equal(result.disposition, "TRANSFORMED");
  assert.ok(result.events.some((event) => event.semanticType === "HOST_OR_SERVICE"));
  assert.ok(result.events.some((event) => event.semanticType === "FILE_OR_RESOURCE_PATH"));
  const visible = JSON.parse(result.transformedFields[0].text);
  assert.ok(visible.customer && visible.project);
  assert.ok(!visible.endpointUrl.includes("service.demo.invalid"));
  assert.equal(visible.port, 9443);
  assert.equal(new URL(visible.endpointUrl).pathname, "/v1/ping");
  assert.ok(visible.outputPath.startsWith("/") && visible.outputPath.endsWith(".json"));
  assert.ok(visible.outputPath !== sample.input.value.outputPath);
  const edited = JSON.parse(result.taskResponse);
  const endpoint = new URL(edited.endpointUrl);
  assert.equal(edited.port, 443);
  assert.equal(Number(endpoint.port || (endpoint.protocol === "https:" ? 443 : 80)), 443);
  assert.equal(endpoint.protocol, "https:");
  assert.equal(endpoint.pathname, "/v1/ping");
  assert.equal(endpoint.hostname, new URL(visible.endpointUrl).hostname);
  assert.equal(edited.customer, visible.customer);
  assert.equal(edited.project, visible.project);
  assert.equal(edited.outputPath, visible.outputPath);
  assert.equal(edited.os, "linux");
  assert.equal(edited.timeoutMs, 2500);
});

test("credential assignments and URL userinfo block even for nonlive synthetic strings", () => {
  const password = run([{ id: "body", text: 'password=DEMO-NONLIVE-NOT-VALID' }]);
  assert.equal(password.disposition, "BLOCK");
  assert.ok(password.events.some((event) => event.semanticType === "CREDENTIAL_OR_SECRET"));
  const jsonToken = run([{ id: "config", hint: "json", text: '{"api_key":"DEMO-NONLIVE-NOT-VALID"}' }]);
  assert.equal(jsonToken.disposition, "BLOCK");
  const urlCredential = run([{ id: "body", text: "https://demo.user:DEMO-NONLIVE-NOT-VALID@host.example.invalid/health" }]);
  assert.equal(urlCredential.disposition, "BLOCK");
  assert.equal(urlCredential.transformedFields, undefined);
});

test("malformed JSON and unsupported sink cannot emit a transformed candidate", () => {
  const malformed = run([{ id: "config", hint: "json", text: '{"port":443,' }]);
  assert.equal(malformed.disposition, "BLOCK");
  assert.equal(malformed.transformedFields, undefined);
  const unknownSink = runReferenceCandidate({ sinkId: "EXTERNAL-NOT-CAPTURE", fields: [{ id: "body", text: "hello" }] });
  assert.equal(unknownSink.disposition, "BLOCK");
  assert.equal(unknownSink.transformedFields, undefined);
});

test("raw-looking field IDs never escape through BLOCK events or transformed fields", () => {
  const unsafeId = "DEMO-NONLIVE-TOKEN-NOT-VALID";
  for (const text of [`token=${unsafeId}`, "health=ok"]) {
    const result = run([{ id: unsafeId, text }]);
    assert.equal(result.disposition, "BLOCK", "reject a field ID copied from candidate text");
    assert.equal(result.events.length, 0, "reject before generating detector events");
    assert.equal(result.transformedFields, undefined);
    assert.equal(result.taskResponse, undefined);
    assert.ok(!JSON.stringify(result).includes(unsafeId), "no protected-looking field ID in result");
  }
});

test("JSON Unicode-escaped duplicate effective outputPath blocks instead of partial rewrite", () => {
  const text = '{"output\\u0050ath":"/opt/demo/outputs/first.json","outputPath":"/opt/demo/outputs/probe.json"}';
  const result = run([{ id: "config", hint: "json", text }]);
  assert.equal(result.disposition, "BLOCK");
  assert.equal(result.transformedFields, undefined);
  assert.equal(result.taskResponse, undefined);
});

test("fixture-authored profiles, policy claims and extra fields are not candidate inputs", () => {
  const result = runReferenceCandidate({
    sinkId,
    fields: [{ id: "body", text: "hello" }],
    destinationProfileProposal: { exposure: "LOCAL" },
  });
  assert.equal(result.disposition, "BLOCK");
  assert.equal(result.transformedFields, undefined);
});
