// Evaluation-only, NON-ENFORCING synthetic reference candidate for public development text.
// No model, network, policy decision, actual send, oracle, original-value mapping or restoration.
const CAPTURE_ID = "CAPTURE-DEMO-MODEL";
const HINTS = new Set(["text", "json", "person", "customer", "project", "outputPath"]);
const OUTPUT_PATH = "/tmp/synthetic/output.json";

const PATTERNS = [
  { regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, type: "PERSON", subtype: "EMAIL", replacement: "[EMAIL]" },
  { regex: /\+1[ -]\d{3}[ -]555[ -]01\d{2}\b/g, type: "PERSON", subtype: "PHONE", replacement: "[PHONE]" },
  { regex: /\bDemo Person [A-Z][a-z]+\b/g, type: "PERSON", subtype: "NAME", replacement: "[PERSON]" },
  { regex: /\bCustomer Demo-[A-Za-z][A-Za-z-]*\b/g, type: "CUSTOMER_OR_PARTNER", replacement: "[CUSTOMER]" },
  { regex: /\bPROJECT-DEMO-\d+\b/g, type: "PROJECT_OR_CONTRACT", replacement: "[PROJECT]" },
  { regex: /\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/g, type: "NETWORK_IDENTIFIER", subtype: "IP", replacement: "192.0.2.1" },
  { regex: /\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(?:invalid|example\.com)\b/gi, type: "HOST_OR_SERVICE", replacement: "host.example.invalid" },
];

function blocked(reason, events = []) {
  return { disposition: "BLOCK", events, reason };
}

function hasKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).every((key) => keys.includes(key));
}

function validInput(input) {
  return hasKeys(input, ["sinkId", "fields", "taskPrompt"])
    && typeof input.sinkId === "string"
    && Array.isArray(input.fields) && input.fields.length > 0 && input.fields.length <= 64
    && (input.taskPrompt === undefined || (typeof input.taskPrompt === "string" && input.taskPrompt.length <= 4096))
    && input.fields.every((field, index) => hasKeys(field, ["id", "text", "hint"])
      // Only an adapter-minted, per-case ordinal may leave the module as a reference.
      && field.id === `f${index}`
      && typeof field.text === "string" && field.text.length <= 65536
      && (field.hint === undefined || HINTS.has(field.hint)));
}

function jsonOutputPath(text) {
  // Escaped JSON keys can alias a plain key after parsing; don't partially rewrite.
  // This tiny candidate handles only unescaped JSON text, including its strings.
  if (text.includes("\\")) return { valid: false };
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { valid: false };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { valid: false };
  if (!Object.hasOwn(parsed, "outputPath")) return { valid: true };
  if (typeof parsed.outputPath !== "string" || !isOutputPath(parsed.outputPath)) return { valid: false };
  // Deliberately handle only a plain, single top-level unescaped JSON string value.
  const occurrences = [...text.matchAll(/"outputPath"\s*:\s*"([^"\\]*)"/g)];
  if (occurrences.length !== 1 || occurrences[0][1] !== parsed.outputPath) return { valid: false };
  const match = occurrences[0];
  return { valid: true, start: match.index + match[0].lastIndexOf(parsed.outputPath), end: match.index + match[0].lastIndexOf(parsed.outputPath) + parsed.outputPath.length };
}

function isOutputPath(value) {
  return /^\/(?:[A-Za-z0-9._-]+\/)+[A-Za-z0-9._-]+\.json$/.test(value)
    && !value.split("/").includes("..");
}

function scanField(field) {
  const { text } = field;
  const spans = [];
  const add = (start, end, type, subtype, replacement) => {
    if (spans.some((span) => start < span.end && end > span.start)) return;
    spans.push({ start, end, type, subtype, replacement });
  };

  if (field.hint === "json") {
    const path = jsonOutputPath(text);
    if (!path.valid) return { invalid: true, spans };
    if (path.start !== undefined) add(path.start, path.end, "FILE_OR_RESOURCE_PATH", undefined, OUTPUT_PATH);
  } else if (field.hint === "outputPath") {
    if (!isOutputPath(text)) return { invalid: true, spans };
    add(0, text.length, "FILE_OR_RESOURCE_PATH", undefined, OUTPUT_PATH);
  }

  // Credential evidence is a blocker even for intentionally nonlive demo strings.
  const assignments = /\b(?:token|api[_-]?key|password|secret)\b["']?\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s,}\]]+))/gi;
  for (const match of text.matchAll(assignments)) {
    const value = match[1] ?? match[2] ?? match[3];
    const start = match.index + match[0].lastIndexOf(value);
    add(start, start + value.length, "CREDENTIAL_OR_SECRET", "SECRET_LOOKING_VALUE", null);
  }
  for (const match of text.matchAll(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi)) {
    add(match.index, match.index + match[0].length, "CREDENTIAL_OR_SECRET", "PRIVATE_KEY", null);
  }
  for (const match of text.matchAll(/\bhttps?:\/\/([^/\s@:"']+:[^/\s@"']+)@/gi)) {
    const start = match.index + match[0].indexOf(match[1]);
    add(start, start + match[1].length, "CREDENTIAL_OR_SECRET", "CONNECTION_SECRET", null);
  }
  for (const { regex, type, subtype, replacement } of PATTERNS) {
    for (const match of text.matchAll(regex)) add(match.index, match.index + match[0].length, type, subtype, replacement);
  }
  // Field hints are non-authoritative candidate cues, never trusted classification.
  if (field.hint === "person" && /^Demo Person [A-Za-z]+$/.test(text)) add(0, text.length, "PERSON", "NAME", "[PERSON]");
  if (field.hint === "customer" && /^Customer Demo-[A-Za-z-]+$/.test(text)) add(0, text.length, "CUSTOMER_OR_PARTNER", undefined, "[CUSTOMER]");
  if (field.hint === "project" && /^PROJECT-DEMO-\d+$/.test(text)) add(0, text.length, "PROJECT_OR_CONTRACT", undefined, "[PROJECT]");
  spans.sort((left, right) => left.start - right.start);
  return { invalid: false, spans };
}

function syntheticTaskResponse(fields, prompt) {
  if (typeof prompt !== "string") return undefined;
  const request = /\bnew HTTPS port (\d{2,5})\b/i.exec(prompt);
  if (!request || fields.length !== 1 || fields[0].hint !== "json") return undefined;
  const requestedPort = Number(request[1]);
  if (requestedPort < 1 || requestedPort > 65535) return undefined;
  let config;
  let endpoint;
  try {
    config = JSON.parse(fields[0].text);
    endpoint = new URL(config.endpointUrl);
  } catch {
    return undefined;
  }
  if (!hasKeys(config, ["customer", "project", "protocol", "endpointUrl", "port", "os", "outputPath", "timeoutMs"])
    || Object.keys(config).length !== 8
    || !Number.isInteger(config.port) || !Number.isInteger(config.timeoutMs)
    || config.customer !== "[CUSTOMER]" || config.project !== "[PROJECT]"
    || config.protocol !== "https" || config.os !== "linux"
    || config.outputPath !== OUTPUT_PATH || endpoint.protocol !== "https:"
    || endpoint.hostname !== "host.example.invalid" || endpoint.username || endpoint.password
    || endpoint.search || endpoint.hash || !endpoint.pathname.startsWith("/")
    || config.port !== Number(endpoint.port || 443)) return undefined;
  endpoint.port = String(requestedPort);
  return JSON.stringify({ ...config, endpointUrl: endpoint.toString(), port: requestedPort });
}

/**
 * Candidate-facing only: { sinkId, fields: [{ id, text, hint? }], taskPrompt? }.
 * Event byte offsets are half-open UTF-8 spans of the original field text.
 * A TRANSFORMED candidate is not a release decision; #5 owns actual routing,
 * independent scoring, exact serialized capture and task grading.
 */
export function runReferenceCandidate(input) {
  if (!validInput(input)) return blocked("UNSUPPORTED_INPUT");
  if (input.sinkId !== CAPTURE_ID) return blocked("UNSUPPORTED_SINK");
  const scans = input.fields.map(scanField);
  if (scans.some((scan) => scan.invalid)) return blocked("UNSUPPORTED_FIELD");
  const events = scans.flatMap(({ spans }, index) => spans.map((span) => {
    const text = input.fields[index].text;
    return {
      fieldId: input.fields[index].id,
      startByte: Buffer.byteLength(text.slice(0, span.start), "utf8"),
      endByte: Buffer.byteLength(text.slice(0, span.end), "utf8"),
      semanticType: span.type,
      ...(span.subtype && { subtype: span.subtype }),
    };
  }));
  if (scans.some(({ spans }) => spans.some((span) => span.type === "CREDENTIAL_OR_SECRET"))) {
    return blocked("SECRET_CANDIDATE", events);
  }
  const transformedFields = input.fields.map((field, index) => {
    let text = field.text;
    for (const span of scans[index].spans.toReversed()) {
      text = text.slice(0, span.start) + span.replacement + text.slice(span.end);
    }
    return { id: field.id, text, ...(field.hint && { hint: field.hint }) };
  });
  // A replacement inside a JSON string may invalidate syntax: never return that candidate.
  for (const field of transformedFields) {
    if (field.hint === "json") {
      try { JSON.parse(field.text); } catch { return blocked("TRANSFORMATION_FAILED", events); }
    }
  }
  const taskResponse = syntheticTaskResponse(transformedFields, input.taskPrompt);
  return { disposition: "TRANSFORMED", events, transformedFields, ...(taskResponse && { taskResponse }) };
}
