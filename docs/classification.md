# Classification

Classification is multi-dimensional. Hylja does not collapse semantic type, sensitivity, and trust into one label.

## Semantic classes

Initial top-level classes:

1. `PERSON`
2. `CREDENTIAL_OR_SECRET`
3. `USER_ACCOUNT`
4. `NETWORK_IDENTIFIER`
5. `HOST_OR_SERVICE`
6. `CLOUD_RESOURCE`
7. `FILE_OR_RESOURCE_PATH`
8. `CUSTOMER_OR_PARTNER`
9. `PROJECT_OR_CONTRACT`
10. `APPLICATION_OR_ENVIRONMENT`
11. `ENGINEERING_IDENTIFIER`
12. `BUSINESS_CONFIDENTIAL`

Representative subtypes:

- `PERSON`: NAME, EMAIL, PHONE; email/phone candidates may also be linked to a person entity without assuming every address or number names a known person.
- `NETWORK_IDENTIFIER`: IP, PORT, DOMAIN, URL, MAC, SUBNET.
- `CREDENTIAL_OR_SECRET`: PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_TOKEN, REFRESH_TOKEN, COOKIE, CONNECTION_SECRET, CERTIFICATE_SECRET.
- `ENGINEERING_IDENTIFIER`: ASSET_TAG, DRAWING_NUMBER, PART_NUMBER, ITEM_ID, DOCUMENT_ID, FUNCTIONAL_LOCATION, PLC_TAG, SCADA_TAG.
- `CLOUD_RESOURCE`: TENANT_ID, SUBSCRIPTION_ID, ACCOUNT_ID, ARN, PROJECT_ID, RESOURCE_GROUP, BUCKET, VAULT, SERVICE_ACCOUNT.

## Sensitivity

- `PUBLIC` - approved for public disclosure.
- `INTERNAL` - intended for organizational use; low impact if exposed.
- `CONFIDENTIAL` - customer, project, infrastructure, or business information requiring controlled disclosure.
- `RESTRICTED` - high-impact identifiers or data requiring strong destination and purpose controls.
- `SECRET` - credentials, private keys, tokens, or information whose plaintext external disclosure is normally blocked.

Sensitivity is policy metadata, not a property inferred from formatting alone.

## Trust

- `CONTROL` - Hylja control-plane policy/instructions.
- `TRUSTED` - authenticated internal data with approved provenance.
- `VERIFIED_EXTERNAL` - external input verified for integrity/source but not promoted to control authority.
- `UNTRUSTED` - user/web/tool/model content that may be useful but must not control policy.
- `HOSTILE` - content with detected injection, abuse, or explicit hostile provenance.

Trust controls influence. Sensitivity controls disclosure. The dimensions interact but remain distinct.

## Classification record

A classification may include:

```ts
interface Classification {
  semanticType: string;
  sensitivity: "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "SECRET";
  trust: "CONTROL" | "TRUSTED" | "VERIFIED_EXTERNAL" | "UNTRUSTED" | "HOSTILE";
  reversible: boolean;
  scope: "request" | "session" | "project" | "tenant";
  confidence?: number;
  provenance: ProvenanceRef[];
  detectorEvidence: DetectorEvidence[];
}
```

This interface is illustrative until the contract issue is implemented. Runtime records also need an explicit unresolved/unknown state rather than treating a missing label as `PUBLIC`; deterministic secret evidence is not downgraded by a semantic judge. Trust comes from authenticated provenance and never becomes `CONTROL` merely because untrusted content claims authority.

## Keys and values

Structured files are parsed. Keys such as `server`, `username`, and `port` usually carry useful semantics and should not be cloaked merely because their values are sensitive. Policy may still classify a key when the key itself embeds a customer name, secret, or identifier.
