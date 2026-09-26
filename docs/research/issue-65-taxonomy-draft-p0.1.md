# #65 taxonomy draft p0.1: semantic type, domain, subtype and orthogonal properties

**RESEARCH DRAFT: not an accepted taxonomy, legal opinion, classifier change or #39 oracle label set.** This is an AI-authored starting point for a nominated human [#65](https://github.com/Marcus-Levin/hylja/issues/65) lead and an independent human reviewer. It builds on the [public source index](issue-65-public-source-index-p0.1.md). The executable form [`src/taxonomy-draft.ts`](../../src/taxonomy-draft.ts) is a frozen data table with consistency tests; it is **not wired** into [`classification.ts`](../../src/classification.ts), policy or any detector. Implementation status lives only in [the plan](../plan.md#current-state).

## Shape

Each concept is a four-part path plus orthogonal properties, avoiding a flat enum explosion:

```ts
{ semanticType: 'ENGINEERING_IDENTIFIER', domain: 'PLM', subtype: 'PART_NUMBER',
  form: 'IDENTIFIER', evidence: ['STRUCTURE', 'TENANT_DICTIONARY'], personalDataPrior: 'NOT_BY_ITSELF',
  v1: { semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'PART_NUMBER' } }
```

- **semanticType**: what kind of thing it is. It carries no sensitivity or treatment.
- **domain**: the practice area the vocabulary comes from. It lets tenants add subtypes without new top-level types.
- **subtype**: globally unique, so a subtype alone identifies its path.
- **form**: `IDENTIFIER` names or references a thing; `CONTENT` describes it; `CREDENTIAL` grants access. This is the fix for `ENGINEERING_IDENTIFIER` being too narrow. Geometry, setpoints or a BOM are sensitive engineering content without being identifiers.
- **evidence**: what can plausibly establish the subtype. `FORMAT` means syntax or a checksum alone; `STRUCTURE` means parser or schema context; `TENANT_DICTIONARY` means tenant/project-scoped configured values or an ontology; `CONTEXT` means surrounding meaning, which only a semantic judge can supply and which stays advisory. A subtype without `FORMAT` cannot be found reliably by pattern matching.
- **personalDataPrior**: a review hint (`ALWAYS`, `CONTEXTUAL` or `NOT_BY_ITSELF`), never a label for a value. Whether a given occurrence is personal data is a contextual attribute ([#66](https://github.com/Marcus-Levin/hylja/issues/66)).
- **jurisdictions**: set only where the concept itself is jurisdiction-specific.

Sensitivity, trust and treatment are deliberately absent (decisions 002 and 003). Sensitivity depends on the tenant and context, not on the kind of value.

## Glossary

### People and personal data

`PERSON` is kept for the natural-person *entity*: `PERSON_NAME` and `PERSON_ALIAS`. Contact points and identifiers that *may* refer to a person move to `PERSONAL_IDENTIFIER`, so that `PERSON` no longer stands in for all personal data:

| Domain | Subtypes | Notes |
| --- | --- | --- |
| `CONTACT` | `EMAIL_ADDRESS`, `PHONE_NUMBER`, `POSTAL_ADDRESS` | Contextual: a shared mailbox or switchboard number may not identify a person. |
| `NATIONAL_ID` | `SE_PERSONNUMMER`, `SE_SAMORDNINGSNUMMER`, `NATIONAL_ID_OTHER` | See below. |
| `ONLINE` | `ONLINE_IDENTIFIER`, `DEVICE_IDENTIFIER` | Cookie IDs, advertising IDs, device serials in a personal context. |
| `EMPLOYMENT` | `EMPLOYEE_NUMBER` | Tenant-specific formats. |

`PERSONAL_ATTRIBUTE` holds content about a person that is not an identifier: `DATE_OF_BIRTH`, `PRECISE_LOCATION` and `HEALTH_INFORMATION`. The last is a likely GDPR Article 9 special category; that is an attribute to assess, not a property of the type.

Personal data can attach to other types. An IP address (`NETWORK_IDENTIFIER` / `IP`) can be personal data in context, as the [European Commission's GDPR guidance](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/application-gdpr_en) notes, yet it stays semantically an IP. The same holds for `USERNAME`, `FILE_PATH` (for example a home directory), `SERIAL_NUMBER`, `MAINTENANCE_RECORD` (a named technician), `INSPECTION_RESULT`, `DEVIATION_REPORT` and `DOCUMENT_CONTROL_METADATA` (approvers).

### Swedish personnummer and samordningsnummer

`SE_PERSONNUMMER` and `SE_SAMORDNINGSNUMMER` are separate subtypes because they are issued differently and a detector must tell them apart. A samordningsnummer's day field is offset, and both carry a check digit, so `FORMAT` evidence is strong but not sufficient: a matching digit string in a part number or log field is not a national ID. Detection should therefore also use `STRUCTURE` (field names, form context). [IMY](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/introduktion-till-gdpr/personuppgifter/personnummer/) describes special Swedish safeguards for these numbers while noting they are **not**, merely by being such numbers, GDPR special-category data. The draft therefore records `jurisdictions: ['SE']` and `personalDataPrior: 'ALWAYS'` and does not mark them special-category. Qualified human review must decide handling. **No example numbers, valid or invalid, appear in this repository**; a test rejects national-ID-shaped digit runs in this document and the draft source.

### Credentials

`CREDENTIAL_OR_SECRET` / `AUTHENTICATION` keeps every v1 subtype: `PASSWORD`, `API_KEY`, `PRIVATE_KEY`, `ACCESS_TOKEN`, `REFRESH_TOKEN`, `COOKIE`, `CONNECTION_SECRET` and `CERTIFICATE_SECRET`. Form `CREDENTIAL` exists so that decision 009 (secrets are not synthetic identities) can key off form rather than a list of names. A session `COOKIE` is `CONTEXTUAL` for personal data because it often identifies a user session.

### IT and cloud

| Type | Subtypes |
| --- | --- |
| `USER_ACCOUNT` | `USERNAME` |
| `NETWORK_IDENTIFIER` | `IP`, `PORT`, `DOMAIN`, `URL`, `MAC`, `SUBNET` |
| `HOST_OR_SERVICE` | `HOSTNAME`, `SERVICE_ENDPOINT`, `DATABASE_NAME` |
| `CLOUD_RESOURCE` (`CLOUD`) | `TENANT_ID`, `SUBSCRIPTION_ID`, `ACCOUNT_ID`, `ARN`, `PROJECT_ID`, `RESOURCE_GROUP`, `BUCKET`, `VAULT`, `SERVICE_ACCOUNT` |
| `FILE_OR_RESOURCE_PATH` | `FILE_PATH` |
| `APPLICATION_OR_ENVIRONMENT` | `APPLICATION_NAME`, `ENVIRONMENT_NAME` |

`PORT` is `NOT_BY_ITSELF` and relies on `STRUCTURE`/`CONTEXT`. A bare `443` is a port only in context, and is often task-critical and low risk.

### Organizations and business

`CUSTOMER_OR_PARTNER` / `ORGANIZATION_NAME` and `PROJECT_OR_CONTRACT` / `PROJECT_NAME`, `CONTRACT_NUMBER` need tenant dictionaries: there is no format for a customer name. `BUSINESS_CONFIDENTIAL` holds content: `PRICING`, `CONTRACT_TERMS` and `STRATEGY_OR_PLAN`. This remains an explicit research gap; no external taxonomy for contract or IP content has been validated.

### Engineering: identifiers versus content

v1's `ENGINEERING_IDENTIFIER` covers only tags and numbers. The draft keeps it for identifiers and adds `ENGINEERING_INFORMATION` for content:

| Domain | `ENGINEERING_IDENTIFIER` | `ENGINEERING_INFORMATION` | Source to verify |
| --- | --- | --- | --- |
| `PLM` | `PART_NUMBER`, `ITEM_ID`, `DRAWING_NUMBER`, `REVISION_ID`, `CHANGE_ORDER_NUMBER` | `BOM_STRUCTURE`, `VARIANT_EFFECTIVITY`, `CHANGE_DESCRIPTION` | [NIST model-based enterprise standards comparison](https://www.nist.gov/publications/open-standards-flexible-discrete-manufacturing-model-based-enterprise) (STEP AP242, QIF, JT) |
| `CAD` | (uses PLM identifiers) | `GEOMETRY`, `PMI_TOLERANCE`, `MATERIAL_SPECIFICATION` | [NIST CAD/CAM/metrology validation](https://www.nist.gov/publications/validation-downstream-computer-aided-manufacturing-and-coordinate-metrology-processes) |
| `CAE` | — | `SIMULATION_MODEL`, `LOAD_CASE`, `SIMULATION_RESULT` | **gap**: no vendor-neutral source cited yet |
| `CAM` | — | `NC_PROGRAM`, `TOOLPATH`, `PROCESS_PARAMETERS`, `PROCESS_PLAN` | [NIST STEP-NC roadmap](https://www.nist.gov/publications/roadmap-step-nc-enabled-interoperable-manufacturing) |
| `PROCESS_PLANT` | `EQUIPMENT_TAG`, `LINE_NUMBER`, `INSTRUMENT_TAG` | `PROCESS_TOPOLOGY`, `PROCESS_CONDITIONS` | [DEXPI P&ID specification](https://dexpi.org/static/pid_specification_1.4/concepts/introduction.html) |
| `ASSET` | `ASSET_TAG`, `FUNCTIONAL_LOCATION`, `SERIAL_NUMBER` | `MAINTENANCE_RECORD`, `INSPECTION_RESULT` | [OPC UA ISA-95 common object model](https://reference.opcfoundation.org/specs/OPC-10030/1) |
| `OT` | `PLC_TAG`, `SCADA_TAG` | `CONTROL_LOGIC`, `CONTROL_SETPOINT`, `CONTROL_SYSTEM_CONFIGURATION` | [NIST SP 800-82r3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) |
| `QUALITY` | `NCR_NUMBER` | `MEASUREMENT_RESULT`, `DEVIATION_REPORT` | [NIST QIF](https://www.nist.gov/publications/quality-information-framework-integrating-metrology-processes) |
| `IM` | `DOCUMENT_ID`, `TRANSMITTAL_NUMBER` | `DOCUMENT_CONTROL_METADATA` | **gap**: no engineering document-control standard cited |
| `IT` | (see IT and cloud) | `SYSTEM_TOPOLOGY`, `INTEGRATION_CONFIGURATION`, `DEPLOYMENT_CONFIGURATION` | **gap**: needs enterprise-architecture sources |

Nearly every engineering identifier needs `TENANT_DICTIONARY` or `STRUCTURE` evidence. Part-number, tag and functional-location schemes are organization-specific, and no global pattern should be shipped for them. `NC_PROGRAM` and `CONTROL_LOGIC` have recognizable file syntaxes (`FORMAT`), but recognizing a G-code or ladder-logic file is not parser support.

## Mapping from classification v1

Every v1 default subtype maps to exactly one draft entry, and every v1 class keeps a home (checked by tests):

| v1 | Draft |
| --- | --- |
| `PERSON` / `NAME` | `PERSON` / `IDENTITY` / `PERSON_NAME` |
| `PERSON` / `EMAIL`, `PHONE` | `PERSONAL_IDENTIFIER` / `CONTACT` / `EMAIL_ADDRESS`, `PHONE_NUMBER` (**type changes**) |
| `ENGINEERING_IDENTIFIER` / `DOCUMENT_ID` | `ENGINEERING_IDENTIFIER` / `IM` / `DOCUMENT_ID` |
| other `ENGINEERING_IDENTIFIER` subtypes | same subtype under `PLM`, `ASSET` or `OT` |
| `CREDENTIAL_OR_SECRET`, `NETWORK_IDENTIFIER`, `CLOUD_RESOURCE` subtypes | unchanged names, domain added |
| v1 classes without subtypes | gain subtypes (`USERNAME`, `HOSTNAME`, `FILE_PATH`, ...) |

`draftEntriesForV1` provides this mapping for migration and replay. New types (`PERSONAL_IDENTIFIER`, `PERSONAL_ATTRIBUTE`, `ENGINEERING_INFORMATION`) and the new identifiers have `v1: null`. v1 can currently express them only through a tenant `extendSubtypeRegistry` extension, or not at all.

**Compatibility impact:** moving EMAIL/PHONE out of `PERSON` changes the semantic type that policy rules select on. A migration therefore needs a classification version bump, a policy bundle version that re-targets rules, and replay of v1 records through the mapping. The v1 enum must not be edited in place.

## Tenant-specific classification required

Tenant/project dictionaries or ontologies are needed for `PERSON_NAME`, `PERSON_ALIAS`, `EMPLOYEE_NUMBER`, `ORGANIZATION_NAME`, `PROJECT_NAME`, and all engineering identifiers and host/application/environment names. They must be tenant-scoped (AGENTS.md: cross-tenant resolution is a security defect). Tenants add subtypes under an existing type and domain; they do not add top-level types.

## Candidate #39 synthetic additions (proposals, not fixtures or blind seeds)

- An obviously synthetic, checksum-*invalid* national-ID-shaped string in a non-ID field (for example a part-number column) as a negative control, and a labeled ID field with an `.invalid`-style placeholder as a positive structural case, without ever committing a valid number.
- `ENGINEERING_INFORMATION` content with no identifier, such as a synthetic setpoint table or tolerance note, to measure misses that identifier-only detection cannot catch.
- A documentation-range IP labeled `NETWORK_IDENTIFIER` / `IP` with `personalData` set by context, scored against `PERSON` confusion.
- Tenant A's dictionary part numbers appearing in tenant B's input, which must not match.
- Harmless task-critical values (`PORT` 443, `ENVIRONMENT_NAME` "staging") as over-hiding controls.

## Recommendation

After human review, record the accepted hierarchy in a new decision record. It would cover the four-part path, form, the `PERSON` / `PERSONAL_IDENTIFIER` split and `ENGINEERING_INFORMATION`, and would be paired with the #66 information-model decision, since classification v2 needs both. Until then the draft is evidence only.

## Open questions for the human reviewers

- Should `PERSONAL_IDENTIFIER` and `PERSON` merge, with entity linking handled separately?
- Is `ENGINEERING_INFORMATION` one type with domains, or several types (`PRODUCT_DEFINITION`, `PROCESS_DEFINITION`, `CONTROL_SYSTEM`)?
- Which CAE, IM and enterprise-architecture sources are authoritative?
- Should `PRECISE_LOCATION` of equipment (not people) be a separate `ASSET` subtype?
- How should relationship-level sensitivity be represented, such as a BOM plus a customer name?
