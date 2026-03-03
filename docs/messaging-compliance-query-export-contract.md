# Messaging Compliance Query + Export Contract (FCA-003)

This contract defines compliance-facing API shapes for legal case retrieval and evidence export over immutable messaging archive data.

## Scope

- Compliance search/query API over immutable archive records.
- Case-bound export request and export manifest contract.
- Cursor pagination for deterministic retrieval.

## Contract versioning

- **Contract version:** `1`
- **Archive schema dependency:** `messaging-compliance-archive-event-schema-v1`
- **Compatibility rule:** additive-only changes for v1 fields; breaking changes require v2 endpoint/model version.

## Query API contract

### Endpoint

- `POST /messaging/compliance/archive/query`

### Request body (`ComplianceArchiveQueryIn`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `case_id` | string | Yes | Legal/compliance case reference. |
| `tenant_id` | string | Yes | Tenant/workspace scope; must match caller authorization. |
| `conversation_id` | string | No | Filter by conversation. |
| `message_id` | string | No | Filter by specific message. |
| `actor_user_id` | string | No | Filter by actor. |
| `effective_user_id` | string | No | Filter by effective actor. |
| `event_types` | string[] | No | Subset of canonical taxonomy. |
| `from_ts` | integer | Yes | Inclusive lower-bound event timestamp. |
| `to_ts` | integer | Yes | Inclusive upper-bound event timestamp. |
| `limit` | integer | No | 1..500 (default 100). |
| `cursor` | string | No | Opaque pagination cursor. |

### Response body (`ComplianceArchiveQueryOut`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `case_id` | string | Yes | Echo of case identifier. |
| `items` | `MessagingComplianceArchiveEventV1[]` | Yes | Immutable archive events. |
| `next_cursor` | string \| null | Yes | Opaque cursor for next page. |
| `total_estimate` | integer \| null | No | Optional estimate only; not required for correctness. |
| `schema_version` | integer | Yes | Query contract schema version (`1`). |

### Pagination semantics

- Stable order: `event_ts ASC`, then `event_id ASC` tie-breaker.
- `cursor` is an opaque encoded tuple of the last read sort key.
- `next_cursor = null` indicates end-of-results.

### Authorization constraints

- Caller must have compliance role and tenant scope.
- Cross-tenant query attempts must fail with `403`.
- Query source must be immutable archive storage/indexes, not mutable operational message tables.

## Export API contract

### Endpoint

- `POST /messaging/compliance/archive/exports`

### Request body (`ComplianceArchiveExportIn`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `case_id` | string | Yes | Legal/compliance case reference. |
| `tenant_id` | string | Yes | Tenant/workspace scope. |
| `query` | `ComplianceArchiveQueryIn` | Yes | Snapshot query definition used to build export. |
| `requested_by_user_id` | string | Yes | Compliance actor id. |
| `export_format` | string enum | Yes | `jsonl` (v1). |

### Response body (`ComplianceArchiveExportOut`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `export_id` | string | Yes | Export job identifier. |
| `case_id` | string | Yes | Case reference. |
| `status` | string enum | Yes | `queued|running|completed|failed`. |
| `manifest_schema_version` | integer | Yes | Export manifest schema version (`1`). |
| `result_manifest_uri` | string \| null | Yes | Populated when completed. |

## Export bundle manifest format (v1)

- JSON file named `manifest.json` in export artifact root.
- Schema: `docs/messaging-compliance-export-bundle-manifest-v1.json`.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `manifest_version` | integer | Const `1`. |
| `export_id` | string | Export identifier. |
| `case_id` | string | Case reference. |
| `tenant_id` | string | Tenant/workspace scope. |
| `archive_schema_version` | integer | Linked archive event schema version. |
| `generated_at` | integer | Unix timestamp. |
| `generated_by_user_id` | string | Compliance actor id. |
| `records_file` | object | Path/checksum/record_count for JSONL payload file. |
| `bundle_checksums` | object | Digest of artifact set. |
| `signature` | object | Signature metadata and key id. |
| `query_snapshot` | object | Immutable copy of query criteria used. |

### Signature metadata

`signature` includes:

- `algorithm` (e.g., `ed25519`)
- `key_id`
- `value` (signature over canonical manifest content)
- optional `certificate_chain`

## Error contract

| Status | Code | Meaning |
|---|---|---|
| 400 | `invalid_query_range` | Invalid `from_ts`/`to_ts` inputs. |
| 401 | `unauthorized` | Caller not authenticated. |
| 403 | `forbidden_scope` | Caller lacks tenant/case access. |
| 404 | `case_not_found` | Referenced case id unknown to compliance domain. |
| 422 | `invalid_event_type_filter` | Query includes unknown event type. |
| 429 | `export_rate_limited` | Too many export jobs requested. |
| 500 | `archive_query_failed` | Archive backend failure. |

## Acceptance notes

- Contract is legal-case centric (`case_id` required).
- Query and export payloads are scoped to immutable archive records.
- Cursor pagination contract supports deterministic, replay-safe retrieval.
