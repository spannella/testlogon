# Messaging Drafts Security & Privacy Review

Date: 2026-04-05  
Scope: Draft CRUD service, router endpoints, frontend draft UX/analytics, storage retention controls.

## Threat model summary

Primary risk areas reviewed:
- plaintext draft content leaking into logs/telemetry
- over-retention of stale draft content
- cross-user/cross-conversation draft access
- insecure transport/storage assumptions

## Findings and safeguards

### 1) Plaintext logging / telemetry

- Backend draft metrics only emit metadata dimensions (`operation`, `source`, `result`, `reason`) and do **not** include draft text.
- Frontend analytics events are schema-constrained metadata events (`event`, `outcome`, `source`, `reason`, timestamp, conversation-id-presence flag).
- Event schema explicitly forbids arbitrary fields via `additionalProperties: false`, preventing accidental inclusion of draft body text.

**Result:** No plaintext draft content in telemetry payload definitions.

### 2) Access control isolation

- Draft endpoints are conversation-scoped and ownership-scoped.
- Service-layer `get_draft` / `list_drafts` enforce owner+conversation constraints.

**Result:** Cross-user and cross-conversation access paths are rejected.

### 3) Retention and deletion behavior

- Draft rows carry a TTL attribute (`ttl_epoch`) derived from server time + retention window (`DRAFTS_RETENTION_DAYS`, default 30).
- TTL is refreshed on update so active drafts are retained and stale drafts expire.
- Explicit delete endpoint removes a specific draft immediately.

**Validated in tests:** service tests assert TTL set on create and refreshed on update.

### 4) Encryption assumptions

- **In transit:** HTTPS/TLS termination is required for client/API communication.
- **At rest:** DynamoDB server-side encryption is required in deployment environments.

These controls are infrastructure/environment requirements and must be enforced in deployment policy.

## Residual risks / follow-ups

- Add a periodic retention audit that samples draft rows and checks TTL drift.
- Add SIEM rule to flag unexpected payload keys in draft analytics ingestion.
