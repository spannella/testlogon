# API Key Capability Namespace & Ownership Policy

This document defines the canonical capability vocabulary for API-key-backed product access and the baseline ownership model.
The machine-readable source of truth is `docs/api-key-capability-contract-v1.json`.

## Canonical capabilities (v1)

- `filemanager:read`
- `filemanager:write`
- `filemanager:share`
- `filemanager:admin`
- `newsfeed:read`
- `newsfeed:write`
- `newsfeed:moderate`
- `tickets:read`
- `tickets:write`
- `tickets:admin`
- `shopping:catalog:read`
- `shopping:cart:write`
- `shopping:checkout:write`
- `shopping:orders:read`
- `messager:read`
- `messager:write`
- `messager:manage`

## Broader-scope inheritance semantics

The following broader capability grants imply narrower capabilities:

- `filemanager:admin` ⇒ `filemanager:read`, `filemanager:write`, `filemanager:share`
- `tickets:admin` ⇒ `tickets:read`, `tickets:write`
- `newsfeed:moderate` ⇒ `newsfeed:read`, `newsfeed:write`
- `messager:manage` ⇒ `messager:read`, `messager:write`

Rules:
- Implications are one-way only.
- There are no wildcard grants (`filemanager:*`) in v1.
- Unknown capability names are invalid and rejected.

## Ownership model

- API keys are always owned by the user account that created them.
- API key capability grants never expand ownership boundaries.
- Route handlers must still enforce resource-level ownership/visibility checks.
- Capability checks are additive to entitlement checks, not replacements.

## Default authorization behavior

- Deny-by-default for API-key requests when a route has no explicit capability mapping (`unmapped_route`).
- Unknown capability names are invalid and must be rejected.
- Capability values are canonicalized as lowercase, trimmed strings.

## Versioning notes

- This is **v1** of the capability namespace.
- Namespace additions are backward-compatible.
- Renames/removals require migration guidance and contract-version announcement.

## Legacy-key migration policy

- Keys created before the `capabilities` field existed are treated as legacy keys.
- Legacy keys default to full v1 capability set at read-time for backward compatibility.
- Optional backfill utility: `scripts/backfill_api_key_capabilities.py` can persist the default
  `capabilities` array onto legacy key rows.

## API management endpoints: scope assignment behavior

Scope grants can be set at key creation time and updated later:

- `POST /ui/api_keys` with `capabilities` (alias: `scopes`)
- `POST /ui/api_keys/scopes`
- `PATCH /ui/api_keys/{key_id}/scopes`

Examples:

```json
{
  "label": "backend-worker",
  "capabilities": ["shopping:catalog:read", "shopping:cart:write"]
}
```

```json
{
  "key_id": "k_123",
  "scopes": ["tickets:read", "tickets:write"]
}
```

Validation contract:

- Unknown scope names are rejected with HTTP 400 and code `api_key_scopes_invalid`.
- Out-of-plan scope grants are rejected with HTTP 403 and code `api_key_scopes_out_of_plan`.
- `PATCH /ui/api_keys/{key_id}/scopes` requires path/body key IDs to match, otherwise HTTP 400
  with code `api_key_scope_target_mismatch`.
