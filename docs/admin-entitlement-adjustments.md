# Admin Entitlement Manual Adjustments (CCE-051)

`/v1/admin/entitlements/*` provides operator APIs for support corrections with strict audit requirements.

## RBAC

- Endpoints require admin/root.
- When `ADMIN_SCOPE_ENFORCE_BILLING_SUPPORT=true`, callers must have `billing_support` scope.
- Scope denials are emitted as `admin_scope_denied` audit events by auth policy.

## Operations

- `POST /v1/admin/entitlements/{entitlement_id}/revoke`
  - Requires `reason_code` and `audit_comment`.
  - Sets entitlement status to `revoked` with actor/reason/comment fields.
- `POST /v1/admin/entitlements/{entitlement_id}/extend`
  - Requires `extend_hours`, `reason_code`, and `audit_comment`.
  - Extends `ends_at` and tracks cumulative extension metadata.
- `POST /v1/admin/entitlements/{entitlement_id}/credits`
  - Requires `credit_units`, `reason_code`, and `audit_comment`.
  - Increases `usage_limit` and tracks cumulative credit adjustment metadata.

## Auditability

- Each adjustment route emits structured `audit_event` entries for success/failure.
- Each adjustment also writes an immutable `entitlement_usage_events` row (`meter=admin.adjustment`) with actor, reason code, and audit comment.
- Together these provide operator action traceability and support workflow evidence.
