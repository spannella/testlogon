# Entitlements Service Core (CCE-011)

`app/services/entitlements_service.py` provides the centralized read/write core for entitlement lifecycle and usage operations.

## Service methods
- `grant_entitlement(order_id)`
- `revoke_entitlement(entitlement_id, reason)`
- `check_access(subject, action, resource)`
- `consume_usage(subject, meter, amount, idempotency_key)`

## Behavior guarantees
- Uses CCE-002 state semantics via `resolve_effective_status(...)` for access checks.
- Uses standardized denial reasons from CCE-003:
  - `denied`
  - `expired`
  - `exhausted`
  - `idempotency_conflict`
- Usage consumption is idempotent by `idempotency_key`:
  - exact replay is non-mutating and returns prior result with `replayed=true`.
  - conflicting replay payload returns `idempotency_conflict`.

## Audit logging
- `grant_entitlement(...)` emits `entitlement_granted` structured audit events.
- `revoke_entitlement(...)` emits `entitlement_revoked` structured audit events.

## Product type support
Grant flow supports order items for:
- `file_bundle`
- `api_package`
- `internal_api_package`

The integration tests in `tests/test_entitlements_service.py` validate product coverage, denial mapping, idempotency behavior, and concurrent consumption consistency.
