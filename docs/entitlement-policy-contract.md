# Entitlement Policy Contract (CCE-003)

This document publishes a shared policy contract for entitlement access checks and usage consumption to avoid service-by-service authorization drift.

Implementation reference: `app/services/entitlement_policy.py`.

## Contract: `check_access(subject, action, resource)`

### Request shape
- `subject` (string): principal identifier (`user:<id>`, `api_key:<id>`, `svc:<name>`).
- `action` (string): operation identifier (examples: `download_file`, `call_route`, `internal_call`).
- `resource` (object): context dimensions used for scope checks (examples: `route_id`, `namespace`, `date`, `file_id`).

### Response shape
- `allowed` (bool)
- `entitlement_id` (string | null)
- `reason_code` (`denied` | `expired` | `exhausted` | null)
- `message` (string | null)

## Contract: `consume_usage(subject, meter, amount, idempotency_key)`

### Request shape
- `subject` (string)
- `meter` (string): usage meter/action name (example: `request_units`).
- `amount` (int, `> 0`)
- `idempotency_key` (string)

### Response shape
- `consumed` (bool)
- `entitlement_id` (string | null)
- `usage_consumed` (int)
- `usage_limit` (int)
- `replayed` (bool)
- `reason_code` (`denied` | `expired` | `exhausted` | `idempotency_conflict` | null)
- `message` (string | null)

## Error taxonomy
- `denied`: no eligible entitlement or scope/action mismatch.
- `expired`: entitlement exists but is outside validity window (`now >= ends_at`) or marked expired.
- `exhausted`: usage limit reached or requested amount exceeds remaining balance.
- `idempotency_conflict`: same idempotency key replayed with different payload (meter/amount/entitlement).

## Idempotency and replay expectations
- First successful consume stores idempotency result.
- Exact replay (same key + same payload) returns the prior response with `replayed=true` and does **not** double-consume.
- Reuse of the same key with different payload returns `idempotency_conflict`.

## Contract examples

### File download check
```python
policy.check_access(
  subject="user:42",
  action="download_file",
  resource={"date": "2026-01-15", "file_id": "f1"},
)
```

### External API call check
```python
policy.check_access(
  subject="api_key:abc",
  action="call_route",
  resource={"route_id": "POST:/v1/messages/send"},
)
```

### Internal API call check
```python
policy.check_access(
  subject="svc:filemanager",
  action="internal_call",
  resource={"namespace": "filemanager.*"},
)
```

## Sign-off checklist
- [ ] API owner sign-off
- [ ] Messaging owner sign-off
- [ ] File Manager owner sign-off
