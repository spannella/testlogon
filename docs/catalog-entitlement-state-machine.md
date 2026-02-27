# Entitlement Domain Model & State Machine Contract (CCE-002)

This document defines the entitlement state machine, required fields, transition rules, and UTC expiration semantics for commercialization products.

## Canonical states
- `pending_payment`
- `active`
- `expired`
- `revoked`
- `consumed`

`expired`, `revoked`, and `consumed` are terminal states.

## Required entitlement fields
- `entitlement_id`
- `user_id`
- `sku`
- `product_type` (`file_bundle` | `api_package` | `internal_api_package`)
- `status`
- `scope` (object defining resource/route/namespace constraints)
- `starts_at` (UTC timestamp)
- `ends_at` (nullable UTC timestamp)
- `usage_limit` (integer)
- `usage_consumed` (integer)
- `created_at` (UTC timestamp)
- `updated_at` (UTC timestamp)
- `created_by` (nullable actor id)

## Transition matrix

| From \ To | pending_payment | active | expired | revoked | consumed |
|---|---:|---:|---:|---:|---:|
| pending_payment | ❌ | ✅ | ❌ | ✅ | ❌ |
| active | ❌ | ❌ | ✅ | ✅ | ✅ |
| expired | ❌ | ❌ | ❌ | ❌ | ❌ |
| revoked | ❌ | ❌ | ❌ | ❌ | ❌ |
| consumed | ❌ | ❌ | ❌ | ❌ | ❌ |

## Forbidden transition examples
- `pending_payment -> consumed`
- `expired -> active`
- `revoked -> active`
- `consumed -> active`

## UTC time and expiration semantics
- All entitlement timestamps are normalized to UTC.
- If an entitlement is `active`, it becomes effectively `expired` when `now_utc >= ends_at`.
- `ends_at` is optional for perpetual purchase-style access.
- If a timestamp is provided without timezone, it is interpreted as UTC by contract.

## API contract notes
- Domain/API models are represented in `app/models_entitlements.py`:
  - `EntitlementModel`
  - `EntitlementResponse`
  - `EntitlementTransitionRequest`
- Transition validation and effective-status resolution are implemented in `app/services/entitlements.py`.
