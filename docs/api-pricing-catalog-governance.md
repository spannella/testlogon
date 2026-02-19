# API Pricing Catalog Schema & Governance (AMB-003)

This document defines the versioned API pricing catalog schema, lifecycle, and governance controls.

## Catalog schema

`API_USAGE_PRICING_CATALOG` is JSON with a `versions` array.

```json
{
  "versions": [
    {
      "pricing_catalog_version": "v1",
      "effective_at": "2026-01-01T00:00:00Z",
      "routes": {
        "POST:/v1/messages/send": {
          "price_per_call_micros": 1200,
          "tiers": [
            { "up_to_calls": 1000, "price_per_call_micros": 1300 },
            { "up_to_calls": 10000, "price_per_call_micros": 1250 }
          ]
        }
      },
      "default_route": {
        "price_per_call_micros": 100
      }
    }
  ]
}
```

### Field semantics
- `pricing_catalog_version` (string): immutable catalog ID.
- `effective_at` (epoch seconds or ISO8601 UTC): point-in-time activation.
- `routes` (map): `route_id -> route pricing`.
- `price_per_call_micros` (int): base unit price used after tier range.
- `tiers` (optional): ascending `up_to_calls` thresholds for lower/higher step pricing.
- `default_route` (optional): fallback pricing for unlisted routes.

## Deterministic lookup rules

1. Select version:
   - If version override is provided, use exact match.
   - Otherwise, choose the latest version with `effective_at <= event_ts`.
   - If all versions are future-dated, choose the earliest version.
2. Select route pricing:
   - Exact `route_id` match first.
   - Fallback behavior from `API_USAGE_PRICING_MISSING_ROUTE_BEHAVIOR`:
     - `default_route` (default): use `default_route` entry, or zero if absent.
     - `zero_price`: force zero price.
     - `error`: reject rating (`400`).
3. Select tier price:
   - Use `call_number_in_period` and first tier where `call_number_in_period <= up_to_calls`.
   - If no tier matches, use `price_per_call_micros` base.

These rules ensure deterministic rating for any request timestamp.

## Governance flow

### Change-management workflow
1. Author a new version entry (`vN`) instead of mutating existing active versions.
2. Set `effective_at` for intended go-live time (UTC).
3. Run validation/tests in CI against representative route set.
4. Obtain approvals:
   - Product (customer impact)
   - Finance (pricing correctness)
   - Engineering (operational safety)
5. Deploy config before `effective_at` (safe no-op until activation time).
6. Monitor metering + charge deltas immediately after activation.

### Audit requirements
- Every catalog change must include:
  - actor/change owner,
  - reason/ticket reference,
  - before/after diff,
  - approval evidence.
- Keep prior versions immutable for invoice replay/reconciliation.

## Operational defaults
- `API_USAGE_DEFAULT_PRICING_CATALOG_VERSION=v1`
- `API_USAGE_PRICING_MISSING_ROUTE_BEHAVIOR=default_route`

Recommended production posture: `default_route` or `error` (avoid silent unintended free usage).
