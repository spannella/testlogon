# GET /api/subscriptions 500 when subscriber holds any syndicate-bundle subscription

## Symptom
`GET /api/subscriptions` (and `GET /api/creators/{id}/subscriptions`) return **500
Internal Server Error** (`fastapi.exceptions.ResponseValidationError`) for any
subscriber who has ever subscribed to a **syndicate bundle**. The whole list
endpoint fails — the user cannot see ANY of their creator subscriptions.

## Root cause
`app/services/syndicate_subscriptions.subscribe_to_bundle()` writes a lightweight
subscriber-index row into the SAME single-table key space that the creator-plan
subscription endpoints read:

    pk = SUBSCRIBER#<user>   sk = SUB#<subscription_id>
    { subscription_id, plan_id, plan_type=syndicate_bundle, syndicate_id, status }

`list_subscriptions` in `app/routers/subscription_server.py` collects every
`SUB#` row under the subscriber pk, runs `normalize_subscription`, and returns
them as `response_model=List[SubscriptionOut]`. `SubscriptionOut` requires
`creator_id, subscriber_id, interval, provider, price_cents, currency, start_at,
current_period_end, cancel_at_period_end, created_at, updated_at` — none of which
the bundle index row carries. `normalize_subscription` short-circuits (returns the
row unchanged) whenever `auto_renew` is present, which the bundle row has, so the
missing fields are never filled → response validation raises → 500.

Syndicate bundles are a separate product with their own listing endpoint
(`GET /syndicates/{id}/subscriptions` via `BundleSubscriptionOut`), so they must
NOT be surfaced through the creator-subscription list.

## Fix
Exclude `plan_type == syndicate_bundle` rows in both `list_subscriptions` and
`list_creator_subscriptions` (`app/routers/subscription_server.py`). Pure additive
filter; creator subscriptions are unaffected. See
`subscriptions_syndicate_bundle_filter.patch` (string-anchored, applies cleanly).

## Prod-mirror status: PROD: APPLIED 2026-07-19
> PROD: APPLIED 2026-07-19 (SSM, i-08f937fc705ebea75). Pre-fix prod was UN-patched
> (single-line `subs=[...]`, no plan_type filter), NOT divergent. Anchored edit applied
> to both list endpoints. bak: `app/routers/subscription_server.py.bak_fs_subscriptions_syndicate_bundle_filter_20260719045927`.
> Verify: live `GET /api/subscriptions` (X-User-Id) 200; in-process list_subscriptions with a
> syndicate_bundle row -> 200, bundle row excluded (was ResponseValidationError 500). dev==prod.

Prod uses a single shared real-DynamoDB table, so any prod user with a syndicate
bundle subscription hits this 500 on their subscriptions page. The dev host (.249)
has no aws/SSM plugin; apply the .patch on prod (`/home/ubuntu/testlogon`) via SSM
from an AWS-credentialed machine, restart uvicorn, and re-verify:
`GET /api/subscriptions` for a bundle subscriber → 200 (bundle rows omitted).

## e2e impact
Unblocks catalog-subscriptions Section 61 (61.1 plan_id / 61.2 invoice-amount)
which read `GET /api/subscriptions` after a fresh subscribe.
