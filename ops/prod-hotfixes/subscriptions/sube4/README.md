# SUB-E4 — Creator subscriber management + MRR/analytics (backend)

LIVE PROD HOTFIX (SSM) + dev-clone mirror. Appends two owner-scoped endpoints to
`app/routers/subscription_server.py` (anchored idempotent patch, appended at EOF).

## Endpoints (header auth `X-User-Id`; owner-scoped, admin/root may see any)

### E4-1 — `GET /api/creators/{creator_id}/subscribers`
Subscriber list off the CREATOR#SUB# index (one CREATOR# partition read).
- Query: `status` (active|trialing|past_due|canceled; canceled maps to
  canceled/expired/canceling), `limit` (1..200, default 50), `cursor` (opaque).
- Per-sub: subscription_id, subscriber_id, subscriber_name + subscriber_profile,
  plan_id, plan_name (tier), status, interval, price_cents, currency,
  since (=start_at), current_period_end, next_billing_date, cancel_at_period_end,
  auto_renew, is_gift, gifter_id, is_trial.
- Response: {creator_id, status_filter, count, total, next_cursor, subscribers[]}.
- 401 no X-User-Id; 403 if caller is neither the creator nor a platform admin.

### E4-2 — `GET /api/creators/{creator_id}/subscription-analytics`
MRR/analytics computed from the real subscription records + creator ledger.
- Query: `period_days` (1..365, default 30).
- Response: active_subscribers, trialing, past_due, canceled_total,
  total_subscribers, mrr_cents (= sum monthly-equivalent GROSS of ACTIVE
  non-trial subs; year plans price/12), arpu_cents (=MRR/active),
  new_subs_30d (start_at in window), churned_30d (canceled/expired in window),
  churn_rate (churned/(active+churned)), gross/fee/refunded/net revenue-to-date
  from the LEDGER# rows.

## Apply / verify
- `ROOT=<repo> python3 apply_sube4.py` (reads `sube4_block.py`, idempotent, py_compile).
- `python3 verify_sube4.py` in-process on prod DDB via SSM.

## Prod deploy
- `.bak_sube4_1783751805` on app/routers/subscription_server.py; restart openapi 200;
  routes `/api/creators/{creator_id}/subscribers` + `.../subscription-analytics` registered.
- Verify OVERALL_ALL_PASS (32/32): known mix 3 active month@1000 + 1 active year@12000
  + 1 trialing + 1 past_due + 1 canceled -> MRR 4000, active 4, trialing 1, past_due 1,
  ARPU 1000, churned 1, churn_rate 0.2, net revenue-to-date 3500; owner-scope isolation
  (creator B 403 on A; B sees only its own sub).

Reuses (unchanged): remove_subscriber, stop_subscriber_renewal, count_active_subscribers.
