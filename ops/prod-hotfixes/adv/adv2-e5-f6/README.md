# ADV2-E5 (F6) — Advertiser direct mass-DM (ADV2-601..610)

Live prod hotfix (backend-only) building the F6 advertiser direct mass-DM on the
shared ad-messaging engine shipped in F5.

## What ships
- `app/services/ad_dm_audience.py` (NET-NEW, committed repo file) — advertiser-scoped
  audience resolution + D1 relationship gate + send-AS-advertiser (platform-100%)
  + send-time re-gate.
- `app/services/ad_messaging.py` (PATCHED) — the shared `_run_send` gains an
  optional `eligibility_fn` (send-time re-gate, ADV2-606). No-op for F5.
- `app/routers/ads.py` (APPENDED) — `/ui/ads/mass-dm/*` endpoints:
  `GET audience/preview`, `POST campaigns` (create+send), `GET campaigns`,
  `GET campaigns/{send_id}`, `POST campaigns/{send_id}/cancel`. The per-user ad
  opt-out (`/messages/ad-preferences`) and the open/click surcharge endpoints
  (`/messages/{ad_click_id}/open|click`) are SHARED with F5 (already live).

## Money-path
- Billing = the shared hybrid funnel-stack via `ad_messaging.charge_event` →
  `ad_billing._process_charge` (funds-guarded, idempotent `{ad_click_id}#{event}`):
  delivered 2c / open +5c / click +10c.
- F6 = PLATFORM-100%: `content_owner_sub=""` → `_split_revenue(creator_id="")`
  books everything to the platform (no creator credit).
- D1 relationship gate: audience = followers ∪ active-subscribers (enumerated via
  GSI5 followers; subscriber-only enumeration deferred to DEC-2), each RE-VERIFIED
  at resolve AND at send, MINUS per-user ad opt-outs. A non-relationship or
  opted-out user is never delivered to (0 charge).
- Funds-guard: insufficient balance stops the send; balance never goes negative.

## Apply (idempotent, marker-guarded)
```
ROOT=/path/to/testlogon python3 apply_adv2e6f6.py   # AMSG_PATCH + APPEND + PYCOMPILE_OK
```

## Verify (in-process on prod DDB via SSM)
```
.venv/bin/python verify_adv2e6f6.py                 # OVERALL ALL_PASS
```

## Backups
- `.bak_adv2e6f6_<ts>` on `app/services/ad_messaging.py` (patched) and
  `app/routers/ads.py` (appended). `ad_dm_audience.py` is net-new (no backup).
