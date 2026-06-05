# CREATOR-004: Affiliate Link System — Investigation & Implementation Write-up

## 1. Summary & Classification

**Type**: Feature — affiliate tracking, commission, frontend dashboard  
**Priority**: Medium-High | **Status**: Core implemented; settings endpoints and several frontend components missing  
**Area**: Creator monetisation — catalog, billing, commerce  
**Persona**: Creators who promote products (own or cross-creator) via external channels; product-owner creators who want to configure commission rates

CREATOR-004 introduces trackable short-link generation (`/r/{code}`), click recording, last-click conversion attribution via a cookie (`afl_ref`), commission ledger entries (debit product-owner / credit affiliate), and a creator-facing dashboard. The system follows patterns already established by the promo codes service (`app/services/promo_codes.py`) for creator-scoped code lookup and the tip ledger (`app/services/tip_ledger.py`) for paired billing entries.

Cross-references: CREATOR-003 (affiliate earnings category in dashboard), FIN-010 (affiliate earnings dashboard), SEC-004 (billing authz integrity), SECOPS-007 (no AWS dependency — all state in DynamoDB Local + billing table).

---

## 2. Current-State Investigation (what exists today)

### 2.1 DynamoDB tables

Both tables are defined in `scripts/local-ddb-init.py`:
- `AffiliateLinks` (line 990) — PK `link_id`, GSIs `ByAffiliate` (GSI1PK/SK), `ByCode` (GSI2PK/SK), `ByProduct` (GSI3PK/SK). `attr_types={"GSI1SK": "N", "GSI3SK": "N"}` correctly declared.
- `AffiliateClicks` (line 1001) — PK `link_id`, SK `click_id`, GSI `ByVisitor` (GSI1PK/SK). `attr_types={"GSI1SK": "N"}`.

Table handles registered in `app/core/tables.py:112–113` (`affiliate_links`, `affiliate_clicks`). Settings at `app/core/settings.py:1436–1441`: `affiliate_links_enabled`, `affiliate_default_commission_percent: int = 10`, `affiliate_max_commission_percent: int = 50`, `affiliate_cookie_duration_days: int = 30`, `affiliate_links_table_name`, `affiliate_clicks_table_name`.

### 2.2 Backend service layer

`app/services/affiliate_links.py` — fully implemented:
- `generate_tracking_code` (`:47`) — SHA256 prefix (3 chars) + 5 `secrets.choice` chars; retry loop up to 10 attempts
- `create_affiliate_link` (`:63`) — writes to `T.affiliate_links` with all GSI fields; validates `target_type` is in allowlist
- `get_link` (`:135`), `get_link_by_code` (`:141`), `list_creator_links` (`:152`), `delete_link` (`:162`)
- `record_click` (`:190`) — hashes `ip:ua:daily_salt` with SHA256, classifies UA (bot/mobile/desktop), checks `_is_first_visit` via ByVisitor GSI, writes to `T.affiliate_clicks`, atomically increments counters on link
- `record_conversion` (`:272`) — validates attribution window, prevents self-attribution, calculates `order_amount_cents * rate_bps // 10_000`, writes paired debit/credit to `T.billing`, increments link stats, marks click as converted
- `get_link_stats` (`:336`) — returns aggregated click/conversion/revenue/commission figures from the link record

### 2.3 Backend router

`app/routers/affiliate_links.py` — registered in `app/main.py:117,452`. Implements:
- `POST /ui/affiliates/links` (`:66`) — `require_ui_session`, calls `create_affiliate_link`
- `GET /ui/affiliates/links` (`:96`) — list creator's links
- `GET /ui/affiliates/links/{link_id}` (`:106`) — link detail
- `DELETE /ui/affiliates/links/{link_id}` (`:120`) — revoke (soft-delete, status→"revoked")
- `GET /ui/affiliates/links/{link_id}/stats` (`:133`) — stats
- `POST /ui/affiliates/links/{link_id}/conversions` (`:148`) — record a conversion (called from the order flow)
- `GET /r/{tracking_code}` (`:174`) — public redirect: record click, set `afl_ref` cookie (HttpOnly, Secure, SameSite=Lax, TTL from `attribution_window_seconds`), 302 redirect

### 2.4 Frontend

`frontend/src/App.tsx:78,189` — lazy import + `<Route path="affiliates" element={<AffiliateDashboard />} />` (plural, not singular).

`frontend/src/pages/affiliates/AffiliateDashboard.tsx` — 204-line all-in-one page. Contains inline create-link form, link list display, and basic stats. Imports from `frontend/src/api/endpoints/affiliates.ts`.

`frontend/src/api/endpoints/affiliates.ts` — wrapper functions for CRUD + stats endpoints.

### 2.5 What is missing vs. specification

#### Backend gaps

**Commission settings endpoints** — The ticket's section 4.3 specifies six endpoints under `/ui/affiliates/settings` (GET + PATCH global, PUT/DELETE per-product, PUT/DELETE per-affiliate). None of these exist in `app/routers/affiliate_links.py`. The `_get_affiliate_settings` helper is referenced inside `record_conversion` (`app/services/affiliate_links.py`) but the settings CRUD API is absent.

**Performance dashboard endpoints** — Section 4.4 specifies four read-only analytics endpoints (`/ui/affiliate/dashboard`, `/ui/affiliate/links/{id}/clicks`, `/ui/affiliate/links/{id}/conversions`, `/ui/affiliate/links/{id}/daily-stats`). None are implemented.

**Admin endpoints** — Section 4.5 (three admin endpoints under `/ui/admin/affiliate/`) are not implemented.

**Earnings classifier gap** — `app/services/creator_earnings.py:36` (`classify_entry`) has no `"affiliate"` branch. Affiliate commissions (reason `"Affiliate commission"`) fall into the `"other"` bucket. See CREATOR-003 gap analysis for the one-line fix.

**Order hook not wired** — `app/services/commerce_order_service.py` `create_order` (`:39`) does not read the `afl_ref` cookie or call `record_conversion`. The attribution chain is: redirect sets `afl_ref` cookie → checkout POST must forward tracking code → `create_conversion` endpoint must be called. Currently the order creation path does not extract the cookie at all.

#### Frontend gaps

Five components are absent (confirmed by search across `frontend/src/`):
- `AffiliateSettingsPanel` — no file, no import
- `ConversionLog` — no file, no import
- `ClickChart` — no file, no import
- `CopyLinkButton` — no separate component (copy may be inline in `AffiliateDashboard.tsx`)
- `QRCodeDisplay` — no file, no import
- `CommissionRateEditor` — no file, no import

The existing `AffiliateDashboard.tsx` is a functional MVP for link creation and listing, but the commission settings panel, time-series click chart, and conversion log are entirely absent.

---

## 3. Gap / Threat Analysis

### 3.1 Attribution chain is broken end-to-end

The complete conversion attribution flow requires four steps:
1. User clicks `/r/{code}` → redirect sets `afl_ref` cookie (**works**)
2. User proceeds to checkout; frontend sends `afl_ref` cookie value in the order request body or as a custom header (**not implemented** — the checkout router does not read the cookie)
3. Backend calls `record_conversion` on order completion (**endpoint exists** but not called from `create_order`)
4. Commission ledger entries written (**implemented** in `record_conversion`)

Steps 2 and 3 are the blocking gaps. Without them, no conversions are ever attributed regardless of clicks.

### 3.2 Settings storage format vs. code behaviour

The ticket's Section 3.8 describes settings stored under `pk="SETTINGS"` in `affiliate_links` table. The `_get_affiliate_settings` function (referenced in `record_conversion`) is not present in the actual `app/services/affiliate_links.py` file — the live code falls back to a hardcoded `default_commission_bps=1000`. This means per-product and per-affiliate rate overrides cannot work.

### 3.3 Cross-creator affiliate permission check missing

For Alice to create an affiliate link to Bob's product, the backend should verify that Bob's `affiliate_enabled` setting is `True`. This check is absent in `create_affiliate_link`. Any creator can generate a link to any product regardless of the product owner's preferences.

### 3.4 Security notes

- Self-attribution prevention exists (`record_conversion` rejects `buyer_user_id == affiliate_user_id`)
- Bot filtering exists (`user_agent_category != "bot"` in attribution query)
- IP hashing with daily salt prevents raw IP storage
- Open-redirect prevention is in the ticket spec (validate destination URL is platform-internal) but `record_click` in the actual service does not validate the destination — `_get_link_by_code` returns whatever `destination_url` was stored at link creation time

### 3.5 Refund clawback not implemented

The ticket section 8.5 describes commission reversal on refund. No refund hook exists in any billing service that touches `T.affiliate_links` or `T.affiliate_clicks`.

---

## 4. Proposed Design / Fix

### 4.1 Wire conversion attribution into order flow

In `app/routers/catalog.py` (or wherever the shopping cart checkout endpoint lives), extract the `afl_ref` cookie from the FastAPI `Request` object and pass it to the service layer:

```python
tracking_code = request.cookies.get("afl_ref")
if tracking_code:
    from app.services.affiliate_links import record_conversion
    record_conversion(
        tracking_code=tracking_code,
        order_id=order["order_id"],
        order_amount_cents=order["amount_cents"],
        buyer_user_id=user_id,
    )
```

This is a low-risk additive call because `record_conversion` already guards all failure paths with `try/except` and returns `None` on no-match.

### 4.2 Implement commission settings CRUD endpoints

Add to `app/routers/affiliate_links.py`:
- `GET /ui/affiliates/settings` — read from `T.affiliate_links` with `link_id="SETTINGS"` + `owner_id=user_id`
- `PATCH /ui/affiliates/settings` — partial update of `default_commission_bps`, `affiliate_enabled`, `default_attribution_window_seconds`
- `PUT /ui/affiliates/settings/products/{item_id}` — upsert product-level rate into `product_overrides` map
- `DELETE /ui/affiliates/settings/products/{item_id}` — remove product-level override

Add `_get_affiliate_settings(owner_id)` helper to `app/services/affiliate_links.py` that reads this record with a `get_item` call (not a query — the PK is deterministic: `"SETTINGS"`, not the owner ID). Update `record_conversion`'s rate resolution to call this helper.

### 4.3 Add cross-creator permission check

In `create_affiliate_link` (`app/services/affiliate_links.py:63`): if `product_owner_id != affiliate_user_id`, call `_get_affiliate_settings(product_owner_id)` and check `affiliate_enabled`. Return 403 if false.

### 4.4 Add performance dashboard endpoints

`GET /ui/affiliates/dashboard` — aggregate by querying the `ByAffiliate` GSI for all links, summing `click_count`, `unique_click_count`, `conversion_count`, `revenue_cents`, `commission_earned_cents`; compute overall conversion rate.

`GET /ui/affiliates/links/{id}/clicks` — query `T.affiliate_clicks` PK=`link_id`, paginated via `LastEvaluatedKey` cursor.

`GET /ui/affiliates/links/{id}/daily-stats` — not directly stored; requires scan of `T.affiliate_clicks` and bucketing by `clicked_at` date. Consider pre-aggregating on click write (increment a `DAILY#{date}` record), similar to how `analytics_rollups` work.

### 4.5 Dev/Prod parity (SECOPS-007)

No AWS dependencies. All state is in DynamoDB Local in dev, DynamoDB in prod. The `afl_ref` cookie is set with `secure=True` — in dev the Vite proxy serves over HTTP, so the cookie will be silently dropped by the browser's `Secure` flag enforcement. For dev testing, set `secure=False` when `S.dev_mode` is True (pattern matches the existing mock billing approach). Add a `dev_mode` guard in `affiliate_redirect`:

```python
response.set_cookie("afl_ref", ..., secure=not S.dev_mode, ...)
```

### 4.6 Fix earnings classifier

`app/services/creator_earnings.py:53` — add `if "affiliate" in reason: return "affiliate"` before `return "other"`.

---

## 5. Testing, Verification & Rollout

### 5.1 Existing E2E test coverage

`frontend/e2e/affiliate-links.spec.ts` — 363 lines, 12 `test(` calls across approximately the CRUD and click sections. The conversion attribution and commission settings sections are likely thin or absent given the backend gaps.

### 5.2 New pytest unit tests (`tests/test_affiliate_links.py`)

| Test case | Assertion |
|---|---|
| `test_create_link_tracking_code_format` | `len(code) == 8`, all alphanum, prefix matches user SHA256 |
| `test_record_click_bot_not_attributed` | click `user_agent_category == "bot"`, `record_conversion` returns None |
| `test_record_conversion_within_window` | commission > 0, two billing entries written (debit + credit) |
| `test_record_conversion_expired_window` | `clicked_at = now - window - 1`, returns None |
| `test_record_conversion_self_attribution` | buyer == affiliate, returns None |
| `test_commission_settings_crud` | GET returns defaults, PATCH updates `default_commission_bps`, persists |
| `test_cross_creator_permission_denied` | `affiliate_enabled=False` on product owner → 403 on link create |
| `test_earnings_classifier_affiliate` | `classify_entry({"reason":"Affiliate commission"}) == "affiliate"` |
| `test_afl_cookie_not_secure_in_dev_mode` | cookie `secure=False` when `S.dev_mode=True` |

All tests run with `moto.mock_dynamodb` — no AWS dependency.

### 5.3 Playwright E2E additions

Add to `frontend/e2e/affiliate-links.spec.ts` section 3 (Conversion Attribution):
- Simulate checkout POST that includes `tracking_code` (extracted from cookie), assert conversion attributed
- Assert Alice's billing ledger has `type=credit, reason="Affiliate commission"`

Section 4 (Commission Settings):
- Alice patches settings to `default_commission_bps: 1500`
- Creates link, triggers conversion, verifies `commission_cents == order_cents * 0.15`

### 5.4 Manual QA

1. Navigate to `/affiliates`
2. Create a link to a catalog item
3. Visit `/r/{code}` directly — verify 302 redirect and `afl_ref` cookie in browser DevTools (note: cookie will not be set in dev unless `secure=False` guard is added)
4. Complete a checkout while `afl_ref` cookie is present
5. Check Alice's earnings in `/creator-dashboard` — affiliate category should appear

### 5.5 Effort estimate

- Wire conversion attribution into order flow: **S** (2 hours)
- Commission settings CRUD endpoints: **M** (1 day)
- Performance dashboard endpoints: **M** (1 day, includes daily-stats aggregation design decision)
- Frontend settings panel + click chart + conversion log: **L** (3–5 days)
- Refund clawback: **M** (1 day)
- Cookie `secure=False` in dev: **S** (30 minutes)

**Rollback**: Feature flag `AFFILIATE_LINKS_ENABLED=false` in `.env.local` disables `_require_enabled()` check at router entry. All DDB writes are to dedicated tables; no existing table schema is modified.
