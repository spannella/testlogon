# FIN-003: Cart Abandonment Reminders

**Ticket**: FIN-003
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-003 extends the existing cart abandonment infrastructure with configurable multi-stage reminders, email notifications with recovery links, an admin configuration UI, and abandonment analytics. The backend already has a background scan loop (`_cart_abandonment_loop` in `shoppingcart.py`), cart TTL (`cart_ttl_days`), `scan_abandoned_carts`, and `send_cart_reminder` -- but the reminders only write alert records, the timing is limited to a single `threshold_hours` + `cooldown_hours` pattern, there is no email delivery with a recovery link, and there is no admin UI for configuration or analytics. This ticket fills those gaps with a complete cart recovery system.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Consumer | As a buyer, I want a reminder email when I leave items in my cart. | Email sent at configured intervals (e.g., 1h, 24h, 48h) with cart summary and recovery link. |
| Consumer | As a buyer, I want the recovery link to restore my cart with all items. | Clicking the recovery link opens the cart page with items intact (not expired). |
| Consumer | As a buyer, I want to opt out of cart reminders. | User preferences include a "cart reminders" toggle; opted-out users receive no emails. |
| Admin | As an admin, I want to configure reminder timing and message templates. | Admin UI with fields: enable/disable reminders, interval schedule, max reminders, email subject/body templates. |
| Admin | As an admin, I want to see cart abandonment analytics. | Dashboard shows: total abandoned carts, recovery rate, average cart value, reminders sent. |
| System | As the platform, I want expired carts to be cleaned up automatically. | Carts past TTL are soft-deleted (status set to "expired"); items remain for recovery within a grace period. |
| System | As the platform, I want to avoid spamming users with reminders. | Per-user cooldown between reminders; max reminders cap; opted-out users excluded. |

### 1.3 Why This Is Needed

Cart abandonment is a major revenue loss vector in e-commerce. The platform already tracks cart last-activity timestamps and has a background scan loop, but the loop only writes internal alerts -- no email is sent, there is no recovery link, timing is rigid, and admins cannot tune behavior without environment variable changes and backend restarts. A proper multi-stage reminder system with email delivery, recovery URLs, and admin controls is standard for e-commerce platforms and directly recovers revenue.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Cart TTL | `app/services/shoppingcart.py:68-75` | `_touch_cart_activity` sets `ttl` epoch on cart records; DynamoDB TTL deletes expired carts |
| Cart settings | `app/core/settings.py:742-746` | `cart_abandonment_enabled`, `cart_abandonment_threshold_hours=24`, `cart_abandonment_scan_interval_sec=300`, `cart_abandonment_max_reminders=2`, `cart_abandonment_reminder_cooldown_hours=48` |
<!-- VERIFIED: app/core/settings.py:742 — cart_abandonment_enabled; :743 — threshold_hours; :744 — scan_interval_sec; :745 — max_reminders; :746 — reminder_cooldown_hours -->
| Abandoned cart scan | `app/services/shoppingcart.py:709` | `scan_abandoned_carts(threshold_hours)` -- scans all carts |
<!-- VERIFIED: app/services/shoppingcart.py:709 — scan_abandoned_carts; :741 — send_cart_reminder; :52 — _cart_from_item -->
| Send reminder | `app/services/shoppingcart.py:741` | `send_cart_reminder(cart)` -- writes alert record |
| Background loop | `app/routers/shoppingcart.py:227` | `_cart_abandonment_loop()` |
<!-- VERIFIED: app/routers/shoppingcart.py:227 — _cart_abandonment_loop; :249 — start_cart_abandonment_task; :205 — stats; :210 — scan -->
| Cart start task | `app/routers/shoppingcart.py:249` | `start_cart_abandonment_task()` |
| Admin stats endpoint | `app/routers/shoppingcart.py:205` | `GET /admin/cart-abandonment/stats` |
| Admin scan endpoint | `app/routers/shoppingcart.py:210` | `POST /admin/cart-abandonment/scan` |
| Cart fields | `app/services/shoppingcart.py:52` | `_cart_from_item` extracts cart fields |
| SES email | `app/services/alerts.py:473` | `ses.send_email` for email delivery |
| Alert service | `app/services/alerts.py` | `write_alert` for in-app notifications |

### 2.2 Gaps

1. **No email delivery** -- `send_cart_reminder` writes an alert record but does not send an email.
2. **No recovery link** -- reminders contain no URL for the user to return to their cart.
3. **No multi-stage scheduling** -- only a single threshold + cooldown pattern; no separate timing for 1st, 2nd, 3rd reminders.
4. **No email templates** -- no configurable subject/body for reminder emails.
5. **No user opt-out** -- no preference to disable cart reminders.
6. **No admin configuration UI** -- all settings are environment variables requiring backend restart.
7. **No cart recovery tracking** -- no way to measure if a reminder led to a completed purchase.
8. **No grace period after TTL** -- DynamoDB TTL deletes carts permanently; no soft-expiry for recovery.
9. **Limited analytics** -- `get_abandonment_stats` returns basic counts but no conversion/recovery metrics.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Cart Reminder Config Table

**Table name**: `cart_reminder_config` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CONFIG` | `GLOBAL` | Global reminder settings | `enabled` (bool), `stages` (list of `{delay_hours, email_subject, email_body_template}`), `max_reminders` (N), `from_email` (S) |
| `OPTOUT` | `USER#{user_sub}` | User opt-out record | `user_sub`, `opted_out_at` |
| `RECOVERY` | `TOKEN#{token}` | Recovery link token | `user_sub`, `cart_id`, `created_at`, `ttl` (epoch, 7-day expiry) |

#### 3.1.2 Shopping Cart Table Additions

Add fields to existing cart records in `shopping_cart` table:

| New Field | Type | Purpose |
|-----------|------|---------|
| `reminder_stage` | N | Current reminder stage (0 = none, 1 = first, 2 = second, etc.) |
| `recovery_token` | S | Unique token for cart recovery URL |
| `recovered_at` | N | Timestamp if cart was recovered via reminder link |
| `reminder_history` | L | List of `{stage, sent_at, channel}` records |

#### 3.1.3 TableDef Entry

```python
TableDef(
    "cart_reminder_config", "pk", "sk",
),
```

#### 3.1.4 Example DynamoDB Items

**Global config**:
```json
{
  "pk": "CONFIG",
  "sk": "GLOBAL",
  "enabled": true,
  "stages": [
    {"delay_hours": 1, "email_subject": "You left items in your cart!", "email_body_template": "Hi {buyer_name}, you have {item_count} items worth ${total} in your cart. {recovery_url}"},
    {"delay_hours": 24, "email_subject": "Your cart is waiting", "email_body_template": "Hi {buyer_name}, don't forget about your {item_count} items. {recovery_url}"},
    {"delay_hours": 48, "email_subject": "Last chance - your cart expires soon", "email_body_template": "Hi {buyer_name}, your cart with {item_count} items will expire soon. {recovery_url}"}
  ],
  "max_reminders": 3,
  "from_email": "noreply@platform.local"
}
```

**Recovery token**:
```json
{
  "pk": "RECOVERY",
  "sk": "TOKEN#abc123def456",
  "user_sub": "alice@test.local",
  "cart_id": "cart_xyz",
  "created_at": 1748520100,
  "ttl": 1749124900
}
```

**User opt-out**:
```json
{
  "pk": "OPTOUT",
  "sk": "USER#alice@test.local",
  "user_sub": "alice@test.local",
  "opted_out_at": 1748520000
}
```

### 3.2 Multi-Stage Reminder Logic

#### 3.2.1 Stage Progression

The background loop processes abandoned carts in stages:

```python
def process_abandoned_carts() -> Dict[str, int]:
    """Scan and process abandoned carts through multi-stage reminders."""
    config = get_reminder_config()
    if not config.get("enabled", False):
        return {"processed": 0}

    stages = config.get("stages", [])
    carts = scan_all_open_carts()
    now = now_ts()
    sent = 0

    for cart in carts:
        last_activity = cart.get("last_activity_at", 0)
        current_stage = cart.get("reminder_stage", 0)
        user_sub = cart["user_sub"]

        # Skip opted-out users
        if is_user_opted_out(user_sub):
            continue

        # Skip if max reminders reached
        if current_stage >= len(stages):
            continue

        # Check if enough time has elapsed for the next stage
        stage = stages[current_stage]
        delay_seconds = stage["delay_hours"] * 3600
        target_time = last_activity + delay_seconds

        if now < target_time:
            continue

        # Send reminder for this stage
        send_stage_reminder(cart, stage, current_stage)
        sent += 1

    return {"processed": sent}
```

#### 3.2.2 Recovery Link Generation

Each reminder email includes a unique recovery URL:

```python
def generate_recovery_link(user_sub: str, cart_id: str) -> str:
    token = uuid4().hex
    T.cart_reminder_config.put_item(Item={
        "pk": "RECOVERY",
        "sk": f"TOKEN#{token}",
        "user_sub": user_sub,
        "cart_id": cart_id,
        "created_at": now_ts(),
        "ttl": now_ts() + (7 * 86400),  # 7-day expiry
    })
    return f"{S.frontend_base_url}/cart/recover/{token}"
```

### 3.3 Backend Service

**New file**: `app/services/cart_reminders.py` (~300 lines)

```python
"""Cart abandonment reminders and recovery (FIN-003)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def get_reminder_config() -> Dict[str, Any]:
    """Get global reminder configuration."""


def update_reminder_config(
    *,
    enabled: Optional[bool] = None,
    stages: Optional[List[Dict[str, Any]]] = None,
    max_reminders: Optional[int] = None,
    from_email: Optional[str] = None,
) -> Dict[str, Any]:
    """Update global reminder configuration (admin only)."""


def is_user_opted_out(user_sub: str) -> bool:
    """Check if user has opted out of cart reminders."""


def set_user_opt_out(user_sub: str, opt_out: bool) -> None:
    """Set or clear user opt-out preference."""


def process_abandoned_carts() -> Dict[str, int]:
    """Process all abandoned carts through multi-stage reminders."""


def send_stage_reminder(
    cart: Dict[str, Any],
    stage: Dict[str, Any],
    stage_index: int,
) -> None:
    """Send a reminder for a specific stage (alert + email)."""


def generate_recovery_link(user_sub: str, cart_id: str) -> str:
    """Generate a recovery token and URL."""


def recover_cart(token: str) -> Optional[Dict[str, Any]]:
    """Validate recovery token, return cart details, mark as recovered."""


def get_abandonment_analytics() -> Dict[str, Any]:
    """Extended analytics: total abandoned, recovered, recovery rate, avg value."""
```

### 3.4 Backend Router

**Modify**: `app/routers/shoppingcart.py` (add endpoints to existing router)

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/shoppingcart/reminders/preferences` | `require_ui_session` | Get user's reminder opt-out status |
| `PUT` | `/ui/shoppingcart/reminders/preferences` | `require_ui_session` | Set user's reminder opt-out preference |
| `GET` | `/ui/shoppingcart/recover/{token}` | None (public) | Validate recovery token, redirect to cart |
| `GET` | `/ui/shoppingcart/admin/reminders/config` | `require_admin_session` | Get global reminder config |
| `PUT` | `/ui/shoppingcart/admin/reminders/config` | `require_admin_session` | Update global reminder config |
| `GET` | `/ui/shoppingcart/admin/reminders/analytics` | `require_admin_session` | Get abandonment analytics |
| `POST` | `/ui/shoppingcart/admin/reminders/test` | `require_admin_session` | Send test reminder email to admin |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Cart Abandonment Reminders (FIN-003) --

class ReminderStageConfig(BaseModel):
    delay_hours: int = Field(ge=1)
    email_subject: str
    email_body_template: str

class ReminderConfigOut(BaseModel):
    enabled: bool = True
    stages: List[ReminderStageConfig] = Field(default_factory=list)
    max_reminders: int = 3
    from_email: str = ""

class ReminderConfigUpdateIn(BaseModel):
    enabled: Optional[bool] = None
    stages: Optional[List[ReminderStageConfig]] = None
    max_reminders: Optional[int] = Field(None, ge=1, le=10)
    from_email: Optional[str] = None

class ReminderPreferencesOut(BaseModel):
    opted_out: bool = False

class ReminderPreferencesIn(BaseModel):
    opted_out: bool

class CartRecoveryOut(BaseModel):
    valid: bool
    cart_id: Optional[str] = None
    item_count: int = 0
    total_cents: int = 0
    redirect_url: str = ""

class AbandonmentAnalyticsOut(BaseModel):
    total_carts_created: int = 0
    total_abandoned: int = 0
    total_recovered: int = 0
    recovery_rate_pct: float = 0.0
    total_reminders_sent: int = 0
    avg_abandoned_cart_value_cents: int = 0
    avg_time_to_recovery_hours: float = 0.0
    period_days: int = 30
```

### 3.7 Email Template Rendering

Templates use simple `{variable}` substitution:

| Variable | Description |
|----------|-------------|
| `{buyer_name}` | User's display name from profile |
| `{item_count}` | Number of items in cart |
| `{total}` | Cart total formatted as "$XX.XX" |
| `{items_summary}` | Comma-separated list of item names (max 3, then "and N more") |
| `{recovery_url}` | Unique recovery link |
| `{cart_expiry}` | Human-readable cart expiration date |

### 3.8 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/shop/CartRecoveryPage.tsx` | Recovery landing page (validates token, redirects to cart) | ~100 |
| `frontend/src/pages/settings/CartReminderPrefs.tsx` | User opt-out toggle (embedded in notification preferences) | ~60 |
| `frontend/src/pages/admin/CartReminderAdmin.tsx` | Admin config + analytics dashboard | ~250 |
| `frontend/src/api/endpoints/cartReminders.ts` | API wrappers | ~70 |

**CartRecoveryPage flow**:

```
User clicks recovery link → /cart/recover/{token}
  → Page loads, calls GET /ui/shoppingcart/recover/{token}
  → If valid: shows "Restoring your cart..." → redirects to /cart?cartId={cart_id}
  → If invalid/expired: shows "This recovery link has expired" + "Browse Shop" button
```

**Admin config UI**:

```
CartReminderAdmin
├── Toggle: "Enable cart abandonment reminders"
├── Reminder stages editor
│   ├── Stage 1: delay (hours input), subject (text input), body (textarea)
│   ├── Stage 2: ...
│   ├── Stage 3: ...
│   ├── "Add stage" button
│   └── "Remove" button per stage
├── Max reminders input
├── From email input
├── "Send Test Email" button
├── "Save Configuration" button
└── Analytics cards
    ├── Total Abandoned (count)
    ├── Total Recovered (count)
    ├── Recovery Rate (percentage)
    ├── Avg Cart Value (dollars)
    └── Reminders Sent (count)
```

### 3.9 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/cart/recover/:token" element={<CartRecoveryPage />} />
```

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/cart_reminders.py` | Reminder config, processing, recovery | ~300 |
| `frontend/src/pages/shop/CartRecoveryPage.tsx` | Recovery landing page | ~100 |
| `frontend/src/pages/settings/CartReminderPrefs.tsx` | User opt-out toggle | ~60 |
| `frontend/src/pages/admin/CartReminderAdmin.tsx` | Admin config + analytics | ~250 |
| `frontend/src/api/endpoints/cartReminders.ts` | API wrappers | ~70 |
| `frontend/e2e/cart-reminders.spec.ts` | E2E tests | ~500 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | No change needed (endpoints added to existing shopping cart router) |
| `app/models.py` | Add reminder config, preferences, recovery, analytics models |
| `app/core/settings.py` | Add `cart_reminder_config_table_name`, `frontend_base_url` settings |
| `app/core/tables.py` | Add `T.cart_reminder_config` table handle |
| `scripts/local-ddb-init.py` | Add `cart_reminder_config` TableDef |
| `app/routers/shoppingcart.py` | Add reminder/recovery/analytics endpoints; update `_cart_abandonment_loop` to call `process_abandoned_carts` |
| `app/services/shoppingcart.py` | Add `reminder_stage`, `recovery_token`, `recovered_at`, `reminder_history` to `_cart_from_item`; update `send_cart_reminder` to use new stage logic |
| `frontend/src/api/types.ts` | Add reminder TypeScript interfaces |
| `frontend/src/App.tsx` | Add recovery route |

---

## 4. Background Processing

### 4.1 Updated Loop

Replace the existing `_cart_abandonment_loop` with a call to `process_abandoned_carts`:

```python
async def _cart_abandonment_loop() -> None:
    """Background loop: process abandoned carts through reminder stages."""
    while True:
        await asyncio.sleep(S.cart_abandonment_scan_interval_sec)
        if not S.cart_abandonment_enabled:
            continue
        try:
            result = process_abandoned_carts()
            if result["processed"] > 0:
                logger.info("Cart reminders sent: %d", result["processed"])
        except Exception:
            logger.exception("Cart abandonment processing failed")
```

### 4.2 Recovery Tracking

When a user accesses their cart via a recovery link, the system marks the cart as recovered:

1. Validate recovery token (exists, not expired, user matches).
2. Touch cart activity to refresh TTL.
3. Set `recovered_at = now_ts()` on the cart record.
4. Delete the recovery token (one-time use).
5. Increment `total_recovered` counter in analytics.

### 4.3 Cart Expiration Grace Period

Currently, DynamoDB TTL hard-deletes carts. To support recovery after TTL:

1. On TTL trigger, set `status = "expired"` instead of relying on DynamoDB TTL deletion.
2. Add a separate `hard_ttl` field set to `ttl + 7 days` for actual DynamoDB TTL deletion.
3. During the 7-day grace period, the cart is "expired" but recoverable via recovery link.
4. After `hard_ttl`, DynamoDB deletes the cart permanently.

---

## 4b. API Request/Response Examples

**Get user reminder preferences** (curl):

```bash
curl -X GET http://localhost:8000/ui/shoppingcart/reminders/preferences \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{"opted_out": false}
```

**Recover cart via token** (curl):

```bash
curl -X GET "http://localhost:8000/ui/shoppingcart/recover/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
```

**Response (200)**:
```json
{
  "valid": true,
  "cart_id": "cart_xyz789",
  "item_count": 3,
  "total_cents": 4500,
  "redirect_url": "/cart?cartId=cart_xyz789"
}
```

**Admin get analytics** (curl):

```bash
curl -X GET "http://localhost:8000/ui/shoppingcart/admin/reminders/analytics?period_days=30" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_r; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "total_abandoned": 142,
  "total_recovered": 23,
  "recovery_rate_pct": 16.2,
  "avg_abandoned_value_cents": 3200,
  "total_recovered_value_cents": 73600
}
```

---

## 5. E2E Test Plan

**File**: `frontend/e2e/cart-reminders.spec.ts`

### Section 547: Cart Reminder Configuration API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 547.1 | Admin can read default reminder config | Root GET `/ui/shoppingcart/admin/reminders/config`; response has `enabled: true`, `stages` array with default entries. |
| 547.2 | Admin can update reminder config | Root PUT with `stages: [{delay_hours: 2, ...}]`; subsequent GET returns updated config. |
| 547.3 | Non-admin cannot access config endpoint | Alice GET `/ui/shoppingcart/admin/reminders/config`; 403. |
| 547.4 | Invalid stage config rejected | Root PUT with `stages: [{delay_hours: 0, ...}]`; 422 (delay_hours must be >= 1). |

### Section 548: User Reminder Preferences API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 548.1 | User reads default preference (not opted out) | Alice GET `/ui/shoppingcart/reminders/preferences`; response `opted_out: false`. |
| 548.2 | User opts out of reminders | Alice PUT `{opted_out: true}`; subsequent GET returns `opted_out: true`. |
| 548.3 | Opted-out user does not receive reminders | Alice opts out. Alice has abandoned cart. Trigger scan. No reminder alert created for Alice. |

### Section 549: Cart Recovery API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 549.1 | Recovery token resolves to correct cart | Generate recovery link for Alice's cart. GET `/ui/shoppingcart/recover/{token}`; response: `valid: true`, `cart_id` matches, `item_count > 0`. |
| 549.2 | Expired recovery token returns invalid | Create token with past TTL. GET returns `valid: false`. |
| 549.3 | Used recovery token cannot be reused | GET recovery token once (success). GET same token again; `valid: false`. |
| 549.4 | Recovery refreshes cart TTL | After recovery, cart `last_activity_at` is updated; cart is no longer considered abandoned. |

### Section 550: Abandonment Analytics API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 550.1 | Analytics returns counts | Root GET `/ui/shoppingcart/admin/reminders/analytics`; response has `total_abandoned >= 0`, `total_recovered >= 0`, `recovery_rate_pct`. |
| 550.2 | Recovery increments recovered count | Before: note `total_recovered`. Recover a cart. After: `total_recovered` incremented by 1. |
| 550.3 | Manual scan trigger returns results | Root POST `/admin/cart-abandonment/scan`; response includes count of processed carts. |
| 550.4 | Analytics period filter works | GET with `period_days=7`; results scoped to last 7 days. |

### Section 551: Reminder Edge Cases & Concurrent Access (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 551.1 | No reminder for purchased cart | Alice purchases cart; trigger scan; no reminder created for that cart |
| 551.2 | No reminder for user who opted out | Alice opts out; abandons cart; trigger scan; no reminder email |
| 551.3 | Multiple carts abandoned by same user | Alice has 2 abandoned carts; each gets independent reminder chain |
| 551.4 | Cart recovery after 2nd stage reminder | Alice ignores 1st reminder, recovers on 2nd; analytics shows stage=2 recovery |
| 551.5 | Recovery link in email is valid URL | Extract recovery URL from reminder alert; parse URL; token is 32-char hex |

### Section 552: Reminder UI Preferences (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 552.1 | Preferences page shows opt-out toggle | Navigate to settings; cart reminders toggle visible |
| 552.2 | Toggling opt-out updates preference | Click toggle to opt out; reload; toggle reflects opted_out=true |
| 552.3 | Admin config page shows stages | Root navigates to admin reminders; stage table with delay, subject, template visible |

**Total E2E tests: 23**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Reminder preferences | `require_ui_session` | Only own preferences |
| Cart recovery | None (public, token-based) | Token validates user identity |
| Admin config | `require_admin_session` | Admin or root role |
| Admin analytics | `require_admin_session` | Admin or root role |

### 6.2 Recovery Token Security

- Tokens are 32-character hex strings (128 bits of entropy) -- not guessable.
- Tokens expire after 7 days (DynamoDB TTL).
- Tokens are single-use (deleted after successful recovery).
- Recovery endpoint does not require authentication (token IS the credential), but the recovered cart is only accessible to the original user after login.
- Recovery link redirects to `/cart?cartId={id}`, which requires `require_ui_session` -- unauthenticated users will hit the login page first.

### 6.3 Email Rate Limiting

- Maximum 3 reminder emails per cart (configurable `max_reminders`).
- Minimum 1-hour delay between stages (validated in config update).
- Per-user cooldown: no more than 5 reminder emails per 24 hours across all carts.
- Test email: max 3 per admin per hour.

### 6.4 Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Recovery token not found | 404 | `token_not_found` | "Recovery link not found" | Request new link from email |
| Recovery token expired | 410 | `token_expired` | "This recovery link has expired" | Request new link |
| Recovery token already used | 410 | `token_used` | "This recovery link has already been used" | Cart should be in account |
| Cart already purchased | 409 | `cart_purchased` | "This cart has already been purchased" | No action needed |
| Cart permanently deleted | 410 | `cart_deleted` | "This cart is no longer available" | Start new cart |
| User opted out | N/A | — | No email sent | Opt back in via preferences |
| Admin config invalid stage | 422 | `validation_error` | "delay_hours must be >= 1" | Fix config values |
| Non-admin access to config | 403 | `forbidden` | "Admin access required" | Use admin account |
| Email delivery failure | 500 | `email_failed` | (No user-facing; logged) | Retry on next scan |

---

## 7. Observability

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cart_abandoned_total` | Counter | — | Carts detected as abandoned |
| `cart_reminder_sent_total` | Counter | `stage` (1/2/3) | Reminder emails sent |
| `cart_recovered_total` | Counter | `stage` | Carts recovered via recovery link |
| `cart_recovery_latency_hours` | Histogram | — | Time from abandonment to recovery |
| `cart_reminder_email_failed_total` | Counter | — | Email delivery failures |
| `cart_abandoned_value_cents` | Histogram | — | Value of abandoned carts |
| `cart_scan_duration_ms` | Histogram | — | Duration of abandonment scan job |

### 7.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Cart abandoned detected | INFO | `cart_id`, `user_sub`, `item_count`, `total_cents`, `hours_since_activity` |
| Reminder email sent | INFO | `cart_id`, `user_sub`, `stage`, `email_address` |
| Cart recovered | INFO | `cart_id`, `user_sub`, `recovery_token`, `hours_since_abandonment` |
| Recovery token expired | DEBUG | `token`, `expired_at` |
| User opted out of reminders | INFO | `user_sub` |
| Scan job completed | INFO | `carts_scanned`, `reminders_sent`, `duration_ms` |

### 7.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Reminder email failure rate | > 10% of sends fail | High | Check SES configuration |
| Recovery rate drop | Recovery rate drops below 5% for 3 days | Medium | Review email content/timing |
| Scan job timeout | Scan takes > 5 minutes | Medium | Check DDB throughput |
| High abandonment rate | > 50% of carts abandoned in 24h | Low | Review checkout UX |

### 7.4 Dashboard Queries

**Recovery funnel**:
```promql
sum(rate(cart_recovered_total[1d])) / sum(rate(cart_abandoned_total[1d])) * 100
```

**Average cart value recovered**:
```promql
histogram_quantile(0.5, rate(cart_abandoned_value_cents_bucket[1d]))
```

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Abandonment scan latency | < 30s for 10K carts | DDB scan with page size 100; filter on `last_activity_at < threshold` |
| Email sending throughput | 10 emails/sec | SES batch sending; async within scan loop |
| Recovery token lookup | < 5ms | Direct GetItem on token PK |
| Cart recovery write | < 20ms | UpdateItem on cart + DeleteItem on token |
| Reminder config read | < 5ms | GetItem; cached in-memory for scan duration |
| Analytics query | < 200ms | Pre-computed aggregates in analytics DDB item; updated on each scan |

---

## 9. Rollout Plan

### 9.1 Feature Flag

```python
cart_reminders_enabled: bool = os.environ.get("CART_REMINDERS_ENABLED", "true").lower() == "true"
```

### 9.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy scan + email logic; flag OFF | 2 days | Unit tests pass |
| Phase 2: Internal | Enable for internal accounts; manually trigger scan | 3 days | Emails arrive; recovery works |
| Phase 3: Canary 10% | Enable auto-scan for 10% of users | 3 days | Recovery rate > 5%; no email complaints |
| Phase 4: GA | Enable for all | Permanent | Positive revenue recovery signal |

### 9.3 Rollback

1. Set `CART_REMINDERS_ENABLED=false` — stops scan loop and email sending
2. Existing recovery tokens remain valid until TTL
3. Preferences and analytics data preserved
4. No impact on cart functionality

---

## 10. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/shoppingcart.py` | Exists (modify) | `scan_abandoned_carts`, `send_cart_reminder`, `_cart_from_item` |
| `app/routers/shoppingcart.py` | Exists (modify) | Existing admin stats/scan endpoints; `_cart_abandonment_loop` |
| `app/core/settings.py` | Exists (modify) | `cart_abandonment_*` settings already defined |
| `app/services/alerts.py` | Exists | `write_alert` for in-app notifications, `ses.send_email` for email |
| `app/services/profile.py` | Exists | Buyer display name and email for email templates |
| `app/auth/deps.py` | Exists | `require_ui_session`, `require_admin_session` |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `cart_reminder_config` table definition |

---

## 8. Acceptance Criteria

1. Multi-stage reminder schedule is configurable by admin (delay hours, subject, body template per stage).
2. Reminder emails include cart summary, item count, total value, and a unique recovery link.
3. Recovery links restore the user's cart and refresh the cart TTL.
4. Recovery tokens are single-use and expire after 7 days.
5. Users can opt out of cart reminder emails via preferences.
6. Opted-out users receive no reminder emails even when their carts are abandoned.
7. Abandonment analytics show total abandoned, recovered, recovery rate, and average cart value.
8. Cart expiration has a 7-day grace period before permanent deletion.
9. All 15 E2E tests pass.

---

## Codebase References

### Existing Files (verified)
| File | Key Functions | Lines |
|------|--------------|-------|
| `app/services/shoppingcart.py` | `_cart_from_item`, `scan_abandoned_carts`, `send_cart_reminder` | 52, 709, 741 |
| `app/routers/shoppingcart.py` | `_cart_abandonment_loop`, `start_cart_abandonment_task`, admin stats/scan | 227, 249, 205, 210 |
| `app/core/settings.py` | `cart_abandonment_*` settings | 742-746 |
| `app/main.py` | `app.add_event_handler("startup", start_cart_abandonment_task)` | 473 |
| `scripts/local-ddb-init.py` | `shopping_cart` table | 67 |

### Files to Create (new implementation)
| File | Purpose |
|------|---------|
| `app/services/cart_reminders.py` | Multi-stage reminder logic, email templates, recovery tokens |
| `cart_reminder_config` DDB table | Admin-configurable reminder schedule |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_cart_reminders.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_fin_003_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_fin_003_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_fin_003_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_fin_003_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_fin_003_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_fin_003_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_fin_003_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_fin_003_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/cart-reminders.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 10

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `CART_REMINDERS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `CART_REMINDERS_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `CART_REMINDERS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
