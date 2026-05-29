# FIN-005: Multi-Currency Display

**Ticket**: FIN-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Low
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-005 adds display-only multi-currency support across the platform. All financial processing remains in USD, but users can set a preferred display currency in their profile settings. Prices, totals, and billing amounts are shown in the user's preferred currency with an approximate conversion indicator ("~") and the original USD amount in smaller text. Exchange rates are fetched from an external API (or a static fallback table) and cached for 1-4 hours. The feature covers 10-15 major world currencies and is designed to be purely presentational -- no changes to billing, payment processing, or ledger storage.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Consumer | As a non-US user, I want to see prices in my local currency. | Setting preferred currency to EUR shows all prices prefixed with "~" in EUR with original USD below. |
| Consumer | As a user, I want to set my preferred currency in settings. | Profile settings page has a currency dropdown; selection persists across sessions. |
| Consumer | As a user, I want to know when exchange rates were last updated. | Tooltip or small text shows "Rates updated X minutes ago" near converted prices. |
| Consumer | As a user, I want to switch back to USD at any time. | Selecting "USD" removes conversion display; prices show as normal. |
| Consumer | As a user, I want accurate conversions on billing and shop pages. | Checkout total, billing history, wallet balance, tip amounts, and subscription prices all show converted amounts. |
| Admin | As an admin, I want to see current exchange rates and refresh them. | Admin endpoint returns current cached rates and supports manual refresh. |
| System | Exchange rate fetch failures should not break price display. | If rate fetch fails, last cached rates are used; if no cache exists, prices show in USD only with a "conversion unavailable" note. |

### 1.3 Why This Is Needed

All prices on the platform are displayed in USD regardless of the user's location. International users must mentally convert prices to understand costs, creating friction in purchase decisions. Adding display-only currency conversion is a low-risk, high-impact UX improvement: it requires no changes to payment processing, billing, or financial records, while making the platform feel native to international users. The "~" prefix and USD reference amount make it clear that conversion is approximate and that actual charges are in USD.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Profile settings | `app/services/profile.py` | User profile CRUD; can store `preferred_currency` field |
| Profile endpoint | `app/routers/profile.py` | `GET /ui/profile`, `PATCH /ui/profile` for reading/updating profile fields |
| Billing display | `frontend/src/pages/billing/` | Wallet balance, payment history, billing ledger -- all display `$` amounts |
| Shop checkout | `frontend/src/pages/shop/Checkout.tsx` | Cart totals, line items, promo discounts -- all USD |
| Subscription page | `frontend/src/pages/subscriptions/` | Plan prices -- all USD |
| Tip/unlock UI | `frontend/src/pages/messages/ComposeBar.tsx`, `MessageBubble.tsx` | Tip amounts, unlock prices -- all USD |
| Newsfeed unlock | `frontend/src/pages/feed/PostCard.tsx` | Post unlock prices -- all USD |
| Auth store | `frontend/src/stores/authStore.ts` | User session data; can include `preferred_currency` |
| Settings page | `frontend/src/pages/settings/` | Profile editing UI |

### 2.2 Gaps

1. **No currency preference** -- user profile has no `preferred_currency` field.
2. **No exchange rate service** -- no backend component fetches or caches exchange rates.
3. **No conversion utility** -- no frontend helper to convert cents to a target currency.
4. **No currency display component** -- all price displays are raw `$` formatting with hardcoded USD.
5. **No rate caching** -- no DynamoDB or in-memory cache for exchange rates.
6. **No supported currency list** -- no defined set of supported currencies with symbols and formatting rules.
7. **No admin rate management** -- no endpoint to view or refresh cached rates.

---

## 3. Technical Design

### 3.1 Supported Currencies

| Code | Name | Symbol | Decimal Places |
|------|------|--------|---------------|
| `USD` | US Dollar | $ | 2 |
| `EUR` | Euro | EUR | 2 |
| `GBP` | British Pound | GBP | 2 |
| `CAD` | Canadian Dollar | CA$ | 2 |
| `AUD` | Australian Dollar | A$ | 2 |
| `JPY` | Japanese Yen | JPY | 0 |
| `CHF` | Swiss Franc | CHF | 2 |
| `SEK` | Swedish Krona | SEK | 2 |
| `NOK` | Norwegian Krone | NOK | 2 |
| `DKK` | Danish Krone | DKK | 2 |
| `NZD` | New Zealand Dollar | NZ$ | 2 |
| `MXN` | Mexican Peso | MX$ | 2 |
| `BRL` | Brazilian Real | R$ | 2 |
| `INR` | Indian Rupee | INR | 2 |
| `PLN` | Polish Zloty | PLN | 2 |

### 3.2 DynamoDB Schema

#### 3.2.1 Exchange Rates Table

**Table name**: `exchange_rates` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `RATES` | `CURRENT` | Current cached exchange rates | `rates` (map: `{EUR: 0.92, GBP: 0.79, ...}`), `source` (S), `fetched_at` (N), `expires_at` (N) |
| `RATES` | `HISTORY#{timestamp}` | Historical rate snapshots (for audit) | Same fields as CURRENT |
| `STATIC` | `FALLBACK` | Static fallback rates (never expires) | `rates` map with conservative estimates |

No GSIs needed -- single-key lookups only.

#### 3.2.2 User Profile Addition

Add to existing profile record in the profiles/users table:

| New Field | Type | Default | Purpose |
|-----------|------|---------|---------|
| `preferred_currency` | S | `"USD"` | User's display currency preference |

#### 3.2.3 TableDef Entry

```python
TableDef(
    "exchange_rates", "pk", "sk",
),
```

#### 3.2.4 Example DynamoDB Items

**Current rates**:
```json
{
  "pk": "RATES",
  "sk": "CURRENT",
  "rates": {
    "EUR": "0.9200",
    "GBP": "0.7900",
    "CAD": "1.3600",
    "AUD": "1.5300",
    "JPY": "149.50",
    "CHF": "0.8800",
    "SEK": "10.45",
    "NOK": "10.80",
    "DKK": "6.87",
    "NZD": "1.6400",
    "MXN": "17.15",
    "BRL": "4.95",
    "INR": "83.20",
    "PLN": "3.98"
  },
  "source": "exchangerate-api.com",
  "fetched_at": 1748520100,
  "expires_at": 1748527300
}
```

**Static fallback**:
```json
{
  "pk": "STATIC",
  "sk": "FALLBACK",
  "rates": {
    "EUR": "0.9200",
    "GBP": "0.7900",
    "CAD": "1.3600",
    "JPY": "150.00"
  }
}
```

### 3.3 Exchange Rate Service

**New file**: `app/services/exchange_rates.py` (~250 lines)

```python
"""Exchange rate fetching and caching (FIN-005)."""

from __future__ import annotations
import logging
from decimal import Decimal
from typing import Any, Dict, Optional
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# In-memory cache for fast reads (refreshed from DDB)
_rate_cache: Optional[Dict[str, Any]] = None
_cache_expires_at: int = 0

SUPPORTED_CURRENCIES = [
    "USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF",
    "SEK", "NOK", "DKK", "NZD", "MXN", "BRL", "INR", "PLN",
]

RATE_TTL_SECONDS = 3600  # 1 hour default; configurable via settings


def get_current_rates() -> Dict[str, Any]:
    """Get current exchange rates. Uses in-memory cache, then DDB, then static fallback."""


def convert_usd_cents(amount_cents: int, target_currency: str) -> Dict[str, Any]:
    """Convert USD cents to target currency.

    Returns:
        {
            "original_cents": 500,
            "original_currency": "USD",
            "converted_amount": "4.60",
            "converted_currency": "EUR",
            "rate": "0.9200",
            "rate_updated_at": 1748520100,
            "approximate": true
        }
    """


def refresh_rates() -> Dict[str, Any]:
    """Fetch fresh rates from external API and update cache."""


def _fetch_from_external_api() -> Dict[str, str]:
    """Fetch rates from exchangerate-api.com (or mock in dev mode)."""


def _load_static_fallback() -> Dict[str, str]:
    """Load static fallback rates from DDB."""


def get_supported_currencies() -> list[Dict[str, str]]:
    """Return list of supported currencies with metadata."""
```

#### 3.3.1 Rate Fetch Strategy

```
get_current_rates():
  1. Check in-memory cache (_rate_cache, _cache_expires_at)
     → If valid: return cached rates
  2. Check DDB (RATES/CURRENT)
     → If valid (expires_at > now): update in-memory cache, return
  3. Try external API fetch
     → If success: write to DDB (CURRENT + HISTORY), update in-memory cache, return
  4. Fallback to DDB (STATIC/FALLBACK)
     → Return conservative estimates with "stale" flag
```

#### 3.3.2 Dev Mode

In dev mode (`S.dev_mode = True`), the external API fetch is replaced by a static rate table. No external HTTP calls are made. Rates are seeded from the `STATIC/FALLBACK` record at startup.

### 3.4 Backend Router

**New file**: `app/routers/exchange_rates.py` (~120 lines)

```python
"""Exchange rate endpoints (FIN-005)."""

from fastapi import APIRouter, Depends
from app.auth.deps import require_ui_session, require_admin_session

router = APIRouter(prefix="/ui/exchange-rates", tags=["exchange-rates"])
admin_router = APIRouter(prefix="/ui/admin/exchange-rates", tags=["exchange-rates-admin"])
```

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/exchange-rates` | `require_ui_session` | Get current rates + supported currencies |
| `GET` | `/ui/exchange-rates/convert` | `require_ui_session` | Convert amount (params: `amount_cents`, `target_currency`) |
| `GET` | `/ui/admin/exchange-rates` | `require_admin_session` | Admin: get rates with source and freshness details |
| `POST` | `/ui/admin/exchange-rates/refresh` | `require_admin_session` | Admin: force rate refresh from external API |

### 3.6 User Profile Currency Preference

**Modify**: `app/routers/profile.py` / `app/services/profile.py`

Add `preferred_currency` to the profile update endpoint. Validation: must be one of `SUPPORTED_CURRENCIES`.

```python
class ProfileUpdateIn(BaseModel):
    # ... existing fields ...
    preferred_currency: Optional[str] = None  # NEW: must be in SUPPORTED_CURRENCIES

# In profile update handler:
if body.preferred_currency:
    if body.preferred_currency not in SUPPORTED_CURRENCIES:
        raise HTTPException(422, "Unsupported currency")
    # Save to profile record
```

### 3.7 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Multi-Currency Display (FIN-005) --

class ExchangeRateOut(BaseModel):
    currency: str
    rate: str  # String to preserve decimal precision
    symbol: str = ""
    name: str = ""
    decimal_places: int = 2

class ExchangeRatesOut(BaseModel):
    rates: List[ExchangeRateOut] = Field(default_factory=list)
    source: str = ""
    fetched_at: int = 0
    expires_at: int = 0
    is_stale: bool = False

class CurrencyConversionOut(BaseModel):
    original_cents: int
    original_currency: str = "USD"
    converted_amount: str  # Formatted string e.g. "4.60"
    converted_currency: str
    rate: str
    rate_updated_at: int = 0
    approximate: bool = True

class SupportedCurrencyOut(BaseModel):
    code: str
    name: str
    symbol: str
    decimal_places: int = 2
```

### 3.8 Frontend Architecture

#### 3.8.1 Currency Context Provider

**New file**: `frontend/src/contexts/CurrencyContext.tsx` (~120 lines)

A React context that provides currency conversion to all components:

```typescript
interface CurrencyContextValue {
  preferredCurrency: string;  // "USD", "EUR", etc.
  rates: Record<string, number>;
  ratesUpdatedAt: number;
  isStale: boolean;
  convert: (usdCents: number) => ConvertedAmount;
  formatPrice: (usdCents: number) => string;
  setPreferredCurrency: (code: string) => void;
}

interface ConvertedAmount {
  original: string;       // "$5.00"
  converted: string;      // "~EUR4.60"
  rate: number;
  approximate: boolean;
}
```

The provider:
1. Reads `preferredCurrency` from user profile (authStore).
2. Fetches rates from `/ui/exchange-rates` on mount and every 30 minutes.
3. Provides `convert(usdCents)` and `formatPrice(usdCents)` to children.
4. If `preferredCurrency === "USD"`, all functions pass through (no conversion).

#### 3.8.2 CurrencyAmount Component

**New file**: `frontend/src/components/shared/CurrencyAmount.tsx` (~80 lines)

A drop-in replacement for raw price displays:

```typescript
interface CurrencyAmountProps {
  cents: number;
  className?: string;
  showOriginal?: boolean;  // default true: show USD below converted
  size?: "sm" | "md" | "lg";
}

// Renders:
// When preferred currency is EUR:
//   ~EUR4.60
//   $5.00 USD (small, muted text)
//
// When preferred currency is USD:
//   $5.00
```

#### 3.8.3 Currency Selector Component

**New file**: `frontend/src/components/shared/CurrencySelector.tsx` (~60 lines)

A dropdown for selecting preferred currency, used in Settings page:

```typescript
interface CurrencySelectorProps {
  value: string;
  onChange: (code: string) => void;
}

// Renders: Select dropdown with flag emoji + currency code + name
// e.g., "EUR - Euro", "GBP - British Pound", ...
```

#### 3.8.4 Integration Points

Replace raw `$` formatting with `<CurrencyAmount>` across all financial display surfaces:

| File | Change |
|------|--------|
| `frontend/src/pages/billing/WalletCard.tsx` | Wallet balance display |
| `frontend/src/pages/billing/BillingHistory.tsx` | Ledger entry amounts |
| `frontend/src/pages/shop/Cart.tsx` | Cart item prices, subtotal |
| `frontend/src/pages/shop/Checkout.tsx` | Order total, discount line |
| `frontend/src/pages/subscriptions/PlanCard.tsx` | Subscription plan prices |
| `frontend/src/pages/messages/ComposeBar.tsx` | Tip amount display |
| `frontend/src/pages/messages/MessageBubble.tsx` | Unlock price, tip badge |
| `frontend/src/pages/feed/PostCard.tsx` | Post unlock price, tip badge |
| `frontend/src/pages/billing/InvoicesPage.tsx` | Invoice amounts (from FIN-001) |

### 3.9 Frontend Routes

No new routes. Currency settings are embedded in the existing profile/settings page.

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/exchange_rates.py` | Rate fetching, caching, conversion | ~250 |
| `app/routers/exchange_rates.py` | REST API endpoints | ~120 |
| `frontend/src/contexts/CurrencyContext.tsx` | Currency context provider | ~120 |
| `frontend/src/components/shared/CurrencyAmount.tsx` | Price display component | ~80 |
| `frontend/src/components/shared/CurrencySelector.tsx` | Currency dropdown | ~60 |
| `frontend/src/api/endpoints/exchangeRates.ts` | API wrappers | ~50 |
| `frontend/e2e/multi-currency.spec.ts` | E2E tests | ~500 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `exchange_rates_router` and `exchange_rates_admin_router` |
| `app/models.py` | Add exchange rate and currency Pydantic models |
| `app/core/settings.py` | Add `exchange_rates_table_name`, `exchange_rate_ttl_seconds`, `exchange_rate_api_url` settings |
| `app/core/tables.py` | Add `T.exchange_rates` table handle |
| `scripts/local-ddb-init.py` | Add `exchange_rates` TableDef; seed static fallback rates |
| `app/services/profile.py` | Add `preferred_currency` to profile fields |
| `app/routers/profile.py` | Accept `preferred_currency` in profile update |
| `frontend/src/main.tsx` | Wrap app in `<CurrencyProvider>` |
| `frontend/src/stores/authStore.ts` | Include `preferred_currency` in user session data |
| `frontend/src/api/types.ts` | Add exchange rate TypeScript interfaces |
| `frontend/src/pages/settings/ProfilePage.tsx` | Add `<CurrencySelector>` to profile settings |
| Multiple price-display pages (listed in 3.8.4) | Replace raw `$` formatting with `<CurrencyAmount>` |

---

## 4. Conversion Logic

### 4.1 Backend Conversion

```python
def convert_usd_cents(amount_cents: int, target_currency: str) -> Dict[str, Any]:
    if target_currency == "USD":
        return {"converted_amount": f"{amount_cents / 100:.2f}", "approximate": False, ...}

    rates = get_current_rates()
    rate = Decimal(rates["rates"].get(target_currency, "1.0"))
    usd_amount = Decimal(amount_cents) / 100
    converted = usd_amount * rate

    # Format based on decimal places
    decimals = CURRENCY_DECIMALS.get(target_currency, 2)
    if decimals == 0:
        formatted = str(int(converted))
    else:
        formatted = f"{converted:.{decimals}f}"

    return {
        "original_cents": amount_cents,
        "original_currency": "USD",
        "converted_amount": formatted,
        "converted_currency": target_currency,
        "rate": str(rate),
        "rate_updated_at": rates.get("fetched_at", 0),
        "approximate": True,
    }
```

### 4.2 Frontend Conversion

```typescript
function convert(usdCents: number): ConvertedAmount {
  if (preferredCurrency === "USD") {
    return { original: formatUSD(usdCents), converted: formatUSD(usdCents), rate: 1, approximate: false };
  }
  const rate = rates[preferredCurrency] ?? 1;
  const usdAmount = usdCents / 100;
  const convertedAmount = usdAmount * rate;
  const decimals = CURRENCY_DECIMALS[preferredCurrency] ?? 2;
  const symbol = CURRENCY_SYMBOLS[preferredCurrency] ?? preferredCurrency;

  return {
    original: formatUSD(usdCents),
    converted: `~${symbol}${convertedAmount.toFixed(decimals)}`,
    rate,
    approximate: true,
  };
}
```

### 4.3 Display Rules

| Scenario | Display |
|----------|---------|
| Preferred = USD | `$5.00` (no conversion) |
| Preferred = EUR | `~EUR4.60` (primary, normal text) / `$5.00 USD` (secondary, small muted text) |
| Preferred = JPY | `~JPY748` (no decimals for JPY) / `$5.00 USD` (secondary) |
| Rates stale | `~EUR4.60*` (asterisk) + tooltip "Exchange rates may be outdated" |
| Rates unavailable | `$5.00` (USD only) + tooltip "Currency conversion unavailable" |

### 4.4 Edge Cases

- **Zero amounts**: `$0.00` stays `$0.00` regardless of currency (no conversion needed).
- **Very small amounts (1 cent)**: `$0.01` → `~EUR0.01` (rounded to nearest cent in target currency).
- **JPY rounding**: JPY has 0 decimal places. `$5.00` at rate 149.5 = JPY 747.5 → displayed as `~JPY748` (round to nearest integer).
- **Rate fetch timeout**: External API calls have a 5-second timeout. On timeout, the last cached rates are used.
- **Multiple workers**: In-memory cache is per-process. Each worker fetches independently, but DDB serves as the shared cache layer.
- **Currency switch during checkout**: If the user changes currency mid-checkout, the converted display updates but the actual charge remains in USD. A warning banner clarifies: "You will be charged in USD. Converted amounts are approximate."

---

## 5. E2E Test Plan

**File**: `frontend/e2e/multi-currency.spec.ts`

### Section 555: Exchange Rate API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 555.1 | Get current rates returns supported currencies | GET `/ui/exchange-rates`; response has `rates` array with entries for EUR, GBP, CAD, JPY, etc. Each has `currency`, `rate`, `symbol`. |
| 555.2 | Convert endpoint returns accurate conversion | GET `/ui/exchange-rates/convert?amount_cents=1000&target_currency=EUR`; response has `converted_amount`, `approximate: true`, `rate`. |
| 555.3 | Convert to USD returns exact amount | GET `/ui/exchange-rates/convert?amount_cents=1000&target_currency=USD`; `converted_amount: "10.00"`, `approximate: false`. |
| 555.4 | Unsupported currency returns 422 | GET `/ui/exchange-rates/convert?amount_cents=1000&target_currency=XYZ`; 422. |

### Section 556: Currency Preference API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 556.1 | Default preference is USD | GET `/ui/profile`; `preferred_currency: "USD"`. |
| 556.2 | Set preference to EUR | PATCH `/ui/profile` with `preferred_currency: "EUR"`. Subsequent GET returns `preferred_currency: "EUR"`. |
| 556.3 | Invalid currency rejected | PATCH `/ui/profile` with `preferred_currency: "INVALID"`; 422. |
| 556.4 | Preference persists across sessions | Set to GBP. Re-inject auth. GET profile returns `preferred_currency: "GBP"`. |

### Section 557: Admin Exchange Rate API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 557.1 | Admin sees rates with source details | Root GET `/ui/admin/exchange-rates`; response has `source`, `fetched_at`, `expires_at` fields. |
| 557.2 | Admin can force refresh | Root POST `/ui/admin/exchange-rates/refresh`; `fetched_at` in response is recent (within 5 seconds of now). |
| 557.3 | Non-admin cannot refresh rates | Alice POST `/ui/admin/exchange-rates/refresh`; 403. |

### Section 558: Currency Display UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 558.1 | Settings page shows currency selector | Navigate to settings. Currency dropdown is visible with supported currencies. |
| 558.2 | Selecting EUR updates price displays | Set preferred currency to EUR. Navigate to billing page. Wallet balance shows `~EUR` prefix. USD amount shown in smaller text. |
| 558.3 | USD selection shows normal prices | Set preferred currency to USD. Navigate to billing page. Prices show `$` format without conversion. |
| 558.4 | Stale rates show warning indicator | (Use mock to set `expires_at` in the past.) Navigate to billing page. Price display includes stale indicator (asterisk or tooltip). |

### Section 559: Currency Edge Cases (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 559.1 | JPY displays without decimals | Set pref to JPY; view price of $10.50; shows ~1,575 (no decimal) |
| 559.2 | Fallback to USD when rate unavailable | Set pref to obscure currency with no rate; prices show in USD with note |
| 559.3 | Rate staleness indicator shows on old rates | Mock stale rate; price shows asterisk or tooltip indicating approximate |
| 559.4 | Zero-amount shows correctly in all currencies | View $0.00 item in EUR; shows ~0,00 EUR (not NaN or blank) |

**Total E2E tests: 19**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Get rates | `require_ui_session` | Any authenticated user |
| Convert amount | `require_ui_session` | Any authenticated user |
| Set preference | `require_ui_session` | Only own profile |
| Admin get rates | `require_admin_session` | Admin or root role |
| Admin refresh rates | `require_admin_session` | Admin or root role |

### 6.2 External API Security

- External rate API calls use HTTPS only.
- API key (if required) stored in environment variable, never in client-side code.
- In dev mode, no external calls are made (static fallback only).
- Rate data is not user-sensitive (public exchange rates), so no PII concerns.

### 6.3 Rate Limiting

- Exchange rate API: max 60 requests per user per minute (reads cached data, not expensive).
- Convert endpoint: max 120 requests per user per minute (simple math, cached rates).
- Admin refresh: max 6 requests per hour (to avoid hammering external API).
- Profile currency update: standard profile update rate limits.

### 6.4 Display Accuracy Disclaimer

- All converted amounts display the "~" prefix to indicate approximation.
- A global disclaimer on checkout pages: "Displayed amounts in {currency} are approximate. You will be charged in USD."
- No rounding manipulation: conversions use standard rounding rules (`ROUND_HALF_UP`).

---

## 7. Observability

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `exchange_rate_fetch_total` | Counter | `source` (external/cache/fallback) | Rate fetch attempts |
| `exchange_rate_fetch_failed_total` | Counter | `reason` | Failed rate fetches |
| `currency_conversion_total` | Counter | `from`, `to` | Conversion requests |
| `currency_preference_set_total` | Counter | `currency` | Preference updates |
| `exchange_rate_staleness_seconds` | Gauge | — | Time since last successful fetch |

### 7.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Exchange rates fetched | INFO | `source`, `currencies_count`, `fetch_duration_ms` |
| Exchange rate fetch failed | WARN | `error`, `using_fallback` |
| Currency preference updated | INFO | `user_sub`, `old_currency`, `new_currency` |
| Stale rates served | WARN | `staleness_hours`, `currencies_affected` |

### 7.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Rate fetch failures | > 3 consecutive failures | High | Check external API status |
| Stale rates | > 24h since last refresh | Medium | Force refresh; check API key |
| Unusual conversion volume | > 10K conversions/hour | Low | Review for abuse |

---

## 8. Rollout Plan

### 8.1 Feature Flag

```python
multi_currency_enabled: bool = os.environ.get("MULTI_CURRENCY_ENABLED", "true").lower() == "true"
```

### 8.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy exchange rate service + endpoints; flag OFF | 2 days | Unit tests pass |
| Phase 2: Internal | Enable with CurrencyAmount component | 3 days | All 15 E2E pass |
| Phase 3: Canary 10% | Enable for 10% of users | 3 days | No display errors; rate freshness OK |
| Phase 4: GA | Enable for all | Permanent | Positive user feedback |

### 8.3 Rollback

1. Set `MULTI_CURRENCY_ENABLED=false` — all prices display in USD only
2. CurrencyAmount component falls back to USD formatting
3. Preferences preserved but ignored until re-enabled

---

## 9. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Exchange rate cache hit | > 99% | In-memory cache refreshed every 1-4h; TTL on DDB fallback |
| Conversion computation | < 1ms | Simple multiplication; no API call |
| CurrencyAmount render | < 1ms per component | Pure function; memoized with useMemo |
| Rate fetch external call | < 2s | Timeout set to 5s; fallback to cache on timeout |
| Multiple currency displays per page | No jank | Batch conversion: convert all amounts at once using cached rate |

---

## 10. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/profile.py` | Exists (modify) | Store `preferred_currency` in user profile |
| `app/routers/profile.py` | Exists (modify) | Accept `preferred_currency` in profile update |
| `app/core/settings.py` | Exists (modify) | Add exchange rate settings |
| `app/core/tables.py` | Exists (modify) | Add `T.exchange_rates` table handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `exchange_rates` table + seed static fallback |
| `app/auth/deps.py` | Exists | `require_ui_session`, `require_admin_session` |
| `httpx` or `requests` | Exists (check) | HTTP client for external rate API (may already be a dependency) |
| `frontend/src/stores/authStore.ts` | Exists (modify) | Include `preferred_currency` in user session |
| `frontend/src/main.tsx` | Exists (modify) | Add `CurrencyProvider` wrapper |
| Multiple frontend pages | Exists (modify) | Replace raw price formatting with `CurrencyAmount` component |

---

## 8. Acceptance Criteria

1. Users can set a preferred display currency from a list of 15 supported currencies.
2. When a non-USD currency is selected, all price displays show the converted amount with "~" prefix and the original USD in smaller text.
3. When USD is selected, prices display normally with no conversion indicators.
4. Exchange rates are cached and refreshed every 1-4 hours (configurable).
5. If rate fetch fails, the last cached rates are used; if no cache exists, prices show in USD only.
6. JPY and other zero-decimal currencies display without decimal places.
7. All billing, shop, subscription, tip, and unlock price displays use the `CurrencyAmount` component.
8. A disclaimer on checkout pages clarifies that charges are in USD.
9. Admins can view rate source details and force a rate refresh.
10. All 15 E2E tests pass.

---

## Codebase References

### Existing Files (verified)
| File | Key References |
|------|---------------|
| `app/services/billing_shared.py` | Ledger entries (all USD) — `new_ledger_entry:217` |
| `app/core/settings.py` | Configuration (no currency settings yet) |
| `frontend/src/pages/billing/` | Billing pages (all USD formatting) |
| `frontend/src/pages/shop/Checkout.tsx` | Cart totals (USD) |
| `frontend/src/pages/feed/PostCard.tsx` | Post unlock prices (USD) |

### Files to Create (new implementation)
| File | Purpose |
|------|---------|
| `app/services/exchange_rates.py` | Rate fetching, caching, conversion logic |
| `exchange_rates` DDB table or cache | Cached rate storage |
| `frontend/src/components/shared/CurrencyAmount.tsx` | Reusable converted price display component |
| `frontend/src/contexts/CurrencyContext.tsx` | Currency provider with user preference + rates |
