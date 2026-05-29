# FIN-018: Billing Configuration UI

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: Billing ledger (`billing_shared.py`), creator payouts (`creator_payouts.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

Billing parameters — platform fee percentages, minimum payout thresholds, minimum deposit amounts, currency settings, and tax rates — are currently configured via environment variables in `.env.local`. Changing any billing parameter requires:

1. Editing the env file
2. Restarting the backend
3. Waiting for the process to reload

There is no admin UI to adjust these values at runtime, no audit log of who changed what, and no way to preview the impact of a change before applying it.

### Why This Is Needed

1. **Runtime configuration**: Business conditions change. A promotional "zero fee" weekend should not require an engineer to edit env vars and restart production servers.

2. **Audit trail**: SOX compliance and investor due diligence require knowing who changed billing parameters, when, and what the previous values were. Env var changes leave no audit trail.

3. **Impact preview**: Changing the platform fee from 20% to 25% affects all future transactions. Admins need to see projected revenue impact before committing.

4. **Multi-parameter coordination**: Changing fee percentage and minimum payout threshold together must be atomic — not two separate env var edits with a restart between them.

5. **Separation of concerns**: Engineers should not be in the loop for business configuration changes. Admins should self-serve through a dedicated UI.

### User Stories

- As a **platform admin**, I want to adjust platform fee percentages through a UI so I can run promotions without engineering involvement.
- As a **platform admin**, I want to change the minimum payout threshold so I can lower it for new creators.
- As a **platform admin**, I want to see an audit log of all billing configuration changes so I can answer compliance questions.
- As a **platform admin**, I want to preview the impact of a fee change before applying it so I can avoid costly mistakes.
- As a **platform admin**, I want changes to take effect immediately without restarting the backend.

### Architecture After This Change

```
Billing Configuration (/admin/billing-config)
│
├── Fee Configuration
│   ├── Platform fee % (per transaction type)
│   │   ├── Tips: 20%
│   │   ├── Unlocks: 20%
│   │   ├── Subscriptions: 15%
│   │   ├── Catalog purchases: 10%
│   │   └── Ad revenue share: 20%
│   ├── Payment processor markup %: 2.9% + $0.30
│   └── Preview impact button
│
├── Payout Configuration
│   ├── Minimum payout threshold: $50.00
│   ├── Payout processing fee: $0.00
│   ├── Payout schedule: weekly
│   └── Auto-payout enabled: true
│
├── Deposit Configuration
│   ├── Minimum deposit amount: $5.00
│   ├── Maximum deposit amount: $10,000.00
│   └── Deposit fee %: 0%
│
├── Currency Settings
│   ├── Default currency: USD
│   ├── Supported currencies: [USD, EUR, GBP]
│   └── Exchange rate source: manual / API
│
├── Tax Settings
│   ├── Tax collection enabled: false
│   ├── Default tax rate %: 0
│   └── Tax-exempt transaction types: []
│
├── Impact Preview
│   ├── Projected daily revenue change
│   ├── Affected transaction count
│   └── Sample transaction before/after comparison
│
└── Audit Log
    ├── All configuration changes
    ├── Who changed, when, old value → new value
    └── Searchable by field name and date
```

---

## 2. Current State Analysis

### 2.1 Current Configuration Source

Billing parameters live in `app/core/settings.py` as fields on the `Settings` dataclass, populated from environment variables:

```python
class Settings:
    platform_fee_bps: int = int(os.environ.get("PLATFORM_FEE_BPS", "2000"))  # 20%
    min_payout_cents: int = int(os.environ.get("MIN_PAYOUT_CENTS", "5000"))   # $50
    min_deposit_cents: int = int(os.environ.get("MIN_DEPOSIT_CENTS", "500"))   # $5
    ...
```

These values are read at startup and remain constant until the process is restarted.

### 2.2 Where Fees Are Applied

- `app/services/billing_shared.py`: `new_ledger_entry` uses fee rates for commission calculation
- `app/services/creator_payouts.py`: `request_payout` checks minimum payout threshold
- `app/routers/billing.py`: Deposit endpoints check minimum deposit amount

### 2.3 Gaps

1. No DynamoDB storage for billing configuration (only env vars)
2. No runtime update mechanism (requires restart)
3. No audit log of configuration changes
4. No impact preview for proposed changes
5. No admin UI for billing configuration
6. No per-transaction-type fee configuration

---

## 3. Technical Design

### 3.1 Billing Config Table: `billing_config`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="billing_config",
    pk="pk", sk="sk",
    gsis=[],
)
```

**Current configuration row** (single item, always overwritten):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BILLING_CONFIG` |
| `sk` | S | `CURRENT` |
| `fee_tips_bps` | N | Fee for tips in basis points (2000 = 20%) |
| `fee_unlocks_bps` | N | Fee for unlock purchases |
| `fee_subscriptions_bps` | N | Fee for subscription charges |
| `fee_catalog_bps` | N | Fee for catalog purchases |
| `fee_ad_revenue_bps` | N | Fee for ad revenue share |
| `min_payout_cents` | N | Minimum payout threshold |
| `payout_fee_cents` | N | Per-payout processing fee |
| `payout_schedule` | S | `"daily"`, `"weekly"`, `"monthly"` |
| `auto_payout_enabled` | BOOL | Auto-payout on schedule |
| `min_deposit_cents` | N | Minimum deposit amount |
| `max_deposit_cents` | N | Maximum deposit amount |
| `deposit_fee_bps` | N | Deposit fee percentage |
| `default_currency` | S | Default currency code |
| `supported_currencies` | L | List of supported currency codes |
| `tax_enabled` | BOOL | Whether tax collection is enabled |
| `default_tax_rate_bps` | N | Default tax rate in basis points |
| `updated_at` | N | Last update timestamp |
| `updated_by` | S | Admin who last updated |

**Audit log rows** (one per change):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BILLING_CONFIG` |
| `sk` | S | `AUDIT#{timestamp}#{event_id}` |
| `admin_sub` | S | Admin who made the change |
| `changes` | L | List of {field, old_value, new_value} |
| `created_at` | N | Unix timestamp |

### 3.2 Billing Config Service: `app/services/billing_config.py`

```python
"""Billing configuration management (FIN-018).

Stores and retrieves billing parameters from DynamoDB,
replacing env-var-based configuration for runtime updates.
"""

# In-memory cache with TTL
_config_cache: Optional[Dict[str, Any]] = None
_cache_ts: int = 0
CACHE_TTL_SECONDS = 60

def get_billing_config() -> Dict[str, Any]:
    """Get current billing configuration.

    Uses in-memory cache with 60-second TTL to avoid
    DDB reads on every transaction.
    Falls back to env var defaults if no DDB config exists.
    """
    ...

def update_billing_config(
    *, admin_sub: str, **updates
) -> Dict[str, Any]:
    """Update billing configuration.

    Writes new values to DDB, logs audit entry with old/new values,
    invalidates in-memory cache.
    """
    ...

def get_fee_bps(entry_type: str) -> int:
    """Get platform fee in basis points for a transaction type.

    Used by billing_shared.py to compute commission.
    """
    config = get_billing_config()
    fee_map = {
        "tip_debit": config.get("fee_tips_bps", 2000),
        "unlock_debit": config.get("fee_unlocks_bps", 2000),
        "subscription_charge": config.get("fee_subscriptions_bps", 1500),
        "catalog_purchase": config.get("fee_catalog_bps", 1000),
    }
    return fee_map.get(entry_type, 2000)

def get_min_payout_cents() -> int:
    """Get minimum payout threshold."""
    ...

def get_min_deposit_cents() -> int:
    """Get minimum deposit amount."""
    ...

def get_max_deposit_cents() -> int:
    """Get maximum deposit amount."""
    ...

def get_audit_log(
    *, limit: int = 50, cursor: str = None
) -> Dict[str, Any]:
    """Get billing configuration change audit log."""
    ...

def preview_impact(
    *, proposed_changes: Dict[str, Any]
) -> Dict[str, Any]:
    """Preview impact of proposed configuration changes.

    Computes projected daily revenue delta based on recent
    transaction volume and proposed fee changes.
    Returns {
        affected_tx_types, projected_daily_delta_cents,
        sample_transaction_before, sample_transaction_after
    }.
    """
    ...
```

### 3.3 Integration with Billing System

Replace hardcoded fee lookups with `billing_config.get_fee_bps(entry_type)`:

```python
# Before (in billing_shared.py or equivalent):
commission_bps = S.platform_fee_bps  # from env var

# After:
from app.services.billing_config import get_fee_bps
commission_bps = get_fee_bps(entry_type)
```

Similarly for `get_min_payout_cents()`, `get_min_deposit_cents()`, etc.

### 3.4 Router: `app/routers/admin_billing_config.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/billing-config` | `require_admin_session` | Get current config |
| PATCH | `/v1/admin/billing-config` | `require_root_session` | Update config |
| GET | `/v1/admin/billing-config/audit` | `require_admin_session` | Audit log |
| POST | `/v1/admin/billing-config/preview` | `require_admin_session` | Preview impact |

### 3.5 Pydantic Models (`app/models.py`)

```python
class BillingConfigOut(BaseModel):
    fee_tips_bps: int
    fee_unlocks_bps: int
    fee_subscriptions_bps: int
    fee_catalog_bps: int
    fee_ad_revenue_bps: int
    min_payout_cents: int
    payout_fee_cents: int
    payout_schedule: str
    auto_payout_enabled: bool
    min_deposit_cents: int
    max_deposit_cents: int
    deposit_fee_bps: int
    default_currency: str
    supported_currencies: List[str]
    tax_enabled: bool
    default_tax_rate_bps: int
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None

class BillingConfigUpdate(BaseModel):
    fee_tips_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_unlocks_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_subscriptions_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_catalog_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_ad_revenue_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    min_payout_cents: Optional[int] = Field(default=None, ge=0)
    payout_fee_cents: Optional[int] = Field(default=None, ge=0)
    payout_schedule: Optional[str] = Field(default=None, pattern=r"^(daily|weekly|monthly)$")
    auto_payout_enabled: Optional[bool] = None
    min_deposit_cents: Optional[int] = Field(default=None, ge=0)
    max_deposit_cents: Optional[int] = Field(default=None, ge=0)
    deposit_fee_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    default_currency: Optional[str] = Field(default=None, pattern=r"^[A-Z]{3}$")
    supported_currencies: Optional[List[str]] = None
    tax_enabled: Optional[bool] = None
    default_tax_rate_bps: Optional[int] = Field(default=None, ge=0, le=10000)

class BillingConfigAuditEntry(BaseModel):
    admin_sub: str
    changes: List[Dict[str, Any]]  # [{field, old_value, new_value}]
    created_at: int

class BillingConfigPreview(BaseModel):
    affected_tx_types: List[str]
    projected_daily_delta_cents: int
    sample_before: Dict[str, Any]
    sample_after: Dict[str, Any]
```

### 3.6 Frontend: Billing Configuration Page

**Route**: `/admin/billing-config` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/billingConfig/BillingConfigPage.tsx`

```tsx
<div className="space-y-6">
  {/* Fee Configuration */}
  <Card>
    <CardHeader><CardTitle>Platform Fees</CardTitle></CardHeader>
    <CardContent>
      <div className="grid grid-cols-2 gap-4">
        <FeeInput label="Tips" value={config.fee_tips_bps} field="fee_tips_bps" />
        <FeeInput label="Unlocks" value={config.fee_unlocks_bps} field="fee_unlocks_bps" />
        <FeeInput label="Subscriptions" value={config.fee_subscriptions_bps} field="fee_subscriptions_bps" />
        <FeeInput label="Catalog" value={config.fee_catalog_bps} field="fee_catalog_bps" />
        <FeeInput label="Ad Revenue" value={config.fee_ad_revenue_bps} field="fee_ad_revenue_bps" />
      </div>
    </CardContent>
  </Card>

  {/* Payout Configuration */}
  <Card>
    <CardHeader><CardTitle>Payout Settings</CardTitle></CardHeader>
    <CardContent>
      <NumberInput label="Min Payout ($)" value={config.min_payout_cents / 100} ... />
      <NumberInput label="Payout Fee ($)" value={config.payout_fee_cents / 100} ... />
      <Select label="Schedule" value={config.payout_schedule} ... />
      <Switch label="Auto-payout" checked={config.auto_payout_enabled} ... />
    </CardContent>
  </Card>

  {/* Deposit Configuration */}
  <Card>
    <CardHeader><CardTitle>Deposit Settings</CardTitle></CardHeader>
    <CardContent>...</CardContent>
  </Card>

  {/* Tax Settings */}
  <Card>
    <CardHeader><CardTitle>Tax Settings</CardTitle></CardHeader>
    <CardContent>...</CardContent>
  </Card>

  {/* Action buttons */}
  <div className="flex gap-2">
    <Button onClick={handlePreview} variant="outline">Preview Impact</Button>
    <Button onClick={handleSave}>Save Changes</Button>
  </div>

  {/* Preview dialog */}
  <ImpactPreviewDialog open={showPreview} preview={previewData} onConfirm={handleConfirmSave} />

  {/* Audit log */}
  <Card>
    <CardHeader><CardTitle>Change History</CardTitle></CardHeader>
    <CardContent><AuditLogTable entries={auditLog} /></CardContent>
  </Card>
</div>
```

### 3.7 Frontend API (`frontend/src/api/endpoints/adminBillingConfig.ts`)

```typescript
export const getBillingConfig = () =>
  client.get("/v1/admin/billing-config");

export const updateBillingConfig = (data: BillingConfigUpdate) =>
  client.patch("/v1/admin/billing-config", data);

export const getBillingConfigAudit = (params?: { limit?: number }) =>
  client.get("/v1/admin/billing-config/audit", { params });

export const previewBillingConfigImpact = (data: BillingConfigUpdate) =>
  client.post("/v1/admin/billing-config/preview", data);
```

---

## 4. Implementation Plan

### Phase 1: Backend Data Layer (Days 1-2)

1. **`scripts/local-ddb-init.py`**: Add `billing_config` table.
2. **`app/core/settings.py`**: Add `billing_config_table_name`.
3. **`app/core/tables.py`**: Add `billing_config` table handle.

### Phase 2: Backend Service (Days 2-4)

4. **`app/services/billing_config.py`**: New file. Config CRUD, caching, audit log, impact preview.
5. **Integration**: Replace env-var fee lookups in `billing_shared.py` and `creator_payouts.py` with `billing_config` calls.

### Phase 3: Backend Router (Days 4-5)

6. **`app/models.py`**: Add billing config Pydantic models.
7. **`app/routers/admin_billing_config.py`**: New router with 4 endpoints.
8. **`app/main.py`**: Register router with prefix `/v1/admin/billing-config`.

### Phase 4: Frontend (Days 5-7)

9. **`frontend/src/api/types.ts`**: Add TypeScript types.
10. **`frontend/src/api/endpoints/adminBillingConfig.ts`**: New file.
11. **`frontend/src/pages/admin/billingConfig/BillingConfigPage.tsx`**: New page.
12. **`frontend/src/App.tsx`**: Add `/admin/billing-config` route.
13. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Billing Config" admin nav link.

### Phase 5: E2E Tests (Days 8-9)

14. **`frontend/e2e/admin-billing-config.spec.ts`**: 13 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-billing-config.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Charlie (admin)
- Seed billing_config table with default configuration values

**Section 543: Config Read API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves billing config` | GET `/v1/admin/billing-config` as Root -> 200; has `fee_tips_bps`, `min_payout_cents`, `default_currency` |
| 2 | `Config has all expected fields` | Response includes all fee fields, payout fields, deposit fields, tax fields |
| 3 | `Non-admin cannot read config` | GET as Alice -> 403 |

**Section 544: Config Update API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 4 | `Root updates fee configuration` | PATCH `/v1/admin/billing-config` with `{fee_tips_bps: 1500}` as Root -> 200; re-GET shows `fee_tips_bps === 1500` |
| 5 | `Root updates payout threshold` | PATCH with `{min_payout_cents: 2500}` -> 200; re-GET confirms |
| 6 | `Non-root cannot update config` | PATCH as Charlie -> 403 |
| 7 | `Invalid fee value returns 422` | PATCH with `{fee_tips_bps: -100}` -> 422 |

**Section 545: Audit Log API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | `Audit log records config change` | GET `/v1/admin/billing-config/audit` -> 200; array has entry with `admin_sub` matching Root, `changes` array listing modified fields |
| 9 | `Audit entry shows old and new values` | Entry's `changes[0]` has `field`, `old_value`, `new_value` |
| 10 | `Multiple changes logged separately` | After 2 updates, audit has >= 2 entries |

**Section 546: Impact Preview API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | `Preview shows affected transaction types` | POST `/v1/admin/billing-config/preview` with `{fee_tips_bps: 2500}` as Root -> 200; `affected_tx_types` includes `"tip_debit"` |
| 12 | `Preview shows projected daily delta` | Response has `projected_daily_delta_cents` (can be positive or negative) |
| 13 | `Preview shows before/after sample` | Response has `sample_before` and `sample_after` with amount fields |

---

## 6. Security Considerations

### 6.1 Role-Based Access
- Read billing config and audit log: ADMIN role
- Update billing config: ROOT role (changes affect all transactions)
- Preview impact: ADMIN role (read-only projection)

### 6.2 Change Safety
- All changes recorded in immutable audit log with admin identity
- Impact preview required before saving (enforced in UI)
- In-memory cache ensures stale config cleared within 60 seconds
- Fee values capped at 50% (5000 bps) to prevent accidental extreme fees

### 6.3 Backward Compatibility
- If no DDB config exists, falls back to env var defaults
- New config values override env vars (DDB takes precedence)
- Config changes do not affect in-flight transactions (only new ones)

### 6.4 Cache Invalidation
- `update_billing_config` invalidates the in-memory cache immediately
- Other backend instances refresh cache within 60 seconds (cache TTL)
- For single-worker dev mode, invalidation is instant

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/billing_config.py` | Billing configuration service |
| `app/routers/admin_billing_config.py` | Admin billing config API (4 endpoints) |
| `frontend/src/api/endpoints/adminBillingConfig.ts` | API wrappers |
| `frontend/src/pages/admin/billingConfig/BillingConfigPage.tsx` | Config page |
| `frontend/e2e/admin-billing-config.spec.ts` | E2E tests (13 tests, sections 543-546) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add billing config Pydantic models |
| `app/main.py` | Register `admin_billing_config_router` |
| `app/core/settings.py` | Add `billing_config_table_name` |
| `app/core/tables.py` | Add `billing_config` table handle |
| `scripts/local-ddb-init.py` | Add `billing_config` table |
| `app/services/billing_shared.py` | Replace env var fee lookups with `billing_config.get_fee_bps()` |
| `app/services/creator_payouts.py` | Use `billing_config.get_min_payout_cents()` |
| `frontend/src/api/types.ts` | Add billing config TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/billing-config` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Billing Config" admin nav link |

## 9. Acceptance Criteria

1. Billing config readable through admin API with all fee, payout, deposit, and tax fields
2. ROOT can update any config field; changes persisted to DDB and effective immediately
3. Non-root admins cannot update config (403)
4. Audit log records every change with admin identity, old value, and new value
5. Impact preview shows affected transaction types and projected revenue delta
6. Billing system uses DDB config values instead of env vars (with env var fallback)
7. In-memory cache invalidated on update with 60-second TTL for other instances
8. Invalid values rejected with 422 (negative fees, fees over 50%)
9. All 13 E2E tests pass in `frontend/e2e/admin-billing-config.spec.ts`
