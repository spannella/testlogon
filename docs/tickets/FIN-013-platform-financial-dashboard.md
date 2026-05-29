# FIN-013: Platform Financial Dashboard

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: Billing ledger (`billing_shared.py`), payment provider routers (`billing.py`, `billing_ccbill.py`), creator payouts (`creator_payouts.py`)

---

## 1. Overview & Motivation

### The Gap

The platform processes payments across three providers (Stripe, PayPal, CCBill), handles creator payouts, wallet deposits, tips, locked-message unlocks, subscription charges, and catalog purchases. All of these operations write individual ledger entries to the `billing` DynamoDB table. However, there is no aggregated view of platform-wide financial health. Admins cannot:

- See gross merchandise value (GMV) across all transaction types
- View net revenue (platform fees / commissions retained)
- Calculate take rate (net revenue / GMV)
- Compare payment provider volumes (Stripe vs PayPal vs CCBill)
- View daily, weekly, or monthly revenue trends
- Identify top creators by revenue generated
- Export financial summaries as CSV or PDF

Without a financial dashboard, business decisions about pricing, provider negotiations, and growth investment are made without data.

### Why This Is Needed

1. **Business visibility**: Platform operators need real-time KPIs to understand revenue health. A single dashboard showing GMV, net revenue, and take rate replaces manual DynamoDB queries.

2. **Provider negotiation**: Knowing the volume split across Stripe, PayPal, and CCBill enables negotiating better processing rates with the dominant provider.

3. **Trend detection**: Daily/weekly/monthly trend lines reveal seasonality, growth rates, and the impact of new features (e.g., did launching locked messages increase revenue?).

4. **Creator economics**: Identifying top creators by revenue helps prioritize creator support, partnership deals, and retention efforts.

5. **Compliance**: Financial reporting is required for tax filings, investor updates, and audit preparation. Exportable summaries in standard formats save hours of manual work.

### User Stories

- As a **platform admin**, I want to see total GMV, net revenue, and take rate for any date range so I can report on platform financial health.
- As a **platform admin**, I want to see payment provider volume breakdown so I can negotiate better rates.
- As a **platform admin**, I want to view daily revenue trend charts so I can detect growth or decline patterns.
- As a **platform admin**, I want to see top creators ranked by revenue so I can prioritize creator partnerships.
- As a **platform admin**, I want to export financial summaries as CSV so I can import them into accounting software.

### Architecture After This Change

```
Admin Dashboard (/admin/financials)
│
├── KPI Cards (real-time)
│   ├── GMV (gross merchandise value)
│   ├── Net Revenue (platform fees)
│   ├── Take Rate % (net / GMV)
│   ├── Active Payers (unique paying users)
│   └── Average Transaction Value
│
├── Revenue Trends (chart)
│   ├── Daily / Weekly / Monthly toggle
│   ├── Line chart: GMV + Net Revenue over time
│   └── Date range picker
│
├── Provider Breakdown (chart)
│   ├── Pie chart: volume by provider
│   └── Table: provider, volume, tx count, avg tx, success rate
│
├── Top Creators (table)
│   ├── Creator, revenue, tx count, avg tx
│   └── Sortable, paginated
│
├── Transaction Type Breakdown (table)
│   ├── Type (tips, unlocks, subscriptions, deposits, catalog)
│   ├── Count, total, avg per tx
│   └── Bar chart
│
└── Export
    ├── CSV download
    └── PDF download (summary report)
```

### Data Flow

```
Billing Ledger (DDB)              Backend Aggregation              Admin Dashboard
─────────────────                 ────────────────────             ─────────────────
LEDGER#ts#id entries              GET /admin/financials/kpis       KPI Cards
  entry_type                      ├─ scan LEDGER# entries         Revenue Chart
  amount_cents                    ├─ group by entry_type          Provider Pie
  currency                        ├─ sum amounts                  Top Creators
  provider                        └─ compute derived metrics      Export buttons
  user_id
  created_at
```

---

## 2. Current State Analysis

### 2.1 Billing Ledger (`app/services/billing_shared.py`)

The billing system uses a single `billing` DynamoDB table. Ledger entries are stored with:
- `pk`: `USER#{user_id}`
- `sk`: `LEDGER#{timestamp}#{entry_id}`
- Fields: `entry_type`, `amount_cents`, `currency`, `description`, `reason`, `created_at`

Key functions:
- `new_ledger_entry(...)`: Creates a new ledger row
- `ledger_sk(ts, entry_id)`: Builds the sort key
- `settle_or_reverse_ledger(...)`: Settles or reverses existing entries

Entry types used across the platform: `tip_debit`, `tip_credit`, `unlock_debit`, `unlock_credit`, `deposit`, `payout_debit`, `subscription_charge`, `platform_commission`, `ad_revenue_credit`, `platform_ad_commission`.

### 2.2 Payment Providers

Three payment provider integrations exist:
- **Stripe** (`app/routers/billing.py`): Primary provider for card payments
- **PayPal** (mock in dev): Alternative payment method
- **CCBill** (`app/routers/billing_ccbill.py`): Specialized provider for high-risk categories

Each provider records transactions in the billing ledger with a `provider` field.

### 2.3 Creator Payouts (`app/services/creator_payouts.py`)

Existing functions:
- `get_available_balance(user_id)`: Returns available payout balance
- `request_payout(user_id, amount_cents, ...)`: Creates payout request
- `list_payouts_admin(status, limit, cursor)`: Admin payout listing
- `get_payout_stats()`: Returns payout queue statistics

### 2.4 Admin Auth (`app/auth/deps.py`)

- `require_admin_session`: Requires role >= ADMIN — used for read-only dashboards
- `require_root_session`: Requires role == ROOT — used for destructive operations

### 2.5 Gaps

1. No aggregation service for cross-user ledger queries
2. No GMV / net revenue / take rate computation
3. No provider volume breakdown
4. No time-series aggregation for trend charts
5. No top-creators ranking by revenue
6. No CSV/PDF export of financial summaries
7. No admin financial dashboard UI

---

## 3. Technical Design

### 3.1 Daily Rollup Table: `financial_rollups`

Real-time aggregation across all users is expensive (full table scan of the `billing` table). Instead, use a daily rollup pattern: a background task aggregates each day's ledger entries into a single rollup row.

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="financial_rollups",
    pk="pk", sk="sk",
    gsis=[],
    attr_types={"sk": "S"},
)
```

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `ROLLUP#DAILY` |
| `sk` | S | `2026-05-29` (date string) |
| `gmv_cents` | N | Total gross merchandise value |
| `net_revenue_cents` | N | Platform fees / commissions |
| `tx_count` | N | Total transaction count |
| `unique_payers` | N | Distinct paying user count |
| `by_type` | M | Map of entry_type -> {count, total_cents} |
| `by_provider` | M | Map of provider -> {count, total_cents, success, failure} |
| `top_creators` | L | List of {user_id, revenue_cents, tx_count} (top 50) |
| `computed_at` | N | Unix timestamp when rollup was computed |

**Platform-level rollup row** (current-day live totals):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `ROLLUP#LIVE` |
| `sk` | S | `CURRENT` |
| `gmv_cents` | N | Running total since midnight |
| `net_revenue_cents` | N | Running platform fees since midnight |
| `tx_count` | N | Running tx count since midnight |
| `last_updated` | N | Unix timestamp |

### 3.2 Aggregation Service: `app/services/financial_dashboard.py`

```python
"""Platform financial dashboard aggregation (FIN-013).

Computes GMV, net revenue, take rate, provider breakdown, and
top creator rankings from the billing ledger and daily rollups.
"""

# Entry types that count toward GMV (user-to-platform payments)
GMV_ENTRY_TYPES = {
    "tip_debit", "unlock_debit", "deposit",
    "subscription_charge", "catalog_purchase",
}

# Entry types that represent platform revenue (platform keeps these)
REVENUE_ENTRY_TYPES = {
    "platform_commission", "platform_ad_commission",
}

def get_kpis(*, start_date: str, end_date: str) -> Dict[str, Any]:
    """Compute KPI summary for a date range.

    Queries daily rollup rows between start_date and end_date.
    Returns GMV, net revenue, take rate, tx count, unique payers, avg tx.
    """
    ...

def get_trends(
    *, start_date: str, end_date: str, granularity: str = "daily"
) -> List[Dict[str, Any]]:
    """Time-series data for revenue trend charts.

    Returns list of {date, gmv_cents, net_revenue_cents, tx_count}.
    Granularity: "daily", "weekly", "monthly".
    """
    ...

def get_provider_breakdown(
    *, start_date: str, end_date: str
) -> List[Dict[str, Any]]:
    """Volume breakdown by payment provider.

    Returns list of {provider, total_cents, tx_count, avg_cents, pct}.
    """
    ...

def get_type_breakdown(
    *, start_date: str, end_date: str
) -> List[Dict[str, Any]]:
    """Volume breakdown by transaction type.

    Returns list of {entry_type, total_cents, tx_count, avg_cents}.
    """
    ...

def get_top_creators(
    *, start_date: str, end_date: str, limit: int = 20
) -> List[Dict[str, Any]]:
    """Top creators ranked by revenue generated.

    Returns list of {user_id, revenue_cents, tx_count, avg_cents}.
    """
    ...

def compute_daily_rollup(date_str: str) -> Dict[str, Any]:
    """Compute and store the daily rollup for a specific date.

    Scans all billing ledger entries for the given date,
    aggregates by type and provider, identifies top creators.
    Called by background task at end of day or on demand.
    """
    ...

def export_summary_csv(
    *, start_date: str, end_date: str
) -> str:
    """Generate CSV export of financial summary.

    Returns CSV string with columns: date, gmv, net_revenue,
    take_rate, tx_count, by_type breakdown.
    """
    ...

def export_summary_pdf(
    *, start_date: str, end_date: str
) -> bytes:
    """Generate PDF export of financial summary.

    Returns PDF bytes with formatted summary report including
    KPI table, trend chart placeholder, and provider breakdown.
    """
    ...
```

### 3.3 Ledger Scan Helper

To compute rollups, the service needs to scan all ledger entries for a date range across all users. Since the billing table is partitioned by `USER#{user_id}`, a full cross-user scan requires a GSI or a table scan.

**New GSI on `billing` table**: `GSI_LEDGER_DATE`

| Key | Attribute | Description |
|-----|-----------|-------------|
| PK | `ledger_date` | `LEDGER#2026-05-29` (date partition) |
| SK | `ledger_ts_id` | `{timestamp}#{entry_id}` |

This GSI allows efficient date-range queries without scanning the entire table.

### 3.4 Router: `app/routers/admin_financials.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/financials/kpis` | `require_admin_session` | KPI summary |
| GET | `/v1/admin/financials/trends` | `require_admin_session` | Time-series trend data |
| GET | `/v1/admin/financials/providers` | `require_admin_session` | Provider volume breakdown |
| GET | `/v1/admin/financials/types` | `require_admin_session` | Transaction type breakdown |
| GET | `/v1/admin/financials/top-creators` | `require_admin_session` | Top creators by revenue |
| POST | `/v1/admin/financials/rollup` | `require_root_session` | Trigger manual rollup |
| GET | `/v1/admin/financials/export/csv` | `require_admin_session` | CSV export |
| GET | `/v1/admin/financials/export/pdf` | `require_admin_session` | PDF export |

### 3.5 Pydantic Models (`app/models.py`)

```python
class FinancialKPIs(BaseModel):
    gmv_cents: int
    net_revenue_cents: int
    take_rate_bps: int  # basis points (e.g., 2000 = 20%)
    tx_count: int
    unique_payers: int
    avg_tx_cents: int
    period: Dict[str, str]

class FinancialTrendPoint(BaseModel):
    date: str
    gmv_cents: int
    net_revenue_cents: int
    tx_count: int

class ProviderBreakdownEntry(BaseModel):
    provider: str
    total_cents: int
    tx_count: int
    avg_cents: int
    pct: float  # percentage of total volume

class TypeBreakdownEntry(BaseModel):
    entry_type: str
    total_cents: int
    tx_count: int
    avg_cents: int

class TopCreatorEntry(BaseModel):
    user_id: str
    revenue_cents: int
    tx_count: int
    avg_cents: int

class FinancialTrendsResponse(BaseModel):
    data: List[FinancialTrendPoint]
    granularity: str

class ProviderBreakdownResponse(BaseModel):
    data: List[ProviderBreakdownEntry]

class TopCreatorsResponse(BaseModel):
    data: List[TopCreatorEntry]
```

### 3.6 Frontend: Admin Financial Dashboard

**Route**: `/admin/financials` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/financials/FinancialDashboard.tsx`

Layout:

```tsx
<div className="space-y-6">
  {/* Date range picker */}
  <DateRangeSelector value={range} onChange={setRange} />

  {/* KPI Cards row */}
  <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
    <KpiCard title="GMV" value={formatCurrency(kpis.gmv_cents)} />
    <KpiCard title="Net Revenue" value={formatCurrency(kpis.net_revenue_cents)} />
    <KpiCard title="Take Rate" value={`${(kpis.take_rate_bps / 100).toFixed(1)}%`} />
    <KpiCard title="Transactions" value={kpis.tx_count.toLocaleString()} />
    <KpiCard title="Avg Transaction" value={formatCurrency(kpis.avg_tx_cents)} />
  </div>

  {/* Charts row */}
  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
    <Card className="lg:col-span-2">
      <CardHeader><CardTitle>Revenue Trends</CardTitle></CardHeader>
      <CardContent><TrendChart data={trends} /></CardContent>
    </Card>
    <Card>
      <CardHeader><CardTitle>Provider Split</CardTitle></CardHeader>
      <CardContent><ProviderPieChart data={providers} /></CardContent>
    </Card>
  </div>

  {/* Tables row */}
  <Tabs defaultValue="creators">
    <TabsList>
      <TabsTrigger value="creators">Top Creators</TabsTrigger>
      <TabsTrigger value="types">By Type</TabsTrigger>
    </TabsList>
    <TabsContent value="creators"><TopCreatorsTable data={topCreators} /></TabsContent>
    <TabsContent value="types"><TypeBreakdownTable data={types} /></TabsContent>
  </Tabs>

  {/* Export buttons */}
  <div className="flex gap-2">
    <Button onClick={exportCsv}><Download /> Export CSV</Button>
    <Button onClick={exportPdf} variant="outline"><FileText /> Export PDF</Button>
  </div>
</div>
```

### 3.7 Frontend API (`frontend/src/api/endpoints/adminFinancials.ts`)

```typescript
export const getFinancialKpis = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/financials/kpis", { params });

export const getFinancialTrends = (params: {
  start_date: string; end_date: string; granularity?: string
}) =>
  client.get("/v1/admin/financials/trends", { params });

export const getProviderBreakdown = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/financials/providers", { params });

export const getTypeBreakdown = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/financials/types", { params });

export const getTopCreators = (params: {
  start_date: string; end_date: string; limit?: number
}) =>
  client.get("/v1/admin/financials/top-creators", { params });

export const triggerRollup = (data: { date: string }) =>
  client.post("/v1/admin/financials/rollup", data);

export const exportFinancialCsv = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/financials/export/csv", { params, responseType: "blob" });

export const exportFinancialPdf = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/financials/export/pdf", { params, responseType: "blob" });
```

---

## 4. Implementation Plan

### Phase 1: Backend Data Layer (Days 1-3)

1. **`scripts/local-ddb-init.py`**: Add `financial_rollups` table definition. Add `GSI_LEDGER_DATE` GSI to `billing` table.
2. **`app/core/settings.py`**: Add `financial_rollups_table_name`.
3. **`app/core/tables.py`**: Add `financial_rollups` table handle.
4. **`app/services/financial_dashboard.py`**: New file. KPI computation, trend aggregation, provider/type breakdown, top creators, daily rollup, CSV/PDF export.
5. **`app/services/billing_shared.py`**: Update `new_ledger_entry` to write `ledger_date` field for the new GSI.

### Phase 2: Backend Router (Days 3-4)

6. **`app/models.py`**: Add financial dashboard Pydantic models.
7. **`app/routers/admin_financials.py`**: New router with 8 endpoints.
8. **`app/main.py`**: Register `admin_financials_router` with prefix `/v1/admin/financials`.

### Phase 3: Frontend (Days 5-8)

9. **`frontend/src/api/types.ts`**: Add TypeScript types for financial KPIs, trends, breakdowns.
10. **`frontend/src/api/endpoints/adminFinancials.ts`**: New file. API wrappers.
11. **`frontend/src/pages/admin/financials/FinancialDashboard.tsx`**: New page with KPI cards, trend chart, provider pie chart, top creators table, export buttons.
12. **`frontend/src/App.tsx`**: Add `/admin/financials` route.
13. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Financials" link under Admin section.

### Phase 4: E2E Tests (Days 9-10)

14. **`frontend/e2e/admin-financials.spec.ts`**: 15 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-financials.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root (admin), Alice (user), Charlie (admin)
- Seed billing ledger entries: 5 tip transactions, 3 unlock transactions, 2 subscription charges, 2 catalog purchases across Stripe and PayPal providers
- Trigger daily rollup via POST `/v1/admin/financials/rollup`

**Section 523: Financial KPI API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves financial KPIs for date range` | GET `/v1/admin/financials/kpis?start_date=...&end_date=...` as Root -> 200; response has `gmv_cents > 0`, `net_revenue_cents >= 0`, `take_rate_bps >= 0`, `tx_count > 0` |
| 2 | `KPIs include unique payer count` | Same response has `unique_payers >= 1`, `avg_tx_cents > 0` |
| 3 | `KPIs for empty date range return zeroes` | GET with future date range -> 200; `gmv_cents === 0`, `tx_count === 0` |
| 4 | `Non-admin cannot access KPIs` | GET as Alice -> 403 |

**Section 524: Revenue Trends API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Daily trends return time series` | GET `/v1/admin/financials/trends?granularity=daily&...` as Root -> 200; `data` is array, each entry has `date`, `gmv_cents`, `net_revenue_cents` |
| 6 | `Weekly granularity aggregates correctly` | GET with `granularity=weekly` -> 200; fewer entries than daily |
| 7 | `Trends data sorted by date ascending` | `data[0].date <= data[1].date` |
| 8 | `Invalid granularity returns 422` | GET with `granularity=hourly` -> 422 |

**Section 525: Provider & Type Breakdown API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Provider breakdown lists all active providers` | GET `/v1/admin/financials/providers` as Root -> 200; `data` array has entries with `provider`, `total_cents`, `tx_count`, `pct` |
| 10 | `Provider percentages sum to ~100` | Sum of `pct` values ~ 100 (within 1% tolerance) |
| 11 | `Type breakdown lists transaction types` | GET `/v1/admin/financials/types` -> 200; array includes entries for seeded types |
| 12 | `Top creators ranked by revenue descending` | GET `/v1/admin/financials/top-creators` -> 200; `data[0].revenue_cents >= data[1].revenue_cents` |

**Section 526: Export & Rollup API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `CSV export returns downloadable content` | GET `/v1/admin/financials/export/csv` as Root -> 200; content-type contains `text/csv`; body contains header row with `date,gmv_cents,net_revenue_cents` |
| 14 | `Root can trigger manual rollup` | POST `/v1/admin/financials/rollup` as Root -> 200; response has `computed_at` |
| 15 | `Non-root cannot trigger rollup` | POST as Charlie (ADMIN, not ROOT) -> 403 |

---

## 6. Security Considerations

### 6.1 Role-Based Access
- All read endpoints require ADMIN role (`require_admin_session`)
- Manual rollup trigger requires ROOT role (`require_root_session`)
- Financial data is sensitive; no public or user-level access

### 6.2 Data Sensitivity
- Top creator rankings expose relative revenue — restrict to admin dashboard only
- CSV/PDF exports should not be cached on CDN (set `Cache-Control: no-store`)
- Export downloads must be transmitted over HTTPS only

### 6.3 Rate Limiting
- Rollup computation is expensive; limit to 1 manual trigger per hour
- Export endpoints limited to 10 requests per minute per admin

### 6.4 Audit Trail
- All export requests logged with admin identity and date range
- Rollup triggers logged with admin identity and target date

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/financial_dashboard.py` | Financial aggregation, rollup, export |
| `app/routers/admin_financials.py` | Admin financial dashboard API (8 endpoints) |
| `frontend/src/api/endpoints/adminFinancials.ts` | API wrappers |
| `frontend/src/pages/admin/financials/FinancialDashboard.tsx` | Dashboard page |
| `frontend/e2e/admin-financials.spec.ts` | E2E tests (15 tests, sections 523-526) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add financial dashboard Pydantic models |
| `app/main.py` | Register `admin_financials_router` |
| `app/core/settings.py` | Add `financial_rollups_table_name` |
| `app/core/tables.py` | Add `financial_rollups` table handle |
| `scripts/local-ddb-init.py` | Add `financial_rollups` table + GSI on billing |
| `app/services/billing_shared.py` | Write `ledger_date` field in `new_ledger_entry` |
| `frontend/src/api/types.ts` | Add financial dashboard TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/financials` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Financials" admin nav link |

## 9. Acceptance Criteria

1. KPI endpoint returns GMV, net revenue, take rate, tx count, unique payers, and avg transaction for any date range
2. Trends endpoint returns daily/weekly/monthly time series data
3. Provider breakdown shows volume, count, and percentage per payment provider
4. Type breakdown shows volume and count per transaction type
5. Top creators endpoint returns creators ranked by revenue descending
6. Manual rollup trigger requires ROOT role and computes daily aggregation
7. CSV export produces valid CSV with financial summary data
8. Non-admin users receive 403 on all endpoints
9. All 15 E2E tests pass in `frontend/e2e/admin-financials.spec.ts`
