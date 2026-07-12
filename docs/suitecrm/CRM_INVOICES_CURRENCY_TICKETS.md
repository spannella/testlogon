# CRM Invoices, Line Items & Multi-currency (AOS) — Implementation Tickets

**Area**: Invoices, Line Items & Multi-currency (Advanced OpenSales / AOS)
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T2] Invoices, Line Items & Multi-currency (AOS) — 12 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Advanced OpenSales (AOS) Invoice module provides: standalone invoice creation (manual B2B and conversion from quotes), a draft→sent→paid→overdue→void/cancelled status lifecycle, line items with quantity × unit price = line total arithmetic, per-line tax rate assignment from a named tax group library, a configurable tax-group registry with jurisdiction labels, a discount line on the invoice header, billing and shipping address blocks, configurable payment terms (Net 30, Net 60, etc.) generating a due date, multi-currency invoicing with exchange-rate conversion at transaction time (original + USD amounts stored), and company-branding customization of the PDF (logo, company name, footer text).

testlogon already has: a fully functional auto-generated invoice system (`app/services/invoices.py`, `app/routers/invoices.py`) that creates PDF invoices from billing events with monotonic invoice numbers, S3 PDF storage, email delivery, and a two-GSI DynamoDB table (`T.invoices`). It stores a flat `currency` string and a single platform-wide `invoices_tax_bps` rate but has no jurisdiction tax registry, no per-line tax assignment, no exchange-rate conversion at transaction time, no billing/shipping address on invoices, no discount rendering, and no branding customization.

**Note on QUO-005 overlap**: The sibling ticket `docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md` (QUO-005) already specifies the invoice status lifecycle (draft/sent/paid/overdue/void), payment terms/due-date, manual B2B invoice creation endpoint, and the `InvoiceLineItemOut.unit_price_cents` field. The INV tickets here extend that foundation but do NOT re-specify what QUO-005 delivers. Each INV ticket explicitly calls out its dependency on QUO-005.

**Already PLANNED (not re-ticketed here)**:
- Exchange rate table with live rates per currency — covered by the Admin currency management ticket in `SUITECRM_GAP_ANALYSIS.md` §Security Suite/Admin ("Admin: currency management") and the FIN-005 spec referenced in the gap analysis header.
- Invoice shipping charge line — marked PLANNED in the gap analysis "Already PLANNED" section.

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag (default `"0"`, off) following the `cart_reminders_enabled` pattern at `app/core/settings.py:821`. With the flag off all new routes return 404 and all background work is a no-op. Existing invoice generation is byte-for-byte unchanged when flags are off.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables use the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha. No `if S.dev_mode` branches in service code; moto intercepts boto3 in dev exactly as in prod.
- **Reuse existing primitives — never fork**:
  - Invoice PDF rendering: `_render_pdf` / `_render_invoice_lines` at `app/services/invoices.py:103–188`; S3 helpers `_store_pdf` / `_fetch_pdf` at `app/services/invoices.py:195–209`.
  - Monotonic counter pattern: `_next_invoice_number` at `app/services/invoices.py:82–92` (atomic DynamoDB `ADD` on `COUNTER/SEQ` row).
  - Ledger entries: `billing_shared.new_ledger_entry` at `app/services/billing_shared.py:224`; `new_ledger_entry` always writes a `ledger_date` string for the financial dashboard.
  - Email dispatch: `app/services/alerts.send_alert_email` at `alerts.py:459`.
  - Audit events: `app/services/alerts.audit_event` at `alerts.py:644`.
  - Pagination: `encode_cursor` / `decode_cursor` at `app/core/cursor.py`.
  - Auth: `require_ui_session` at `app/services/sessions.py:330`; `require_admin_or_root` at `app/auth/policy.py:67`.
  - Billing config pattern (runtime-editable DDB override + in-memory cache): `app/services/billing_config.py` (single `pk="BILLING_CONFIG"` partition, `_cache_ttl`, `invalidate_cache`).
  - S3 client factory: `app.core.aws_clients.s3_client` (same as used in `invoices.py:35`).
- **Hermetic offline tests**: All pytest use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles, matching the pattern in `tests/test_gap_0220_0221_ssh_stored_key.py`. No real AWS or network calls.

---

### INV-001: Invoice line items — unit_price_cents, subtotal, discount, and address fields

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the existing invoice data model and PDF renderer to carry the fields that SuiteCRM invoices expose but testlogon currently omits: `unit_price_cents` on each line item (so a line is fully self-describing as qty × unit_price = line_amount), `discount_cents` and `shipping_cents` on the invoice header, and `billing_address` / `shipping_address` structs.

This ticket only touches `app/models.py`, `app/services/invoices.py`, and `app/routers/invoices.py` — no new DDB table is required because all new fields are additive attributes on the existing `T.invoices` items.

**Model changes** (`app/models.py`):

- `InvoiceLineItemOut` (at line 9539): add `unit_price_cents: int = 0`. The existing `amount_cents` field remains the persisted line total; `unit_price_cents` is the per-unit price before quantity multiplication.
- New `InvoiceAddressIn` / `InvoiceAddressOut` structs: `{street: str, city: str, state: str = "", postal_code: str, country: str}`.
- `InvoiceOut` (at line 9545): add `billing_address: Optional[InvoiceAddressOut] = None`, `shipping_address: Optional[InvoiceAddressOut] = None`, `discount_cents: int = 0`, `shipping_cents: int = 0`.

**Service changes** (`app/services/invoices.py`):

- `create_invoice(...)` signature gains keyword args: `unit_price_cents_per_item: Optional[List[int]] = None`, `discount_cents: int = 0`, `shipping_cents: int = 0`, `billing_address: Optional[dict] = None`, `shipping_address: Optional[dict] = None`. All are persisted on the DDB item.
- `norm_items` loop (at line 314): if `unit_price_cents_per_item` is provided, write `unit_price_cents` alongside existing `quantity` and `amount_cents` into each line item dict.
- `total_cents` computation: `total_cents = amount_cents + tax_cents + shipping_cents - discount_cents` (shipping and discount are already present on many platform billing calls but previously ignored).
- `_render_invoice_lines` (at line 150): add "Billing Address:" / "Shipping Address:" blocks after the bill-to/seller block; add a "Discount" row (negative) and "Shipping" row to the totals section. Both sections are omitted when the values are zero/None, so existing PDF output is unchanged for auto-generated invoices.
- `_serialize` (at line 218): include `unit_price_cents` on each line item, `discount_cents`, `shipping_cents`, `billing_address`, `shipping_address`.

**No new DDB tables or GSIs** — all new fields are stored as attributes on existing `pk=USER#{sub} / sk=INV#{number}` items.

**Settings**: No new flags; this extends under the existing `INVOICES_ENABLED` gate (`app/core/settings.py:2568`). A separate `AOS_INVOICE_FIELDS_ENABLED` flag (default `"0"`) gates the new fields in `create_invoice` so callers that do not pass the new args see no change; when off the new fields are silently ignored and the existing totals formula applies.

**Acceptance Criteria**

- `create_invoice(unit_price_cents_per_item=[1000, 500], discount_cents=200, billing_address={...})` persists all fields; `get_invoice` returns them in `InvoiceOut`.
- `InvoiceLineItemOut.unit_price_cents` is `0` (not an error) for invoices created without the field (backward compatibility).
- PDF downloaded via `GET /ui/invoices/{number}/pdf` shows "Discount" and "Billing Address" sections when values are non-zero/non-null; plain existing PDF when they are absent.
- `total_cents = amount_cents + tax_cents + shipping_cents - discount_cents` is correct.
- With `AOS_INVOICE_FIELDS_ENABLED=0` (default), calls to `create_invoice` without the new args behave identically to before.
- Hermetic offline test `tests/test_inv_001_line_item_fields.py` with moto DDB bound to `T.invoices` via `object.__setattr__`; covers create + serialize + PDF render.

**Dependencies**

- `AOS_INVOICE_FIELDS_ENABLED` flag (default off).
- Existing `app/services/invoices.py` (extended, not forked).
- Existing `app/models.py` `InvoiceOut`, `InvoiceLineItemOut` (additive only).
- QUO-005 (adds `unit_price_cents` to `InvoiceLineItemOut` as well — coordinate merge; INV-001 may land before or after QUO-005 but must not conflict on the same field).

---

### INV-002: Admin currency management — currency registry and exchange rates

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement the admin currency management surface: a DynamoDB-backed registry of supported currencies and their exchange rates relative to the platform's default currency (USD), admin CRUD endpoints, and a `get_exchange_rate(from_currency, to_currency)` accessor that the transaction-time conversion ticket (INV-003) will call. This is the foundation for all multi-currency work.

The gap analysis marks "Exchange rate table with live rates per currency" as PLANNED (not ticketed), but "Currency conversion at transaction/charge time" (INV-003) depends on a rate lookup function. This ticket delivers the rate registry as a dependency of INV-003; it does NOT implement live-rate fetching from an external feed (that remains in the planned Admin currency management ticket in the Security Suite area).

**DynamoDB table** (`crm_currencies`, env `CRM_CURRENCIES_TABLE_NAME`, default `"crm_currencies"`):

```
PK = CURRENCY#{iso_code}         # e.g. CURRENCY#EUR
SK = META
── iso_code       str             # ISO 4217 e.g. "eur", "gbp"
── name           str             # e.g. "Euro"
── symbol         str             # e.g. "€"
── rate_to_usd    Decimal          # e.g. 1.08  (1 EUR = 1.08 USD)
── is_default     bool
── is_active      bool
── decimal_places int              # 2 for most; 0 for JPY
── created_at     int (N)
── updated_at     int (N)
── GSI1: GSI1PK="CURRENCIES#ACTIVE", GSI1SK=iso_code (S) → list active currencies
```

`attr_types={"GSI1SK": "S"}` — sort key here is string (iso_code), not numeric; GSI1SK does NOT need `"N"`. GSI1SK is string so no `attr_types` numeric declaration needed.

**Service** (`app/services/crm_currencies.py`):

- `create_currency(iso_code, name, symbol, rate_to_usd, decimal_places=2, is_active=True, created_by=None)` — validates iso_code length (3 chars), normalizes to lowercase; writes DDB item; emits `audit_event("currency.created", ...)`.
- `update_currency(iso_code, **fields)` — only `name`, `symbol`, `rate_to_usd`, `is_active`, `decimal_places` are mutable; emits `audit_event("currency.rate_updated", ...)`.
- `get_currency(iso_code) -> dict | None`
- `list_currencies(active_only=True) -> list[dict]` — queries GSI1 when `active_only=True`; full scan otherwise.
- `get_exchange_rate(from_iso: str, to_iso: str) -> Decimal` — looks up both currencies; returns `from_rate_to_usd / to_rate_to_usd` for cross-rate conversion. When `from_iso == "usd"` (default), returns `1 / to_rate_to_usd`. Raises `ValueError` if either currency is not found or inactive.
- `convert_amount(amount_cents: int, from_iso: str, to_iso: str) -> int` — applies `get_exchange_rate` and rounds to integer cents.
- All functions gated on `S.crm_currencies_enabled`.

**Router** (`app/routers/crm_currencies.py`, prefix `/ui/admin/currencies`):

All endpoints require `require_admin_or_root` (`app/auth/policy.py:67`).

- `POST /ui/admin/currencies` — body `CurrencyCreateIn`; returns `CurrencyOut`.
- `GET /ui/admin/currencies` — query `?active_only=true`; returns `CurrencyListOut`.
- `GET /ui/admin/currencies/{iso_code}` — returns `CurrencyOut`.
- `PATCH /ui/admin/currencies/{iso_code}` — body `CurrencyPatchIn`; returns `CurrencyOut`.

**Pydantic models** added to `app/models.py`:

- `CurrencyCreateIn` (iso_code, name, symbol, rate_to_usd: Decimal, decimal_places=2, is_active=True)
- `CurrencyPatchIn` (name, symbol, rate_to_usd, is_active, decimal_places — all optional)
- `CurrencyOut` (iso_code, name, symbol, rate_to_usd, decimal_places, is_active, created_at, updated_at)
- `CurrencyListOut` (currencies: list[CurrencyOut])

**Settings** added to `app/core/settings.py` (after `invoices_tax_bps` at line 2569):

```python
crm_currencies_enabled: bool = os.environ.get("CRM_CURRENCIES_ENABLED", "0") not in ("1", "true")
crm_currencies_table_name: str = os.environ.get("CRM_CURRENCIES_TABLE_NAME", "crm_currencies")
```

Register router in `app/main.py` alongside `invoices_admin_router`.

**Acceptance Criteria**

- Admin can create EUR with `rate_to_usd=1.08`; `get_exchange_rate("usd", "eur")` returns `Decimal("0.9259...")`.
- `convert_amount(10000, "usd", "eur")` returns `9259` (rounded cents).
- `list_currencies(active_only=True)` queries GSI1 and excludes inactive currencies.
- Deactivating a currency (`is_active=False`) excludes it from the active list.
- With `CRM_CURRENCIES_ENABLED=0` all endpoints return 404 and `get_exchange_rate` raises `ValueError("currency management not enabled")`.
- Hermetic offline test `tests/test_inv_002_currencies.py` with moto DDB; covers create / rate update / cross-rate conversion math / inactive exclusion.

**Dependencies**

- `CRM_CURRENCIES_ENABLED` flag (default off).
- INV-003 (transaction-time currency conversion) depends on `crm_currencies.get_exchange_rate`.
- INV-004 (multi-currency on invoices) depends on this ticket.

---

### INV-003: Currency conversion at transaction / charge time

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

When an invoice is created in a non-USD currency (or when the buyer pays in a currency different from the invoice currency), record both the original currency amount and the USD equivalent computed using the live exchange rate from INV-002. This satisfies the "Currency conversion at transaction / charge time" gap and enables accurate financial reporting in a single base currency alongside multi-currency display.

**Schema extension on existing `T.invoices` items** (no new table):

Add four new attributes to `pk=USER#{sub} / sk=INV#{number}` items:

- `original_currency: str` — the currency code provided at invoice creation (e.g. `"eur"`).
- `original_amount_cents: int` — the amount in the original currency.
- `usd_amount_cents: int` — the equivalent amount in USD, computed at creation time via `crm_currencies.convert_amount(original_amount_cents, original_currency, "usd")`.
- `exchange_rate_snapshot: Decimal` — the `rate_to_usd` value used at conversion time, stored for audit purposes.

When `original_currency == "usd"` (or `CRM_CURRENCIES_ENABLED=0`), all four fields are set to the existing values without any conversion call.

**Service changes** (`app/services/invoices.py`):

In `create_invoice(...)` (at line 272), after the existing tax/total computation block:

```python
if S.crm_currencies_enabled and currency and currency != "usd":
    try:
        from app.services.crm_currencies import convert_amount, get_exchange_rate
        rate = get_exchange_rate(currency, "usd")
        usd_amount = convert_amount(amount_cents, currency, "usd")
    except Exception:
        rate = Decimal("1")
        usd_amount = amount_cents
else:
    rate = Decimal("1")
    usd_amount = amount_cents
```

Store `original_currency`, `original_amount_cents = amount_cents`, `usd_amount_cents = usd_amount`, `exchange_rate_snapshot = rate` on the DDB `record` dict. The existing `currency` field and `amount_cents` continue to store the invoice-currency values unchanged, preserving backward compatibility.

**Model changes** (`app/models.py`):

`InvoiceOut` gains optional additive fields:

- `original_currency: str = ""` — original currency code.
- `original_amount_cents: int = 0`
- `usd_amount_cents: int = 0`
- `exchange_rate_snapshot: Optional[float] = None` (Decimal serialized to float for JSON).

`_serialize` in `app/services/invoices.py:218` maps these new DDB attributes.

**Router**: No new endpoints. `GET /ui/invoices/{number}` and the admin list endpoints surface the new fields via the updated `InvoiceOut` model automatically.

**Settings** added to `app/core/settings.py`:

```python
aos_invoice_currency_conversion_enabled: bool = os.environ.get(
    "AOS_INVOICE_CURRENCY_CONVERSION_ENABLED", "0"
) not in ("1", "true")
```

The conversion block in `create_invoice` is additionally gated on this flag (in addition to `crm_currencies_enabled`) so it can be turned on independently once the currency registry is populated.

**Acceptance Criteria**

- Creating an invoice with `currency="eur"` and EUR/USD rate = 1.08 stores `usd_amount_cents = round(amount_cents * 1.08)` and `exchange_rate_snapshot = 1.08`.
- When `CRM_CURRENCIES_ENABLED=0` or `AOS_INVOICE_CURRENCY_CONVERSION_ENABLED=0`, `create_invoice` with any currency stores the amount unchanged (no conversion call).
- When the exchange rate lookup fails (unknown currency), the invoice is still created with `usd_amount_cents = amount_cents` (fail-open, best-effort conversion).
- Existing invoices with no `original_currency` field return `original_currency=""` and `usd_amount_cents=0` (backward compatible defaults on `InvoiceOut`).
- Hermetic offline test `tests/test_inv_003_currency_conversion.py` with moto DDB; moto `T.crm_currencies` bound via `object.__setattr__`; tests correct conversion math, flag-off no-op, and fail-open behavior.

**Dependencies**

- `AOS_INVOICE_CURRENCY_CONVERSION_ENABLED` flag (default off).
- INV-002 (`crm_currencies.get_exchange_rate`, `crm_currencies.convert_amount`) — must ship before or alongside.
- Existing `app/services/invoices.py:272` `create_invoice` (extended, not forked).

---

### INV-004: Multi-currency on invoices — currency display and exchange rate on invoice PDF

**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Surface multi-currency information in the invoice PDF and in the `InvoiceOut` model so a customer receiving a EUR invoice sees EUR amounts, and the admin can see both the EUR and USD values. This is a thin rendering extension that builds on INV-002 (registry) and INV-003 (stored conversion).

**PDF renderer changes** (`app/services/invoices.py`, `_render_invoice_lines` at line 150):

- `_money()` helper (line 146) updated to accept an optional currency code and symbol; e.g. `_money(1000, "eur", "€")` → `"€10.00"`. Falls back to `"$"` when no symbol.
- In `_render_invoice_lines`, if `record.get("original_currency")` is non-empty and != `"usd"`:
  - All line-item and total amounts are rendered in the original currency with its symbol (looked up from `crm_currencies.get_currency()`, fail-open fallback to the iso code string).
  - Append a "USD equivalent:" line at the foot of the totals block showing `usd_amount_cents` in USD, and "Rate: 1 {orig} = {rate} USD".
  - When currency == "usd" (or `original_currency` is absent), the PDF is unchanged from today.

**`InvoiceOut` already carries** `original_currency`, `usd_amount_cents`, `exchange_rate_snapshot` from INV-003. No additional model changes needed.

**Frontend (`frontend/src/pages/billing/InvoiceRow.tsx`)**: Add a currency badge next to the total amount when `original_currency` is non-empty and != `"usd"` (e.g. "€10.00 EUR"). The `frontend/src/api/types.ts` `Invoice` type gains the three new fields from INV-003. No new API endpoints.

**Acceptance Criteria**

- An invoice created with `currency="eur"` and EUR symbol "€" renders line-item amounts as "€N.NN" in the PDF.
- PDF footer includes "USD equivalent: $N.NN" and "Rate: 1 EUR = 1.08 USD" when exchange rate was recorded.
- USD invoices produce an identical PDF to today (no currency lines appended).
- `InvoiceRow.tsx` displays "€10.00 EUR" badge for EUR invoices.
- Hermetic offline test `tests/test_inv_004_multicurrency_pdf.py` verifies that rendered PDF bytes include the EUR symbol and USD equivalent line.

**Dependencies**

- INV-002 (currency registry, for symbol lookup).
- INV-003 (stored `usd_amount_cents`, `exchange_rate_snapshot` on invoice record).
- Existing `app/services/invoices.py:150` `_render_invoice_lines` (extended).

---

### INV-005: Named tax groups and jurisdiction tax rate registry

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Build a configurable tax rate registry: admins define named tax groups (e.g. "CA Sales Tax 9.5%", "VAT EU Standard 20%") with a jurisdiction label and a rate in basis points. Tax groups are then referenced at line-item level (INV-006). This ticket delivers the data model, service, and admin CRUD endpoints; it does NOT yet wire tax groups into invoice creation (that is INV-006).

**DynamoDB table** (`crm_tax_rates`, env `CRM_TAX_RATES_TABLE_NAME`, default `"crm_tax_rates"`):

```
PK = TAXRATE#{tax_rate_id}       # "tr_" + uuid4().hex[:12]
SK = META
── name          str              # e.g. "CA Sales Tax"
── rate_bps      int              # basis points, e.g. 950 for 9.5%
── jurisdiction  str              # ISO 3166-1 alpha-2 country or "US-CA" subdivision
── description   str | ""
── is_active     bool
── created_by    str
── created_at    int (N)
── updated_at    int (N)
── GSI1: GSI1PK="TAXRATES#ACTIVE", GSI1SK=name (S) → list active rates alphabetically
── GSI2: GSI2PK=f"JURISDICTION#{jurisdiction}", GSI2SK=name (S) → rates by jurisdiction
```

No numeric GSI sort keys on this table; both GSI sort keys are string (name), so no `attr_types` numeric declaration needed.

**Service** (`app/services/crm_tax_rates.py`):

- `create_tax_rate(name, rate_bps, jurisdiction, description="", created_by=None) -> dict` — validates `rate_bps` in `[0, 10000]`; writes DDB item; emits `audit_event("tax_rate.created", ...)`.
- `update_tax_rate(tax_rate_id, **fields)` — only `name`, `rate_bps`, `jurisdiction`, `description`, `is_active` are mutable; emits `audit_event("tax_rate.updated", ...)`.
- `get_tax_rate(tax_rate_id) -> dict | None`
- `list_tax_rates(jurisdiction=None, active_only=True) -> list[dict]` — when `jurisdiction` is provided, queries GSI2; else queries GSI1 (active only) or scans.
- `get_tax_rate_by_name(name) -> dict | None` — used by invoice creation to resolve a name to `rate_bps`.
- All functions gated on `S.crm_tax_rates_enabled`.

**Router** (`app/routers/crm_tax_rates.py`, prefix `/ui/admin/tax-rates`):

All endpoints require `require_admin_or_root` (`app/auth/policy.py:67`).

- `POST /ui/admin/tax-rates` — body `TaxRateCreateIn`; returns `TaxRateOut`.
- `GET /ui/admin/tax-rates` — query `?jurisdiction=US-CA&active_only=true`; returns `TaxRateListOut`.
- `GET /ui/admin/tax-rates/{tax_rate_id}` — returns `TaxRateOut`.
- `PATCH /ui/admin/tax-rates/{tax_rate_id}` — body `TaxRatePatchIn`; returns `TaxRateOut`.

**Pydantic models** added to `app/models.py`:

- `TaxRateCreateIn` (name, rate_bps: int ge=0 le=10000, jurisdiction, description="")
- `TaxRatePatchIn` (name, rate_bps, jurisdiction, description, is_active — all optional)
- `TaxRateOut` (tax_rate_id, name, rate_bps, jurisdiction, description, is_active, created_at, updated_at)
- `TaxRateListOut` (tax_rates: list[TaxRateOut])

**Settings** added to `app/core/settings.py`:

```python
crm_tax_rates_enabled: bool = os.environ.get("CRM_TAX_RATES_ENABLED", "0") not in ("1", "true")
crm_tax_rates_table_name: str = os.environ.get("CRM_TAX_RATES_TABLE_NAME", "crm_tax_rates")
```

Register router in `app/main.py` alongside `invoices_admin_router`.

**Acceptance Criteria**

- Admin creates "CA Sales Tax" at 950 bps for jurisdiction "US-CA"; `list_tax_rates(jurisdiction="US-CA")` returns it.
- `get_tax_rate_by_name("CA Sales Tax")` returns the correct `rate_bps`.
- Deactivating a tax rate removes it from `list_tax_rates(active_only=True)`.
- `rate_bps` outside `[0, 10000]` is rejected with 422.
- With `CRM_TAX_RATES_ENABLED=0` all endpoints return 404.
- Hermetic offline test `tests/test_inv_005_tax_rates.py` with moto DDB; covers CRUD, jurisdiction filter, and active-only exclusion.

**Dependencies**

- `CRM_TAX_RATES_ENABLED` flag (default off).
- INV-006 (per-line tax assignment) depends on this ticket.

---

### INV-006: Per-line-item tax rate assignment on invoices

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Allow each invoice line item to carry its own tax rate, either specified as raw `tax_rate_bps` or by reference to a named tax group from INV-005. The per-line tax is computed at invoice creation time, summed to `tax_cents`, and rendered in the PDF as a per-line tax column. This replaces the current single platform-wide `invoices_tax_bps` fallback for invoices that opt in.

**Model changes** (`app/models.py`):

- `InvoiceLineItemOut` (at line 9539): add `tax_rate_bps: int = 0` and `tax_cents: int = 0` (per-line computed tax, not total invoice tax).
- `InvoiceOut`: add `tax_breakdown: list[dict] = []` — list of `{name, rate_bps, tax_cents}` entries aggregating per-rate contributions across all lines. Used for itemized tax display.

**Service changes** (`app/services/invoices.py`):

In `create_invoice(...)`, extend the line-item normalization loop (at line 314). Each incoming line item may carry `tax_rate_bps: int` (raw) or `tax_rate_id: str` (looked up via `crm_tax_rates.get_tax_rate` from INV-005). Resolution:

```python
# For each line item li:
raw_bps = int(li.get("tax_rate_bps", 0))
tax_rate_id = li.get("tax_rate_id", "")
if not raw_bps and tax_rate_id and S.crm_tax_rates_enabled:
    tr = crm_tax_rates.get_tax_rate(tax_rate_id)
    if tr and tr.get("is_active"):
        raw_bps = int(tr.get("rate_bps", 0))
line_tax = (line_amount * raw_bps) // 10_000
norm_item["tax_rate_bps"] = raw_bps
norm_item["tax_cents"] = line_tax
```

After the loop, `total_tax_cents = sum(item["tax_cents"] for item in norm_items)`. When `total_tax_cents > 0`, it overrides the platform-wide `invoices_tax_bps` fallback computation; when all per-line rates are 0, the existing fallback `tax_cents = (amount_cents * S.invoices_tax_bps) // 10_000` applies unchanged.

`_render_invoice_lines` (at line 174): when any line item has `tax_rate_bps > 0`, add a "Tax Rate" column to the line-item table header and a per-line tax-rate display (e.g. `"9.5%"`). In the totals block, render `tax_breakdown` entries as separate rows (e.g. `"CA Sales Tax (9.5%): $0.95"`).

**`_serialize`** (at line 218): include `tax_rate_bps` and `tax_cents` on each serialized line item; compute and include `tax_breakdown`.

**Settings** added to `app/core/settings.py`:

```python
aos_per_line_tax_enabled: bool = os.environ.get("AOS_PER_LINE_TAX_ENABLED", "0") not in ("1", "true")
```

The per-line tax logic block in `create_invoice` is gated on this flag. When off, all `tax_rate_bps` and `tax_rate_id` fields in line items are silently ignored and the existing platform-wide `invoices_tax_bps` applies.

**Acceptance Criteria**

- `create_invoice` with two line items at `tax_rate_bps=950` each computes `line_tax = (line_amount * 950) // 10000` per line; `InvoiceOut.tax_cents` equals the sum.
- Line item with `tax_rate_id=<id>` resolves to the named tax group's `rate_bps` via `crm_tax_rates.get_tax_rate`.
- When all line items have `tax_rate_bps=0`, the existing `invoices_tax_bps` platform rate applies unchanged.
- PDF includes "Tax Rate" column and itemized tax breakdown rows.
- With `AOS_PER_LINE_TAX_ENABLED=0` (default), line-item `tax_rate_bps` fields are ignored and output is identical to today.
- Hermetic offline test `tests/test_inv_006_per_line_tax.py` with moto DDB; patched `crm_tax_rates.get_tax_rate`; covers both raw bps path and tax_rate_id lookup path, and the platform-fallback path.

**Dependencies**

- `AOS_PER_LINE_TAX_ENABLED` flag (default off).
- INV-005 (`crm_tax_rates.get_tax_rate`) — optional dependency; per-line tax works without INV-005 when callers supply raw `tax_rate_bps`.
- Existing `app/services/invoices.py:272` `create_invoice` and `_render_invoice_lines` (extended, not forked).
- QUO-001 (`docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md`) already carries `tax_rate_bps` on quote line items — the same bps value flows through QUO-003 quote-to-invoice conversion without needing a `tax_rate_id` lookup.

---

### INV-007: Invoice-level discount rendering

**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

The gap analysis lists "Invoice-level discount line" as PARTIAL — `create_invoice` does not currently receive or persist `discount_cents`, and `_render_invoice_lines` does not render a discount row. INV-001 adds `discount_cents` to the model and PDF renderer as part of the broader field extension. This ticket is therefore a focused check that the discount rendering added in INV-001 is complete and correct, and that the `VALID_TYPES` guard and ledger integration correctly reflect discounts.

**Changes beyond INV-001** (INV-001 already adds `discount_cents` to the model and `_render_invoice_lines`):

- In `create_invoice(...)`: when `discount_cents > amount_cents`, cap it at `amount_cents` and log a warning (negative totals are rejected).
- Write `discount_cents` as a negative `new_ledger_entry` extra field so the platform financial dashboard (`app/services/platform_financial_dashboard.py`) can report net revenue after discounts.
- Add `invoice.discount_cents` to `_serialize` and confirm it is returned in `InvoiceOut`.
- `_render_invoice_lines` discount row: show `"Discount"` as a separate line with a negative formatted amount (e.g. `"-$2.00"`), placed after the subtotal and before tax.

**Acceptance Criteria**

- `create_invoice(amount_cents=1000, discount_cents=200, tax_cents=80)` stores `total_cents=880` and `discount_cents=200`; PDF shows "Discount: -$2.00" line.
- `discount_cents > amount_cents` is capped and logged, not silently producing negative totals.
- `InvoiceOut.discount_cents` defaults to `0` for old invoices (backward compatible).
- Existing invoices with no discount are byte-for-byte unchanged.
- Unit test `tests/test_inv_007_discount_line.py` covers cap logic, PDF row presence, and zero-discount backward compatibility.

**Dependencies**

- INV-001 (adds `discount_cents` field and initial `_render_invoice_lines` row — INV-007 verifies and strengthens that work).
- `AOS_INVOICE_FIELDS_ENABLED` flag (from INV-001, same gate).
- Existing `app/services/billing_shared.py:224` `new_ledger_entry` (extra field pass-through pattern per CLAUDE.md ledger provider attribution note).

---

### INV-008: Invoice PDF branding — admin-configurable logo, company name, and footer

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Allow admins to customize the invoice PDF with company-specific branding: a company logo (uploaded to S3), a company name, a company address block, and a footer text line. The branding config is stored in DynamoDB (single-row, reusing the `billing_config` single-partition pattern from `app/services/billing_config.py`) and is loaded at PDF render time with a short in-memory cache to avoid a DDB read per invoice.

**Storage**: Single row in the existing `T.billing_config` table (no new table needed):

```
pk = "INVOICE_BRANDING"
sk = "CURRENT"
── company_name   str
── company_address_lines  list[str]   # up to 5 lines
── footer_text    str
── logo_s3_key    str | ""            # e.g. "invoice-branding/logo.png"
── logo_bucket    str | ""
── updated_at     int
── updated_by     str
```

Uses the existing `T.billing_config` table (`app/core/settings.py:2625`) — no new table, no schema change to `scripts/local-ddb-init.py`.

**Service** (`app/services/invoice_branding.py`):

- `get_branding() -> dict` — reads `pk="INVOICE_BRANDING" / sk="CURRENT"` from `T.billing_config`; caches for `S.invoice_branding_cache_ttl_seconds` (default 60); returns defaults (empty company name / footer) on cache miss.
- `update_branding(admin_sub, company_name=None, company_address_lines=None, footer_text=None) -> dict` — writes the row, invalidates cache, emits `audit_event("invoice_branding.updated", ...)`.
- `upload_logo(admin_sub, image_bytes, content_type) -> str` — stores logo at `invoice-branding/logo.{ext}` in `S.filemgr_bucket` via `app.core.aws_clients.s3_client`; updates `logo_s3_key` in branding row; returns the S3 key.
- `get_logo_bytes() -> Optional[bytes]` — fetches logo from S3 using `_fetch_pdf` pattern from `app/services/invoices.py:204`; returns `None` when no logo configured or on S3 error.

**PDF renderer changes** (`app/services/invoices.py`, `_render_invoice_lines` at line 158):

When `S.aos_invoice_branding_enabled` is on, call `invoice_branding.get_branding()` at the start of `_render_invoice_lines`. Prepend:

```
{company_name}
{company_address_line_1}
...
{company_address_line_N}
==========================================
```

Replace the hardcoded `"INVOICE"` header with `f"{company_name} INVOICE"` when company_name is non-empty. Append `footer_text` as the last line before `"Thank you for your purchase."`. Logo embedding in the text-based PDF is not feasible (it is a pure-PostScript text renderer per `app/services/invoices.py:8–10`); instead, a `"[Logo: {s3_key}]"` placeholder line is written so the QUO-002 PDF template engine (when configured) can inject a real image. When `AOS_INVOICE_BRANDING_ENABLED=0` or branding returns empty values, the PDF is unchanged from today.

**Router additions** to `app/routers/invoices.py` (`invoices_admin_router`, prefix `/ui/admin/invoices`):

- `GET /ui/admin/invoices/branding` — `require_admin_or_root`; returns `InvoiceBrandingOut`.
- `PATCH /ui/admin/invoices/branding` — `require_admin_or_root`; body `InvoiceBrandingPatchIn`; returns `InvoiceBrandingOut`.
- `POST /ui/admin/invoices/branding/logo` — `require_admin_or_root`; multipart `image/png` or `image/jpeg` upload; calls `invoice_branding.upload_logo`; returns `{"logo_s3_key": "..."}`.

Declare these **before** `/{invoice_number}` in the router to avoid the literal `branding` being captured as an invoice number (same ordering rule as KYC templates endpoint per CLAUDE.md).

**Pydantic models** added to `app/models.py`:

- `InvoiceBrandingPatchIn` (company_name, company_address_lines: Optional[list[str]], footer_text — all optional)
- `InvoiceBrandingOut` (company_name, company_address_lines, footer_text, logo_s3_key, updated_at)

**Settings** added to `app/core/settings.py`:

```python
aos_invoice_branding_enabled: bool = os.environ.get("AOS_INVOICE_BRANDING_ENABLED", "0") not in ("1", "true")
invoice_branding_cache_ttl_seconds: int = int(os.environ.get("INVOICE_BRANDING_CACHE_TTL_SECONDS", "60"))
```

**Acceptance Criteria**

- Admin updates company_name to "Acme Corp" and footer_text to "Net 30"; subsequent `GET /ui/invoices/{number}/pdf` includes "Acme Corp INVOICE" and "Net 30" footer.
- With `AOS_INVOICE_BRANDING_ENABLED=0` (default), the PDF is byte-for-byte unchanged from today.
- Logo upload stores bytes in S3 at `invoice-branding/logo.png`; branding row carries the key.
- `GET /ui/admin/invoices/branding` does not conflict with `GET /ui/admin/invoices/{invoice_number}` (route ordering test).
- Cache invalidation: after `update_branding`, the next PDF render uses new values.
- Hermetic offline test `tests/test_inv_008_branding.py` with moto DDB + patched S3; covers branding update, cache invalidation, PDF line presence, and flag-off invariant.

**Dependencies**

- `AOS_INVOICE_BRANDING_ENABLED` flag (default off).
- Existing `T.billing_config` table (no new table needed).
- Existing `app/services/invoices.py:150` `_render_invoice_lines` (extended).
- Existing `app.core.aws_clients.s3_client` (same usage as `invoices.py:35`).
- QUO-002 (`docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md`) — the AOS PDF template engine can later replace the text-based fallback with a real branded PDF; INV-008 branding config is also readable by QUO-002's `render_template` merge vars.

---

### INV-009: Invoice status lifecycle extension and overdue checker (dependency bridge to QUO-005)

**Type:** Chore  **Priority:** P1  **Estimate:** 1d

**Description**

QUO-005 (`docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md`) specifies the full invoice lifecycle (draft/sent/paid/overdue/void), the `update_invoice_status` function, the void endpoint, and the overdue background checker. Several other INV tickets (INV-003, INV-007) call `update_invoice_status` or depend on `status="void"` being present. This ticket is a coordination and integration chore: it ensures the INV ticket set integrates cleanly with QUO-005 on the shared `app/services/invoices.py` and `app/models.py` files, and it authors the E2E test coverage for the AOS invoice lifecycle as it applies to B2B invoices created via INV-001.

**Scope** (no new backend implementation beyond QUO-005 — this ticket co-authors tests and integration glue):

1. **Confirm QUO-005 is delivered first** (hard dependency). If QUO-005 is merged, this ticket closes immediately; if not yet merged, this ticket is the blocker for INV-003 void integration.

2. **Integration test** `tests/test_inv_009_invoice_lifecycle.py` — covers the full lifecycle for a manually-created B2B invoice (from `POST /ui/admin/invoices/manual` → draft → sent → paid → overdue → void) with moto DDB. Verifies:
   - A `paid→void` transition writes a reversal `new_ledger_entry` (negative amount) via `billing_shared.new_ledger_entry` at `app/services/billing_shared.py:224`.
   - The overdue checker correctly marks invoices where `due_date < now_ts()` and `status="sent"`.
   - The void endpoint at `POST /ui/invoices/{number}/void` is authenticated via `require_ui_session` (owner-only) and returns 403 for a different user's invoice.

3. **Frontend wiring**: `frontend/src/api/endpoints/invoices.ts` gains `voidInvoice(invoiceNumber)` and `patchInvoiceStatus(invoiceNumber, status)` wrappers (POST and PATCH respectively). `frontend/src/pages/billing/InvoicesPage.tsx` adds a "Void" action button on draft and sent invoices.

**Acceptance Criteria**

- QUO-005 is a hard prerequisite; this ticket's tests pass only after QUO-005 is merged.
- Full lifecycle test passes with moto DDB, including ledger reversal on paid→void.
- `InvoicesPage` renders a "Void" button for `status=draft` and `status=sent` invoices; button calls `voidInvoice` and invalidates the `["invoices"]` React Query key.
- Ownership check: voiding another user's invoice returns 403.

**Dependencies**

- QUO-005 (`docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md`) — hard prerequisite; delivers `update_invoice_status`, void endpoint, and overdue checker.
- INV-001 (billing_address/discount fields co-tested in the B2B invoice lifecycle test).
- INV-007 (discount ledger integration tested here).
- Existing `app/services/billing_shared.py:224` `new_ledger_entry`.
- `frontend/src/api/endpoints/invoices.ts` (extended, not forked).

---

### INV-010: Invoice CRM record linking — account and contact association

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Invoices in SuiteCRM can be linked to an Account (B2B organization) and a Contact (individual buyer). testlogon's invoices currently carry only flat `buyer_name` / `buyer_email` strings. This ticket adds optional `account_id` / `contact_id` reference fields to invoices so they can be related to Party/Contact records once the PTY module ships, and immediately enables a per-account invoice list query.

**Schema extension on existing `T.invoices` items** (no new table):

Add new attributes to `pk=USER#{sub} / sk=INV#{number}` items:

- `account_id: str | ""` — future PTY-012 PARTY_GROUP party_id (set by QUO-003 quote-to-invoice conversion or manual invoice creation).
- `contact_id: str | ""` — future PTY-011 PERSON party_id.

**New GSI on `T.invoices`** — add `GSI3` to the existing `invoices` TableDef in `scripts/local-ddb-init.py`:

```
GSI3PK = ACCOUNT#{account_id}     (string; omitted when account_id is empty)
GSI3SK = created_at               (N)
```

`attr_types` addition: `"GSI3SK": "N"` alongside existing `"GSI1SK": "N", "GSI2SK": "N"` at line 2277.

**Service changes** (`app/services/invoices.py`):

- `create_invoice(...)` gains `account_id: str = ""`, `contact_id: str = ""`. When `account_id` is non-empty, write `GSI3PK = f"ACCOUNT#{account_id}"` and `GSI3SK = created_at` onto the item.
- New `list_invoices_for_account(account_id, limit=50, cursor=None) -> dict` — queries GSI3 by `GSI3PK = "ACCOUNT#{account_id}"`, `ScanIndexForward=False`; returns paginated invoice list.
- `_serialize`: include `account_id` and `contact_id`.

**Model changes** (`app/models.py`):

- `InvoiceOut`: add `account_id: str = ""`, `contact_id: str = ""`.

**Router additions** to `app/routers/invoices.py`:

- `GET /ui/admin/invoices/by-account/{account_id}` — `require_admin_or_root`; queries `list_invoices_for_account`; returns `InvoiceListOut`. Route declared before `/{invoice_number}` to avoid capture.

**Acceptance Criteria**

- `create_invoice(account_id="acct_123")` stores `GSI3PK="ACCOUNT#acct_123"` on the item; `list_invoices_for_account("acct_123")` returns it.
- Invoices without `account_id` are not written to GSI3 (sparse GSI — no `GSI3PK` attribute on item, DDB omits them automatically).
- `InvoiceOut.account_id` defaults to `""` for old invoices (backward compatible).
- `GET /ui/admin/invoices/by-account/acct_123` requires ADMIN or ROOT role; returns 403 otherwise.
- Hermetic offline test `tests/test_inv_010_crm_linking.py` with moto DDB + GSI3 declared; covers create with account_id, list by account, and sparse-GSI omission for no-account invoices.

**Dependencies**

- `AOS_INVOICE_FIELDS_ENABLED` flag (from INV-001; `account_id`/`contact_id` also gated).
- Existing `app/services/invoices.py` and `scripts/local-ddb-init.py` (additive GSI3 — requires `just restart` after DDB init script change in dev).
- PTY-011 / PTY-012 (`docs/suitecrm/CRM_CONTACTS_EXTRA_TICKETS.md` / PARTY_CRM_TICKETS): when those ship, `contact_id` and `account_id` values will be resolvable to full Party records. Until then they are opaque strings stored for future linking.

---

### INV-011: Invoice frontend — admin invoice management UI

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Build the admin-facing invoice management UI so sales reps and admins can create B2B invoices, view all invoices across users, filter by status/account, and perform lifecycle actions (send, void). The user-facing `frontend/src/pages/billing/InvoicesPage.tsx` and `InvoiceRow.tsx` already exist; this ticket adds an admin view and a manual invoice creation form.

**New frontend files**:

- `frontend/src/pages/billing/AdminInvoicesPage.tsx` — admin invoice list with filters: user_sub, status (all/draft/sent/paid/overdue/void), date range. Uses `useQuery(["admin-invoices", filters], () => adminListInvoices(filters))`. Shows a table with invoice_number, buyer_name, total_cents (with currency badge from INV-004), status badge, due_date (from QUO-005/INV-009), and action buttons (Send, Void, Download PDF).
- `frontend/src/pages/billing/ManualInvoiceForm.tsx` — form using React Hook Form + Zod. Fields: buyer_name, buyer_email, billing_address (street/city/state/postal_code/country from INV-001), currency (select from active currencies via `listCurrencies()` from INV-002 endpoint), payment_terms_days (default 30, from QUO-005), dynamic line items (add/remove rows with description, quantity, unit_price_cents, tax_rate_id select from `listTaxRates()` from INV-005). On submit calls `createManualInvoice(data)`.

**New API endpoint wrappers** (`frontend/src/api/endpoints/invoices.ts`):

- `adminListInvoices(params)` — `GET /ui/admin/invoices` (exists in router).
- `createManualInvoice(body)` — `POST /ui/admin/invoices/manual` (from QUO-005).
- `sendInvoice(invoiceNumber)` — `POST /ui/invoices/{number}/send` (status transition from QUO-005 via `update_invoice_status`).
- `listCurrencies()` — `GET /ui/admin/currencies` (from INV-002).
- `listTaxRates()` — `GET /ui/admin/tax-rates` (from INV-005).

**TypeScript types** (`frontend/src/api/types.ts`):

- `Invoice` type gains: `original_currency`, `usd_amount_cents`, `exchange_rate_snapshot` (from INV-003), `billing_address`, `discount_cents` (from INV-001), `account_id`, `contact_id` (from INV-010), `payment_terms_days`, `due_date`, `voided_at` (from QUO-005/INV-009).
- New `Currency` type (from INV-002 `CurrencyOut`).
- New `TaxRate` type (from INV-005 `TaxRateOut`).

**Route** added to `frontend/src/App.tsx`:

```tsx
{ path: "/admin/invoices", element: lazy(() => import("@/pages/billing/AdminInvoicesPage")) }
```

**Acceptance Criteria**

- Admin navigating to `/admin/invoices` sees all invoices; filtering by `status=draft` shows only draft invoices.
- "Create Invoice" button opens `ManualInvoiceForm`; submitting creates an invoice and refreshes the list.
- Line items in the form support add/remove rows; tax rate select populates from `GET /ui/admin/tax-rates`.
- Currency select populates from `GET /ui/admin/currencies` (shows active currencies only).
- "Void" action button is visible only for `status=draft` or `status=sent` invoices; clicking calls `voidInvoice` and updates the list.
- `InvoicesPage` (user-facing, existing) is unchanged when `AOS_STANDALONE_INVOICES_ENABLED=0`.

**Dependencies**

- QUO-005 (`docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md`) — `POST /ui/admin/invoices/manual` endpoint.
- INV-001 (billing_address, discount_cents, unit_price_cents fields).
- INV-002 (currencies list for the form).
- INV-004 (currency badge display).
- INV-005 (tax rates for line-item select).
- INV-009 (void action, status lifecycle).
- INV-010 (account_id/contact_id fields in the table).
- Existing `frontend/src/pages/billing/InvoicesPage.tsx` (unchanged).

---

### INV-012: Invoice E2E tests

**Type:** Chore  **Priority:** P2  **Estimate:** 2d

**Description**

Author Playwright E2E tests covering the full AOS invoice feature set delivered by INV-001 through INV-011. Tests run against the live dev stack (DynamoDB Local + moto + uvicorn) and use the existing `injectAuth` / session-cookie pattern from `frontend/e2e/README` (following `frontend/e2e/catalog-subscriptions.spec.ts` as the template).

**Test file**: `frontend/e2e/invoices-crm.spec.ts`

**Sections and test cases**:

- **Section 1 — Invoice line items and fields API** (INV-001): Charlie (ADMIN) creates an invoice via `POST /ui/admin/invoices/manual` with `billing_address`, `discount_cents`, and line items with `unit_price_cents`; asserts `InvoiceOut` carries all fields; downloads PDF and asserts non-empty bytes.
- **Section 2 — Currency registry API** (INV-002): Admin creates EUR currency; `GET /ui/admin/currencies` lists it; `PATCH` updates exchange rate; deactivating removes it from active list.
- **Section 3 — Currency conversion on invoice creation** (INV-003 + INV-004): Admin creates EUR invoice; asserts `usd_amount_cents` is non-zero; PDF download includes "EUR".
- **Section 4 — Tax rate registry API** (INV-005): Admin creates "EU VAT 20%"; `GET /ui/admin/tax-rates?jurisdiction=EU` returns it; deactivate removes from active list.
- **Section 5 — Per-line tax on invoice** (INV-006): Admin creates invoice with line items carrying `tax_rate_bps=2000`; asserts `tax_cents = sum(line_tax_cents)` and `tax_breakdown` field.
- **Section 6 — Invoice discount line** (INV-007): Invoice with `discount_cents=500`; asserts `total_cents = amount + tax + shipping - discount`; PDF bytes include "Discount".
- **Section 7 — Invoice branding** (INV-008): Admin PATCH branding with `company_name="Test Corp"`; download PDF; assert bytes include "Test Corp"; reset branding.
- **Section 8 — Invoice lifecycle** (INV-009, depends on QUO-005): Draft invoice → send → paid → void; assert status transitions and 409 on paid→void without admin role.
- **Section 9 — Invoice CRM linking API** (INV-010): Admin creates invoice with `account_id="acct_test"`; `GET /ui/admin/invoices/by-account/acct_test` returns it.
- **Section 10 — Admin Invoice UI** (INV-011): Admin navigates to `/admin/invoices`; creates manual invoice via form; verifies row appears in table; clicks Void; row status updates.

**Setup/teardown**: `beforeAll` seeds Charlie as ADMIN via `e2e_admin_session_setup.py` (already exists). `afterAll` calls API DELETEs for created currencies and tax rates to clean up (or they are created with unique-per-run ISO codes/names using `Date.now()` suffixes).

**Acceptance Criteria**

- All sections pass in CI against `just restart && just e2e --grep "invoices-crm"`.
- Feature-flag-off sections (covered by unit tests, not E2E): when `CRM_CURRENCIES_ENABLED=0`, currency endpoints return 404 — validated in hermetic unit tests (INV-002), not E2E.
- Each section is independent (no cross-section state leaks); unique timestamps in all created record names/numbers.

**Dependencies**

- INV-001 through INV-011 (all implementation tickets).
- QUO-005 (`docs/suitecrm/CRM_QUOTES_CONTRACTS_TICKETS.md`) for Section 8 lifecycle.
- Existing `frontend/e2e/e2e_admin_session_setup.py` for Charlie ADMIN session seeding.
- Dev stack feature flags must be enabled in `.env.local` for the test run: `AOS_INVOICE_FIELDS_ENABLED=1`, `CRM_CURRENCIES_ENABLED=1`, `AOS_INVOICE_CURRENCY_CONVERSION_ENABLED=1`, `CRM_TAX_RATES_ENABLED=1`, `AOS_PER_LINE_TAX_ENABLED=1`, `AOS_INVOICE_BRANDING_ENABLED=1`, `AOS_STANDALONE_INVOICES_ENABLED=1`.
