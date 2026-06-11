# CRM Quotes, Products, Contracts & PDF Templates (AOS) — Implementation Tickets

**Area**: Quotes, Products, Contracts & PDF Templates (Advanced OpenSales / AOS)
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T2] Quotes, Products, Contracts & PDF Templates (AOS) — 5 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Advanced OpenSales (AOS) modules provide: a sales quote entity with header/status/expiry/assigned user/billing+shipping address and multi-line-item editing; quote-to-invoice and quote-to-contract conversion; a standalone contract record (name, account, start/end dates, value, status, renewal notification); a module-agnostic PDF template engine where admins upload templates with `{{merge_field}}` placeholders for Quotes, Invoices, and Contracts; and multi-currency quote/invoice support with configurable exchange rates.

testlogon already has: a working product catalog with flat categories and stock management (`app/routers/catalog.py`), auto-generated billing invoices (PDF + email delivery via `app/services/invoices.py`), a sophisticated KYC-domain PDF template engine with merge fields (`app/services/kyc_document_templates.py`), and full billing ledger infrastructure (`app/services/billing_shared.py`). Product depth features (category trees, variants, bundles, price lists, tiered pricing) are **fully planned** under PRD-001..PRD-016 and OFBiz specs — those are NOT re-ticketed here.

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag (default `"0"`, off) following the `cart_reminders_enabled` pattern at `app/core/settings.py:821`. With the flag off all new routes return 404 and all background work is a no-op. Existing surfaces are byte-for-byte unchanged.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables use the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha — omitting this causes `ValidationException` at query time. No `if S.dev_mode` branches in service code; moto intercepts boto3 in dev exactly as in prod.
- **Reuse existing primitives — never fork**:
  - Invoice PDF rendering: `_render_pdf` / `_render_invoice_lines` at `app/services/invoices.py:103–188`; S3 helpers `_store_pdf` / `_fetch_pdf` at `app/services/invoices.py:195–209`.
  - Monotonic sequence counter: `_next_invoice_number` pattern at `app/services/invoices.py:82–92` (atomic DynamoDB `ADD` on a `COUNTER/SEQ` row).
  - Merge-field substitution: `_VAR_RE` regex and `_render()` at `app/services/notification_templates.py:23,245`.
  - KYC document template engine: `KycDocumentTemplateService` at `app/services/kyc_document_templates.py:108`; S3 put/get via `app.core.aws_clients.s3_client`; placeholder rendering pattern at `kyc_document_templates.py:48–73`.
  - Email dispatch: `app/services/alerts.send_alert_email` at `alerts.py:459`.
  - Audit events: `app/services/alerts.audit_event` at `alerts.py:644`.
  - Pagination: `encode_cursor` / `decode_cursor` at `app/core/cursor.py:94,103`.
  - Auth: `require_ui_session` at `app/services/sessions.py:330`; `require_admin_or_root` at `app/auth/policy.py:67`.
- **Planned upstream dependencies**: PRD-001..PRD-016 deliver product depth (variants, bundles, price lists, tiered pricing) — the AOS quote line-item model uses catalog item IDs from the existing `T.catalog` table and optionally the PRD product-depth table once delivered. AOS tickets cite which PRD tickets they extend.
- **Hermetic offline tests**: All pytest use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles per the project test-isolation pattern (see `tests/test_gap_0220_0221_ssh_stored_key.py` for the canonical form). No real AWS or network calls.

---

### QUO-001: Sales Quote entity — DynamoDB model, service, and REST API

**Type:** Feature  **Priority:** P1  **Estimate:** 4d

**Description**

Build the core sales quote entity: DynamoDB table, Pydantic models, service layer, and REST router. A quote is a pre-invoice sales proposal with a lifecycle (draft → sent → accepted → rejected → expired → converted) and multi-line-item composition.

**DynamoDB table** (`aos_quotes`, env `AOS_QUOTES_TABLE_NAME`, default `"aos_quotes"`):

```
PK  = USER#{user_sub}
SK  = QUOTE#{quote_id}           # quote_id = "quo_" + uuid4().hex[:16]
─ header fields:
    quote_number   str            # AOS-NNNN, from COUNTER/SEQ row
    title          str
    stage          str            # draft|sent|accepted|rejected|expired|converted
    valid_until    int            # Unix timestamp; null = no expiry
    assigned_user_sub  str | ""
    account_id     str | ""       # future PTY-012 PARTY_GROUP reference
    contact_id     str | ""       # future PTY-011 PERSON party reference
    currency       str            # default "usd"
    billing_address  dict         # {street, city, state, postal_code, country}
    shipping_address dict
    notes          str | ""
    line_items     list[dict]     # [{catalog_item_id, description, qty, unit_price_cents, discount_bps, tax_rate_bps, line_total_cents}]
    subtotal_cents int
    discount_cents int
    tax_cents      int
    total_cents    int
    created_at     int (N)
    updated_at     int (N)
─ GSI1: GSI1PK = "QUOTES#ALL", GSI1SK = created_at (N) → admin cross-user list
─ GSI2: GSI2PK = USER#{user_sub}#STAGE#{stage}, GSI2SK = created_at (N) → per-user stage filter
─ COUNTER/SEQ row: PK="COUNTER" SK="QUOTE_SEQ" for atomic `_next_quote_number()`
```

`attr_types={"GSI1SK": "N", "GSI2SK": "N"}` required in `scripts/local-ddb-init.py`.

**Service** (`app/services/aos_quotes.py`):

- `create_quote(user_sub, ...)` — validates inputs, computes `subtotal_cents`/`tax_cents`/`total_cents` from line items, mints quote_number via atomic counter (same pattern as `_next_invoice_number` at `app/services/invoices.py:82`), writes DDB item, emits `audit_event("quote.created", ...)`.
- `get_quote(user_sub, quote_id) -> dict | None`
- `list_quotes(user_sub, stage=None, limit=50, cursor=None) -> {"quotes": [...], "next_cursor": ...}` — queries GSI2 when stage is provided, else scans by PK prefix.
- `update_quote(user_sub, quote_id, **fields)` — patch any mutable field; recalculates totals if line_items change; emits audit event.
- `transition_stage(user_sub, quote_id, new_stage)` — validates allowed transitions (draft→sent, sent→accepted|rejected, any→expired); emits `audit_event("quote.stage_changed", ...)`.
- `admin_list_quotes(limit, cursor) -> dict` — queries GSI1.
- All functions are gated: if `not S.aos_quotes_enabled: return None` (or raise 404 in router).

**Router** (`app/routers/aos_quotes.py`, prefix `/ui/quotes`):

- `POST /ui/quotes` — `require_ui_session`; body `QuoteCreateIn`; returns `QuoteOut`.
- `GET /ui/quotes` — `require_ui_session`; query params `stage`, `limit`, `cursor`; returns `QuoteListOut`.
- `GET /ui/quotes/{quote_id}` — `require_ui_session`; returns `QuoteOut`.
- `PATCH /ui/quotes/{quote_id}` — `require_ui_session`; body `QuotePatchIn`; returns `QuoteOut`.
- `POST /ui/quotes/{quote_id}/stage` — `require_ui_session`; body `{"stage": "sent"|"accepted"|"rejected"}`; returns `QuoteOut`.
- `GET /ui/admin/quotes` — `require_admin_or_root` (`app/auth/policy.py:67`); returns `QuoteListOut`.

**Pydantic models** added to `app/models.py`:

- `QuoteLineItemIn` (catalog_item_id, description, qty, unit_price_cents, discount_bps=0, tax_rate_bps=0)
- `QuoteAddressIn` (street, city, state, postal_code, country)
- `QuoteCreateIn` (title, valid_until, assigned_user_sub, account_id, contact_id, currency, billing_address, shipping_address, notes, line_items: list[QuoteLineItemIn])
- `QuotePatchIn` (all fields optional)
- `QuoteLineItemOut`, `QuoteOut`, `QuoteListOut`

Register router in `app/main.py` alongside `invoices_router`.

**Settings** added to `app/core/settings.py` (after `invoices_enabled` at line 2568):

```python
aos_quotes_enabled: bool = os.environ.get("AOS_QUOTES_ENABLED", "0") not in ("1", "true")
aos_quotes_table_name: str = os.environ.get("AOS_QUOTES_TABLE_NAME", "aos_quotes")
```

**Note**: Quote line items reference `catalog_item_id` values from the existing `T.catalog` table (`app/routers/catalog.py`). When PRD-001..PRD-007 land, variants/bundles can be referenced by the same field without schema change.

**Acceptance Criteria**

- `POST /ui/quotes` creates a quote with auto-generated `quote_number` (AOS-00001 format), correct `total_cents` computed from line items, and `stage=draft`.
- `GET /ui/quotes` with `?stage=sent` returns only sent quotes for the authenticated user.
- `POST /ui/quotes/{id}/stage` with `{"stage": "sent"}` transitions draft→sent and rejects invalid transitions (e.g. draft→accepted) with 400.
- `GET /ui/admin/quotes` requires ADMIN or ROOT role and returns quotes across all users.
- With `AOS_QUOTES_ENABLED=0` all endpoints return 404.
- Hermetic offline test in `tests/test_aos_quotes.py` covering CRUD + stage transitions with moto DDB bound via `object.__setattr__`.

**Dependencies**

- Feature flag `AOS_QUOTES_ENABLED` (default off).
- Existing `app/services/invoices.py` for counter pattern (no fork, just model).
- Existing `app/auth/policy.py:67` `require_admin_or_root`.
- QUO-002 (PDF rendering) depends on this ticket.
- QUO-003 (quote-to-invoice/contract conversion) depends on this ticket.

---

### QUO-002: AOS PDF Template engine — module-agnostic merge-field PDF for Quotes, Invoices, and Contracts

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Generalize the KYC document template library (`app/services/kyc_document_templates.py`) into a reusable, module-agnostic PDF template engine that admins can use to create branded PDF templates for Quotes, Invoices, and Contracts. The engine stores admin-uploaded PDF templates with `{{placeholder}}` markers on S3, renders them with record-specific merge fields at download time, and returns the flattened PDF.

**What to reuse and extend** (not fork):

The `KycDocumentTemplateService` at `app/services/kyc_document_templates.py:108` already handles: S3 upload/download of PDF templates, slug-based deduplication, version management (`VERSION#{n}` rows), placeholder extraction, and status lifecycle (active/inactive/archived). Rather than duplicating this, a new thin `AosPdfTemplateService` delegates storage to the same structural pattern but on a dedicated DynamoDB table (`aos_pdf_templates`) and S3 prefix, with a `module` dimension replacing `required_tier`.

**DynamoDB table** (`aos_pdf_templates`, env `AOS_PDF_TEMPLATES_TABLE_NAME`):

```
PK  = template_id               # "apdt_" + uuid4().hex[:16]
SK  = VERSION#{n}               # n=0 is metadata placeholder row
─ module       str               # "quote" | "invoice" | "contract"
─ slug         str               # unique human-readable key per module
─ display_name str
─ description  str
─ status       str               # active | inactive | archived
─ placeholder_fields  list[str]  # e.g. ["quote_number","buyer_name","total"]
─ s3_key       str
─ latest_version int
─ created_by   str
─ created_at   int (N)
─ updated_at   int (N)
─ GSI slug-module-index: PK=slug, SK=module   → unique slug-per-module lookup
─ GSI status-module-index: PK=f"{module}#{status}", SK=updated_at (N) → list by module
```

`attr_types={"updated_at": "N"}` required in `scripts/local-ddb-init.py` (mirrors `kyc_document_templates` at line 207).

**Service** (`app/services/aos_pdf_templates.py`):

Implements the same interface as `KycDocumentTemplateService` but parameterized by `module`:

- `create_template(module, slug, display_name, ...)` — validates module enum; checks slug+module uniqueness via slug-module GSI; writes VERSION#0 row.
- `upload_template_version(template_id, pdf_bytes, uploaded_by)` — validates `pdf_bytes[:5] == b"%PDF-"` (same guard as `kyc_document_templates.py:228`); stores to S3 at `aos-pdf-templates/{module}/{template_id}/v{n}.pdf`; increments `latest_version`.
- `render_template(template_id, merge_vars: dict[str, str]) -> bytes` — fetches latest active PDF bytes from S3; substitutes `{{field_name}}` using `_VAR_RE` from `app/services/notification_templates.py:23` (same pattern, not forked); returns rendered bytes. In dev (no real PDF bytes): returns a synthetic text-based PDF via `_render_pdf` from `app/services/invoices.py:103`.
- `list_templates(module, status="active") -> list[dict]` — queries status-module GSI.
- `get_template(template_id) -> dict | None`, `archive_template(template_id)`.
- All functions gated on `S.aos_pdf_templates_enabled`.

**Router** (`app/routers/aos_pdf_templates.py`, prefix `/ui/admin/pdf-templates`):

All endpoints require `require_admin_or_root` (`app/auth/policy.py:67`).

- `POST /ui/admin/pdf-templates` — body `AosPdfTemplateCreateIn`; returns `AosPdfTemplateOut`.
- `POST /ui/admin/pdf-templates/{template_id}/upload` — multipart PDF upload; returns updated `AosPdfTemplateOut`.
- `GET /ui/admin/pdf-templates` — query `?module=quote|invoice|contract`; returns list.
- `GET /ui/admin/pdf-templates/{template_id}` — returns `AosPdfTemplateOut`.
- `POST /ui/admin/pdf-templates/{template_id}/archive` — archives the template.
- `GET /ui/admin/pdf-templates/{template_id}/preview` — returns rendered PDF bytes (`application/pdf`) using `MOCK_PROFILE`-style sample data (same preview pattern as `kyc_document_templates.py:48`).

**Wiring into Quote and Invoice PDF downloads**:

- `GET /ui/quotes/{quote_id}/pdf` (added in QUO-001 router): if an active `module="quote"` template exists, call `render_template(template_id, quote_merge_vars)`; else fall back to `_render_pdf(_render_quote_lines(record))` (text-based PDF, same pattern as `app/services/invoices.py:103`).
- `GET /ui/invoices/{invoice_number}/pdf` (existing `app/routers/invoices.py:65`): same active-template-or-fallback logic. When no template is configured the existing PDF is unchanged.

**Pydantic models** added to `app/models.py`:

- `AosPdfTemplateCreateIn` (module, slug, display_name, description, placeholder_fields)
- `AosPdfTemplateOut` (template_id, module, slug, display_name, status, latest_version, placeholder_fields, created_at, updated_at)

**Settings** added to `app/core/settings.py`:

```python
aos_pdf_templates_enabled: bool = os.environ.get("AOS_PDF_TEMPLATES_ENABLED", "0") not in ("1", "true")
aos_pdf_templates_table_name: str = os.environ.get("AOS_PDF_TEMPLATES_TABLE_NAME", "aos_pdf_templates")
aos_pdf_templates_bucket: str = os.environ.get("AOS_PDF_TEMPLATES_BUCKET", "local-uploads")
```

**Acceptance Criteria**

- Admin can upload a PDF template with `{{quote_number}}` and `{{total_cents}}` placeholders; `GET .../preview` returns a PDF with those fields rendered.
- `GET /ui/quotes/{id}/pdf` uses the active quote template when one exists; falls back to text PDF when no active template.
- `GET /ui/invoices/{number}/pdf` continues to work unchanged when `AOS_PDF_TEMPLATES_ENABLED=0`.
- Hermetic offline test `tests/test_aos_pdf_templates.py` covers template CRUD, version upload validation, and render (with `_render_pdf` fallback since no real PDF renderer in dev).

**Dependencies**

- `AOS_PDF_TEMPLATES_ENABLED` flag (default off).
- QUO-001 (quote entity) for quote merge vars.
- Existing `app/services/kyc_document_templates.py:108` (structural model; not forked).
- Existing `app/services/notification_templates.py:23` `_VAR_RE` for placeholder substitution.
- Existing `app/services/invoices.py:103` `_render_pdf` for text-PDF fallback.
- QUO-004 (contract entity) extends this with `module="contract"` templates.

---

### QUO-003: Quote-to-invoice and quote-to-contract conversion

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Implement the conversion endpoints that advance a sales quote through its business lifecycle: `POST /ui/quotes/{quote_id}/convert-to-invoice` (accepted quote → draft invoice record) and `POST /ui/quotes/{quote_id}/convert-to-contract` (accepted quote → draft contract record). Both transitions update the quote stage to `converted` and stamp a `converted_to` reference.

**Quote → Invoice conversion**:

Call `invoice_service.create_invoice(...)` from `app/services/invoices.py:272` with:
- `user_sub` from the quote.
- `invoice_type="shop"` (the closest existing VALID_TYPE; the invoice gains an `aos_quote_id` extra field).
- `amount_cents` = quote `subtotal_cents`.
- `tax_cents` = quote `tax_cents`.
- `line_items` = quote line items mapped to `{description, quantity, amount_cents}`.
- `buyer_name`, `buyer_email` from the quote's contact or caller profile.
- `currency` from the quote.

Add `aos_quote_id` as an extra persisted field on the invoice item (passed via `extra` kwarg pattern used in `billing.py` for `provider` attribution per CLAUDE.md). The existing `InvoiceOut` model gains an optional `aos_quote_id: str = ""` field.

Update the quote's `stage` to `converted` and write `converted_to_invoice_number` on the quote item.

**Quote → Contract conversion**:

Calls `create_contract(...)` from QUO-004's `app/services/aos_contracts.py` (dependency). The contract is initialized with `stage=draft`, `value_cents` from the quote total, `account_id`/`contact_id` from the quote, and `aos_quote_id` back-reference.

Update the quote's `stage` to `converted` and write `converted_to_contract_id`.

**Router additions** to `app/routers/aos_quotes.py` (from QUO-001):

- `POST /ui/quotes/{quote_id}/convert-to-invoice` — `require_ui_session`; quote must be in `accepted` stage; returns `InvoiceOut`.
- `POST /ui/quotes/{quote_id}/convert-to-contract` — `require_ui_session`; quote must be in `accepted` stage; returns `ContractOut` (from QUO-004).

Both endpoints emit `audit_event("quote.converted", ...)` via `app/services/alerts.audit_event` at `alerts.py:644`.

**Acceptance Criteria**

- `POST .../convert-to-invoice` on an `accepted` quote creates an invoice with matching total and line items; quote stage becomes `converted`; `converted_to_invoice_number` is set.
- `POST .../convert-to-invoice` on a `draft` quote returns 400 ("quote must be accepted before conversion").
- `POST .../convert-to-contract` creates a draft contract with matching value and account/contact linkage; quote `converted_to_contract_id` is set.
- Converting the same quote twice returns 409 ("quote already converted").
- Hermetic offline test `tests/test_aos_quote_conversion.py` with moto DDB + patched invoice service.

**Dependencies**

- `AOS_QUOTES_ENABLED` flag.
- QUO-001 (quote entity and `transition_stage`).
- QUO-004 (contract entity — `convert-to-contract` calls `create_contract`).
- Existing `app/services/invoices.py:272` `create_invoice` (no fork).

---

### QUO-004: CRM Contract entity — DynamoDB model, service, and REST API

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Build the CRM contract entity: DynamoDB table, Pydantic models, service layer, and REST router. A contract records a formal agreement with a lifecycle (draft → active → expired → terminated | renewed) and supports renewal notifications.

**DynamoDB table** (`aos_contracts`, env `AOS_CONTRACTS_TABLE_NAME`):

```
PK  = USER#{user_sub}
SK  = CONTRACT#{contract_id}    # contract_id = "con_" + uuid4().hex[:16]
─ contract_number str            # CON-YYYY-NNNNN; atomic counter (same _next_X pattern)
─ title          str
─ stage          str             # draft|active|expired|terminated|renewed
─ account_id     str | ""        # PTY-012 PARTY_GROUP party_id (future link)
─ contact_id     str | ""        # PTY-011 PERSON party_id (future link)
─ aos_quote_id   str | ""        # back-reference if converted from a quote (QUO-003)
─ start_date     int             # Unix timestamp
─ end_date       int             # Unix timestamp (null = open-ended)
─ value_cents    int
─ currency       str
─ description    str | ""
─ renewal_notice_days int        # days before end_date to send renewal alert (default 30)
─ renewal_notified_at int | None
─ billing_address  dict
─ shipping_address dict
─ created_at     int (N)
─ updated_at     int (N)
─ GSI1: GSI1PK = "CONTRACTS#ALL", GSI1SK = created_at (N) → admin cross-user list
─ GSI2: GSI2PK = USER#{user_sub}#STAGE#{stage}, GSI2SK = end_date (N) → per-user expiry queries
─ COUNTER/SEQ: PK="COUNTER", SK="CONTRACT_SEQ"
```

`attr_types={"GSI1SK": "N", "GSI2SK": "N"}` required in `scripts/local-ddb-init.py`.

**Service** (`app/services/aos_contracts.py`):

- `create_contract(user_sub, ...)` — mints contract_number (atomic `ADD` on COUNTER/SEQ row, same pattern as `app/services/invoices.py:82`); writes DDB item; emits `audit_event("contract.created", ...)`.
- `get_contract(user_sub, contract_id) -> dict | None`
- `list_contracts(user_sub, stage=None, limit=50, cursor=None) -> dict`
- `update_contract(user_sub, contract_id, **fields)`
- `transition_stage(user_sub, contract_id, new_stage)` — validates: draft→active, active→expired|terminated|renewed.
- `admin_list_contracts(limit, cursor) -> dict` — queries GSI1.
- `check_expiring_contracts() -> int` — called by a background task (registered in `app/main.py`); scans contracts with `end_date` within the next `renewal_notice_days` days AND `renewal_notified_at IS NULL`; for each, calls `send_alert_email([owner_email], subject, body)` from `app/services/alerts.py:459` and sets `renewal_notified_at = now_ts()`. Gated on `S.aos_contracts_renewal_notifications_enabled`.

**Background task** registered in `app/main.py` as a startup hook (pattern: `start_compute_billing_timer_task` from `app/services/compute_billing.py`):

```python
if S.aos_contracts_renewal_notifications_enabled:
    asyncio.create_task(run_contracts_renewal_check_loop())
```

Loop interval: `S.aos_contracts_renewal_check_interval_seconds` (default 3600).

**Router** (`app/routers/aos_contracts.py`, prefix `/ui/contracts`):

- `POST /ui/contracts` — `require_ui_session`; body `ContractCreateIn`; returns `ContractOut`.
- `GET /ui/contracts` — `require_ui_session`; query `stage`, `limit`, `cursor`; returns `ContractListOut`.
- `GET /ui/contracts/{contract_id}` — `require_ui_session`; returns `ContractOut`.
- `PATCH /ui/contracts/{contract_id}` — `require_ui_session`; body `ContractPatchIn`; returns `ContractOut`.
- `POST /ui/contracts/{contract_id}/stage` — `require_ui_session`; body `{"stage": "active"|"terminated"|"renewed"}`.
- `GET /ui/admin/contracts` — `require_admin_or_root`; returns `ContractListOut`.

**Pydantic models** added to `app/models.py`:

- `ContractCreateIn` (title, account_id, contact_id, start_date, end_date, value_cents, currency, description, renewal_notice_days, billing_address, shipping_address)
- `ContractPatchIn` (all optional)
- `ContractOut` (contract_id, contract_number, title, stage, account_id, contact_id, aos_quote_id, start_date, end_date, value_cents, currency, renewal_notice_days, renewal_notified_at, created_at, updated_at)
- `ContractListOut`

**Settings** added to `app/core/settings.py`:

```python
aos_contracts_enabled: bool = os.environ.get("AOS_CONTRACTS_ENABLED", "0") not in ("1", "true")
aos_contracts_table_name: str = os.environ.get("AOS_CONTRACTS_TABLE_NAME", "aos_contracts")
aos_contracts_renewal_notifications_enabled: bool = os.environ.get("AOS_CONTRACTS_RENEWAL_NOTIFICATIONS_ENABLED", "0") not in ("1", "true")
aos_contracts_renewal_check_interval_seconds: int = int(os.environ.get("AOS_CONTRACTS_RENEWAL_CHECK_INTERVAL_SECONDS", "3600"))
```

**Acceptance Criteria**

- `POST /ui/contracts` creates a contract with auto-generated `contract_number` (CON-2026-00001 format) and `stage=draft`.
- `POST /ui/contracts/{id}/stage` with `{"stage": "active"}` succeeds for draft; rejects draft→expired with 400.
- Renewal notification check: a contract with `end_date = now + 5 days` and `renewal_notice_days=30` triggers `send_alert_email`; subsequent run does not re-notify (idempotent via `renewal_notified_at`).
- With `AOS_CONTRACTS_ENABLED=0` all endpoints return 404.
- Hermetic offline test `tests/test_aos_contracts.py` with moto DDB + patched `send_alert_email`.

**Dependencies**

- `AOS_CONTRACTS_ENABLED` flag (default off).
- QUO-001 (quote entity; contract is created independently but referenced by QUO-003 conversion).
- QUO-003 (`convert-to-contract` calls `create_contract`).
- QUO-002 (`module="contract"` PDF templates extend QUO-002 engine).
- Existing `app/services/alerts.py:459` `send_alert_email` (no fork).
- Existing `app/services/invoices.py:82` counter pattern (model, not fork).

---

### QUO-005: Standalone invoice lifecycle — draft/sent/paid/overdue/void and manual B2B invoice creation

**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Extend the existing invoice system (`app/services/invoices.py`, `app/routers/invoices.py`) with a standalone invoice lifecycle, manual B2B invoice creation by admins, payment terms / due-date tracking, and a void endpoint. This closes the AOS-INV-001 and AOS-INV-VOID gaps from the gap analysis without touching the existing auto-generation path.

**What is already built**: `create_invoice` at `app/services/invoices.py:272` generates invoices from billing events with `status="generated"`. The DDB table has `pk=USER#{sub} / sk=INV#{number}` with two GSIs (type, admin). The existing path is unchanged when `AOS_STANDALONE_INVOICES_ENABLED=0`.

**Lifecycle extension**:

Add new status values to the existing invoice: `draft | generated | sent | paid | overdue | void`. The existing `generated` status is preserved as-is for backward compatibility; new standalone invoices start at `draft`.

New `update_invoice_status(user_sub, invoice_number, new_status)` in `app/services/invoices.py`:
- Validates allowed transitions: `draft→sent`, `sent→paid`, `sent|draft→void`, any→`overdue` (set by background checker only).
- For `void`: writes a reversal ledger entry via `billing_shared.new_ledger_entry(...)` if the invoice was previously `paid` (to trigger AR reversal); sets `voided_at = now_ts()`.
- Emits `audit_event("invoice.status_changed", ...)` via `alerts.audit_event` at `alerts.py:644`.

**Payment terms and due date** (addresses AOS gap analysis "Invoice payment terms and due date"):

Add optional `payment_terms_days: int` and `due_date: int` fields to `InvoiceOut` and `create_invoice(...)` signature. When `payment_terms_days` is provided at creation, `due_date = created_at + payment_terms_days * 86400`. Both are persisted on the DDB item and rendered in `_render_invoice_lines` (add "Due Date:" and "Terms:" lines after the date).

**Overdue background checker**:

New `check_overdue_invoices()` in `app/services/invoices.py`: queries GSI1 for `status=sent` invoices (scans ADMIN_ALL GSI2); for items where `due_date < now_ts()`, calls `update_invoice_status(user_sub, number, "overdue")`. Called from a startup loop gated on `S.aos_invoice_overdue_checker_enabled` (default off), interval `S.aos_invoice_overdue_check_interval_seconds` (default 3600).

**Manual B2B invoice creation** (addresses AOS gap analysis "Manual invoice creation by admin or sales rep"):

New endpoint `POST /ui/admin/invoices/manual` (added to `app/routers/invoices.py`, requires `require_admin_or_root`):

Body `ManualInvoiceCreateIn` (added to `app/models.py`):
```
buyer_user_sub: str        # platform user or empty for external
buyer_name: str
buyer_email: str
billing_address: dict
line_items: list[{description, quantity, unit_price_cents, tax_rate_bps}]
currency: str = "usd"
payment_terms_days: int = 30
notes: str = ""
```

Calls existing `create_invoice(invoice_type="shop", ...)` with `status="draft"` override; returns `InvoiceOut` with `status="draft"` and `due_date` set from `payment_terms_days`.

**Void endpoint**:

`POST /ui/invoices/{invoice_number}/void` — `require_ui_session`; the authenticated user must own the invoice; calls `update_invoice_status(user_sub, invoice_number, "void")`; returns updated `InvoiceOut`.

**Pydantic model changes** in `app/models.py`:

- `InvoiceOut` gains: `payment_terms_days: Optional[int] = None`, `due_date: Optional[int] = None`, `voided_at: Optional[int] = None`.
- New `ManualInvoiceCreateIn` as above.
- `InvoiceLineItemOut` gains `unit_price_cents: int = 0` (addresses the gap analysis "Invoice line items — unit_price_cents field").

**Settings** added to `app/core/settings.py`:

```python
aos_standalone_invoices_enabled: bool = os.environ.get("AOS_STANDALONE_INVOICES_ENABLED", "0") not in ("1", "true")
aos_invoice_overdue_checker_enabled: bool = os.environ.get("AOS_INVOICE_OVERDUE_CHECKER_ENABLED", "0") not in ("1", "true")
aos_invoice_overdue_check_interval_seconds: int = int(os.environ.get("AOS_INVOICE_OVERDUE_CHECK_INTERVAL_SECONDS", "3600"))
```

**Acceptance Criteria**

- `POST /ui/admin/invoices/manual` creates a `draft` invoice with `due_date = created_at + payment_terms_days * 86400`; invoice PDF includes "Due Date:" and "Terms:" lines.
- `POST /ui/invoices/{number}/void` transitions `draft→void` and `sent→void`; rejects `paid→void` with 409 unless caller is admin.
- `InvoiceLineItemOut` now includes `unit_price_cents`.
- Overdue checker marks `sent` invoices with `due_date < now` as `overdue`; does not re-process already-overdue invoices.
- Existing auto-generated invoices (created by `create_invoice_safe`) are byte-for-byte unchanged when `AOS_STANDALONE_INVOICES_ENABLED=0`.
- Hermetic offline test `tests/test_aos_invoice_lifecycle.py` with moto DDB; `send_alert_email` patched.

**Dependencies**

- `AOS_STANDALONE_INVOICES_ENABLED` flag (default off).
- Existing `app/services/invoices.py` (extended, not forked).
- Existing `app/routers/invoices.py` (extended, not forked).
- Existing `app/models.py` `InvoiceOut`, `InvoiceLineItemOut` (extended additively).
- QUO-003 (quote-to-invoice conversion also lands `status="draft"` invoices; that ticket and this one share the same status field extension — coordinate merge order).
