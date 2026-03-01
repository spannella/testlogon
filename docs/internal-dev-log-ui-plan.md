# Internal Dev Log UI Plan

## 1. Goals and Non-Goals

### Goals
- Build a **read-only internal developer UI** that surfaces local test artifacts in familiar formats:
  - Gmail-like inbox/message detail for `email.log`.
  - iMessage-like conversation view for `sms.log`.
  - Live TOTP code generator from pasted MFA configuration.
  - Billing ledger that normalizes mock processor transactions (Stripe, CCBill, PayPal) and computes totals.
- Support **multiple email addresses/inboxes** in the email experience.
- Keep data entry/write actions disabled except for **frontend-only TOTP config paste**.
- Make it easy to run locally and have it start automatically with `scripts/run_dev.sh`.

### Non-Goals
- No external auth accounts or outbound mailbox/SMS integrations.
- No write-back flows to logs or payment providers.
- No persistence requirement for pasted TOTP config beyond local browser storage/session.

---

## 2. Target User Experience

### Shell Navigation
Add a new route group under the existing frontend app (e.g., `/dev-tools/log-ui`) with tabs:
1. **Email**
2. **SMS**
3. **MFA (TOTP)**
4. **Billing Ledger**

### Email (Gmail-like, read-only)
- Left rail: list of mailboxes (email addresses discovered in `email.log`).
- Main pane: inbox thread list for selected mailbox.
- Detail pane: selected message/thread with headers, text/html body, timestamp, delivery state.
- Filters: unread/sent/all, search by subject/from/to.
- Multi-address support via mailbox switcher and aggregate “All inboxes” view.

### SMS (iMessage-like, read-only)
- Conversation list on the left, ordered by last activity.
- Message bubbles in thread view, grouped by sender/recipient and timestamp.
- Display metadata (to/from, gateway status, message id) in an info panel.
- Optional compact mode to quickly inspect webhook/transport anomalies.

### MFA (TOTP generator)
- Input area to paste:
  - `otpauth://` URI, or
  - raw Base32 secret plus metadata fields.
- Frontend parses and validates locally, then starts a 30-second live countdown.
- Display current code + next code preview.
- Allow storing config in `localStorage` (opt-in) and clear/reset action.
- Explicit label that this feature is local-only and never sent to backend.

### Billing Ledger (read-only)
- Unified table with normalized fields: provider, event type, amount, currency, fee, net, timestamp, external id, status.
- Provider filters (Stripe/CCBill/PayPal), date range, and transaction status.
- Summary cards:
  - Gross inflow
  - Fees
  - Net total balance
  - Counts by provider/status
- “Source detail” drawer to inspect raw event payload for debugging.

---

## 3. Data Sources and Contracts

## 3.1 Log Inputs
- `email.log`: parse line-delimited JSON if available; fallback to regex parser for plain-text entries.
- `sms.log`: same strategy as `email.log`.
- Billing inputs: read mock transaction logs/artifacts produced by current mock provider flows.
  - If processor-specific logs differ, normalize through a provider adapter layer.

## 3.2 Proposed Backend Endpoints (read-only)
Create an internal-only API namespace:
- `GET /internal/dev-tools/email/messages`
  - Query: `mailbox`, `thread_id`, `q`, `limit`, `cursor`.
- `GET /internal/dev-tools/sms/conversations`
  - Query: `participant`, `q`, `limit`, `cursor`.
- `GET /internal/dev-tools/billing/ledger`
  - Query: `provider`, `status`, `from`, `to`, `limit`, `cursor`.
- `GET /internal/dev-tools/billing/summary`

No endpoint for TOTP generation is required; perform this entirely in frontend.

## 3.3 Parsing and Normalization Layer
Introduce parser modules:
- `app/services/devtools/email_log_parser.py`
- `app/services/devtools/sms_log_parser.py`
- `app/services/devtools/billing_log_parser.py`

Each parser should:
- Stream files safely (tail-friendly, bounded memory).
- Return canonical models with stable IDs.
- Tolerate malformed lines and expose parse warnings.

---

## 4. System Design

## 4.1 Backend
- Add internal router (e.g., `app/routers/internal_dev_tools.py`) guarded by local/dev-only gate.
- Provide read models from parsers and in-memory cache with short TTL (e.g., 2–5s) to avoid reparsing on every request.
- Add config env vars:
  - `DEVTOOLS_EMAIL_LOG_PATH` (default to local generated path)
  - `DEVTOOLS_SMS_LOG_PATH`
  - `DEVTOOLS_BILLING_LOG_DIR`

## 4.2 Frontend
- New page container: `frontend/src/pages/devtools/DevToolsLogUiPage.tsx`.
- Reusable components:
  - Mailbox/Conversation lists
  - Message viewer
  - Ledger table + summary cards
  - TOTP panel
- Keep TOTP logic in frontend utility (e.g., `frontend/src/utils/totp.ts`) using a vetted implementation approach.
- Add API client wrappers in `frontend/src/api/endpoints/...` for the new internal endpoints.

## 4.3 Security and Safety
- Default hidden behind a development feature flag (`VITE_ENABLE_DEVTOOLS_LOG_UI=1`).
- Backend route disabled outside local/dev mode.
- Read-only guarantees:
  - Backend exposes only `GET` endpoints.
  - UI disables mutating actions.
- TOTP secret never transmitted to backend; keep in memory unless user opts into local storage.

---

## 5. Implementation Phases

### Phase 0 — Discovery and Contract Freeze
- Inventory current log formats and sample records.
- Define canonical schema for email, sms, and billing events.
- Confirm log file paths produced in local environment.

### Phase 1 — Backend Parsers + Internal APIs
- Implement parser modules + tests for malformed/partial lines.
- Add internal dev-tools router and response DTOs.
- Add summary computation for ledger balances.

### Phase 2 — Frontend UI Skeleton
- Add new route and tab layout.
- Wire API calls and loading/empty/error states.
- Implement Gmail-like and iMessage-like layouts with read-only semantics.

### Phase 3 — TOTP Panel (Frontend-only)
- Parse otpauth URI/raw secret.
- Live code generation with timer and validation UX.
- Optional localStorage persistence toggle.

### Phase 4 — `run_dev.sh` Integration
- Ensure logs are generated in predictable locations.
- Auto-enable dev-tools route when `scripts/run_dev.sh` launches frontend (set env flag).
- Print direct local URL in startup output.

### Phase 5 — Hardening and QA
- Unit tests for parser edge cases and ledger math.
- Frontend tests for read-only behavior and TOTP lifecycle.
- End-to-end smoke test covering each tab.

---

## 6. `run_dev.sh` Integration Plan

1. Extend script env bootstrap to export:
   - `VITE_ENABLE_DEVTOOLS_LOG_UI=1`
   - default log paths for email/sms/billing if unset.
2. Ensure dependent mock services emit expected logs before frontend starts.
3. On startup, print:
   - `Dev Tools Log UI: http://localhost:5173/dev-tools/log-ui`
4. Keep `--no-clean` behavior compatible by preserving log files and reusing history.

---

## 7. Testing Strategy

### Backend Tests
- Parser fixtures for valid/invalid/mixed log lines.
- API tests for filtering, pagination, and summary totals.
- Access control tests ensuring routes are disabled outside local/dev mode.

### Frontend Tests
- Component tests for:
  - multi-mailbox switching
  - SMS conversation rendering
  - billing summary consistency
  - TOTP parse + countdown + refresh rollover
- E2E smoke: navigate all tabs and verify read-only controls.

### Manual Validation Checklist
- Launch with `scripts/run_dev.sh` and verify route is reachable.
- Confirm mailbox list includes multiple addresses.
- Confirm SMS grouping resembles iMessage threading.
- Paste known TOTP seed and verify code correctness against reference app.
- Validate ledger totals match underlying mock transaction data.

---

## 8. Open Questions
- Exact canonical location/format of `email.log`, `sms.log`, and provider logs in current local stack.
- Whether billing data should include refunds/disputes in first release.
- Whether to offer downloadable JSON for selected events.
- Expected retention limits for very large log files (performance budget).

---

## 9. Deliverables
- Internal API routes + parser services + tests.
- Dev tools frontend route with four tabs.
- Frontend-only TOTP utility and UI panel.
- `scripts/run_dev.sh` updates for auto-enable behavior.
- Documentation snippet in `README.md` for usage.
