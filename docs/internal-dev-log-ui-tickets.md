# Internal Dev Log UI — Implementation Tickets

This ticket set maps directly to `docs/internal-dev-log-ui-plan.md` and breaks execution into backend contracts, frontend UX, TOTP handling, run script integration, and QA hardening.

---

## Epic A — Discovery, contracts, and data model alignment

### DLU-001 — Inventory and lock log input formats
- **Type:** Backend / Discovery
- **Priority:** P0
- **Size:** S
- **Description:** Confirm canonical location and shape of `email.log`, `sms.log`, and billing-provider logs produced by the local mock stack.
- **Deliverables:**
  - Format matrix with sample records per source.
  - Canonical dev path defaults for each log input.
  - List of malformed-line patterns that must be tolerated.
- **Acceptance criteria:**
  - All required log sources are documented with at least one real sample.
  - Path defaults are agreed and ready for env wiring.
  - Unknown/ambiguous fields are flagged and resolved.
- **Dependencies:** None.

### DLU-002 — Define canonical read models for email/SMS/billing
- **Type:** Backend / API
- **Priority:** P0
- **Size:** S
- **Description:** Establish stable schema contracts returned by internal dev-tools APIs.
- **Deliverables:**
  - Canonical model definitions for mailbox/message/thread, SMS conversation/message, and billing ledger entry/summary.
  - Stable ID strategy and timestamp normalization rules.
- **Acceptance criteria:**
  - Schemas cover all fields needed by target UI.
  - Stable IDs are deterministic across refreshes for unchanged logs.
  - All models include parse warning surfaces where needed.
- **Dependencies:** DLU-001.

### DLU-003 — Define internal API contract and pagination behavior
- **Type:** Backend / API
- **Priority:** P0
- **Size:** S
- **Description:** Finalize request/response contracts for internal read-only endpoints.
- **Deliverables:**
  - Contract for:
    - `GET /internal/dev-tools/email/messages`
    - `GET /internal/dev-tools/sms/conversations`
    - `GET /internal/dev-tools/billing/ledger`
    - `GET /internal/dev-tools/billing/summary`
  - Cursor semantics, filtering/query behavior, and error mapping.
- **Acceptance criteria:**
  - Contract documented and testable.
  - Pagination and filter semantics are deterministic.
  - No mutating verbs are present in this surface.
- **Dependencies:** DLU-002.

---

## Epic B — Backend parsers and read-only API implementation

### DLU-004 — Build `email.log` parser with mailbox/thread extraction
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Description:** Implement robust parser supporting line-delimited JSON and plain-text fallback parsing for email logs.
- **Deliverables:**
  - Parser module for mailbox/message/thread canonicalization.
  - Multi-address mailbox extraction and All Inboxes aggregation support.
  - Parse-warning collection for malformed lines.
- **Acceptance criteria:**
  - Parser handles mixed valid/invalid lines without crashing.
  - Mailbox and thread lists are deterministic.
  - Large files are streamed with bounded memory.
- **Dependencies:** DLU-001, DLU-002.

### DLU-005 — Build `sms.log` parser with conversation grouping
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Description:** Implement SMS parser that normalizes conversation participants and message ordering.
- **Deliverables:**
  - Parser module for conversation-level and message-level records.
  - Grouping logic matching iMessage-style thread expectations.
  - Metadata mapping (`to`, `from`, status, external message ID).
- **Acceptance criteria:**
  - Conversations sort by latest activity deterministically.
  - Message ordering/grouping is stable.
  - Parse warnings are exposed without blocking results.
- **Dependencies:** DLU-001, DLU-002.

### DLU-006 — Build billing parser/adapter normalization for Stripe/CCBill/PayPal
- **Type:** Backend / Billing
- **Priority:** P0
- **Size:** M
- **Description:** Normalize provider-specific transaction artifacts into unified ledger entries.
- **Deliverables:**
  - Provider adapters for Stripe, CCBill, and PayPal mock logs.
  - Canonical fields (`provider`, `event_type`, `amount`, `currency`, `fee`, `net`, `status`, `timestamp`, `external_id`, raw payload pointer).
  - Warning handling for unsupported event variants.
- **Acceptance criteria:**
  - Unified schema produced for all three providers.
  - Summary math inputs are complete and consistent.
  - Parser tolerates partial provider outages/missing files.
- **Dependencies:** DLU-001, DLU-002.

### DLU-007 — Implement internal dev-tools router and service wiring
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Add read-only internal routes backed by parser services and query filters.
- **Deliverables:**
  - Router implementation and registration.
  - Endpoint filtering, pagination, and response DTOs.
  - Short-TTL in-memory cache for file parse reuse.
- **Acceptance criteria:**
  - All four endpoints return contract-compliant responses.
  - Filters and cursors work consistently across refreshes.
  - Parse cache respects TTL and invalidation rules.
- **Dependencies:** DLU-003, DLU-004, DLU-005, DLU-006.

### DLU-008 — Enforce local/dev-only and read-only security controls
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** S
- **Description:** Guard internal dev-tools endpoints from non-dev environments and preserve strict read-only posture.
- **Deliverables:**
  - Environment gate (disabled outside local/dev mode).
  - Explicit GET-only routing and hardened error behavior.
  - Logging/audit note for route access in dev context.
- **Acceptance criteria:**
  - Routes are unavailable in non-dev mode.
  - No accidental write paths are exposed.
  - Unauthorized/disabled responses are deterministic.
- **Dependencies:** DLU-007.

### DLU-009 — Implement billing summary aggregation service
- **Type:** Backend / Billing
- **Priority:** P0
- **Size:** S
- **Description:** Compute gross, fees, net balance, and provider/status counts from normalized ledger entries.
- **Deliverables:**
  - Summary aggregation service and DTO.
  - Currency and sign-handling rules for totals.
- **Acceptance criteria:**
  - Totals match ledger source data.
  - Empty/partial datasets return valid zero-state summaries.
- **Dependencies:** DLU-006, DLU-007.

---

## Epic C — Frontend route, layouts, and data integration

### DLU-010 — Add dev-tools route shell and feature-flag gating
- **Type:** Frontend
- **Priority:** P0
- **Size:** S
- **Description:** Add `/dev-tools/log-ui` route and gate visibility with `VITE_ENABLE_DEVTOOLS_LOG_UI`.
- **Deliverables:**
  - Route registration and nav entry.
  - Tabbed shell for Email, SMS, MFA (TOTP), and Billing.
- **Acceptance criteria:**
  - Route hidden when flag is disabled.
  - Route accessible and tabbed when enabled.
- **Dependencies:** None.

### DLU-011 — Implement frontend API clients and query hooks for dev-tools endpoints
- **Type:** Frontend / API
- **Priority:** P0
- **Size:** M
- **Description:** Add typed endpoint clients and query hooks for email, SMS, ledger, and summary data.
- **Deliverables:**
  - New endpoint client methods.
  - Query hooks with filter/cursor support and cache keys.
  - Standard loading/empty/error state support.
- **Acceptance criteria:**
  - Requests map correctly to backend contracts.
  - Cache keying avoids collisions across tabs and filters.
  - Error states display actionable debug info.
- **Dependencies:** DLU-003, DLU-010.

### DLU-012 — Build Gmail-like email UI with multi-mailbox support
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Create read-only email experience with mailbox switcher, thread list, and message detail pane.
- **Deliverables:**
  - Mailbox rail, thread list, and detail panel.
  - All Inboxes aggregate mode.
  - Search and state filters (e.g., unread/sent/all as available by data).
- **Acceptance criteria:**
  - Multi-address browsing works end-to-end.
  - Selected message/thread renders headers and body metadata.
  - No mutating controls are exposed.
- **Dependencies:** DLU-011.

### DLU-013 — Build iMessage-like SMS UI with conversation list and bubble thread
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Create read-only SMS experience mirroring iMessage conversation ergonomics.
- **Deliverables:**
  - Left-side conversation list ordered by latest activity.
  - Bubble thread renderer with sender grouping.
  - Metadata drawer/info panel for status and IDs.
- **Acceptance criteria:**
  - Conversation switching is fast and stable.
  - Bubble grouping/order matches canonical data.
  - No message send/edit/delete actions exist.
- **Dependencies:** DLU-011.

### DLU-014 — Build billing ledger table, filters, and summary cards
- **Type:** Frontend / Billing
- **Priority:** P0
- **Size:** M
- **Description:** Implement unified billing ledger experience across Stripe/CCBill/PayPal.
- **Deliverables:**
  - Ledger data table with provider/status/date filters.
  - Summary cards (gross, fees, net, counts).
  - Raw source detail drawer.
- **Acceptance criteria:**
  - Table reflects backend filtering and pagination.
  - Summary values stay consistent with visible dataset scope.
  - Raw payload inspection is read-only.
- **Dependencies:** DLU-011, DLU-009.

---

## Epic D — Frontend-only TOTP support

### DLU-015 — Implement TOTP parser utility (otpauth URI + raw secret)
- **Type:** Frontend / Security
- **Priority:** P0
- **Size:** S
- **Description:** Build utility to parse/validate pasted MFA configuration locally in browser.
- **Deliverables:**
  - Parser for `otpauth://` URI and raw Base32 input mode.
  - Validation feedback for invalid secrets and unsupported parameters.
- **Acceptance criteria:**
  - Valid inputs normalize into one internal config shape.
  - Invalid inputs produce clear non-blocking errors.
  - No network calls occur for parser execution.
- **Dependencies:** DLU-010.

### DLU-016 — Implement live TOTP generator panel with countdown and reset
- **Type:** Frontend / Security
- **Priority:** P0
- **Size:** M
- **Description:** Build UI panel to generate live codes entirely client-side.
- **Deliverables:**
  - Current code, next rollover countdown, and refresh cadence.
  - Optional localStorage persistence toggle.
  - Clear/reset controls and local-only disclosure text.
- **Acceptance criteria:**
  - Codes update on 30-second cadence.
  - Reset clears in-memory and optional stored values.
  - TOTP secret is never sent to backend.
- **Dependencies:** DLU-015.

---

## Epic E — Dev runtime integration (`run_dev.sh`) and docs

### DLU-017 — Wire `scripts/run_dev.sh` to auto-enable Dev Log UI
- **Type:** DevEx / Tooling
- **Priority:** P0
- **Size:** S
- **Description:** Set required frontend/backend env defaults and startup messaging so the UI comes up automatically in local runs.
- **Deliverables:**
  - Export `VITE_ENABLE_DEVTOOLS_LOG_UI=1` in dev flow.
  - Default `DEVTOOLS_*` log path variables when unset.
  - Startup output line with direct UI URL.
- **Acceptance criteria:**
  - Running `scripts/run_dev.sh` exposes the dev-tools route without extra setup.
  - `--no-clean` mode remains compatible with retained logs.
  - Existing startup behavior remains stable.
- **Dependencies:** DLU-007, DLU-010.

### DLU-018 — Add operator/developer documentation for local usage
- **Type:** Docs
- **Priority:** P1
- **Size:** S
- **Description:** Document feature purpose, route, log inputs, and limitations.
- **Deliverables:**
  - README (or docs) section with quickstart and troubleshooting.
  - Note that UI is read-only except local TOTP config paste.
- **Acceptance criteria:**
  - New developers can discover and run the tool from docs only.
  - Known limitations and security boundaries are explicit.
- **Dependencies:** DLU-017.

---

## Epic F — Quality, test coverage, and release readiness

### DLU-019 — Add backend tests for parsers and internal APIs
- **Type:** Backend / QA
- **Priority:** P0
- **Size:** M
- **Description:** Cover parser edge cases, endpoint filtering/pagination, security gating, and summary math.
- **Deliverables:**
  - Unit tests for email/SMS/billing parser robustness.
  - API tests for endpoint contract, query filters, cursor behavior.
  - Access-control tests for dev-only route availability.
- **Acceptance criteria:**
  - Core parser and API scenarios are deterministic in CI.
  - Security gate tests fail if route is exposed outside dev.
  - Summary totals are verified with fixture data.
- **Dependencies:** DLU-004, DLU-005, DLU-006, DLU-007, DLU-008, DLU-009.

### DLU-020 — Add frontend tests for read-only UX and TOTP lifecycle
- **Type:** Frontend / QA
- **Priority:** P0
- **Size:** M
- **Description:** Validate tab behavior, rendering, and TOTP runtime updates.
- **Deliverables:**
  - Component/hook tests for email/SMS/billing tabs.
  - Tests asserting absence of mutating actions.
  - TOTP tests for parse, countdown, rollover, and reset.
- **Acceptance criteria:**
  - Major loading/empty/error/content states are covered.
  - TOTP behavior is deterministic under controlled timers.
  - Read-only contract is enforced via UI tests.
- **Dependencies:** DLU-012, DLU-013, DLU-014, DLU-016.

### DLU-021 — Add end-to-end smoke for full tab flow in dev mode
- **Type:** E2E / QA
- **Priority:** P1
- **Size:** S
- **Description:** Add e2e scenario validating accessibility of all tabs and basic data rendering using mock artifacts.
- **Deliverables:**
  - E2E spec that opens `/dev-tools/log-ui`, visits all tabs, and verifies expected read-only markers.
  - Optional fixture seed or setup helper for predictable logs.
- **Acceptance criteria:**
  - Smoke test passes locally/CI with mock stack.
  - Regressions in route wiring and primary render paths are caught.
- **Dependencies:** DLU-017, DLU-020.

---

## Suggested Milestones
- **Milestone 1 (MVP backend + shell):** DLU-001 through DLU-011.
- **Milestone 2 (Core UX):** DLU-012 through DLU-014.
- **Milestone 3 (MFA local tooling):** DLU-015 and DLU-016.
- **Milestone 4 (Autostart + docs):** DLU-017 and DLU-018.
- **Milestone 5 (QA hardening):** DLU-019 through DLU-021.
