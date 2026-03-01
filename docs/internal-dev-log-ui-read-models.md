# DLU-002 — Canonical Read Models (Email / SMS / Billing)

This document defines the stable response contracts for internal Dev Log UI read APIs.

## Stability rules
- **Stable IDs:** every mailbox/thread/message/conversation/ledger row includes `id` + `id_strategy`.
- **Timestamp normalization:** all API timestamps are normalized to UTC RFC3339 (`YYYY-MM-DDTHH:MM:SSZ`).
- **Parse warnings:** top-level and item-level `parse_warnings` arrays surface non-fatal parser issues.

## Model families

### Email models
- `DevtoolsEmailMailboxOut`
- `DevtoolsEmailThreadOut`
- `DevtoolsEmailMessageOut`
- `DevtoolsEmailMessagesOut`

### SMS models
- `DevtoolsSmsConversationOut`
- `DevtoolsSmsMessageOut`
- `DevtoolsSmsConversationsOut`

### Billing models
- `DevtoolsBillingLedgerEntryOut`
- `DevtoolsBillingLedgerSummaryOut`
- `DevtoolsBillingLedgerOut`

## Parse warning model
- `DevtoolsParseWarningOut`
  - `source`: `email | sms | billing`
  - `line_number` (optional)
  - `code`
  - `message`
  - `sample` (optional)

## Source of truth
Canonical model definitions live in `app/models.py` under the **Internal Dev Tools (DLU-002) canonical read models** section.
