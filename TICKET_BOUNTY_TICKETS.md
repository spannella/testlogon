# Ticket Bounties & Attachments — Implementation Tickets

**Status:** Planning (2026-06-11). Investigated against the live ticket system
(`app/services/tickets.py`, `app/routers/tickets.py`) and money primitives
(`app/services/billing_shared.py`, `tip_ledger.py`, `group_treasury.py`,
`billing.py`). Prefix: **`TBT`** (bounty/escrow) and **`TKA`** (attachments).

Feature: a ticket can carry a **dollar bounty** that is **escrowed** when posted,
shown to users so they can **self-claim** the work, paid out to the assignee only
on **admin approval**, and **refunded to the poster** if the ticket is cancelled in
any state other than `paid_out`. Plus **file attachments** on tickets.

## Cross-cutting constraints (non-negotiable)
- **Additive + flag-gated** (`TICKET_BOUNTIES_ENABLED`, default **off**). With the
  flag off, the ticket system is byte-for-byte unchanged (no new statuses reachable,
  no bounty fields populated, existing helpdesk/support flows untouched).
- **One refund mechanism**: every money-out (cancel refund) reuses
  `settle_or_reverse_ledger` + `new_ledger_entry(entry_type="adjustment", state="settled")`
  exactly as `refund_payment` does (`billing.py:1286-1345`). Never fork billing.
- **Atomic escrow**: hold/debit is a single `transact_write_items` (the
  `group_treasury.py` precedent) so a poster's wallet debit and the escrow record
  can never diverge.
- **No double-charge**: the poster is debited ONCE at post time. Release credits the
  assignee directly + settles the escrow — it does NOT call `write_tip_ledger`
  (which would debit the poster a second time).
- **Charge gating**: posting a bounty runs `_fraud_gate(...)` + `is_frozen` checks
  (`billing.py:118-175`).
- **Idempotency**: deterministic ids (`bounty_id = sha256(ticket_id)[:..]`),
  conditional puts (`attribute_not_exists`), single-winner conditional claim.
- **Dev/prod parity (SECOPS-007)**: no `dev_mode` branch; moto in dev, real DDB/S3 in prod.
- **Hermetic offline tests**: frozen `T`/`S` via `object.__setattr__`, moto-bound
  tables, route-handler coroutines called directly (TestClient is broken in this env).

---

## Milestone 1 — Escrow & bounty foundation

### TBT-001: Feature flag, settings & escrow table decision
**Type:** Chore | **Priority:** P0 | **Estimate:** 1 day
**Description**
- Add `S.ticket_bounties_enabled` (env `TICKET_BOUNTIES_ENABLED`, default `false`) to
  `app/core/settings.py`, plus `ticket_bounty_min_cents` (default 100),
  `ticket_bounty_max_cents` (default 100_000_00), `ticket_bounty_fee_bps`
  (default **0** — see Open Decision D1), and `ticket_bounty_payout_hold_seconds`
  (default 0).
- Decide escrow record home: **reuse `T.billing`** (single-table) with a sentinel
  row `pk=BOUNTY#{bounty_id}`, `sk=ESCROW` (co-located with the ledger, so refund &
  audit queries stay on one table). No new table.
- `_bounties_enabled()` / `_require_bounties_enabled()` helpers (mirror
  `inventory.py:50-56`).

**Acceptance Criteria**
- Flag defaults off; all new endpoints 404 when off.
- Settings load with documented defaults; `.env.local.example` gains the keys.

**Dependencies** — none.

---

### TBT-002: Ticket bounty fields + projection (additive)
**Type:** Feature | **Priority:** P0 | **Estimate:** 1 day
**Description**
- Extend the ticket META row (`tickets.py` `create_ticket` ~`:440`) with optional,
  default-absent fields: `bounty_amount_cents: int|None`, `bounty_currency: str`,
  `bounty_status: str|None` (`none|funded|claimed|submitted|paid_out|cancelled`),
  `bounty_id: str|None`, `claimed_by_sub: str|None`, `claimed_at: int|None`,
  `bounty_funded_at`, `bounty_submitted_at`, `bounty_paid_at`, `bounty_cancelled_at`.
- Surface them in the ticket projection (`_ticket_out` ~`:528-566`) so detail/list
  responses carry the amount + bounty_status. Pydantic `TicketOut` gains the optional
  fields (additive).
- A `ByBounty` sparse projection: set `gsi_bounty_pk="BOUNTY#OPEN"` /
  `gsi_bounty_sk=created_at` ONLY when `bounty_status=="funded"` (drives the bounty
  board, TBT-008) — sparse so non-bounty tickets never hit the index. Declare the
  numeric GSI sort key with `attr_types={"gsi_bounty_sk":"N"}` in
  `scripts/local-ddb-init.py`.

**Acceptance Criteria**
- Tickets without a bounty serialize exactly as today (no new keys populated / all null).
- Bountied ticket projection includes amount + status; sparse GSI only indexes funded ones.

**Dependencies** — TBT-001.

---

### TBT-003: Escrow service — `post_bounty` (atomic hold)
**Type:** Feature | **Priority:** P0 | **Estimate:** 2 days
**Description**
- New `app/services/ticket_bounties.py`. `post_bounty(ticket_id, poster_sub, amount_cents, currency, request)`:
  1. `_require_bounties_enabled()`; validate amount within min/max; ticket must exist,
     be owned by `poster_sub`, status `open`, and not already funded.
  2. `_fraud_gate(poster_sub, amount_cents, "bounty_hold", tx_id=ticket_id, enforce_block=True)`
     + `is_frozen` (`billing.py:118-175`).
  3. `bounty_id = sha256(f"bounty:{ticket_id}".encode()).hexdigest()[:24]` (deterministic, idempotent).
  4. **Atomic `transact_write_items`** (the `group_treasury.py` pattern):
     (a) wallet debit on `USER#{poster}` via the conditional
     `wallet_balance_cents >= :amount` guard (`apply_wallet_delta` semantics) — fails
     → 402 "insufficient balance"; (b) put `BOUNTY#{bounty_id}/ESCROW`
     (`{ticket_id, poster_sub, amount_cents, currency, status:"held", created_at, ledger_sk}`)
     with `attribute_not_exists(pk)` (idempotent double-post guard); (c) put an audit
     ledger entry `new_ledger_entry(USER#{poster}, type="debit", state="pending",
     reason="bounty_escrow", meta={bounty_id, ticket_id, escrow_state:"held"})`.
  5. Update the ticket META → `bounty_status="funded"`, `bounty_id`, `bounty_amount_cents`,
     set the `ByBounty` sparse GSI keys.
  6. `audit_event("bounty_posted", ...)`.

**Acceptance Criteria**
- Funds leave the poster's wallet atomically with the escrow record; insufficient
  balance → 402 and nothing is written.
- Re-posting the same ticket's bounty is idempotent (no double-debit).
- Frozen/blocked poster → 403.

**Dependencies** — TBT-001, TBT-002.

---

### TBT-004: Bounty state machine (gates existing transitions)
**Type:** Feature | **Priority:** P0 | **Estimate:** 1.5 days
**Description**
- Add statuses `claimed`, `pending_approval`, `paid_out`, `cancelled` to
  `_TICKET_STATUSES`, and a SEPARATE `_BOUNTY_TRANSITIONS` map applied only when
  `bounty_status` is set:
  `funded→claimed|cancelled`, `claimed→pending_approval|cancelled`,
  `pending_approval→paid_out|in_progress(reject)|cancelled`, `paid_out` terminal,
  `cancelled` terminal.
- Gate the existing `update_status(...,"done")`: for a bountied ticket, a claimant's
  "mark done" routes to `pending_approval` (NOT `done`) — the admin-approval gate.
  Non-bounty tickets keep today's `_STATUS_TRANSITIONS` exactly.
- `paid_out` and `cancelled` are reachable ONLY through the dedicated bounty endpoints
  (TBT-006/007), never via the generic status endpoint.

**Acceptance Criteria**
- With flag off / no bounty, the existing transition map is unchanged.
- A claimant cannot self-mark `paid_out`; only admin approval reaches it.

**Dependencies** — TBT-002.

---

### TBT-005: Self-claim (any user assigns themselves)
**Type:** Feature | **Priority:** P0 | **Estimate:** 1.5 days
**Description**
- `claim_bounty(ticket_id, claimer_sub)`: ticket must be `bounty_status=="funded"`
  and unclaimed. **Single-winner** via conditional `update_item`
  (`ConditionExpression="attribute_not_exists(claimed_by_sub)"`) so two simultaneous
  claims → one wins, the other gets 409. Sets `claimed_by_sub`, `claimed_at`,
  `assigned_to_sub=claimer`, `bounty_status="claimed"`, ticket status `in_progress`;
  clears the `ByBounty` open-index keys (no longer on the board).
- This is the **new self-assign path** distinct from the admin-only `assign_ticket`
  (`tickets.py:807`) — a regular `require_ui_session` user may claim, but only
  bountied+funded+unclaimed tickets.
- `unclaim_bounty(ticket_id, claimer_sub)`: claimant releases → back to `funded`,
  re-index on the board; escrow stays held. (Abandonment path.)

**Acceptance Criteria**
- Two concurrent claims → exactly one `claimed`, other 409.
- Only the bounty board's funded/unclaimed tickets are claimable; claiming a
  non-bounty ticket → 404/409.

**Dependencies** — TBT-003, TBT-004.

---

### TBT-006: Submit-for-approval + admin approve → release escrow → assignee
**Type:** Feature | **Priority:** P0 | **Estimate:** 2 days
**Description**
- `submit_bounty(ticket_id, claimer_sub)`: claimant marks work done →
  `bounty_status="submitted"`, ticket `pending_approval`, `bounty_submitted_at`.
- `approve_bounty(ticket_id, admin_sub, request)` (**admin/root only**):
  1. Load `BOUNTY#{bounty_id}/ESCROW`; require `status=="held"`.
  2. Compute fee: `fee = amount * ticket_bounty_fee_bps // 10000`; `net = amount - fee`
     (default fee 0 → net = amount). If a fee, record it on the platform per the
     existing `split_fee`/tip-fee convention.
  3. **Credit the assignee directly** (NOT `write_tip_ledger` — poster already debited
     at TBT-003): `new_ledger_entry(USER#{assignee}, type="credit", state="settled",
     amount_cents=net, reason="bounty_payout", meta={bounty_id, ticket_id, fee_cents})`
     + credit the assignee's wallet/earnings so it shows in payout balance
     (`creator_payouts.get_available_balance` already sums credits).
  4. `settle_or_reverse_ledger(escrow audit entry → "settled_released")`; update
     `BOUNTY#{bounty_id}/ESCROW` → `status="released", released_to, released_by, released_at`.
  5. Ticket → `bounty_status="paid_out"`, status `paid_out`; notify assignee
     (`bounty_awarded`); `audit_event("bounty_released", ...)`.
- `reject_bounty(ticket_id, admin_sub, reason)`: `pending_approval → in_progress`,
  `bounty_status="claimed"`, escrow stays held, notify claimant.

**Acceptance Criteria**
- Approve pays the assignee `net` exactly once; poster is NOT debited again.
- Escrow record flips held→released atomically with the assignee credit (idempotent
  on replay — second approve is a no-op).
- Only admin/root can approve/reject.

**Dependencies** — TBT-003, TBT-005.

---

### TBT-007: Cancel + refund → poster (any non-paid_out state)
**Type:** Feature | **Priority:** P0 | **Estimate:** 1.5 days
**Description**
- `cancel_bounty(ticket_id, actor_sub, reason, is_admin)`:
  - **Permitted when**: poster cancels while `funded` & unclaimed; OR an admin/root
    cancels in ANY state except `paid_out`/`cancelled`.
  - Refund (the mandated path, mirrors `refund_payment` `billing.py:1286-1345`):
    `new_ledger_entry(USER#{poster}, type="adjustment", state="settled",
    amount_cents=amount, reason="bounty_refund", meta={bounty_id, reason})` +
    `settle_or_reverse_ledger(escrow audit entry → "reversed")` +
    `apply_wallet_delta(USER#{poster}, +amount)` to return funds to spendable balance —
    all in one `transact_write_items`.
  - `BOUNTY#{bounty_id}/ESCROW` → `status="refunded", refunded_at, refund_ledger_sk`
    (conditional on `status=="held"` → idempotent; a second cancel is a no-op).
  - Ticket → `bounty_status="cancelled"`, status `cancelled`; clear board index;
    notify poster (+ claimant if any); `audit_event("bounty_cancelled", ...)`.
- Guard: `paid_out` escrow can NEVER be refunded (409 "already paid out").

**Acceptance Criteria**
- Refund returns the full amount to the poster's wallet exactly once; escrow flips
  held→refunded idempotently.
- Cancelling a `paid_out` bounty → 409, no money moves.
- Non-admin, non-poster, or poster-after-claim → 403.

**Dependencies** — TBT-003.

---

### TBT-008: Bounty board (claimable list) + amount visibility
**Type:** Feature | **Priority:** P1 | **Estimate:** 1 day
**Description**
- `list_open_bounties(cursor, limit)` queries the `ByBounty` sparse GSI
  (`gsi_bounty_pk="BOUNTY#OPEN"`, newest-first) → only funded+unclaimed tickets, each
  carrying `bounty_amount_cents`, subject, labels, created_at.
- Ensure the single-ticket projection (already extended in TBT-002) shows the amount
  + bounty_status to any viewer so "a user looks at it to assign themselves".

**Acceptance Criteria**
- Board lists only funded/unclaimed bounties; claimed/paid/cancelled drop off.
- Amount is visible on the ticket detail before claiming.

**Dependencies** — TBT-002, TBT-005.

---

### TBT-009: Bounty router endpoints + auth
**Type:** Feature | **Priority:** P0 | **Estimate:** 1.5 days
**Description**
- In `app/routers/tickets.py` (all `_require_bounties_enabled()` first):
  | Method | Path | Auth | → |
  |---|---|---|---|
  | POST | `/tickets/{id}/bounty` | owner (`require_ui_session`, owner check) | `post_bounty` |
  | POST | `/tickets/{id}/bounty/claim` | any user | `claim_bounty` |
  | POST | `/tickets/{id}/bounty/unclaim` | claimant | `unclaim_bounty` |
  | POST | `/tickets/{id}/bounty/submit` | claimant | `submit_bounty` |
  | POST | `/tickets/{id}/bounty/approve` | admin/root | `approve_bounty` |
  | POST | `/tickets/{id}/bounty/reject` | admin/root | `reject_bounty` |
  | POST | `/tickets/{id}/bounty/cancel` | owner(unclaimed) or admin | `cancel_bounty` |
  | GET | `/tickets/bounties/open` | any user | `list_open_bounties` |
- Map service errors to HTTP (402 insufficient balance, 403 frozen/forbidden, 409
  already claimed/paid/wrong-state). Reuse the `_is_admin_actor` inline check.

**Acceptance Criteria**
- Each endpoint enforces its auth; flag-off → 404.
- Error codes match the service contracts.

**Dependencies** — TBT-003, TBT-005, TBT-006, TBT-007, TBT-008.

---

### TBT-010: Frontend — bounty UI
**Type:** Feature | **Priority:** P1 | **Estimate:** 3 days
**Description**
- Types + endpoint wrappers (`frontend/src/api/endpoints/tickets.ts`).
- Ticket card/detail: bounty **amount badge** + status chip; "Post bounty" form for
  owners (amount input, balance check); **"Claim"** button for funded tickets;
  **"Submit for approval"** for the claimant; **admin approval queue** (approve/reject)
  for `pending_approval`; **"Cancel & refund"** for owner(unclaimed)/admin.
- A **Bounty Board** page listing `GET /tickets/bounties/open`.
- All bounty UI gated on a client flag fetched from config (hidden when feature off).

**Acceptance Criteria**
- Owner can post/cancel; user can claim/submit; admin can approve/reject; amounts and
  statuses render; board lists open bounties.

**Dependencies** — TBT-009.

---

### TBT-011: Bounty tests (hermetic pytest + E2E)
**Type:** Chore | **Priority:** P0 | **Estimate:** 2 days
**Description**
- `tests/test_ticket_bounties.py` (moto-bound frozen `T.tickets`/`T.billing`, `S` flag
  via `object.__setattr__`, handlers called directly): post→claim→submit→approve→paid_out
  (assignee credited net, poster debited once); cancel-unclaimed→refund; admin-cancel
  mid-flight→refund; double-claim race→one 409; approve idempotent; cancel-after-paid_out→409;
  insufficient-balance→402; frozen poster→403; flag-off→404.
- E2E `frontend/e2e/ticket-bounties.spec.ts`: board → claim → submit → admin approve;
  cancel→refund visible in balance.

**Acceptance Criteria**
- All money invariants asserted (no double-charge, full refund, exactly-once payout).

**Dependencies** — TBT-001..TBT-010.

---

## Milestone 2 — Ticket file attachments

### TKA-001: Attachment presign + store
**Type:** Feature | **Priority:** P1 | **Estimate:** 1.5 days
**Description**
- Reuse the messaging presign→S3 pattern (`messaging.py` `CreateImageMessageIn` flow):
  `POST /tickets/{id}/attachments/presign` (owner or assignee) returns a presigned PUT
  URL (900s) for key `tickets/{ticket_id}/attachments/{attachment_id}/{safe_filename}`
  on `S.filemgr_bucket`.
- `add_attachment(ticket_id, attachment_id, bucket, key, filename, filesize, mime_type,
  uploader_sub)` writes an `ATTACHMENT#{attachment_id}` row under the ticket partition;
  validate magic-bytes + size cap (mirror `license_agreements.py:114-146`).
- Feature flag `S.ticket_attachments_enabled` (default off).

**Acceptance Criteria**
- Presign returns a working PUT URL scoped to the ticket; metadata row persists;
  oversize/bad-mime rejected.

**Dependencies** — TBT-001 (settings pattern) — independent of the bounty flag otherwise.

### TKA-002: Attachment list / get-download / delete + projection
**Type:** Feature | **Priority:** P1 | **Estimate:** 1 day
**Description**
- `GET /tickets/{id}/attachments` (owner/assignee/admin) → list; `GET .../{aid}/download`
  → presigned GET (or dev `/mock/s3/...` URL); `DELETE .../{aid}` (uploader/admin).
- Extend `get_ticket` projection to include an `attachments` array.

**Acceptance Criteria**
- Attachments listed on the ticket; download URL resolves; delete removes row + (best-effort) object.

**Dependencies** — TKA-001.

### TKA-003: Frontend attachments + tests
**Type:** Feature | **Priority:** P2 | **Estimate:** 1.5 days
**Description**
- Ticket detail: drag-drop/upload, attachment list with download, delete.
- `tests/test_ticket_attachments.py` (presign, store, list, delete, flag-off) + E2E.

**Acceptance Criteria**
- Upload→list→download→delete round-trips; flag-off hides UI + 404s API.

**Dependencies** — TKA-001, TKA-002.

---

## Open Decisions (need product input)
- **D1 — Platform fee on bounty payouts.** Tips take a platform fee
  (`split_fee`). Bounties default here to **0%** (`ticket_bounty_fee_bps=0` → assignee
  gets the full posted amount). Alternative: take the standard tip fee. *Recommend 0%
  (the poster pays X, the worker earns X); trivially changed via the setting.*
- **D2 — Funding source.** Design debits the poster's **wallet balance**
  (`apply_wallet_delta`, conditional guard). Alternative: allow a fresh card charge at
  post time (heavier — adds provider + 3DS). *Recommend wallet-only for v1.*
- **D3 — Who may post bounties.** Any user on their own ticket vs. a gated/role.
  *Recommend any owner, bounded by min/max + fraud gate.*
- **D4 — Assignee abandonment.** `unclaim` returns the ticket to the board, escrow
  stays held (TBT-005). Alternative: auto-refund after N days idle. *Recommend manual
  unclaim for v1; idle-sweep is a follow-up.*
