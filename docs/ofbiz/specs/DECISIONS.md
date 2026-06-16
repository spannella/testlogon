# OFBiz Specs — Canonical Decisions (pre-build reconciliation)

Authoritative resolutions for the 132 pass-3 escalations. The reconciliation pass bakes these into the specs so the set is internally consistent before Phase 1. See `ESCALATIONS.md` for the full per-item list and `<ID>.md §13` for per-spec resolution logs.

## Cross-cutting decisions (user-approved 2026-06-10)

### D1 — Canonical GL posting interface  *(approved)*
`app/services/gl_posting.py` (owned by **OFB-014**) exports ONE public function:
```python
def post_journal_entry(
    lines: list[JournalLine], *,
    source_type: str, source_entity_id: str,
    memo: str, gl_date: int, journal_id: str | None = None,
) -> str   # returns journal_entry_id; asserts debits == credits
```
- The billing-derived path (`post_ledger_entry(ledger_item: dict)`) becomes a thin adapter that builds `lines` and calls `post_journal_entry`.
- OFB-018's divergent `post_journal_entry(source_entry, *, dry_run)` is reconciled to this signature.
- **Callers** (must align their specs to call this, NOT invent their own poster): FXA-009 (depreciation), FXA-011 (disposal), HRM-010 (payroll expense), MFG-008 (costed production).
- OFB-014 also adds public `list_journal_entries(start_date, end_date, cursor, limit)` + `get_journal_entry_header(journal_entry_id)` for OFB-017 browsing.
- **OFB-013** chart adds `contra_asset` account class (`normal_balance='credit'`); **OFB-016** adds its balance-sheet sign handling (required for accumulated depreciation).

### D2 — Canonical pricing façade  *(approved)*
`app/services/pricing_rules.py` (owned by **OFB-019**) exports ONE public façade:
```python
def apply_pricing_rules(
    user_sub: str, items: list[dict], *, checkout_type: str,
    exclude_rule_ids: set[str] | None = None,
) -> PricingBreakdownResult
```
- `resolve_applicable_rules` gains an `exclude_rule_ids` param (kills the promo double-count).
- Canonical redemption-counter export name is **`redeem_rule`** (fix OFB-019 §7.3 which used `record_rule_redemption`).
- **Consumers**: OFB-020 cart total, checkout, ECM-009 storefront — all call `apply_pricing_rules` (no per-caller primitive orchestration).
- Authoritative breakdown model lives in **ECM-003** (`AppliedPricingRuleLineOut`, field `discount_cents`); ECM-009 adopts it.

### D3 — AR/AP semantics: richer model  *(approved — NOT the MVP proxy)*
- Add a real **`paid`** invoice status to `app/services/invoices.py`; AR-closed is driven by invoice status, not only ledger `state='settled'`.
- AP subledger includes **accrued creator-wallet balances** (a wallet-accrual aging view) in addition to explicit payout requests.
- OFB-015 spec widened accordingly; `AR_AP_SUBLEDGERS_ENABLED` stays an independent flag; note the one-time `paid` backfill in the migration section.

### D4 — Feature-category scope: per-creator  *(approved)*
Product feature categories (Color, Size, …) carry `creator_id` and are scoped per-creator (no global marketplace governance). Locks PRD-001 / PRD-006 design.

### D5 — Asset-disposal accounts: split  *(default, not separately asked)*
FXA-008 seeds TWO accounts — `Gain on Disposal` (credit-normal) and `Loss on Disposal` (debit-normal); FXA-011 posts to whichever applies via D1's `post_journal_entry`.

## Determinate principle for the 44 mechanical plan-gaps
When two specs disagree, the **foundation ticket that physically owns the artifact is authoritative**; amend the dependent spec to match:
- DDB keys / GSIs / table shape → the module's **`-002` tables** ticket (e.g. FAC-002, HRM-002, MKT-002, POS-003 for settings).
- Pydantic models → the module's **`-003` models** ticket (e.g. ECM-003, PRD-003, MFG-003, SHP-003).
- Settings keys → the module's settings ticket (POS-003, MFG-002).
- Service/function ownership → the natural owner named in `ESCALATIONS.md` col 4.

Per-item resolutions are in `ESCALATIONS.md` §A (plan-gaps) and §B (open decisions, recommended defaults applied unless overridden above).
