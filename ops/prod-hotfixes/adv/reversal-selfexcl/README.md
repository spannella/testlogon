# Hotfix: reversed-credit gross true-up (FIX1) + self-ad-exclusion (FIX3)

LIVE PROD HOTFIX (backups on prod: `*.bak_reveselfex_<ts>` on creator_earnings.py + ad_serving.py).
Restart: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"` -> openapi 200.

## FIX 1 — reversed credit excluded from GROSS earnings
`app/services/creator_earnings.py`: both `_query_credit_entries` (the get_earnings_summary
path) and the paginated list path filtered only `Attr("type").eq("credit")`, so a REVERSED
tip/ad credit (state="reversed") still counted toward the dashboard GROSS total even though
`creator_payouts.get_available_balance` already excluded it (spendable money was correct; only
the gross analytics figure over-counted). Added `& Attr("state").ne("reversed")` at both sites
(NE is True on legacy rows with no `state` attr -> backward compatible; mirrors the existing
`get_available_balance` idiom in creator_payouts).

Verify: `verify_fix1_reversal.py` — seed a credit 400 -> gross 400 -> flip state=reversed ->
gross 0, available stays 0. PASS on prod.

## FIX 3 — advertiser never served (nor charged for) their OWN ad
`app/services/ad_serving.py` `serve_ad` eligibility loop: added a self-exclusion — skip any
campaign whose ad-account owner_sub == the viewer (`user_id`). Resolved via
`ad_accounts.get_ad_account(account_id).owner_sub` (try/except, fail-open per-campaign).
Guards the money-path so an advertiser viewing content is never shown / charged / credited by
their own creative.

Verify: `verify_e2e_3user.py` — full 3-user path (U1 advertiser fund/campaign/creative,
U2 creator allow_ads, U3 viewer pre-roll). U3 served the U1 creative surface=preroll owner=U2;
completion charged U1 (funds-guarded) + credited U2 the 70% poster split + platform 30%,
idempotent (repeat=0); U1 viewing was served a DIFFERENT advertiser (self-exclusion), never
charged for its own ad. OVERALL PASS.

## Apply
`python3 apply_reversal_selfexcl.py /home/ubuntu/testlogon`
(idempotent, anchor-matched — safe to re-run on the dev clone AND prod).
