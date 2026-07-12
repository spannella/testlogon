# PAY-F backend (PAY-50 + PAY-51) — app-facing money-OUT read surface + deep-links

LIVE PROD HOTFIX via SSM. Prod `i-08f937fc705ebea75` (us-east-2). Applied on
android-impl HEAD `a305223c`. `.bak_payf_1783841809` on the 3 patched files.

## What shipped

PAY-50 (read surface — pure reads over the PAY-A ledger + payout records, no new state):
- `GET /ui/payouts/wallet` -> `WalletSummaryOut` — available / held(+`held_release_at`,
  `held_count`) / pending(+`pending_count`) / `lifetime_paid_cents` / total_earned.
  Reconciles to `get_available_balance` (single source of truth).
- `GET /ui/payouts/{payout_id}` -> `PayoutDetailOut` — statement/detail: lifecycle
  `timeline` (requested/approved/held/hold_released/processing/paid/failed/returned),
  `transfer_provider`+`transfer_ref`, `method_last4` (resolved from the co-located
  payout_method row), `fail_reason`, `manual_hold`+`hold_reason`, `debit_reversed`,
  `transfer_attempts`. User-scoped: 403 on another creator's payout, 404 if unknown.
  Registered LAST so literal GET routes (/balance,/wallet,/methods,/tax-info,/connect) win.
- History = the EXISTING `GET /ui/payouts` (list_user_payouts, ByUserCreatedAt GSI,
  cursor-paginated) — already covers status/amount/method/timestamps; reused as-is.

PAY-51 (deep-links): the PAY-D lifecycle alerts (`payout_initiated`/`payout_paid`/
`payout_failed`/`payout_returned`, already default-ON) now carry
`action_url=/wallet/payouts/{payout_id}` so the app can deep-link straight to the
statement detail. Events remain registered in alerts.ALERT_EVENT_TYPES +
DEFAULT_PUSH_EVENT_TYPES (PAY-D).

## Files patched
- `app/services/creator_payouts.py` — get_wallet_summary, get_payout_detail, helpers
  (_held_release_info / _count_active_payouts / _resolve_method_last4 /
  _build_payout_timeline) + 3 emit action_url deep-links.
- `app/models.py` — WalletSummaryOut, PayoutTimelineEvent, PayoutDetailOut.
- `app/routers/creator_payouts.py` — GET /wallet + GET /{payout_id} + imports.

## Apply / verify
- `apply_payf.py` — anchored + idempotent (marker-guarded). Dev + prod files were
  byte-identical on the anchored regions (identical byte deltas). Run:
  `TL_ROOT=/home/ubuntu/testlogon BAK_SUFFIX=.bak_payf_<ts> .venv/bin/python apply_payf.py`
  (DRY=1 to preview).
- `verify_payf.py` — in-process on prod DDB; seeds a synthetic user with a
  requested/paid/failed-returned/held mix + credit ledger, asserts wallet reconciles,
  history lists all, statement detail correct, cross-user scoped (403), cleans up.
  **PROD RESULT: OVERALL ALL_PASS 28/28** (avail 65000 = past-hold 100000 - lifetime-paid
  20000 - pending 15000; held 50000; lifetime 20000; U2 blocked + all-zero; unknown 404).

Restart: `sudo -u ubuntu bash -lc "bash /home/ubuntu/restart_backend.sh"` (NOT `su -` —
the SSM session is not root). openapi 200; both new routes live.

---

## PAY-54 (build-gate + 2-device money-OUT E2E) — app-only follow-up

**No new prod backend change.** PAY-50/51 backend (this fold) was already LIVE + 28/28 verified. PAY-54 = the app build-gate + on-device E2E.

**App gap found & fixed during the E2E (committed with the epic, NOT a prod change):**
android/app/src/main/java/com/testlogon/android/navigation/MoreRoutes.kt — the PAY-52 Wallet-home route (`WALLET` = "wallet") was missing from `MoreRoutes.REGISTERED`, so `MoreAvailabilityResolver` resolved the "Wallet" hub entry to `Hidden` and the PAY-52 Wallet home was unreachable from the More/earnings hub. Added `WALLET,` to REGISTERED → the Wallet tile renders and opens the Wallet home. Also aligned `WalletScreen.kt` ReceiptLong icon to the non-AutoMirrored import (compile fix). `:app:assembleDebug` BUILD SUCCESSFUL.

**On-device 2-device money-OUT E2E (A15 .238, creator ben.buyer.1783715432, prod backend tl-api.bitbazaar.cc):**
Seeded KYC-approved + certified W-9 + a matured $60 credit on prod DDB. Wallet home showed REAL available $60.00 / on-hold $16.20 (Releases Jul 18) / pending $0 / lifetime $0 / total earned $76.20 (reconciles to get_wallet_summary). Withdraw → gate Identity=Done + Tax(W-9)=Done → picked verified bank ••6789 → $20 → Request payout → available dropped $60→$40, backend payout requested $20 method bank_ach. Ran run_payout_sweep (= POST /ui/admin/payouts/run) → requested→processing→paid→completed, transfer_provider=mock, transfer_ref=mock_transfer_payout_476f..., lifetime paid $20, pending $0. Alerts inbox rendered "Your withdrawal was paid" + "is processing" (payouts category, default-ON); tapping "paid" deep-linked (action_url /wallet/payouts/{id}) to the statement showing Completed + transfer ref + timeline Requested→Processing→Paid. Gate-block: un-certified W-9 → Withdraw screen showed Tax(W-9)=Required + W-9 form, submit blocked (403 tax_info_required); re-certified after. Fail/return: requested $15 → available $40→$25 → returned ("bank returned: account closed") → available restored to $40; history shows Completed + Returned chips. Empty crash buffer (0 FATAL). Recording ~/Desktop/testlogon-demos/payf_moneyout_e2e.mp4.
