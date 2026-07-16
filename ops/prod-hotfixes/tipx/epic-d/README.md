# TIPX-D — Measurement / reconciliation (the ONE TRUE TOTAL)

**Status: SHIPPED to prod + dev clone `android-impl`.** Prod backend restarted, openapi 200, the four
new `/ui/tips/*` routes live, `/ui/alerts/tips-summary` now ledger-backed. Verifier 19/19 PASS on prod
DDB-Local, 0 residue. App `assembleDebug` green + on-device spot-check (creator sees real reconciled
tips-received). Web tsc-0 + build green + vitest 3/3.

## The problem (audit)

Three disagreeing "tips received" totals:

| Source | Was | Now |
|---|---|---|
| `creator_earnings` tips bucket | NET credit rows, reversed-excluded (correct) | unchanged (canonical) |
| `tip_leaderboard` | NET credit rows; reversed-exclusion added in Epic A6 | unchanged (canonical) |
| `alerts.get_tips_summary` → web **TipsFeed** "Total Earned" | **GROSS**, `post_tip`+`message_tip` ONLY, capped at last 1000 alerts | **retired**; now reads the LEDGER (NET, all 8 surfaces, reversed-excluded) |

All three now converge on the ledger: `TipsFeed total == earnings tips bucket == leaderboard total`.

## Ticket-by-ticket

| Ticket | Delivered |
|---|---|
| **D1** one true total | New `app/services/tips_measurement.py` — the single ledger-backed source (NET credit rows, `reason begins_with "Tip"`, `state != "reversed"`, per-surface breakdown for all 8 surfaces). `alerts.get_tips_summary` rewritten to delegate to it (retires the alert-stream/gross/2-surface/capped total). Web `TipsFeed` relabeled **"Total Earned" → "Net tips received"** + honest reconcile note + all-surface breakdown, repointed at the ledger-backed `/ui/tips/received`. |
| **D2** leaderboard reversed-exclusion | Already live (`tip_leaderboard.aggregate_tips_for_creator` gained `& Attr("state").ne("reversed")` under Epic A6). Verified here: a reversed tip drops from top-supporters AND stays reconciled with earnings. |
| **D3** app creator tip-measurement screen | New **Tip insights** screen (`feature/tipinsights/*` + `data/tipinsights/*`) backed by `GET /ui/tips/received` (+ `/received/history`): net tips-received, top supporters, per-surface breakdown, all reconciling to the earnings tips bucket + leaderboard. Reachable from the More → Wallet hub (`MoreRoutes.TIP_INSIGHTS`, added to `REGISTERED`). |
| **D4** tipper sent history + receipts | New `GET /ui/tips/sent` + `/ui/tips/sent/summary` (tipper's GROSS `debit`, `reason begins_with "Tip"`, reversed-excluded). Surfaced on the app Tip-insights screen ("Tips sent" section) and on web (`TipsSentFeed` under the Tips & Earnings tab). Each row is a receipt (recipient + amount + platform fee + date). |
| **D5** wire pending payout | `creator_earnings.get_quick_stats` `pending_payout_cents` was hard-coded `0` (`# populated after MON-004`). Now wired to `creator_payouts.get_available_balance(...)["pending_cents"]` (real in-flight payout total), best-effort → 0 on failure. |

## New / changed backend files
- NEW `app/services/tips_measurement.py` — the reconciled measurement service (received summary/history, sent, sent summary).
- NEW `app/routers/tips_measurement.py` — `GET /ui/tips/{received,received/history,sent,sent/summary}`.
- `app/main.py` — import + `include_router(tips_measurement_router)`.
- `app/routers/alerts.py` — `get_tips_summary` now ledger-backed (retires alert-stream total; keeps legacy `by_type.post_tip/message_tip` keys for the web + adds `by_surface`, `net`, `source`).
- `app/services/creator_earnings.py` — `pending_payout_cents` wired (D5).
- (D2 `app/services/tip_leaderboard.py` already shipped in Epic A6.)

## New / changed web files
- NEW `frontend/src/api/endpoints/tips.ts` — `getTipsReceivedSummary`, `getTipsSent`, `getTipsSentSummary`.
- NEW `frontend/src/pages/alerts/TipsSentFeed.tsx` — tipper receipts.
- NEW `frontend/src/pages/alerts/TipsFeed.test.tsx` — reconciliation + honest-label + sent-receipt tests (3 tests, PASS).
- `frontend/src/api/types.ts` — `TipsSummary` (net/source/by_surface), `TipSentItem`/`TipsSentResp`/`TipsSentSummary`.
- `frontend/src/pages/alerts/TipsFeed.tsx` — ledger-backed, "Net tips received", all-surface breakdown.
- `frontend/src/pages/alerts/AlertsPage.tsx` — renders `TipsSentFeed` under Tips & Earnings.

## New / changed app files
- NEW `data/tipinsights/{TipInsightsApi,TipInsightsRepository,TipInsightsDataModule}.kt`.
- NEW `feature/tipinsights/{TipInsightsViewModel,TipInsightsScreen}.kt`.
- NEW `navigation/TipInsightsNavigation.kt`.
- NEW `app/src/test/.../data/tipinsights/TipInsightsRepositoryContractTest.kt` (well-formed; NB the repo's `testDebugUnitTest` source set is PRE-BROKEN at HEAD by unrelated tests — syndicates/videos/vod ViewModel tests reference changed constructors — so the gradle test task can't compile; `assembleDebug` is green).
- `navigation/{AuthenticatedGraph,MoreRoutes}.kt` — register route + add to `REGISTERED` allowlist (else `MoreAvailability` hides the tile).
- `feature/more/MoreCatalog.kt` + `res/values/strings.xml` — the "Tip insights" More entry.

## Verify matrix — 19/19 PASS (live-DDB-direct on prod DDB-Local, pattern-tagged, 0 residue)

`verify_tipx_d.py` (same DDB-Local transact proxy as Epic A — see epic-a/README):
- Seed 5 tips across post/message/comment/video/post_react (gross 5300 → net 4240).
- **D1** earnings tips bucket == leaderboard == tips_measurement == alerts-summary == 4240 (all reconcile); `by_surface` covers all seeded surfaces.
- **D3** received history sums to net (4240, 5 rows).
- **D4** tipper sent history sums to GROSS spend (3000, 3 rows); sent summary + receipt fee/recipient present.
- **D2** reverse the 2000 comment tip → drops from earnings AND leaderboard AND tips_measurement (all → 2640, still reconciled); reversed tipper's remaining leaderboard == video-only net.
- **D5** quick-stats returns a real `pending_payout_cents` (≥0).
- CORE: idempotent replay does not double-count. Cleanup: 0 residue.

## On-device (A15, admin creator `crash1782189692@testlogon.example`)
Seeded 5 real demo tips → Tip insights shows **Net received $104.00 / 5 tips / 3 tippers**, top supporters + all-5-surface breakdown summing to $104, honest reconcile note, and a "Tips sent" section. No crash.

## Apply on prod (SSM)
`apply_prod.sh` (run via the dev-host SSM helper against `i-08f937fc705ebea75`): backs up
alerts.py/creator_earnings.py/main.py, writes the two new files, applies the three content-anchored
edits, chowns `ubuntu:ubuntu`, `restart_backend.sh`, checks openapi 200 + the new routes.

## `.bak` names (prod)
`app/routers/alerts.py.bak_tipx_1784215000`, `app/services/creator_earnings.py.bak_tipx_1784215000`,
`app/main.py.bak_tipx_1784215000`.

## Env note
Same as Epic A: `transact_write_items` is routed through a plain low-level `boto3.client("dynamodb")`
in the verifier because the resource client rejects low-level AV maps against DDB-Local; production
runs on real AWS where the shipped transactional rail is valid. Verify in-process via the prod venv
against DDB-Local (the SSM shell role has no direct DynamoDB IAM).
