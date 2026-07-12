# PAY-D (PAY-30..34) — Scheduled payout RUNNER + lifecycle + manual holds + retries + notifications (LIVE PROD HOTFIX)

Turns payouts from "only advance on an admin `/complete` click" into a real,
idempotent, self-progressing money-OUT pipeline built on the PAY-A honest
transfer + debit foundation. Applied to EC2 `i-08f937fc705ebea75` via SSM, then
mirrored to the dev clone (this commit). Applied by the idempotent anchor-based
`patch_payd.py` (asserts each anchor; re-run is a no-op) so the identical
transform lands on prod + the dev clone despite alerts/settings/main drift.

## What changed (files)
- `app/services/creator_payouts.py` — the runner + lifecycle + holds + retries +
  notification emit (append `service_block.py` + two in-place emit hooks).
- `app/routers/admin_payouts.py` — admin fail/return/hold/release + `/ui/admin/payouts/run`
  trigger + `/v1/payouts/webhook` provider seam (append `router_block.py`).
- `app/services/alerts.py` — register `payout_initiated/paid/failed/returned` as
  ALERT_EVENT_TYPES + DEFAULT_PUSH (default-ON transactional) + a `payouts`
  category + `/wallet/payouts` action-URL deep-links.
- `app/core/settings.py` — runner/retry config flags.
- `app/main.py` — import + `startup` registration of `start_payout_runner_task`
  + include the two PAY-D routers.

## PAY-30 — scheduled runner (`start_payout_runner_task`)
`run_payout_sweep()` scans requested + approved + processing payouts (ByStatusCreatedAt
GSI), and `process_one_payout` drives each EXACTLY ONCE: atomic status-claim ->
`processing` -> PAY-A `payout_transfer` (mock now / real when keyed) -> on success
`_finalize_paid` writes the idempotent `type="debit"` (balance drops) + status
`completed`. Registered as a 300s periodic task in `main.py` (mirrors
`subscription_renewal.start_subscription_renewal_task`) + a manual admin trigger
`POST /ui/admin/payouts/run` (`now_override`/`payout_id`/`limit`). Idempotent per
payout: the atomic claim + the PAY-A `PAYOUTDEBIT#` marker guarantee no
double-transfer / double-debit even if two sweeps race.

## PAY-31 — lifecycle + fail/return (+ webhook seam)
Clean requested->approved?->processing->paid, with failed/returned/canceled
terminals. `POST /v1/admin/payouts/{id}/fail` and `/{id}/return` wire
`fail_payout(returned=)` — reversing a PAID payout's debit (funds return,
idempotent) or just releasing the reservation when never paid. `POST
/v1/payouts/webhook` maps a provider `returned`/`failed` event to the same
handler (guarded by `PAYOUT_WEBHOOK_SECRET` when set). Cancel of a still-requested
payout is unchanged (PAY-A `cancel_payout`).

## PAY-32 — manual admin hold
`place_payout_hold` / `release_payout_hold` set a `manual_hold` flag; the runner
SKIPS a held payout (both the eligibility check and the atomic claim condition
exclude `manual_hold=True`). The 7-day BALANCE hold (`payout_hold_period_seconds`)
is unchanged. Admin: `POST /v1/admin/payouts/{id}/hold` + `/{id}/release-hold`.

## PAY-33 — bounded retries
Transient transfer failures are retried on a bounded backoff
(`payout_retry_backoff_seconds` default `60,300,900`, up to
`payout_max_transfer_attempts` = 4), recording `transfer_attempts` +
`next_attempt_at` + `last_transfer_error` on the payout; once exhausted (or a HARD
`PayoutTransferError(transient=False)`) -> `failed` + reverse. A `force_transfer_result`
attribute is an honest TEST seam (never present on real payouts) to drive the
retry/hard-fail paths under verification.

## PAY-34 — notifications
`payout_initiated` (processing), `payout_paid`, `payout_failed`, `payout_returned`
emitted via the shared `emit_social_alert` rail (a non-self `system` actor so they
are not self-suppressed) and registered in `alerts.DEFAULT_PUSH_EVENT_TYPES` =>
default-ON transactional push. PAY-F completes the full set + app wallet.

## No PAY-A/B/C regression
The runner reuses `payout_transfer` (PAY-A) + `_finalize_paid` debit; `request_payout`
still runs the PAY-C KYC+W-9 gate + PAY-B verified-method check + PAY-A balance
check. A failed/returned payout reverses the real debit (never inflates).

## Config flags (all default to the honest/mock-safe values)
`PAYOUT_RUNNER_ENABLED` (default on), `PAYOUT_RUNNER_INTERVAL_SECONDS` (300),
`PAYOUT_RUNNER_MIN_AGE_SECONDS` (0), `PAYOUT_MAX_TRANSFER_ATTEMPTS` (4),
`PAYOUT_RETRY_BACKOFF_SECONDS` (`60,300,900`), `PAYOUT_WEBHOOK_SECRET` (unset => open).

## Deploy (prod EC2 i-08f937fc705ebea75 via SSM)
- Backups (pre-change originals, on prod for rollback): `*.bak_payd_20260712_025429`
  alongside each of the 5 patched files under `/home/ubuntu/testlogon`.
- Deployed md5 (prod): creator_payouts `f39aa51fbf33b719e5d7a4bfa89812b3`,
  admin_payouts `93e80e9ad6d821974b6a78263b5e328e`, alerts
  `eeaa56c09fc369a087bb27ba7013c627`, settings `fa0d2e606541373490350fbd3b6fcf85`,
  main `aeebab3dff7350a19d2046def9ad5078`. `py_compile` OK; restart via
  `restart_backend.sh`; openapi 200; the 6 PAY-D routes present; the
  `payout_runner` startup task registered.

## Verify (in-process on PROD DDB, synthetic users, auto-cleaned): 30/30 PASS
- **S1 happy + idempotency + return**: gated+funded creator requests 3000; the
  runner processes requested->processing->paid, `transfer_provider=mock`, writes
  exactly ONE debit(3000) (balance 10000->7000); re-run = SKIPPED, still 1 debit,
  balance 7000 (no double-debit/transfer); admin `/return` reverses the debit
  (state settled->reversed) -> balance back to 10000; re-return idempotent.
- **S2 hard fail**: `force=hard_fail` -> `failed` in 1 attempt, NO debit (never
  paid), balance back to full (reservation released).
- **S3 bounded retries**: `force=transient_fail` -> attempt1 retry (backoff blocks
  a same-clock re-run) -> ... -> attempts == max(4) -> `failed`; no debit; balance back.
- **S4 manual hold**: place hold -> runner SKIPS (status stays requested, 0
  attempts) -> release -> runner pays it (1 debit 3000, balance 8000->5000).
- **Notifications**: `payout_initiated/paid/returned` (S1), `payout_initiated/failed`
  (S2), `payout_initiated/paid` (S4) rows written; all four events are default-ON.
- Cleanup left ZERO residue (payouts/markers/methods/billing/kyc/w9/alerts/
  sentinels/connect all deleted; residual_users_with_billing=0).
