# PAY-B (PAY-10..12) — Routable payout methods + Connect + verify seam (LIVE PROD HOTFIX)

Makes a payout method a ROUTABLE DESTINATION the PAY-A `payout_transfer` can
target — instead of cosmetic last-4 metadata — while keeping SEC-004 (never store
a full account number). Files changed:
`app/services/creator_payouts.py`, `app/routers/creator_payouts.py`,
`app/models.py`. Applied by `patch_payb.py` (idempotent find/replace, asserts each
anchor) so the identical transform lands on prod + the dev clone regardless of
models.py drift.

## PAY-10 — routable method model
- `PAYOUT_METHOD_TYPES` gains `stripe_connect` (now {bank_ach, bank_wire, paypal,
  check, stripe_connect}).
- Method record carries the fields the transfer needs:
  - **bank** → `bank_token` (opaque `btok_mock_<sha256>` ref) + `account_last4` /
    `routing_last4` for display. `external_account_ref = bank_token`.
    `_tokenize_bank_ref` derives the token from a salted hash of the full
    account/routing and returns only {token, last4} — **the raw number is never
    stored and never logged (SEC-004)**. The full number is a WRITE-ONLY input
    (`PayoutMethodIn.account_number`/`routing_number`, tokenized server-side).
  - **paypal** → `paypal_email`; `external_account_ref = paypal:<email>`.
  - **stripe_connect** → `connect_account_id`; `external_account_ref =
    connect_account_id`.
- `method_status` ∈ {unverified, verifying, verified, failed}; new methods start
  `unverified`. Exposed on `PayoutMethodOut` along with `connect_account_id` +
  `external_account_ref`.

## PAY-11 — Stripe Connect ACCOUNT + onboarding seam
- `create_connect_account(user_id)` — idempotent; real
  `stripe.Account.create(type="express")` when `STRIPE_CONNECT_ENABLED=1` +
  `S.stripe_secret_key`; mock `acct_mock_<hash>` otherwise. Stored under
  `payout_id=CONNECT#{user_id}` (`record_kind=connect_account`) with
  `onboarding_status` + `payouts_enabled`.
- `create_connect_onboarding_link(user_id)` — real `stripe.AccountLink.create`
  (`type=account_onboarding`) when keyed; **mock marks onboarding-complete +
  payouts_enabled** so a `stripe_connect` method can be verified (honest: no real
  account is linked under the mock).
- Routes: `POST /ui/payouts/connect/account`, `POST
  /ui/payouts/connect/onboarding-link`, `GET /ui/payouts/connect`.

## PAY-12 — verification seam (payout only to verified)
- `verify_payout_method(user_id, method_id)` — mock → `verified`; real (keyed) →
  `verifying` (bank micro-deposit pending) or `verified` iff the Connect account's
  `payouts_enabled` capability is live. Route: `POST
  /ui/payouts/methods/{method_id}/verify`.
- `request_payout` resolution now loads the resolved method (explicit `method_id`
  or the creator's default), **rejects `method_status != "verified"` with
  `method_not_verified`**, and stamps `connect_account_id` / `external_account_ref`
  / `paypal_email` onto the payout item — which PAY-A `payout_transfer` reads
  (`payout.get("connect_account_id") …`). No-method legacy path is unchanged, so
  PAY-A is not regressed.

## The gate is honest
Under the mock (today, no creds): the destination is a routable-shaped
token/ref/acct_mock id + a `verified-mock` status — no real bank/Connect account
is linked, no external money moves (PAY-A transfer stays `provider=mock`, the real
`type="debit"` still lands). When `STRIPE_CONNECT_ENABLED` / `PAYOUT_USE_REAL_PROVIDER`
are keyed the real Connect onboarding + bank tokenization + transfer drop in.

## Deploy (prod EC2 i-08f937fc705ebea75 via SSM)
- Backups: `app/services/creator_payouts.py.bak_payb_1783830784`,
  `app/routers/creator_payouts.py.bak_payb_1783830784`,
  `app/models.py.bak_payb_1783830784` (pre-change originals, on prod for rollback).
- Deployed md5: service `f2295b80ae3022f7351b8313dab587f6` (== dev clone),
  router `c2fa2cc2b3f70a7953453764ccdda125` (== dev clone),
  models `48f3ef9051ce9f1b38c274f25488a494` (prod; dev clone models differs
  pre-image but the PAY-B class edits are identical). Restart via
  `restart_backend.sh`; openapi 200; new routes present.

## Verify (in-process on PROD DDB, synthetic users, auto-cleaned): 18/18 PASS
seed 5000 → available 5000; add bank method (full acct/routing supplied) → only
last-4 in dict, **NO raw account/routing number stored** (asserted absent from the
raw item), `bank_token`/`external_account_ref` present, status `unverified`;
request payout to the UNVERIFIED default → rejected (`method_not_verified`); verify
→ `verified`; request 3000 → available 2000 + payout carries `external_account_ref`
(routable dest); approve+complete → `transfer_provider=mock` + available STAYS 2000
(no revert / PAY-A intact); Connect: `create_connect_account` → `acct_mock_…`,
onboarding seam → onboarding-complete + payouts_enabled (real=False), a
`stripe_connect` method routes to that `connect_account_id` + verify → `verified`.
Cleanup left zero residue.
