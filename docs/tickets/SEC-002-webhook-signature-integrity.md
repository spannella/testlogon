# SEC-002: Webhook Signature/Secret Integrity (forged-webhook → unpaid entitlement)

**Ticket**: SEC-002 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (item 2)

## Problem
Inbound provider webhooks can be **forged** to grant unpaid entitlements (credit
wallet, activate/renew subscription, mark order delivered, approve KYC/tier) when
secrets fall back to hardcoded defaults or verification is weak:
- `app/services/billing_ccbill.py:159-172` — "local" mode default secret
  `"local-ccbill-webhook-secret"` (dev default) → forge CCBill NewSale/Renewal.
- `app/services/kyc_eidv.py:202` — default `"dev-mock-eid-signing-key"` → forge
  eIDV assertion → identity-verified / tier upgrade.
- `app/routers/billing_ccbill.py:515` — IP policy "monitor" mode lets disallowed
  IPs through.
- `app/routers/paypal.py:1299-1313` — user derived by parsing untrusted `custom_id`
  (vs server-side order→user map).
- `app/routers/billing.py:1261` (Stripe) — dedupe vs processing race → possible
  double-credit; UPS webhook (`ups.py:91`) has **no timestamp/replay** check.

## Fix
- **Fail-closed secrets:** remove hardcoded webhook-secret fallbacks; require strong
  per-provider secrets (KMS/env); reject if unset in non-dev (startup check).
- Enforce **`ip+sig`** (not "monitor") for CCBill in prod.
- Derive the user from a **server-side order_id→user_sub mapping**, not parsed
  `custom_id`.
- Make event dedupe an **atomic conditional write before processing**; ensure
  downstream credit is idempotent (by event id + amount + reason).
- Add **timestamp tolerance + processed-id replay store** to all provider webhooks
  (incl. UPS).

## Testing
pytest per provider: a body signed with the default/empty secret is rejected;
correctly-signed is accepted once; replay (same event id / old timestamp) is
rejected; forged "succeeded/approved" does not credit/activate.
