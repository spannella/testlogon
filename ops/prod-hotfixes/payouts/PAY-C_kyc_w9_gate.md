# PAY-C — KYC + W-9 tax gate on request_payout (PAY-20/21)

LIVE PROD HOTFIX applied to EC2 i-08f937fc705ebea75 via SSM, then mirrored to the
dev clone (this commit). Prod .bak files: `*.bak_payc_20260712_053338` alongside
each patched file under /home/ubuntu/testlogon.

## What changed (verified-before-any-payout)
- **PAY-20 KYC gate** — `app/services/creator_payouts.py`: `request_payout` now calls
  `_enforce_payout_gate(user_id)` before claiming the sentinel. `resolve_kyc_status`
  reads the EXISTING kyc_cases store (`KycCaseStore.list_cases_by_owner`, same store the
  B6 admin review writes) — approved iff any owned case is `approved`; otherwise it
  returns the most-informative in-progress status. Not approved -> `PayoutGateError(
  code="kyc_required", kyc_status=<current>)`.
- **PAY-21 W-9 gate + endpoint** — reuses the existing KMS-backed W-9 store
  (`app/services/tax_info_w9.py`): the raw TIN is NEVER stored (KMS token `tin_encrypted`
  + masked `tin_last4` only; safe-view excludes the ciphertext). `has_tax_info_on_file`
  requires a certified W-9. Missing -> `PayoutGateError(code="tax_info_required")`.
  New payouts-namespaced endpoints on the payouts router:
  `GET/POST /ui/payouts/tax-info` (`PayoutTaxInfoOut{on_file,...masked}`, TIN masked
  after submit). Model `PayoutTaxInfoOut` added to `app/models.py`.
- **Router** — `app/routers/creator_payouts.py` catches `PayoutGateError` -> HTTP 403
  `{code, message, kyc_status}` so the app can route to KYC or the W-9 form.
- **Flag** — `app/core/settings.py`: `payout_verification_gate_enabled`
  (env `PAYOUT_VERIFICATION_GATE_ENABLED`), default **ON** (gate enabled now).

## Prod verify (in-process on prod DDB, real KMS) — all PASS
- gate_enabled = true
- no approved KYC (case=submitted) -> `kyc_required` + kyc_status="submitted"
- KYC approved, no W-9 -> `tax_info_required" + kyc_status="approved"
- W-9 submit(raw TIN) -> stored item keys have `tin_last4`=6789 + `tin_encrypted` token;
  raw "123456789" ABSENT from the item (asserted), no raw-TIN field present
- both satisfied (+seeded matured credit) -> request_payout PROCEEDED (status=requested),
  through PAY-A balance + PAY-B method checks
- all test writes cleaned up

Does NOT regress PAY-A (debit ledger) or PAY-B (verified-method) — the gate runs before
those checks and only adds rejections.
