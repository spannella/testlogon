# GAP-0286: Per-API-key rate limiting is completely absent from all partner API endpoints

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-021 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-021.md`); see also `docs/tickets/writeups/KYC-021.md`

## Location
`app/routers/kyc_partner_api.py`

## Problem / Impact
the ticket (§4.7) specifies 100/hour for `POST /applications`, 200/hour for `POST /documents`, 1000/hour for GET endpoints, and 10/hour for webhook test; the existing `rate_limit_or_429` infrastructure (`app/services/rate_limit.py`) supports `user_sub` + `factor` keys and is used throughout the platform; without limits a single partner can exhaust KYC case creation capacity or DynamoDB write throughput

## Fix
add `rate_limit_or_429(user_sub=f"apikey:{api_key_id}", factor="kyc_api:applications")` etc. at the top of each endpoint handler

## Notes
This gap was identified by the second-pass as-built review of KYC-021. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
