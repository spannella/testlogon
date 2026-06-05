# GAP-0264: `case["signature"]` stores single packet; template packets require a list

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-007 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-007.md`); see also `docs/tickets/writeups/KYC-007.md`

## Location
`case["signature"]`

## Problem / Impact
existing structure holds one `packet_id`; template flow needs `signature.template_packets` list to avoid breaking existing single-packet check at `_signature_status_for_case()` line 184

## Fix
extend case META to store `signature.template_packets = [{template_type, packet_id, version}]` using `list_append`

## Notes
This gap was identified by the second-pass as-built review of KYC-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
