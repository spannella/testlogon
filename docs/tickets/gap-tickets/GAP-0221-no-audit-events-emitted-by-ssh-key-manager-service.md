# GAP-0221: No audit events emitted by SSH key manager service

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-002.md`); see also `docs/tickets/writeups/INFRA-002.md`

## Location
`app/services/ssh_key_manager.py`

## Problem / Impact
ticket spec requires audit events for `ssh_key.generate`, `ssh_key.upload`, `ssh_key.delete`, `ssh_key.decrypt`, `ssh_key.associate/disassociate`; only `logger.info` structured logs are emitted; no entries reach the audit trail or SECOPS-001 telemetry

## Fix
import `audit_event` from `app.services.alerts` and call it in `generate_key`, `upload_key`, `delete_key`, `get_decrypted_private_key`, `associate_key_with_host`, `disassociate_key_from_host`

## Notes
This gap was identified by the second-pass as-built review of INFRA-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
