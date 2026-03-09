# AD Admin SSO Security Controls Checklist (AD-002)

This checklist maps mandatory controls from the threat model to implementation tasks/tickets.

## Control Mapping

| Control ID | Control Requirement | Implementation Tasks | Related Tickets | Verification Method |
|---|---|---|---|---|
| ADSEC-001 | State/nonce must be cryptographically strong, short-lived, and single-use | Implement state/nonce generation + signed persistence + replay rejection in SSO start/callback | AD-005, AD-006, AD-016 | Unit + integration tests for replay and expiry handling |
| ADSEC-002 | Token/assertion signature must be validated with trusted keys | Validate JWT/assertion signature using trusted metadata/JWKS; reject unknown key IDs/algorithms | AD-006, AD-016 | Negative tests for invalid signature/key confusion |
| ADSEC-003 | Issuer/audience/tenant checks must be mandatory | Enforce exact `iss`/`aud` checks and `allowed_tenants` policy | AD-006, AD-010, AD-016 | Integration tests for wrong issuer/audience/tenant |
| ADSEC-004 | Token freshness and anti-replay validation required | Enforce `exp`, `iat`, `auth_time`, nonce/state checks and single-use flow artifacts | AD-006, AD-016 | Security test matrix for expired/replayed tokens |
| ADSEC-005 | Role mapping must be deterministic and deny-by-default | Implement mapping precedence; deny when no explicit mapping/default role policy | AD-008, AD-016 | Unit tests for precedence and deny behavior |
| ADSEC-006 | External identities must never grant `root` | Add hard policy gate blocking `root` from all external mappings/claims | AD-009, AD-016 | Regression tests for root-claim injection attempts |
| ADSEC-007 | Break-glass root local access must remain available | Preserve root local auth path independent from admin SSO enforcement toggle | AD-009, AD-011, AD-017 | E2E outage/rollback scenario validation |
| ADSEC-008 | IdP secret material must not be stored in plaintext DB | Persist `secret_ref` only; use secret-store retrieval + redaction controls | AD-004, AD-013 | Schema/code review and log redaction tests |
| ADSEC-009 | Key rotation must be operationally safe | Implement metadata/JWKS refresh and failure-mode handling runbook | AD-014, AD-015 | Non-prod rotation drill + runbook validation |
| ADSEC-010 | Auth/config actions must be fully auditable | Emit structured audit events with actor, provider, outcome, and reason code | AD-013, AD-014 | Audit event contract tests + dashboard checks |

## Required Policy Statements

1. `root` role is internal-only and cannot be assigned through external claims or mappings.
2. Admin SSO must fail closed on token/assertion validation failures.
3. Production activation requires explicit tenant allow-listing and validated role mappings.

## Implementation readiness gates

- [ ] Gate 1: Threat scenarios in `docs/ad-admin-sso-threat-model.md` are represented in automated tests (unit/integration/security).
- [ ] Gate 2: Security review confirms fail-closed behavior for token/assertion validation and tenant checks.
- [x] Gate 3: Break-glass runbook validated in staging with root-only recovery drill (`docs/ad-admin-sso-recovery-checklist-staging.md`, validated 2026-03-06).
- [ ] Gate 4: Audit dashboard shows success/failure reason-code coverage for SSO start/callback.
- [ ] Gate 5: Root-assignment prohibition regression tests are mandatory in CI.

## Sign-off

- Security Engineering: **approved**
- Platform Engineering: **approved**
- Date: `2026-03-04`
- Ticket: `AD-002`

## Operational references

- `docs/ad-admin-sso-oncall-handbook.md`
- `docs/ad-admin-sso-operational-runbook.md`
- `docs/ad-admin-sso-recovery-checklist-staging.md`
