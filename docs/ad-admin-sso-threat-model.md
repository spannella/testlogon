# AD Admin SSO Threat Model (AD-002)

## Scope

This threat model covers admin authentication via federated Active Directory identity providers (OIDC in v1, SAML in follow-up), including SSO initiation, callback handling, token/assertion validation, role mapping, session issuance, and break-glass root access.

### Assets in scope

- Admin SSO state/nonce artifacts
- OIDC authorization code and ID/access tokens (and SAML assertions in phase 2)
- IdP metadata and signing keys (JWKS/certs)
- Group/claim-to-role mapping configuration
- Admin session artifacts (`auth_method=ad_sso`)
- Security audit events and authentication telemetry
- Root local account and break-glass access controls

### Trust boundaries

1. **Admin browser/client** (untrusted endpoint; can be tampered with)
2. **Application auth service** (state, callback validation, role mapping, session issuance)
3. **Identity provider boundary** (Entra/ADFS/other IdP token issuance and keys)
4. **Secret store + configuration store** (client secrets, signing cert references, tenant allow-lists)
5. **Observability/audit systems** (must not receive sensitive credential material)

---

## Threats and mitigations

| Threat | Description | Primary mitigations | Residual risk |
|---|---|---|---|
| State/nonce tampering | Attacker reuses or forges callback state/nonce to hijack auth flow | Signed, short-lived, single-use state/nonce; strict state/nonce verification before token exchange | Small race window if endpoint/client compromised before expiry |
| Token/assertion replay | Captured token/assertion replayed to obtain admin session | Token freshness checks (`exp`, `iat`, `auth_time`), nonce binding, audience/issuer validation, single-use flow artifacts | Replay possible within validity window if full endpoint compromise exists |
| Signature bypass / key confusion | Malicious token with invalid signature or wrong key accepted | Strict signature validation, expected alg enforcement, trusted issuer metadata, key ID checks, secure JWKS/cert refresh | Transient auth failures during key rollover/misconfiguration |
| Issuer/audience confusion | Token from wrong tenant or app accepted | Exact `iss` and `aud` checks; explicit tenant allow-list (`allowed_tenants`) | Misconfiguration can cause deny-all until corrected |
| Privilege escalation via group claims | User injects/abuses claims to obtain excessive role | Deterministic mapping with explicit precedence; deny-by-default for unmatched mappings; mapping simulation before activation | Incorrect admin-defined mapping can still over-grant non-root roles |
| External assignment of `root` | IdP claim/group maps user to root role | Hard policy block: external identities cannot map to `root`; root remains local/internal-only | None if rule is enforced server-side on every login |
| IdP outage/admin lockout | IdP unavailable blocks all admin access | Root local break-glass login always available; rollback/deactivate SSO path | Operational pressure during incidents if root credentials are not maintained |
| Secret leakage | IdP client secret/cert leaked via DB/logs | Store only `secret_ref` in DB; secret-store retrieval at runtime; redact logs and forbid secret logging | Insider misuse risk remains without strict access governance |
| Audit/telemetry data leakage | Sensitive tokens/claims logged unintentionally | Structured reason codes; no raw tokens/assertions in logs; redaction controls and logging lint/tests | Regression risk from future code changes |

---

## Mandatory controls (security baseline)

1. **State/nonce protection**
   - Generate cryptographically strong state/nonce per login.
   - Enforce short expiration and one-time usage.
2. **Token/assertion validation**
   - Require signature, issuer, audience, and token lifetime verification.
   - Enforce nonce binding and tenant allow-list checks.
3. **Key rotation handling**
   - Support trusted metadata refresh for JWKS/certs.
   - Fail safely (deny auth) on signature/key validation errors.
4. **Authorization safeguards**
   - Deny-by-default role mapping for unmapped identities.
   - Block any external mapping to `root` role.
5. **Break-glass policy**
   - Keep root local authentication path available and documented.
   - Require root re-auth for critical SSO configuration changes.
6. **Auditability**
   - Emit immutable auth/config events with reason codes.
   - Capture actor, provider, outcome, and mapped role context.

## Abuse-case validation scenarios (must-pass)

1. Callback with mismatched `state` is rejected and audited with a stable failure code.
2. Replayed callback with previously consumed nonce is rejected.
3. Expired token/assertion and not-yet-valid token/assertion are both rejected.
4. Token/assertion signed with unknown key ID (`kid`) or algorithm mismatch is rejected.
5. Valid token from non-allow-listed tenant is rejected.
6. Mapped role attempt to `root` via external claim is rejected even when mapping exists.
7. IdP unavailable path preserves root break-glass login and allows SSO disable/rollback.

---

## Break-glass root access policy

- Root authentication is local/internal and not federated.
- Root access remains available regardless of SSO enforcement state for admins.
- Root is the recovery path for:
  - IdP outage
  - IdP misconfiguration
  - Invalid role mapping lockouts
- SSO activation and rollback actions must be auditable and require high-assurance confirmation.
- Root credentials must follow stronger controls than admin accounts:
  - MFA required.
  - Hardware-backed/WebAuthn factor preferred.
  - Offline recovery procedure documented and access-limited.

**Explicit policy:** `root` cannot be assigned via external claims, external groups, or IdP role mappings.

---

## Security sign-off

- Security Engineering: **approved**
- Platform Engineering: **approved**
- Date: `2026-03-04`
- Ticket: `AD-002`

Linked docs:
- `docs/adr/ADR-0001-admin-ad-sso-protocol-sequencing.md`
- `docs/active-directory-tenant-capability-matrix.md`
- `docs/ACTIVE_DIRECTORY_ADMIN_LOGIN_PLAN.md`
