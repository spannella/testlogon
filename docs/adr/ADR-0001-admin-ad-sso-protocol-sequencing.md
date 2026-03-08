# ADR-0001: Active Directory Admin SSO Protocol Sequencing (OIDC-first)

- **Status:** Approved
- **Date:** 2026-03-04
- **Owners:** Platform Engineering, Security Engineering
- **Related Tickets:** AD-001
- **Related Docs:**
  - `docs/ACTIVE_DIRECTORY_ADMIN_LOGIN_PLAN.md`
  - `docs/ACTIVE_DIRECTORY_ADMIN_LOGIN_TICKETS.md`
  - `docs/active-directory-tenant-capability-matrix.md`

## Context
We need a secure and supportable way for enterprise admin users to authenticate with Active Directory-backed identity systems while preserving a local root break-glass path. Customer environments vary:
- On-prem AD only.
- Hybrid AD + Microsoft Entra ID.
- Entra-only.

Protocol selection affects security posture, implementation complexity, and operational overhead.

## Decision
1. **Primary protocol: OIDC (Authorization Code + PKCE) via Microsoft Entra ID.**
2. **Secondary protocol: SAML 2.0 support after OIDC baseline is stable**, for tenants with hard SAML requirements.
3. **No direct LDAP/LDAPS password bind in initial release** (explicitly deferred due to higher credential-handling risk and operational complexity).

## Rationale
- OIDC offers modern token validation, stronger developer ergonomics, and easier integration with existing session/auth layers.
- OIDC aligns with Conditional Access and MFA controls configured in Entra.
- Deferring SAML reduces initial blast radius while preserving a compatibility path.
- Avoiding LDAP bind minimizes password handling and secure channel/certificate burden.

## Required Identity Claims (Admin SSO)
The following normalized claims are required for authorization and auditing:
- `sub` (immutable subject identifier)
- `iss` (issuer)
- `aud` (audience/client)
- `exp` / `iat` / `auth_time`
- `tid` or equivalent tenant identifier (`tenant_id` normalized)
- `groups` or role/group claims required for admin mapping

Preferred claims:
- `email`
- `name`
- `preferred_username`

## Tenant Constraints
- **Tenant allow-list required** (`allowed_tenants`) for production activation.
- **Single active IdP per tenant in v1** (multi-IdP deferred).
- **Group-to-role mapping required** for admin access; deny by default if mapping is absent.
- **External identities cannot grant `root` role.**
- **Root local login remains available** regardless of admin SSO enforcement toggle.

## Security Requirements
- Validate signature, issuer, audience, nonce, state, expiration.
- Require short-lived, single-use state/nonce values.
- Enforce secure key discovery/rotation handling (JWKS metadata refresh).
- Emit auditable reason codes for login failures and denied mappings.

## Considered Options

### Option A — OIDC-first, SAML second (**Selected**)
- Pros: Faster secure delivery, modern standards, lower implementation risk.
- Cons: SAML-only customers wait for phase 2.

### Option B — OIDC + SAML simultaneously
- Pros: Broad compatibility on day one.
- Cons: Larger scope, slower delivery, broader test matrix and risk.

### Option C — LDAP/LDAPS direct bind first
- Pros: Works in pure on-prem environments without federation.
- Cons: Highest risk and operational burden; direct password verification concerns.

## Consequences
### Positive
- Clear phased delivery with reduced initial complexity.
- Better default security posture and easier observability.

### Negative / Trade-offs
- SAML-only tenants may require temporary delay or onboarding workaround.
- On-prem-only AD environments need federation bridge (e.g., ADFS/Entra sync) before v1.

## Approval
- **Security Engineering:** Approved
- **Platform Engineering:** Approved
