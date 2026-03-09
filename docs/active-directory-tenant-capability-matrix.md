# Active Directory Admin SSO — Tenant Capability Matrix & Assumptions

This matrix captures supported deployment shapes and protocol requirements for AD-backed admin authentication.

## Capability Matrix

| Deployment Shape | Typical Identity Stack | v1 Protocol Support | Admin SSO Readiness | Key Constraints | Notes |
|---|---|---|---|---|---|
| Entra-only | Microsoft Entra ID | OIDC ✅ (primary), SAML ⚠️ (phase 2) | High | Must provide tenant ID, issuer metadata, admin group claims | Preferred launch cohort |
| Hybrid AD + Entra | On-prem AD synced/federated to Entra | OIDC ✅ (primary), SAML ⚠️ (phase 2) | High | Group claim sync must include admin groups used in mapping | Strong candidate for pilot |
| On-prem AD + ADFS federation | AD + ADFS (OIDC/SAML exposure) | OIDC ✅ if available, SAML ⚠️ (phase 2) | Medium | Stable federation metadata and signing key rollover process required | Validate claim shape early |
| On-prem AD only (no federation) | AD DS only | OIDC ❌, SAML ❌ in v1 | Low | Federation bridge required before onboarding | LDAP/LDAPS is deferred by ADR |

Legend: ✅ supported in v1, ⚠️ planned follow-up, ❌ not supported.

## Assumptions
1. Each product tenant has one active IdP configuration in v1.
2. Admin authorization is claim/group-based and deny-by-default.
3. Root role is internal-only and never granted from external claims.
4. Root local login remains available for break-glass recovery.
5. Customer IdP administrators can provide stable metadata URLs and complete certificate/key rollover procedures.

## Customer Requirement Checklist (Discovery)

### Protocol + Platform
- Is OIDC available and approved by customer IAM/security?
- Is SAML mandatory for policy/compliance reasons?
- Are there tenant restrictions requiring allow-listing of specific tenant IDs?

### Claim Availability
- Can the IdP provide immutable subject ID (`sub`) and tenant identifier (`tid`/equivalent)?
- Are admin groups/roles emitted in tokens/assertions at login time?
- Is `email` available and verified (if required by account-linking policy)?

### Security + Operations
- Can the customer enforce MFA/Conditional Access for admin applications?
- What is signing key rotation cadence and notification process?
- Who owns incident response if IdP outage blocks SSO?

## Required Claims & Constraints Summary
- Required: `sub`, `iss`, `aud`, `exp`, tenant identifier (`tid` or normalized `tenant_id`), and group/role claim used for mapping.
- Required controls: state/nonce validation, signature verification, issuer/audience checks, token freshness checks.
- Required policy: explicit tenant allow-list for production activation.

## Onboarding Decision Rules
1. If OIDC is available and required claims are present, tenant is v1-eligible.
2. If only SAML is available, tenant is queued for phase-2 SAML support.
3. If no federation protocol is available, tenant is blocked until federation bridge exists.
4. If group claims are unavailable, tenant is blocked pending role mapping strategy.
