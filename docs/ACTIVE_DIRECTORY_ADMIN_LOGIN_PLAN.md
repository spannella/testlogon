# Active Directory Admin Login & Root Admin Configuration Plan

## Goals
- Allow enterprise **admin users** to authenticate using Active Directory (AD) credentials.
- Preserve existing local/root authentication as a break-glass path.
- Let **root admin** configure and manage AD integration safely from the product.
- Add clear observability and auditing for security/compliance.

## Non-Goals (Phase 1)
- End-user (non-admin) AD login.
- Full AD object synchronization for all users/groups in the directory.
- Multi-forest federation beyond one AD integration at initial launch.

## Recommended Integration Model
Use standards-based identity federation instead of direct LDAP password verification:
1. Prefer **OIDC** via Microsoft Entra ID (Azure AD) when available.
2. Support **SAML 2.0** as a secondary compatibility path for organizations that require it.
3. Keep direct LDAP/LDAPS bind as optional legacy mode only if strictly needed (higher operational/security burden).

This allows strong MFA/Conditional Access policies to remain in the customer's identity platform and reduces password-handling risk.

---

## Phase 0: Discovery & Security Requirements
1. Confirm customer identity topology:
   - On-prem AD only, hybrid AD + Entra, or Entra-only.
   - Required protocols (OIDC/SAML), tenant constraints, MFA expectations.
2. Define authorization mapping strategy:
   - AD group/claim mapping to internal roles (`admin`, optional scoped admin roles).
3. Security baseline:
   - Enforce signed assertions/tokens.
   - Enforce clock-skew-safe token validation.
   - Require least-privilege service principals.
   - Document key rotation and certificate rollover requirements.
4. Compliance requirements:
   - Audit event retention, admin login traceability, and configuration change logs.

## Phase 1: Backend Foundations
1. **Identity Provider (IdP) abstraction**
   - Add provider-agnostic interfaces for external login (OIDC, SAML).
   - Normalize identity payload (`sub`, `email`, `name`, `groups`, `tenant_id`, `auth_time`).
2. **Configuration model**
   - Add persisted AD/IdP integration config fields:
     - `enabled`, `protocol`, `issuer`, `client_id`, `client_secret_ref`, `metadata_url`, `redirect_uri`, `allowed_tenants`, `group_role_mappings`, `default_role`, `fail_open=false`.
   - Store secrets in the existing secret store abstraction; never plaintext in DB.
3. **Authentication flow**
   - Add `/auth/admin/sso/start` and `/auth/admin/sso/callback` endpoints.
   - Verify token/assertion signature, issuer, audience, nonce/state.
   - Upsert/link admin identity record by immutable external subject + tenant.
4. **Session issuance**
   - Reuse existing admin session cookie/JWT mechanics after successful federation.
   - Tag session as `auth_method=ad_sso` for downstream policy checks.
5. **Fallback and lockout strategy**
   - Root local login remains available as break-glass path.
   - Optional policy toggle: "enforce SSO for admins" with exemption for root.

## Phase 2: Authorization & Role Mapping
1. Implement deterministic role mapping:
   - Claim/group -> internal role map with explicit precedence.
   - Deny login if no matching admin role and no default role configured.
2. Add sync semantics:
   - Evaluate roles at each login (authoritative claim-based mapping).
   - Optional periodic background refresh for long sessions.
3. Guardrails:
   - Prevent external claims from assigning `root` role.
   - `root` remains local/internal-only and manually controlled.

## Phase 3: Root Admin Configuration UX/API
1. Build root-only settings area:
   - "Identity & SSO" page in admin settings.
2. Root admin can:
   - Enable/disable AD integration.
   - Choose protocol (OIDC/SAML).
   - Enter metadata/issuer/client values.
   - Configure group-to-role mappings.
   - Test connection with non-destructive validation.
   - Save staged config and explicitly "Activate".
3. Safety controls:
   - Two-step activation (Save -> Validate -> Activate).
   - "Rollback to local auth" one-click option.
   - Confirmation modal requiring root re-auth for critical changes.
4. API protections:
   - Root-only endpoints with explicit policy checks.
   - Field-level validation and secure secret references.

## Phase 4: Operational Readiness
1. Audit logs for:
   - Config created/updated/activated/deactivated.
   - Login success/failure with reason codes (issuer mismatch, mapping denied, expired token).
   - Role assignment results from group mapping.
2. Metrics/alerts:
   - SSO login failure rate, callback latency, config validation failures.
   - Alert on sudden spikes in denied admin logins.
3. Runbooks:
   - Cert/key rotation.
   - IdP outage handling.
   - Emergency lockout recovery via root account.

## Phase 5: Testing Strategy
1. Unit tests:
   - Token/assertion validation paths.
   - Role mapping precedence and deny-by-default behavior.
2. Integration tests:
   - Full OIDC and/or SAML callback flow with mock IdP.
   - Root-only config endpoint authorization.
3. Security tests:
   - Replay/state/nonce tampering.
   - Expired token and invalid signature handling.
   - Privilege escalation attempts (group spoofing, root claim injection).
4. E2E tests:
   - Root configures integration -> admin logs in via AD -> admin role enforced.
   - Rollback to local login when IdP is unavailable.

## Suggested Data Model Additions
- `identity_providers`
  - `id`, `type`, `enabled`, `issuer`, `metadata_url`, `client_id`, `secret_ref`, `allowed_tenants`, `created_by`, `updated_by`, `created_at`, `updated_at`
- `identity_provider_role_mappings`
  - `id`, `provider_id`, `external_group_or_claim`, `internal_role`, `priority`
- `external_identities`
  - `id`, `user_id`, `provider_id`, `external_subject`, `external_tenant`, `last_login_at`
- `auth_audit_events`
  - extend with `auth_method`, `provider_id`, `failure_reason`, `mapped_role`

## API/UX Milestones (Incremental Delivery)
1. **Milestone A**: Backend config schema + root-only CRUD APIs (integration disabled by default).
2. **Milestone B**: OIDC login flow for admin users + role mapping.
3. **Milestone C**: Root admin UI for configuration + validation/activation workflow.
4. **Milestone D**: SAML support (if required) + full audit/metrics hardening.
5. **Milestone E**: Enforce-SSO policy toggle and recovery runbook finalization.

## Rollout Plan
1. Dark launch behind feature flag (`admin_ad_sso`).
2. Internal test tenant + synthetic admin accounts.
3. Pilot with one customer tenant.
4. Gradual enablement for all tenants, with root break-glass always preserved.

## Risks & Mitigations
- **Risk:** Misconfigured IdP locks out admins.  
  **Mitigation:** Root break-glass local auth + staged activation + rollback.
- **Risk:** Group mapping mistakes grant excess access.  
  **Mitigation:** Deny-by-default mapping + explicit test simulation before activate.
- **Risk:** Key rollover causes auth failures.  
  **Mitigation:** Metadata refresh + proactive monitoring + runbook.

## Open Decisions
1. Is OIDC-only acceptable for first release, or is SAML required immediately?
2. Single IdP per tenant vs multiple IdPs?
3. Should JIT provisioning create admin records automatically, or require pre-approved invite?
4. How long should AD-derived admin sessions remain valid?
5. Should SCIM provisioning be considered for future lifecycle management?
