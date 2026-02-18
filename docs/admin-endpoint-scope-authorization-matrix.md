# AP-007 Endpoint-to-scope authorization matrix

This matrix inventories all currently admin-gated API routes and classifies each route to one of:

- `auth_support`
- `billing_support`
- `content_moderation`
- `general_admin_only`

Routes that are not safely classifiable to a domain scope are explicitly marked as deferred for security review.

## Scope mapping decisions

- **`auth_support`**: login/session/account-access support actions.
- **`billing_support`**: payment, charge, and account-balance support actions.
- **`content_moderation`**: user-generated content review/moderation enforcement actions.
- **`general_admin_only`**: privileged cross-domain or governance actions not limited to one support domain.

## Admin-gated route inventory

| Method | Route | Current guard | Classified scope | Owner | Status | Notes |
|---|---|---|---|---|---|---|
| POST | `/admin/impersonation/start` | `require_admin_or_root` | `auth_support` | Auth Platform | Classified | Account access troubleshooting; root-only target guardrails remain in handler. |
| POST | `/admin/impersonation/stop` | `require_admin_or_root` | `auth_support` | Auth Platform | Classified | Ends support impersonation sessions. |
| GET | `/admin/impersonation/audit` | `require_admin_or_root` | `general_admin_only` | Security Operations | Deferred (security review) | Audit visibility is cross-domain and may require narrower read policy than action policy. |
| POST | `/admin/roles/grant` | `require_root` | `general_admin_only` | Identity & Access Management | Classified | Governance-critical role assignment; root-only preserved. |
| POST | `/admin/roles/revoke` | `require_root` | `general_admin_only` | Identity & Access Management | Classified | Governance-critical role revocation; root-only preserved. |
| POST | `/admin/roles/update-profile` | `require_root` | `general_admin_only` | Identity & Access Management | Classified | Capability-profile governance; root-only preserved. |
| GET | `/admin/roles/audit` | `require_root` | `general_admin_only` | Identity & Access Management | Classified | Role governance audit stream. |
| POST | `/api/billing/_dev/add-charge` | `require_admin_or_root_session` | `billing_support` | Billing Platform | Classified | Billing-only mutation for support/testing flows. |
| POST | `/ui/billing/_dev/add-charge` | `require_admin_or_root_session` | `billing_support` | Billing Platform | Classified | UI alias for same billing support mutation. |
| GET | `/v1/fs/admin/list` | `_admin_or_root_ctx` | `content_moderation` | Trust & Safety | Deferred (security review) | File inventory may be moderation-related, but ownership/privacy constraints require review. |
| GET | `/v1/fs/admin/search` | `_admin_or_root_ctx` | `content_moderation` | Trust & Safety | Deferred (security review) | Metadata search can be moderation tooling or support tooling depending on intent. |
| GET | `/v1/fs/admin/read` | `_admin_or_root_ctx` | `content_moderation` | Trust & Safety | Deferred (security review) | Potential content access; existing feature flag allows root-only content read in some tiers. |
| GET | `/v1/fs/admin/audit` | `_admin_or_root_ctx` | `general_admin_only` | Security Operations | Deferred (security review) | Cross-domain telemetry; needs decision on least-privilege read audience. |
| POST | `/v1/fs/purge-deleted` | `_admin_or_root_ctx` | `general_admin_only` | Storage Platform | Deferred (security review) | Destructive operation without domain ownership encoded in route. |

## Explicitly unresolved/ambiguous routes for review

The following routes are intentionally deferred and require security sign-off before AP-008+ enforcement migrations:

1. `GET /admin/impersonation/audit`
2. `GET /v1/fs/admin/list`
3. `GET /v1/fs/admin/search`
4. `GET /v1/fs/admin/read`
5. `GET /v1/fs/admin/audit`
6. `POST /v1/fs/purge-deleted`

## Coverage check

All currently admin-gated routes identified via broad admin/root checks are included above:

- `require_admin_or_root` routes in `app/routers/admin_impersonation.py`
- root-governed role routes in `app/routers/admin_roles.py`
- `require_admin_or_root_session` route aliases in `app/routers/billing.py`
- `_admin_or_root_ctx` routes in `app/routers/filemanager.py`
