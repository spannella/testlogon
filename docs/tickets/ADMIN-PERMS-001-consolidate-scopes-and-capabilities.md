# ADMIN-PERMS-001: Consolidate Admin Permissions (API scopes vs rootctl capabilities)

**Ticket**: ADMIN-PERMS-001
**Author**: Engineering
**Status**: Open
**Priority**: High (security: a permission grant path that does nothing)
**Date**: 2026-06-04
**Dependencies**: `app/auth/roles.py`, `app/auth/policy.py`, `app/routers/admin_roles.py`, `app/cli/rootctl.py`, `frontend/src/api/endpoints/adminRoles.ts`

---

## 1. Overview & Motivation

There are **two parallel admin-permission systems that don't align**, and one of
them is **dead code** that gives a false sense of having granted access.

### System 1 — `admin_profile.scopes` (API; ENFORCED) ✅
- Enum: `app/auth/roles.py:14-18` — `auth_support`, `billing_support`,
  `content_moderation`, `content_moderation_senior`.
- Written by `POST /admin/roles/grant` + `/admin/roles/update-profile`
  (`app/routers/admin_roles.py:235,307`) → `users.admin_profile = {type, scopes}`.
- **Enforced** by `require_admin_scope(...)` (`app/auth/policy.py:122-169`), used by
  admin endpoints (billing, filemanager, impersonation, …). Scope-denied requests
  audit + emit metrics. This is the real system.

### System 2 — `admin_capabilities` (rootctl; NOT ENFORCED) ❌
- Enum: `app/cli/rootctl.py:51-58` — `billing_ops`, `billing_read`,
  `file_metadata`, `file_content`, `user_support`, `impersonation` (different set,
  zero overlap with System 1).
- Written by `rootctl admin permissions set` → `users.admin_capabilities`
  (`rootctl.py:1703`), behind flag `ROOTCTL_ADMIN_CAPABILITIES_ENABLED`.
- **Read nowhere in `app/` for authorization** — only echoed back by
  `rootctl admin permissions list` (`rootctl.py:1759`). Confirmed **decorative/dead**.

### Concrete problems
1. **False permission grant (security):** an operator runs `rootctl admin
   permissions set --capability billing_ops …`, believes they granted access — but
   nothing enforces it. Conversely it may imply a restriction that isn't real.
2. **No CLI path to the enforced scopes:** `rootctl admin grant` sets only `role`,
   never `admin_profile.scopes`. The *enforced* scopes can be set **only via the
   API** — the CLI can create/grant an admin but can't scope them.
3. **Frontend drift:** `frontend/src/api/endpoints/adminRoles.ts:4` lists
   `auth_support | billing_support | content_moderation` — **missing**
   `content_moderation_senior` which the backend enforces.

## 2. Proposed Fix — one model (API scopes), enforced everywhere

1. **Make `admin_profile.scopes` the single source of truth** (it's the enforced
   one). 
2. **rootctl writes the enforced scopes:** add `--scope <auth_support|…>`
   (repeatable) to `rootctl admin grant` (and a `permissions set`/`update-profile`
   equivalent) that writes `admin_profile = {type: scoped, scopes:[…]}` mirroring
   the API's validation in `admin_roles.py`. So CLI and API set the same field.
3. **Remove `admin_capabilities`** (and the `ROOTCTL_ADMIN_CAPABILITIES_ENABLED`
   flag): delete the write path + `permissions set/list` capability variant, or
   repoint them at `admin_profile.scopes`. Migrate any existing `admin_capabilities`
   data to scopes if present (likely none in prod).
4. **Frontend:** add `content_moderation_senior` to the `AdminScope` type and the
   grant UI so the full enforced set is selectable.
5. **(Optional) Admin visibility (A1):** add `GET /admin/roles` (list admins) and
   `GET /admin/roles/{user_sub}` so operators can see who has which scopes without
   scanning the audit log.

### Design Principles
- Exactly **one** permission concept (`admin_profile.scopes`), enforced by
  `require_admin_scope`, settable identically via API and CLI.
- No stored-but-ignored permission fields (no false grants).
- Backend ↔ frontend ↔ CLI all share the same scope enum.

## 3. Implementation Sketch
- `app/cli/rootctl.py`: add scope-setting to `admin grant`/permissions writing
  `admin_profile`; remove `ADMIN_CAPABILITIES` + capability commands (or alias to
  scopes); keep audit (`role_audit`, `source: rootctl`).
- `app/routers/admin_roles.py`: (optional) add list/get endpoints (root/admin-gated).
- `frontend/src/api/endpoints/adminRoles.ts` + grant UI: add `content_moderation_senior`.
- One-off migration: `admin_capabilities` → `admin_profile.scopes` (best-effort) or drop.

## 4. Testing
- pytest: a scope set via CLI is enforced by `require_admin_scope` exactly like one
  set via API; removing `admin_capabilities` doesn't break grant/revoke; list/get
  return correct scopes. E2E: grant `content_moderation_senior` in the UI and verify
  enforcement.

## 5. Out of Scope
- rootctl break-glass auth (**ROOTCTL-001**); root login (**ROOT-AUTH-001**).

## 6. Confirmed evidence
- Enforced scopes: `roles.py:14-18`, `policy.py:122-169`, written `admin_roles.py:235,307`.
- Dead capabilities: defined `rootctl.py:51-58`, written `:1703`, read only by
  `permissions list` `:1759`, enforced nowhere in `app/`.
- CLI grant sets role only (not admin_profile): `rootctl.py` admin grant/revoke.
- Frontend missing senior scope: `frontend/src/api/endpoints/adminRoles.ts:4`.
