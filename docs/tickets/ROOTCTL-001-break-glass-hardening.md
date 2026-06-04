# ROOTCTL-001: rootctl Break-Glass Hardening (auth/approval, missing lifecycle cmds)

**Ticket**: ROOTCTL-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: High
**Dependencies**: `app/cli/rootctl.py`, role/audit system (`role_audit`), `docs/security-hardening-runbook.md`

---

## 1. Overview & Motivation

`scripts/rootctl` → `app/cli/rootctl.py` is the break-glass CLI. It mutates
DynamoDB **directly** (no backend call) and identifies the operator only via a
`--actor-sub` **flag** — there is no authentication, secret, signature, or
approval. Anyone with DDB access + the flag can act as root (reset root password,
deactivate/delete users, grant admin). It is well-audited (every mutation calls
`audit_event(..., cli=True)`, role events tagged `source: rootctl`) but **not
authenticated**. The security-hardening runbook flags this for hardening.

This ticket hardens the break-glass path and fills missing lifecycle commands.

### Findings (from gap analysis)
- **C1 (Critical):** no auth/approval on mutations — `--actor-sub` is just a flag
  (`app/cli/rootctl.py:2006-2018`); only a string-equality `requires_root` check.
- **C2:** `rotate-secrets` is a placeholder (`rootctl.py:2134-2144`).
- **C3:** `deactivate`/`delete` exist but there is **no `reactivate`/`undelete`**
  — a deactivated/soft-deleted user can't be restored without manual DDB repair.
- (Already good: audit emission `cli=True`; root immutability invariants.)

## 2. Proposed Hardening

1. **Authenticated / approved invocation (C1):**
   - Require a **break-glass secret** (KMS-backed or env-injected, not a CLI flag)
     to authorize mutations; verify before any write. Reuse the mock KMS in dev.
   - Optional **two-person rule** for the highest-risk commands (root
     reset-password/reset-mfa, user delete): a second approver token / a pending
     approval record in DDB that a second operator confirms.
   - Bind `--actor-sub` to the authenticated principal (don't trust the bare flag).
2. **Complete the lifecycle (C3):** add `rootctl user reactivate` and
   `rootctl user undelete` (restore `account_state`/`status`, clear soft-delete),
   mirroring the deactivate/delete guards (`--ticket`, `--confirm`).
3. **Implement `rotate-secrets` (C2)** or remove the placeholder; if implemented,
   rotate the relevant signing/break-glass secrets with audit.
4. **Harden audit:** record the authenticated identity + approval id (not just the
   flag) so "who ran rootctl" is provable.

### Design Principles
- Break-glass stays usable offline (direct DDB) but **gated** by a secret/approval,
  not merely by possessing DDB credentials.
- All mutations remain audited; high-risk ones become two-person where feasible.
- No new standing backdoor; root role still ungrantable (invariant preserved).

## 3. Implementation Sketch
- `app/cli/rootctl.py`: a `_require_break_glass_auth()` gate (verify secret/KMS +
  optional approval record) invoked by all mutating command handlers; new
  `user reactivate`/`undelete` handlers; real `rotate-secrets`.
- Settings: `ROOTCTL_BREAK_GLASS_SECRET` / KMS key id, `ROOTCTL_TWO_PERSON_COMMANDS`,
  `ROOTCTL_APPROVAL_TTL_SECONDS`.
- Approval record table (or reuse `rate_limits`/a small ops table) for pending
  two-person approvals.

## 4. Testing
- pytest: mutation rejected without break-glass secret; accepted with it; two-person
  command blocked until a distinct approver confirms; reactivate/undelete restores
  a deactivated/soft-deleted user; audit records authenticated identity + approval id.

## 5. Out of Scope
- The dev-only rootctl terminal UI (see DEVTOOLS-001).
- Root login flow gaps (tracked separately — see "related gaps" below).

## 6. Related gaps (separate tickets recommended)
- **B3 (security hole):** root network gate is enforced on `/auth/root/login` but
  **not** on the shared `/ui/session/finalize`, so a root challenge minted from an
  allowed IP could be finalized from another IP. (`root_auth.py:23` vs
  `ui_session.py:170-189`.) Worth its own ROOT-AUTH ticket.
- **A3:** two unaligned admin-permission systems — API `admin_profile.scopes`
  (enforced via `require_admin_scope`, `policy.py:122-169`) vs rootctl
  `admin_capabilities` (`rootctl.py:50-58`) which are **stored but never enforced**
  by the backend (decorative). Consolidate.
- **B2:** no interactive root bootstrap for a fresh prod deploy (chicken-and-egg:
  login needs MFA configured; MFA setup needs a session). Currently only rootctl
  can seed it.
- **A1:** no admin LIST/GET API (grant/revoke/update-profile/audit exist) — admins
  can only be discovered via the audit log.
