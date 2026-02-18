# Root Break-Glass CLI Plan

## Purpose and constraints
Build a server-side **break-glass root CLI** for controlled account recovery and privileged user lifecycle actions, while preserving existing security invariants:

- single immutable root identity (`ROOT_USER_SUB`),
- dedicated root auth controls,
- strict auditability of privileged actions,
- least-privilege behavior for admin/user flows.

This CLI complements (does not replace) existing root/admin APIs and operational runbooks.

## Primary use cases
The CLI is intended for controlled operational actions by trusted server operators:

- root security recovery: reset root password, root MFA factors, and root verification metadata,
- user lifecycle management: create, verify, list, deactivate, and delete users,
- credential updates: set/reset user passwords and update account status,
- admin lifecycle management: create admin users, grant/revoke admin role, inspect role audits.

## Non-goals
- No bypass of root network, role, or session invariants.
- No direct replacement of normal app flows for day-to-day support.
- No unaudited privileged mutations.

## Architecture

### Execution model
Create a server-side executable (`rootctl`) under a dedicated module (for example `app/cli/rootctl.py`) with subcommands.

- Default mode: calls existing backend services/modules used by routers.
- Optional mode: calls root/admin API endpoints (same policy checks), useful when direct service access is constrained.

### Command groups
- `rootctl root ...` — root account recovery/security operations.
- `rootctl user ...` — user lifecycle management.
- `rootctl admin ...` — admin role/permission management.
- `rootctl audit ...` — audit timeline/query helpers.

### Suggested command surface
#### Root security
- `rootctl root reset-password --reason ... --ticket ...`
- `rootctl root reset-mfa --factor all|totp|sms|email --reason ... --ticket ...`
- `rootctl root set-email --email ... --verify`
- `rootctl root set-verification --email verified|unverified --phone verified|unverified`

#### User lifecycle
- `rootctl user create --user-sub ... --email ... [--temporary-password ...]`
- `rootctl user verify --user-sub ... [--email-verified] [--phone-verified]`
- `rootctl user set-password --user-sub ... --password ... [--temporary]`
- `rootctl user list [--role user|admin|root] [--status active|deactivated] [--cursor ...]`
- `rootctl user deactivate --user-sub ... --reason ...`
- `rootctl user delete --user-sub ... --reason ... --confirm <user_sub>`

#### Admin lifecycle
- `rootctl admin create --user-sub ... --email ... --reason ...`
- `rootctl admin grant --user-sub ... --reason ...`
- `rootctl admin revoke --user-sub ... --reason ...`
- `rootctl admin permissions set --user-sub ... --scope ... --reason ...` (if granular permission model is enabled)
- `rootctl admin audit [--actor-sub ...] [--start-ts ...] [--end-ts ...] [--cursor ...]`

#### Audit helpers
- `rootctl audit roles ...`
- `rootctl audit impersonation ...`
- `rootctl audit files ...`
- `rootctl audit security-events ...`

## Security controls

### Authentication and authorization
- CLI must verify the acting principal is the configured root subject before any privileged mutation.
- CLI must not allow creating an additional root identity.
- Root/admin changes must continue to reuse canonical role checks and existing policy helpers.

### Step-up controls for sensitive operations
For destructive or credential-reset actions require:
- explicit `--reason`,
- optional `--ticket` / incident reference,
- confirmation challenge (`--confirm`),
- optional local step-up (OS auth/HSM secret prompt) where supported.

### Rate limiting and abuse controls
- Reuse privileged action rate limits for root/admin mutation command paths.
- Enforce per-action budgets for bulk operations.

### Auditability
Every privileged CLI action must emit immutable audit records including:
- `actor_sub`, `effective_sub`,
- `action`, `target_user_sub`,
- reason/ticket, request/correlation id,
- outcome and timestamp,
- source host/process metadata.

## Operational behavior

### Safety defaults
- `--dry-run` for mutation commands.
- `--output table|json`.
- destructive actions require explicit confirmation token.
- idempotent command behavior where feasible.

### Correlation for bulk actions
Bulk commands must produce and propagate a `correlation_id` to support forensics and rollback workflows.

### Break-glass workflow integration
Document exact CLI runbook procedures for:
- root account compromise,
- compromised admin sessions,
- emergency account lockouts/recovery,
- post-incident evidence capture.

## Rollout plan

### Phase 0 — design and policy contract
- finalize command taxonomy and safety requirements,
- map each command to existing policy helpers and audit events.

### Phase 1 — read-only foundation
- implement list/query/audit commands,
- validate access checks and output formats.

### Phase 2 — controlled user lifecycle writes
- implement create/verify/set-password/deactivate,
- enforce reason and audit requirements.

### Phase 3 — root recovery and admin lifecycle
- implement root reset operations,
- implement admin create/grant/revoke + audit integrations.

### Phase 4 — hardening and drills
- add end-to-end CLI policy matrix tests,
- execute break-glass tabletop drills,
- finalize runbook sign-off with ops/security.

## Acceptance criteria
- Root CLI cannot create additional root identities.
- All privileged mutations require reason and are immutably audited.
- Root recovery actions are gated and traceable.
- User/admin lifecycle commands enforce least privilege and role policy consistency.
- Audit queries support filtering by actor, target user, action, and time range.
- Operational runbooks include CLI playbooks for incident handling.
