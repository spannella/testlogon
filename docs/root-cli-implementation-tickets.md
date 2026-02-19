# Root Break-Glass CLI — Implementation Ticket Backlog

This backlog translates the root break-glass CLI plan into actionable tickets.

## Epic C0 — CLI foundations and safety contract

### CLI-001: Bootstrap `rootctl` command framework
**Goal**: Create a stable server-side CLI entrypoint and command group structure.

**Scope**
- Add `rootctl` executable/module with subcommand groups (`root`, `user`, `admin`, `audit`).
- Add shared option handling (`--output`, `--dry-run`, request/correlation id plumbing).
- Implement standard exit code conventions for success/validation/authz/backend errors.

**Acceptance criteria**
- Operators can run `rootctl --help` and each command group help successfully.
- Shared output/error handling is consistent across command groups.

---

### CLI-002: Add shared policy/runtime guard layer
**Goal**: Ensure all CLI operations enforce existing security invariants before execution.

**Scope**
- Add shared preflight that validates configured immutable root subject (`ROOT_USER_SUB`).
- Enforce root-only execution for privileged mutation commands.
- Disallow any command path that could create/assign additional `root` identities.

**Acceptance criteria**
- CLI blocks mutation commands for non-root actors with explicit policy errors.
- No CLI command can grant/create root role outside immutable root identity.

---

### CLI-003: Add mandatory reason/ticket/confirm guardrails
**Goal**: Prevent unsafe privileged mutations and improve accountability.

**Scope**
- Require `--reason` for all mutation commands.
- Require `--ticket` for high-risk actions (root recovery, destructive user ops).
- Add `--confirm` challenge for destructive actions.

**Acceptance criteria**
- Missing required safety flags fails fast with clear validation messages.
- High-risk and destructive flows cannot proceed without explicit operator intent.

---

## Epic C1 — Root recovery and security operations

### CLI-004: Implement root password reset operation
**Goal**: Provide break-glass recovery for root authentication credentials.

**Scope**
- Add `rootctl root reset-password` command.
- Support secure password input flow (non-echoed prompt or approved secret source).
- Integrate with existing credential/session invalidation behavior.

**Acceptance criteria**
- Root password reset succeeds only for immutable root principal.
- Action emits immutable privileged audit event with actor/reason/ticket metadata.

---

### CLI-005: Implement root MFA reset and verification-state operations
**Goal**: Allow controlled root factor recovery and verification repairs.

**Scope**
- Add `rootctl root reset-mfa --factor ...` command.
- Add root verification-state update command (`email/phone verified/unverified`) with strict validation.
- Ensure reset operations revoke/rotate affected active sessions where policy requires.

**Acceptance criteria**
- Root MFA reset paths are constrained, audited, and traceable.
- Verification-state updates are explicit and include required reason/ticket fields.

---

### CLI-006: Implement root email/security profile update operations
**Goal**: Enable emergency correction of root identity contact/security metadata.

**Scope**
- Add `rootctl root set-email` and related root security metadata update commands.
- Validate input format and enforce immutable root subject.
- Emit high-severity privileged audit events for all root profile/security changes.

**Acceptance criteria**
- Root metadata updates are successful only when validation/policy checks pass.
- Security reviewers can trace root metadata changes via audit events.

---

## Epic C2 — User lifecycle operations

### CLI-007: Implement user create/list commands
**Goal**: Support operational onboarding and inventory from CLI.

**Scope**
- Add `rootctl user create` and `rootctl user list`.
- Support role/status filtering and pagination/cursor output.
- Preserve default least-privilege role assignment for new users.

**Acceptance criteria**
- Operators can create non-root users with validated inputs.
- List output supports machine-readable (`json`) and operator-readable formats.

---

### CLI-008: Implement user verify and password update commands
**Goal**: Support account recovery and verification correction workflows.

**Scope**
- Add `rootctl user verify` command for email/phone verification flags.
- Add `rootctl user set-password` with secure input handling.
- Ensure commands honor account state constraints (deactivated/deleted users).

**Acceptance criteria**
- Verification and password updates enforce validation and policy checks.
- Every credential/verification mutation is auditable with actor and target metadata.

---

### CLI-009: Implement user deactivate/delete commands
**Goal**: Provide safe, explicit account containment/removal operations.

**Scope**
- Add `rootctl user deactivate` and `rootctl user delete`.
- Require destructive safety controls (`--confirm`, reason/ticket where required).
- Support optional soft-delete/hard-delete behavior per existing policy.

**Acceptance criteria**
- Destructive operations require explicit confirmation and cannot run accidentally.
- Deactivate/delete events are immutable, queryable, and include full context.

---

## Epic C3 — Admin lifecycle and permissions

### CLI-010: Implement admin grant/revoke commands (root-only)
**Goal**: Provide CLI parity with root-managed admin role APIs.

**Scope**
- Add `rootctl admin grant` and `rootctl admin revoke`.
- Reuse role transition checks and assignable-role policy constraints.
- Wire to existing immutable role-audit model.

**Acceptance criteria**
- Only root actor can grant/revoke admin via CLI.
- Role transitions reject invalid targets and always generate audit records.

---

### CLI-011: Implement admin creation workflow
**Goal**: Simplify controlled creation of new admin operators.

**Scope**
- Add `rootctl admin create` command (create user + grant admin in controlled flow).
- Require reason and optional ticket metadata.
- Ensure rollback/error handling when multi-step flow partially fails.

**Acceptance criteria**
- Admin creation flow is deterministic and auditable end-to-end.
- Partial failures are visible and recoverable without inconsistent role state.

---

### CLI-012: Add optional granular admin permission management
**Goal**: Support future fine-grained admin scopes beyond role-only model.

**Scope**
- Add command scaffolding for scoped permissions (`admin permissions set/list`) behind feature flag.
- Define capability schema and validation rules.
- Audit all permission grants/revokes with old/new scope values.

**Acceptance criteria**
- Capability commands are disabled by default unless feature flag is enabled.
- When enabled, permission changes are policy-checked and fully audited.

---

## Epic C4 — Audit, observability, and integrations

### CLI-013: Implement CLI audit query commands
**Goal**: Provide operational visibility and forensic query tools from CLI.

**Scope**
- Add `rootctl audit` commands for role, impersonation, file, and security event timelines.
- Support filters by actor, target user, action/event, and time range.
- Support cursor pagination for large result sets.

**Acceptance criteria**
- Operators can reconstruct privileged timelines from CLI without ad-hoc DB access.
- Query output supports both human-readable and JSON forms.

---

### CLI-014: Propagate correlation IDs for bulk operations
**Goal**: Improve traceability for multi-target CLI operations.

**Scope**
- Add correlation id generation/propagation for bulk commands.
- Include correlation id in emitted audit events and CLI output.
- Add bulk summary result reporting (success/fail per target).

**Acceptance criteria**
- Bulk operations always produce a correlation id.
- Security queries can pivot by correlation id across emitted events.

---

### CLI-015: Integrate CLI actions with alerting/SIEM hooks
**Goal**: Ensure root CLI actions are visible in monitoring and detection systems.

**Scope**
- Confirm privileged CLI events flow through existing audit -> alert -> SIEM pipeline.
- Add explicit event naming conventions for root CLI operations.
- Add failure telemetry for webhook/SIEM delivery errors.

**Acceptance criteria**
- Privileged CLI mutations appear in configured alerting/SIEM streams.
- Delivery failures are logged and observable for follow-up.

---

## Epic C5 — QA, docs, and operational readiness

### CLI-016: Add unit tests for CLI guardrails and argument validation
**Goal**: Prevent regressions in command safety behavior.

**Scope**
- Test required flags (`reason`, `ticket`, `confirm`) and argument parsing.
- Test root-only mutation guard and immutable root invariant checks.
- Test output/error shape for scriptability.

**Acceptance criteria**
- Invalid invocations fail with deterministic, test-covered errors.
- Guardrail regressions are caught by automated tests.

---

### CLI-017: Add integration tests for privileged lifecycle command matrix
**Goal**: Validate end-to-end allow/deny behavior across CLI operations.

**Scope**
- Add integration tests for root recovery/user lifecycle/admin lifecycle commands.
- Cover allow/deny paths and audit emission assertions.
- Include destructive command confirmation and dry-run behavior tests.

**Acceptance criteria**
- Test matrix covers representative allow/deny paths for all privileged command families.
- CI blocks merges when CLI privileged policy matrix tests fail.

---

### CLI-018: Add CI workflow for CLI test suite
**Goal**: Enforce ongoing CLI security guarantees in automation.

**Scope**
- Add/extend CI workflow to run CLI unit/integration suites on PRs.
- Include policy matrix and lint/type checks relevant to CLI module.
- Publish test artifacts/logs for failed privileged cases.

**Acceptance criteria**
- PRs execute CLI security regression tests automatically.
- Failing CLI privileged tests block merge.

---

### CLI-019: Publish operator runbook for root CLI procedures
**Goal**: Operationalize safe usage of root CLI in real incidents.

**Scope**
- Document step-by-step procedures for root recovery and user/admin lifecycle operations.
- Add “when to use CLI vs API/UI” decision guidance.
- Add evidence capture checklist (request ids, correlation ids, SIEM links).

**Acceptance criteria**
- Operators can execute break-glass procedures end-to-end from documentation alone.
- Runbook includes required approval/escalation points.

---

### CLI-020: Execute security review and break-glass drill sign-off
**Goal**: Validate readiness with operations and security stakeholders.

**Scope**
- Run tabletop/exercise for compromised root/admin scenarios using CLI.
- Validate audit and SIEM visibility for all drill actions.
- Capture remediation items and sign-off from ops/security.

**Acceptance criteria**
- Stakeholders approve CLI control design and operational runbook.
- Drill outputs confirm privileged CLI events are detectable and reconstructable.

---

## Suggested delivery order
1. CLI-001 → CLI-003 (framework and safety invariants)
2. CLI-004 → CLI-006 (root recovery controls)
3. CLI-007 → CLI-009 (user lifecycle)
4. CLI-010 → CLI-012 (admin lifecycle/scopes)
5. CLI-013 → CLI-015 (audit/correlation/SIEM)
6. CLI-016 → CLI-018 (tests + CI)
7. CLI-019 → CLI-020 (runbook + drill sign-off)

## Definition of done (program-level)
- Root CLI exists as a controlled break-glass operational tool, not a policy bypass.
- Single immutable root identity is preserved across all CLI commands.
- All privileged mutations are explicitly justified and immutably audited.
- User/admin lifecycle flows are enforceably least-privilege and test-covered.
- Security/ops can detect, investigate, and reconstruct CLI privileged actions in monitoring/SIEM.
