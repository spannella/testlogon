# DEVTOOLS-001: Dev-Only rootctl Terminal UI in Dev Tools (devtools.html)

**Ticket**: DEVTOOLS-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Dependencies**: Dev Tools app (port 3001, proxies `/internal`), `app/cli/rootctl.py`, `S.dev_mode`

---

## 1. Overview & Motivation

Running `rootctl` locally means dropping to a shell with the venv + AWS/DDB env.
For local dev/QA it would be much faster to have a **terminal UI inside the Dev
Tools app** (the standalone, no-auth React app on port 3001 that proxies
`/internal` to the backend) to run rootctl subcommands and see output — e.g. grant
an admin, reset a test user's MFA, list users, query the audit log, while iterating.

This is a **dev-only convenience** and MUST NOT exist in production.

### Feasibility
High. The Dev Tools app already exists and proxies `/internal`. We add a backend
`/internal/rootctl` exec endpoint (hard-gated to `dev_mode`) that runs rootctl in
the same process/venv and streams output, plus a terminal component in the Dev
Tools UI.

## 2. Scope & Safety

- **Hard dev gate:** the endpoint returns 404 unless `S.dev_mode` is true AND it's
  bound to localhost; never registered/enabled in prod. Also require the local
  stack's `DEV_MODE=1`.
- **Allowlist subcommands:** only expose the rootctl command groups
  (root/user/admin/audit); reject arbitrary shell. Execute via the rootctl
  arg-parser (call `app.cli.rootctl.main(argv)` in-process / `python -m app.cli.rootctl`),
  NOT a raw shell string — no shell injection.
- **Default actor/reason:** prefill `--actor-sub root --reason "devtools"` for
  convenience; surface `--dry-run` prominently.
- **Audit unchanged:** rootctl already audits (`cli=True`); these runs are tagged
  (e.g. `source: devtools`) so they're distinguishable.
- Pairs with ROOTCTL-001: once break-glass auth lands, the dev terminal supplies
  the dev break-glass secret automatically in dev only.

## 3. Implementation Sketch

### Backend (`app/routers/internal_*` or a dev-tools router)
- `POST /internal/rootctl` `{ argv: string[] }` — gated by `dev_mode` + localhost;
  validates argv[0] ∈ {root,user,admin,audit}; runs the rootctl parser in-process
  capturing stdout/stderr + exit code; returns `{exit_code, stdout, stderr}`.
  (Optional: SSE/chunked streaming for long output.)
- Reuse rootctl's existing `ExitCode` + JSON `--output json` for structured results.

### Frontend (Dev Tools app)
- A "rootctl" page/panel: a command input (with subcommand autocomplete/help from
  rootctl's parser), a run button (+ dry-run toggle), and an output console
  (monospace, stdout/stderr, exit code). History of recent commands.

## 4. Testing
- The `/internal/rootctl` endpoint returns 404 when `dev_mode` is false; runs an
  allowlisted subcommand and returns output when true; rejects non-allowlisted
  argv[0]; `--dry-run` performs no mutation. Dev Tools panel renders output + exit
  code.

## 5. Out of Scope
- Any production exposure (explicitly forbidden).
- rootctl auth/approval hardening itself (ROOTCTL-001).
