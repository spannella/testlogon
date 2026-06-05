# DEVTOOLS-001: Dev-Only rootctl Terminal UI in Dev Tools — Investigation & Implementation Write-up

## 1. Summary & Classification

**Type**: Feature — dev-only tooling; MUST be absent in production  
**Priority**: Medium | **Status**: Not implemented  
**Area**: Developer experience — Dev Tools app (port 3001), break-glass CLI  
**Who is affected**: Local developers and QA engineers iterating on root/admin operations during development  

**Critical constraint**: This feature is explicitly forbidden from production. It provides an in-browser UI to execute `rootctl` subcommands against DynamoDB Local. Any production exposure would give any localhost-adjacent attacker the ability to manipulate the user, role, and audit tables without authentication. The implementation MUST follow the `_require_devtools_enabled()` gate pattern already established in `app/routers/internal_devtools.py:27–33` and must additionally verify the request originates from localhost.

Cross-references: ROOTCTL-001 (break-glass hardening — this ticket intentionally does NOT tackle auth hardening; once ROOTCTL-001 lands, the dev terminal can supply the dev break-glass secret automatically), SECOPS-007 (dev/prod parity — this entire feature is dev-only and must never enter the prod code path), SEC-007 (`prod-exposure-and-config-hardening` — mock/debug routes must be gated).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Dev Tools app

The standalone Dev Tools application runs on port 3001. It is a separate React entry point (`frontend/src/devtools-main.tsx:1–26`) that renders only `<DevToolsLogUiPage />` (`frontend/src/pages/devtools/DevToolsLogUiPage.tsx`). It has no auth (deliberately — it is development-only local tooling).

The Vite dev server for the Dev Tools app proxies `/internal/*` to the backend (`http://localhost:8000`) — this is the channel through which all internal/dev endpoints are accessed.

The existing internal dev tools backend router is `app/routers/internal_devtools.py` (registered at `app/main.py:98,559`). It implements four endpoints:
- `GET /internal/dev-tools/email/messages`
- `GET /internal/dev-tools/sms/conversations`
- `GET /internal/dev-tools/billing/ledger`
- `GET /internal/dev-tools/billing/summary`

Each endpoint calls `_require_devtools_enabled()` (`app/routers/internal_devtools.py:27–33`) as its first action:

```python
def _require_devtools_enabled() -> None:
    if not S.dev_mode:
        raise HTTPException(
            status_code=404,
            detail={"code": "devtools_disabled", ...},
        )
```

This is the established pattern: return 404 (not 403) when dev mode is off, which prevents endpoint enumeration in production.

The router uses prefix `/internal/dev-tools` and is always registered in `app/main.py:559` — there is no conditional registration; the `dev_mode` gate is at the request level, not the router level.

### 2.2 rootctl CLI

`app/cli/rootctl.py` — 2453 lines. `main(argv=None)` at `:2442` parses an `argv` list and returns an `int` exit code. `build_parser()` at `:2386` constructs the argparse parser with four top-level subcommand groups:
- `root` — reset-password, reset-mfa, set-verification, set-email, set-security-profile
- `user` — create, list, verify, set-password, deactivate, deactivate-bulk, delete
- `admin` — grant, revoke, create, permissions set/list
- `audit` — timeline query

`_run_with_args` at `:2408` is the dispatch function: it calls `_validate_preflight(args)` which enforces `--actor-sub` is non-empty (`app/cli/rootctl.py:2006–2008`) and checks `requires_root` (`app/cli/rootctl.py:2010–2018`). There is **no secret or credential check** — `--actor-sub` is purely a flag string. ROOTCTL-001 identifies this as finding C1 (Critical).

All mutating handlers emit an audit event via `audit_event(..., cli=True)` (`app/services/alerts.py:634–638` stamps `event_source: "rootctl"`). This audit trail is intact and will continue to work when rootctl is called in-process from a backend endpoint.

`ExitCode` enum at `:29–33`: `SUCCESS=0`, `VALIDATION_ERROR=2`, `AUTHZ_ERROR=3`, `BACKEND_ERROR=4`.

Subcommands support `--output json` for structured output. The `--dry-run` flag (`_shared_opts` at `:103`) is threaded through all mutating handlers.

### 2.3 What is missing

No `/internal/rootctl` endpoint exists anywhere in the backend. No `RootctlTerminalPanel` or similar component exists in `frontend/src/pages/devtools/`. The Dev Tools page (`DevToolsLogUiPage.tsx`) has no routing or tab for rootctl operations.

The `app/cli/rootctl.py` `main()` function is designed to be callable in-process (`main(argv=[...])`) which makes the backend exec endpoint straightforward: capture stdout/stderr from `_emit`/`_emit_error` by temporarily redirecting `sys.stdout`/`sys.stderr`, then return the captured output and exit code.

---

## 3. Gap / Threat Analysis

### 3.1 Dev/prod leakage risk

The most serious implementation risk is accidental production exposure. Unlike the existing dev tools endpoints (which are read-only — they read log files and billing records), the rootctl terminal is a **write path** capable of resetting passwords, deactivating users, and granting admin roles directly in DynamoDB. The `_require_devtools_enabled()` check alone is necessary but may not be sufficient if `S.dev_mode` is accidentally set to True in a misconfigured production deployment.

**Additional gate required**: Verify the request originates from localhost. FastAPI's `Request.client.host` gives the connecting client IP. Any request where `host not in {"127.0.0.1", "::1", "localhost"}` must be rejected with 404, regardless of `dev_mode`. This is a defence-in-depth layer.

The ticket specification states: "hard-gated to `dev_mode` AND bound to localhost." The `internal_devtools.py` pattern does not currently check `request.client.host`. This check should be added to both the existing dev tools router and the new rootctl endpoint.

### 3.2 Shell injection risk

The endpoint must never invoke a raw shell string. The designed approach — calling `app.cli.rootctl.main(argv)` in-process, where `argv` is an allowlisted array — eliminates shell injection entirely. The argparse validation in `main()` handles input sanitization: unrecognised subcommands raise `SystemExit(2)`, which `main()` catches and returns as an exit code.

The additional constraint: `argv[0]` (the group) must be validated against `{"root", "user", "admin", "audit"}` before calling `main()`. The endpoint must reject any `argv[0]` not in this set, even though argparse would also reject it — defence in depth.

### 3.3 Audit tagging

rootctl already audits all mutations with `source: "rootctl"`. The dev terminal runs must be distinguishable from shell-initiated runs. Add `source: "devtools"` override by passing `--request-id devtools:{uuid}` or by adding a `DEVTOOLS_SOURCE` environment variable that `_validate_preflight` or the audit emitter checks. The simplest approach: prepend `"--request-id", f"devtools:{uuid.uuid4().hex[:8]}"` to the `argv` before calling `main()`.

### 3.4 ROOTCTL-001 interaction

ROOTCTL-001 is open (not yet implemented). It plans to add a break-glass secret requirement to all mutating commands. Until ROOTCTL-001 lands, the devtools terminal endpoint will reach rootctl with no secret validation — the same situation as running rootctl directly from a shell. This is acceptable for local dev (the terminal is localhost-only) but the endpoint design should reserve the `break_glass_secret` field in the request body so that when ROOTCTL-001 is implemented, the terminal can forward the dev break-glass secret automatically without an API change.

---

## 4. Proposed Design / Fix

### 4.1 Backend endpoint

Add to `app/routers/internal_devtools.py` (or a new `app/routers/internal_rootctl.py`):

```python
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List
import io, contextlib, uuid

from app.core.settings import S

ALLOWED_GROUPS = {"root", "user", "admin", "audit"}

class RootctlRunIn(BaseModel):
    argv: List[str]  # e.g. ["user", "list", "--output", "json"]
    dry_run: bool = False
    break_glass_secret: str = ""  # reserved for ROOTCTL-001

class RootctlRunOut(BaseModel):
    exit_code: int
    stdout: str
    stderr: str

@router.post("/internal/dev-tools/rootctl", response_model=RootctlRunOut)
def run_rootctl(body: RootctlRunIn, request: Request):
    _require_devtools_enabled()
    _require_localhost(request)

    if not body.argv:
        raise HTTPException(status_code=400, detail="argv must not be empty")
    if body.argv[0] not in ALLOWED_GROUPS:
        raise HTTPException(status_code=400, detail=f"argv[0] must be one of {sorted(ALLOWED_GROUPS)}")

    # Inject convenience defaults
    argv = list(body.argv)
    if "--actor-sub" not in argv:
        argv += ["--actor-sub", "root.admin@testdev.local"]
    if "--reason" not in argv:
        argv += ["--reason", "devtools"]
    if body.dry_run and "--dry-run" not in argv:
        argv = ["--dry-run"] + argv
    argv += ["--request-id", f"devtools:{uuid.uuid4().hex[:8]}"]

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        from app.cli.rootctl import main as rootctl_main
        exit_code = rootctl_main(argv)

    return RootctlRunOut(
        exit_code=exit_code,
        stdout=stdout_buf.getvalue(),
        stderr=stderr_buf.getvalue(),
    )


def _require_localhost(request: Request) -> None:
    host = request.client.host if request.client else ""
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise HTTPException(status_code=404, detail="not found")
```

**Notes**:
- `_require_devtools_enabled()` returns 404 if `S.dev_mode` is False — same as existing pattern
- `_require_localhost()` returns 404 (not 403) for non-localhost clients — prevents endpoint enumeration
- `contextlib.redirect_stdout` captures rootctl's `_emit` output (rootctl writes to stdout directly)
- The `import main` is lazy (inside the handler) so it does not trigger rootctl's DynamoDB initialisation at startup
- `--dry-run` is threaded through argv when `body.dry_run=True`
- `--request-id devtools:{uuid}` tags all audit events as devtools-originated
- `argv[0]` allowlist validation before calling `main()` (argparse also validates, but defence-in-depth)

### 4.2 Frontend component

Add a new tab/section to `DevToolsLogUiPage.tsx` or create `frontend/src/pages/devtools/RootctlTerminalPanel.tsx`:

```tsx
export function RootctlTerminalPanel() {
  const [argv, setArgv] = useState("user list --output json");
  const [dryRun, setDryRun] = useState(true);  // dry-run on by default
  const [output, setOutput] = useState<RootctlRunOut | null>(null);
  const [history, setHistory] = useState<string[]>([]);

  const runMut = useMutation({
    mutationFn: (args: { argv: string[]; dry_run: boolean }) =>
      api.post<RootctlRunOut>("/internal/dev-tools/rootctl", args).then(r => r.data),
    onSuccess: (data) => {
      setOutput(data);
      setHistory(prev => [argv, ...prev.slice(0, 19)]);
    },
  });

  function handleRun() {
    const parsedArgv = argv.trim().split(/\s+/);
    runMut.mutate({ argv: parsedArgv, dry_run: dryRun });
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-center">
        <Input
          value={argv}
          onChange={e => setArgv(e.target.value)}
          placeholder="user list --output json"
          className="font-mono"
          onKeyDown={e => e.key === "Enter" && handleRun()}
        />
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={dryRun} onChange={e => setDryRun(e.target.checked)} />
          Dry Run
        </label>
        <Button onClick={handleRun} disabled={runMut.isPending}>
          {runMut.isPending ? "Running..." : "Run"}
        </Button>
      </div>

      {output && (
        <pre className={cn(
          "rounded bg-black p-4 text-sm font-mono overflow-auto max-h-96",
          output.exit_code === 0 ? "text-green-400" : "text-red-400"
        )}>
          Exit: {output.exit_code}{"\n"}
          {output.stdout || output.stderr}
        </pre>
      )}

      {history.length > 0 && (
        <div className="text-xs text-muted-foreground">
          Recent: {history.map((h, i) => (
            <button key={i} className="underline mr-2" onClick={() => setArgv(h)}>{h}</button>
          ))}
        </div>
      )}
    </div>
  );
}
```

Key design decisions:
- **Dry-run checkbox defaults to `true`** — operators must explicitly uncheck to execute mutations
- **History of last 20 commands** — click to replay
- **Monospace terminal output** — green for exit code 0, red otherwise
- **No subcommand autocomplete at MVP** — can be added later via a `GET /internal/dev-tools/rootctl/help` endpoint that calls `build_parser()` and extracts subcommand names

### 4.3 Dev/Prod parity (SECOPS-007)

This feature is explicitly dev-only. It must not appear in production at all. Three enforcement layers:

1. `S.dev_mode` check: endpoint returns 404 if `dev_mode=False`
2. `request.client.host` check: endpoint returns 404 for non-localhost requests
3. Documentation: `docs/run-deploy.md` and `docs/security-hardening-runbook.md` should note that `DEV_MODE=0` is required in production and that the internal routes are 404 in prod

The endpoint calls `rootctl_main(argv)` which uses `app/core/tables.py` DynamoDB handles. In dev these point to DynamoDB Local (port 8001). In prod they would point to real DynamoDB — but the `S.dev_mode` gate prevents the endpoint from ever being reached in prod.

No new AWS services, no new DynamoDB tables, no new environment variables. The endpoint is purely in-process plumbing.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_internal_rootctl.py`)

| Test | Assertion |
|---|---|
| `test_rootctl_endpoint_404_when_dev_mode_false` | Set `S.dev_mode=False`, `POST /internal/dev-tools/rootctl` → 404 |
| `test_rootctl_endpoint_404_non_localhost` | `S.dev_mode=True`, client.host=`"192.168.1.1"` → 404 |
| `test_rootctl_user_list_success` | `argv=["user","list","--output","json"]` → `exit_code=0`, stdout contains JSON |
| `test_rootctl_dry_run_no_mutation` | `argv=["user","create",...]`, `dry_run=True` → no DDB write, exit code 0 |
| `test_rootctl_non_allowlisted_group_rejected` | `argv=["shell","rm","-rf","/"]` → 400 `argv[0] not in allowed` |
| `test_rootctl_empty_argv_rejected` | `argv=[]` → 400 |
| `test_rootctl_audit_tag` | After a `user list` call, audit log entry has `request_id` starting with `"devtools:"` |

All tests run with `moto.mock_dynamodb` + `S.dev_mode=True`. No real DynamoDB needed.

### 5.2 Playwright E2E (`frontend/e2e/devtools.spec.ts`)

The existing `devtools.spec.ts` covers the log UI. Add a new section:
- Navigate to `http://localhost:3001` (Dev Tools app)
- Find the "rootctl" panel/tab
- Enter `user list --output json`, click Run with Dry Run checked
- Assert output pane shows `"exit_code": 0` and JSON user list
- Enter `admin grant ...` with Dry Run unchecked → assert modal/warning before execution (if any)
- Assert that visiting `http://localhost:3000/internal/dev-tools/rootctl` (main app port, behind auth proxy) returns 404 in production mode (set `DEV_MODE=0` for this test via a test fixture)

### 5.3 Manual verification

1. `just restart` to start dev stack with `DEV_MODE=1`
2. Open Dev Tools app at `http://localhost:3001`
3. Navigate to rootctl tab
4. Run `user list --output json` with Dry Run checked — confirm user list appears
5. Run `user status --output json` — confirm status output
6. Toggle off Dry Run, run `user create --email test@test.local --password-stdin < /dev/null --actor-sub root.admin@testdev.local` — confirm user created in DynamoDB Local
7. Verify audit log via `GET /internal/dev-tools/...` shows the event tagged with `devtools:{id}`

### 5.4 Security acceptance criteria

- `curl http://localhost:8000/internal/dev-tools/rootctl -X POST -d '{"argv":["user","list"]}' -H 'Content-Type: application/json'` from a non-localhost IP (simulate by spoofing `request.client.host`) → 404
- `DEV_MODE=0 uvicorn app.main:app ...` then same POST → 404
- Only `{"root","user","admin","audit"}` argv[0] values accepted; anything else → 400

### 5.5 ROOTCTL-001 integration path

When ROOTCTL-001 is implemented and adds a break-glass secret requirement, the terminal endpoint's `break_glass_secret` field (already reserved in `RootctlRunIn`) will be forwarded. In dev mode, the secret will be auto-populated from `S.rootctl_break_glass_secret_dev` (a new settings field per ROOTCTL-001 design). The terminal UI can show a "Secret required" warning when ROOTCTL-001 auth is active and no secret is pre-configured.

### 5.6 Effort estimate

- Backend endpoint (`POST /internal/dev-tools/rootctl`): **S** (2–3 hours including localhost check + argv validation + stdout capture)
- Frontend `RootctlTerminalPanel.tsx`: **S** (3–4 hours including integration into `DevToolsLogUiPage`)
- Unit tests: **S** (2 hours)
- E2E tests: **S** (2 hours)

**Total: M (1–2 days)**

**Rollback**: Remove the endpoint from `internal_devtools.py` and the panel from `DevToolsLogUiPage.tsx`. No DDB schema changes, no persistent state added.
