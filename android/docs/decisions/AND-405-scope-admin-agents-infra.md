# ADR AND-405: Admin / Agents / Infra are out of scope for mobile

- **Status:** Accepted (2026-06-05)
- **Deciders:** Android lead, Product
- **Backlog:** AND-405 (Milestone M8 / Epic E53) — Type Chore, Priority P1, Deps None
- **App:** `com.testlogon.android` (monorepo subfolder `android/`, branch `android-impl`)
- **Canonical ADR location:** the program's established ADR folder is the
  monorepo-root `docs/adr/`. Per FR-1 this record is co-located with the port at
  `android/docs/decisions/AND-405-scope-admin-agents-infra.md` so it travels with
  the Android module; a one-line pointer stub is filed at
  `docs/adr/ADR-AND-405-scope-admin-agents-infra.md`. The two paths are aliases of
  the same decision.

## Context

The TestLogon web reference app (`frontend/`) and the FastAPI backend expose large
administration, agent/bot-fleet, and infrastructure-control surfaces. Their
existence on the web does **not** imply a mobile obligation. This ADR removes
ambiguity: it records which backend categories are **explicitly excluded** from the
native Android port so that downstream implementers, reviewers, and estimators do
not speculatively scaffold screens, DTOs, navigation routes, or Retrofit clients
for surfaces that will never ship on mobile.

This is a scope/governance decision. It ships **no production Kotlin** and creates
or deletes no Kotlin module. The deliverable is this record plus the backlog/epic
edits that make the exclusions authoritative.

## Decision

The following backend categories are **OUT OF SCOPE for `com.testlogon.android`**.
The "Backend surface" column cites verified evidence. Because no checked-in
`reference/openapi.index.txt` is present in this repo, the authoritative,
checked-in evidence used here is the web reference client under
`frontend/src/api/endpoints/*.ts` (verified 2026-06-13). Route-prefix counts that
the original spec attributed to an OpenAPI index are reproduced as openapi-sourced
context where the FE client corroborates the prefix.

| # | Category | Backend surface (verified evidence) | Rationale (mobile) |
|---|----------|--------------------------------------|--------------------|
| 1 | Full administration | `/admin/*` (roles, impersonation), `/ui/admin/*` (ad-platform, etc.), `/v1/admin/compute/*`; FE `adminRoles.ts`, `adminImpersonation.ts`, `adminCompute.ts`, `adminAdPlatform.ts` | Desktop-class, high-privilege management task; not a phone workflow. |
| 2 | Agents / bots fleet | `/ui/agent/fleet/*`, `/ui/agent/orchestrator/*`, `/ui/bots`; FE `agentFleet.ts`, `agentOrchestrator.ts`, `bots.ts` | Fleet orchestration is low-frequency, ops-oriented; negligible mobile usage. |
| 3 | Compute / Kubernetes / EC2 | `/ui/remote/ec2/*`, `/ui/remote/k8s/*`, `/ui/remote/billing/*`, `/v1/admin/compute/*`; FE `ec2.ts`, `k8s.ts`, `computeBilling.ts`. **`/infra/*` does NOT exist (0 routes)** and bare `/compute/*` does not exist. | Cluster/instance ops are a desktop ops workflow, not mobile. |
| 4 | SSH bastion | `/ui/compute/bastion/*`, `/ui/remote/ssh-keys/*` (FE-verified); plus openapi-sourced `/api/browser-ssh/*`, `/browser-ssh`; FE `sshBastion.ts`, `sshKeys.ts` | Interactive shell / jump-host access is a security/form-factor mismatch on a device more easily lost or on untrusted networks. |
| 5 | VNC | `/api/vnc/session`, `/api/vnc/session/{id}`, `/api/vnc/session/{id}/transfer-fallback`; FE `vnc.ts` | Remote-desktop sessions are not a viable mobile UX. |
| 6 | Devtools | `/internal/dev-tools/*` (billing ledger/summary, email messages, sms conversations) — FE-verified in `devtools.ts`. (The spec §16 cited `/broadcast-devtools` from an OpenAPI index; the checked-in FE evidence shows the prefix is `/internal/dev-tools/*`. See "Evidence corrections" below.) | Internal developer/diagnostic tooling; not a user-facing mobile surface. |

## Exceptions

Not "None." Two **narrow, read-only, role-gated** admin views are deliberately in
scope as the agreed exceptions (exception type (a): a narrow read-only view mobile
may surface). They do **not** reopen full administration:

- **AND-403 — Read-only admin alerts / dashboards:** scoped read-only admin alerts
  and metrics only, **no mutations**, role-gated. Does not include user/tenant
  admin, system config, impersonation, or role granting.
- **AND-404 — Admin email / SMS dashboards (read):** `/ui/admin/email|sms/
  dashboard/*` read-only dashboards, role-gated.

All other admin/agents/compute/k8s/EC2/bastion/VNC/devtools surfaces remain fully
excluded. There is **no** exception for any mutating admin operation, any agent/bot
fleet control, any compute/k8s/EC2 management, SSH bastion, VNC, or devtools.

Graceful-degradation requirement (exception type (b)) is captured under
**Enforcement** below.

## Classification & Evidence

Verified 2026-06-13 against the checked-in web reference client
`frontend/src/api/endpoints/*.ts` (the authoritative checked-in evidence in this
repo). Spot-check method: grep each cited prefix in the named FE file and confirm
at least one matching route; confirm `/infra/*` appears nowhere.

- All 14 named FE evidence files exist: `adminRoles.ts`, `adminImpersonation.ts`,
  `adminCompute.ts`, `adminAdPlatform.ts`, `agentFleet.ts`, `agentOrchestrator.ts`,
  `bots.ts`, `ec2.ts`, `k8s.ts`, `computeBilling.ts`, `sshBastion.ts`, `sshKeys.ts`,
  `vnc.ts`, `devtools.ts`.
- Confirmed prefixes: admin (`/admin/roles/*`, `/admin/impersonation/*`,
  `/ui/admin/ad-platform`, `/v1/admin/compute`), agents (`/ui/agent/fleet`,
  `/ui/agent/orchestrator`, `/ui/bots`), compute (`/ui/remote/ec2`,
  `/ui/remote/k8s`, `/ui/remote/billing`), bastion/ssh (`/ui/compute/bastion`,
  `/ui/remote/ssh-keys`), vnc (`/api/vnc/session`), devtools
  (`/internal/dev-tools/*`).
- `/infra/*`: **not found** in any endpoint file — confirmed absent, matching the
  spec's review correction.

### Evidence corrections (vs the AND-405 draft/spec §16)

- **Devtools prefix:** spec §16 claim 6 cited `/broadcast-devtools` from an OpenAPI
  index. That index is not checked into this repo; the checked-in FE client
  (`devtools.ts`) uses `/internal/dev-tools/*`. The FE-verified prefix is recorded
  as authoritative; `/broadcast-devtools` is retained only as openapi-sourced
  context. Either way, devtools is out of scope.
- **OpenAPI index absence:** `reference/openapi.index.txt` does not exist in this
  repo. Classification therefore rests on the checked-in `frontend/src/api/
  endpoints/*.ts` client (FR-4 explicitly permits the frontend client as evidence).
  Route-count figures from the spec (e.g. "admin ~170 routes") are reproduced as
  context, not re-verified, since their cited source is absent.
- All other spec corrections stand: no `/agents/*`, no `/infra/*`, no bare
  `/compute/*`, no `/bastion/*`, no bare `/vnc/*`; VNC surface definitively exists
  at `/api/vnc/session*`.

## Enforcement

The shipped Android app enforces these exclusions structurally:

- **No-route guarantee:** the Navigation-Compose graph contains **no destinations**
  for excluded categories. There is no in-app way to reach them — no nav routes, no
  bottom-nav entries, no menu/More-catalog entries.
- **No Hilt-bound clients:** `core-network` defines **no** `AdminApi` (beyond the
  read-only AND-403/AND-404 surfaces), `AgentsApi`, `InfraApi`, `BastionApi`, or
  `VncApi` Retrofit interfaces, and Hilt binds none. `core-data` / `core-model`
  acquire no admin/agents/infra DTOs, Room tables, or DataStore keys.
- **Safe deep-link / server-driven reference state:** if the backend or a
  notification payload references an excluded surface (e.g., a deep link to
  `/admin/...`, `/api/vnc/session`, `/ui/compute/bastion/...`), the app MUST resolve
  it to a safe terminal state — a "Not available on the mobile app" screen or a
  no-op — and MUST NOT crash, show a blank screen, or issue a network call to an
  unbuilt client. **This requirement is owned and implemented by the
  navigation/deep-link guard ticket (AND-022; App Links routing AND-396), not by
  AND-405.** The "Not available on the mobile app" string must be localizable and
  accessible when implemented.
- **Telemetry (forward, optional):** if the deep-link guard blocks an excluded
  surface, a low-cardinality, non-PII breadcrumb
  (`event=excluded_surface_blocked, category=<...>`) may be logged via the existing
  redacted telemetry pathway (AND-052). Owned by the implementing ticket.

## Security & Privacy

Excluding SSH bastion, VNC, compute/k8s/EC2 control, and full administration is a
deliberate security-posture decision: these are high-privilege, high-blast-radius
operations, and a mobile device is more easily lost, stolen, or on an untrusted
network. The app never stores, requests, or transmits admin/infra credentials,
kubeconfig, SSH keys, or session tokens for these surfaces. Excluding them does not
weaken backend authorization — the backend remains responsible for rejecting any
privileged call; mobile simply never makes one. This record contains no PII (route
prefixes / file paths only).

The in-scope, user-facing surfaces use the verified web UI session: the `ui_csrf`
cookie echoed as the `X-CSRF-Token` header, with a single retry via
`POST /ui/session/refresh` on a 401 (only when previously authenticated). Backend
validation errors follow FastAPI standard shapes (422 `HTTPValidationError`
`{ detail: ValidationError[] }`; auth failures `{ detail: string }`).

## Consequences

- Positive: minimal module graph (no `feature-admin`, `feature-agents`,
  `feature-infra`), minimal Room/DataStore surface, no dead model code, reduced
  attack surface.
- Negative / constraint: any future need to contact an excluded surface, or to
  reverse any exclusion, requires a **superseding ADR that references AND-405**.
  Ad-hoc reintroduction is not permitted.
- Reviewer obligation (AC-7): a PR adding a Kotlin module, Retrofit interface, or
  nav route for an excluded category must be rejected.

## Links

- Backlog ticket: AND-405 (M8 / E53).
- Epic: E53 — Admin-lite (optional / scoped); see
  `android/tickets/M8-long-tail-admin-lite.md`.
- In-scope exceptions: AND-403, AND-404 (read-only, role-gated); tests AND-406.
- Downstream owner of the safe deep-link state: AND-022 (nav/deep-link guard),
  AND-396 (App Links routing); telemetry AND-052.
- Alias / pointer stub: `docs/adr/ADR-AND-405-scope-admin-agents-infra.md`.
