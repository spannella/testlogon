---
id: AND-405
title: "Scope decision: admin/agents/infra"
milestone: M8
epic: E53
priority: P1
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: []
blocks: []
---

# AND-405 — Scope decision: admin/agents/infra

## 1. Overview & Goal

This ticket is a documentation-only **scope decision (Chore)**. It produces a
durable, version-controlled record that confirms a category of TestLogon backend
surface area is **explicitly excluded** from the native Android port and that the
Android backlog/epics reflect those exclusions. The categories ruled out for
mobile are: full **administration** (admin console / admin-only management
surfaces), the **agents/bots fleet** (agent registration, orchestration, fleet
control), **compute / Kubernetes / EC2** management, **SSH bastion** access, **VNC**
remote-desktop sessions, and **developer tools (devtools)**. Any genuine
exceptions (a narrow read-only view, a deep-link that must not crash, an entry
point that must be gracefully hidden) are to be captured in the same record.

The goal is not to build a feature. It is to remove ambiguity so that downstream
implementers, reviewers, and estimators do not speculatively scaffold screens,
DTOs, navigation routes, or API clients for surfaces that will never ship on
mobile. The deliverable is a committed Markdown decision document in the repo plus
the backlog/epic edits that make the exclusions authoritative. A reader of the
Android backlog must be able to find, in one place, *what mobile will not do* in
the admin/agents/infra space and *why*, with the small set of exceptions named.

Goal statement: a decision record exists in the repo, is linkable from the M8/E53
epic, lists each excluded category with a one-line rationale, enumerates
exceptions explicitly (or states "none"), and the Android backlog contains no open
implementation tickets for the excluded categories.

## 2. Context & References

- Repo: `spannella/testlogon`; the Android app lives in the monorepo subfolder
  `android/` on branch `android-port`. Canonical namespace / applicationId base:
  `com.testlogon.android`.
- The web reference app (`frontend/`) is the source of truth for *what the product
  can do today*. Admin/agents/infra surfaces, if present, live there and in the
  FastAPI backend; their existence on web does **not** imply a mobile obligation.
  This ticket records that delta.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). The authoritative inventory of backend surface is its OpenAPI
  document at `/openapi.json`; the API layer on web is under
  `frontend/src/api/endpoints/*.ts` with shared types in `frontend/src/api/types.ts`.
  These are used here only as *evidence inputs* to classify which route groups are
  admin/agents/infra — no client code is written.
- Stack (for context on what is *not* being added): Kotlin 2.0.21, Compose +
  Material 3, single-Activity Navigation-Compose, Hilt (KSP), Retrofit/OkHttp/Moshi,
  Room + DataStore. Module layering `app -> feature-* -> core-*`. This ticket adds
  none of the above; it prevents the creation of `feature-admin`, `feature-agents`,
  `feature-infra`, or equivalent modules.
- Milestone/epic: M8 / E53. This is a P1 chore with **no dependencies** per the
  backlog and (per the analysis below) no hard blocks, though it informs scoping
  across the program.
- Backlog source (authoritative): AND-405 — Type Chore, Priority P1, Deps None.
  Scope: "Document confirmation that full admin, agents/bots fleet,
  compute/k8s/ec2, SSH bastion, VNC, devtools are out of scope for mobile; capture
  any exceptions." Acceptance: "Decision recorded in repo; backlog reflects
  exclusions."

## 3. Functional Requirements

FR-1. A decision record file is created and committed at
`android/docs/decisions/AND-405-scope-admin-agents-infra.md` (an ADR-style
document under the Android subfolder so it travels with the port). If the program
already has an established ADR location, the file is placed there instead and this
path is recorded as the alias.

FR-2. The decision record MUST list each of the following categories as **Out of
scope for mobile**, each with a one- to two-line rationale tied to the mobile use
case (form-factor, security posture, or low expected mobile usage):
1. Full **administration** (admin console, user/tenant admin, system config).
2. **Agents/bots fleet** (agent enrollment, orchestration, fleet status/control).
3. **Compute / Kubernetes / EC2** management (cluster, node, instance operations).
4. **SSH bastion** access (interactive shell / jump-host workflows).
5. **VNC** remote-desktop sessions.
6. **Devtools** (developer/diagnostic tooling surfaces).

FR-3. The record MUST contain an **Exceptions** section. Each exception is one of:
(a) a narrow read-only view that mobile *may* surface, (b) a graceful-degradation
requirement (an entry point or deep-link that must be hidden or must show a
"not available on mobile" state rather than crash), or (c) "None." If no
exceptions are agreed, the section MUST explicitly say "None" — silence is not
acceptable.

FR-4. The record MUST include a **classification table** mapping the excluded
categories to their evidence in the codebase/OpenAPI (the *actual* route prefixes —
see the verified list below, e.g. `/ui/admin/*`, `/ui/agent/*`, `/ui/compute/*`,
`/api/vnc/*` — or the corresponding `frontend/src/api/endpoints/*` files), so a future
reader can verify the classification rather than trust it. Where a category does not
exist in the current backend, the row states "no backend surface found (as of <date>)".
**Note (review correction):** an earlier draft assumed bare prefixes `/admin/*`,
`/agents/*`, `/infra/*`, `/compute/*`, `/bastion/*`, `/vnc/*`, `/devtools/*`. These are
mostly INCORRECT. Verified against `reference/openapi.index.txt`, the real surface is
under `/ui/...`, `/api/...`, and `/v1/admin/...` prefixes — and `/infra/*` does not
exist at all (0 routes). All six categories DO have substantial backend surface (see
§16). The corrected prefixes are reflected in the §4.1 table below.

FR-5. The Android backlog MUST be updated so that it **reflects** the exclusions:
any open Android tickets that would implement an excluded category are closed or
marked `wont-do (out of scope, see AND-405)`; the M8/E53 epic description links to
this record. If no such tickets exist, the backlog change is the addition of an
"Out of scope (mobile)" note in the epic referencing AND-405.

FR-6. The record MUST state the **enforcement posture** for excluded surfaces in
the shipped app (see Section 7): excluded categories have no navigation routes, no
bottom-nav entries, no Hilt-bound API clients; any deep-link or server-driven
reference to them resolves to a safe "unavailable on mobile" state, never a crash.

FR-7. The record MUST be **dated and attributed** (decision date, deciders,
status: Accepted) and reference the backlog ticket AND-405. Status starts as
`Proposed` in the PR and flips to `Accepted` on merge.

Out of scope of *this ticket*: implementing any of the excluded features,
implementing the graceful-degradation/deep-link guard code itself (that is a small
implementation item owned by the navigation/deep-link tickets; AND-405 only states
the requirement), and re-architecting web admin surfaces.

## 4. Technical Design

AND-405 ships **no production Kotlin**. The "design" is the structure of the
decision record and the backlog edits.

### 4.1 Decision record structure

Markdown ADR with sections: Title/metadata (id, date, status, deciders), Context,
Decision (the exclusion list, FR-2), Exceptions (FR-3), Classification &
Evidence (FR-4), Enforcement (FR-6), Consequences, and Links (epic, AND-405,
related tickets). Skeleton:

```markdown
# ADR AND-405: Admin / Agents / Infra are out of scope for mobile
- Status: Accepted (2026-06-05)
- Deciders: <android lead>, <product>
- Backlog: AND-405 (M8 / E53)

## Decision
The following are OUT OF SCOPE for com.testlogon.android. Backend-surface column
uses the **verified** prefixes from `reference/openapi.index.txt` (review-corrected):
| # | Category            | Backend surface (verified evidence)                                   | Rationale            |
|---|---------------------|-----------------------------------------------------------------------|----------------------|
| 1 | Full administration | `/admin/*` (12) + `/ui/admin/*` (158) + `/v1/admin/*`; FE `adminRoles.ts`, `adminImpersonation.ts`, `adminCompute.ts`, `adminAdPlatform.ts`, etc. | desktop-class task   |
| 2 | Agents/bots fleet   | `/ui/agent/*`, `/ui/agent/fleet/*`, `/ui/agent/orchestrator/*`; FE `agentFleet.ts`, `agentOrchestrator.ts`, `bots.ts` | low mobile usage     |
| 3 | Compute/k8s/EC2     | `/ui/compute/*`, `/ui/remote/ec2/*`, `/ui/remote/k8s/*`, `/v1/admin/compute/*`; FE `ec2.ts`, `k8s.ts`, `computeBilling.ts` (NOTE: `/infra/*` does NOT exist) | ops workflow         |
| 4 | SSH bastion         | `/ui/compute/bastion/paths*`, `/api/browser-ssh/*`, `/browser-ssh`, `/ui/remote/ssh-keys/*`; FE `sshBastion.ts`, `sshKeys.ts` | security/form-factor |
| 5 | VNC                 | `/api/vnc/session*`; FE `vnc.ts`                                       | not a mobile UX      |
| 6 | Devtools            | `/broadcast-devtools`; FE `devtools.ts`                               | internal tooling     |

## Exceptions
- None.  // OR explicit list per FR-3

## Enforcement
No routes / nav / Hilt API clients for the above. Deep-links resolve to a
"Not available on mobile" state (owned by AND-022 nav host / deep-link guard).
```

### 4.2 Evidence-gathering procedure (one-time, for the author)

To populate FR-4 accurately, the author inspects (read-only)
`frontend/src/api/endpoints/*.ts` for endpoint groups whose path prefixes map to
the six categories, and `/openapi.json` (`paths`) on the dev backend when
reachable. If the host is down (it is unreliable), cached OpenAPI in the repo or
the frontend client serves as fallback evidence and the row notes its source. This
produces the classification table; it is documentation work, not a test harness.

### 4.3 Backlog edits

Mechanical: locate any Android tickets under E53/M8 (or elsewhere) titled or
scoped around admin/agents/compute/k8s/ec2/bastion/vnc/devtools; set their status
to closed/`wont-do` with a comment linking AND-405; add an "Out of scope (mobile)"
note to the E53 epic. No code module is created or deleted by this ticket.

## 5. API Contract

N/A. This ticket consumes no endpoint and ships no client. It *references*
`/openapi.json` and `frontend/src/api/endpoints/*.ts` only as read-only evidence to
classify which route groups are excluded; it defines no request/response shapes and
no Retrofit interfaces. The deliberate outcome is the **absence** of API contracts
for the excluded surfaces: no `AdminApi`, `AgentsApi`, `InfraApi`, `BastionApi`, or
`VncApi` Retrofit definitions will exist in `core-network`. Any future need to
contact an excluded surface would require superseding this decision via a new ADR.

## 6. Data & State Management

N/A for app runtime. No `StateFlow<UiState>`, no Room entities/DAOs, no DataStore
keys, and no `ApiResult<T>` flows are introduced — because the excluded categories
have no screens to hold state for. The only "state" is documentary:

- The decision record file (source-controlled, the durable artifact).
- Backlog/epic status of affected tickets (tracked in the issue tracker).

Positive consequence to record: `core-data`, `core-model`, and `core-network`
acquire **no** admin/agents/infra DTOs, cache tables, or preference keys. This keeps
the Room schema and DataStore surface minimal and avoids dead model code.

## 7. Error Handling & Resilience

There is no runtime error path *in this ticket*, but the record MUST specify the
**resilience contract for excluded surfaces** so downstream code honors it:

- **No-route guarantee:** the Navigation-Compose graph (owned by AND-022 and the
  unauthenticated/authenticated graph tickets) contains no destinations for excluded
  categories. There is therefore no in-app way to reach them.
- **Deep-link / server-driven reference safety:** if the backend or a notification
  payload references an excluded surface (e.g., a deep link to `/admin/...`), the
  app MUST resolve it to a safe terminal state — a "Not available on the mobile app"
  screen or a no-op — and MUST NOT crash, show a blank screen, or attempt a network
  call to an unbuilt client. This requirement is recorded here and **implemented by**
  the deep-link/navigation guard ticket (AND-022 / the deep-link handler), not by
  AND-405.
- **Dev-backend unreliability:** the only network touch in this ticket is the
  author optionally fetching `/openapi.json` for evidence; the dev host
  (`http://18.222.237.167:8000`) is plaintext and unreliable, so the procedure
  tolerates it being down by falling back to repo/frontend evidence (Section 4.2)
  and the document is still completable offline.

## 8. Security & Privacy

This decision is partly a **security posture** statement and should be framed so:

- SSH bastion, VNC, compute/k8s/EC2 control, and full admin are high-privilege,
  high-blast-radius operations. Excluding them from a mobile client reduces the
  app's attack surface and removes the risk of privileged operations from a device
  more easily lost, stolen, or on untrusted networks.
- No admin/infra credentials, kubeconfig, SSH keys, or session tokens for these
  surfaces are ever stored, requested, or transmitted by `com.testlogon.android`.
  The cookie-based UI session (`ui_csrf` cookie echoed as the `X-CSRF-Token` header,
  single retry via `POST /ui/session/refresh` on 401 — **verified** against
  `src/api/client.ts`) governs only the in-scope user-facing surfaces.
- Excluding these surfaces does not weaken backend authorization: the backend
  remains responsible for rejecting any privileged call; mobile simply never makes
  one. The decision record itself contains no PII — the classification table
  references route prefixes/file paths only.

## 9. Accessibility & i18n

N/A for shipped UI — this ticket delivers no user-facing screens, so there are no
TalkBack, touch-target, contrast, or RTL concerns here. One forward note: the only
user-visible artifact the exclusions may produce is the "Not available on the
mobile app" deep-link terminal state (owned by the nav/deep-link ticket); that
string must be localizable and accessible when implemented, but its delivery is out
of scope for AND-405. The decision document itself is an English-only,
developer-facing engineering artifact.

## 10. Telemetry & Logging

N/A for app runtime telemetry — no analytics events or log statements are added.
The record SHOULD note, as a forward requirement, that if the deep-link guard
surfaces an excluded category, a low-cardinality, **non-PII** breadcrumb (e.g.,
`event=excluded_surface_blocked, category=<...>`) may be logged via the existing
redacted telemetry pathway (AND-052) to measure how often users hit excluded
deep-links. That instrumentation is owned by the implementing ticket, not AND-405.
The "telemetry" of this chore is the git history of the decision record.

## 11. Testing Strategy

There is no executable code, so "tests" are document/backlog review checks:

1. **Completeness (FR-2):** the record lists all six categories — administration,
   agents/bots fleet, compute/k8s/EC2, SSH bastion, VNC, devtools — each marked out
   of scope with a rationale. Reviewer confirms none is missing.
2. **Exceptions present (FR-3):** the Exceptions section is non-empty — either an
   explicit list or the literal "None". A blank/absent section fails review.
3. **Evidence verifiable (FR-4):** for each category, the cited route prefix or
   `frontend/src/api/endpoints/*` file is checked to either exist (confirming the
   classification) or be marked "no backend surface found". Reviewer spot-checks at
   least two rows against `/openapi.json` or the frontend client.
4. **Backlog reflects exclusions (FR-5, Acceptance):** a search of the Android
   backlog for admin/agents/compute/k8s/ec2/bastion/vnc/devtools returns no *open
   implementation* tickets; any found are closed/`wont-do` with an AND-405 link, and
   the E53 epic links the record.
5. **Enforcement stated (FR-6):** the record states the no-route / safe-deep-link
   guarantee and names the downstream owning ticket.
6. **Metadata (FR-7):** status, date, deciders, and AND-405 reference are present;
   status is `Accepted` post-merge.
7. **No code leakage (negative test):** confirm the PR adds no Kotlin module,
   Retrofit interface, or nav route for any excluded category — the diff is
   documentation/backlog only.

## 12. Dependencies & Sequencing

- **Depends on:** none (per backlog). The decision can be authored at any time; it
  only needs read access to `frontend/` and, ideally, `/openapi.json`.
- **Informs / soft-blocks (not hard deps):** module-creation and scoping decisions
  across the port. It prevents creation of `feature-admin`, `feature-agents`,
  `feature-infra` modules and their `core-network` clients, and supplies the
  requirement that the nav/deep-link ticket (AND-022) implements the "not available
  on mobile" guard. These are *consumers* of the decision, not tickets AND-405
  cannot proceed without, so `blocks` is empty in frontmatter.
- **Sequencing:** best landed early in M8 (or earlier) so program estimation and
  module scaffolding never include excluded surfaces. There is no build/runtime
  ordering constraint.
- **External prerequisite:** read access to the web reference and, when up, the dev
  backend OpenAPI for evidence; neither is a code dependency.

## 13. Risks & Open Questions

- **R1 (Open):** Are there *any* exceptions? The backlog says "capture any
  exceptions" — the most likely candidate is a narrow read-only admin/status view
  or a graceful deep-link state. Product/Android-lead must confirm before the record
  flips to `Accepted`; defaulting to "None" if unconfirmed.
- **R2 (Risk):** Misclassification — a route that *looks* like infra but is
  user-facing (or vice versa) gets wrongly excluded. Mitigation: FR-4 evidence table
  + reviewer spot-check against `/openapi.json`/frontend.
- **R3 (Open):** Where is the canonical ADR/decision location for the program? FR-1
  proposes `android/docs/decisions/`; confirm whether an existing ADR folder should
  be used and alias accordingly.
- **R4 (Risk):** Decision drift — a future feature request reintroduces an excluded
  surface ad hoc. Mitigation: require a superseding ADR referencing AND-405 to
  reverse any exclusion; the enforcement note makes the bar explicit.
- **R5 (Resolved by review):** Does the backend currently expose all six categories,
  or only some? **Verified 2026-06-06 against `reference/openapi.index.txt`: ALL SIX
  categories have real backend surface** (admin ~170 routes across `/admin/*`,
  `/ui/admin/*`, `/v1/admin/*`; agents/bots/fleet under `/ui/agent/*`; compute/k8s/EC2
  under `/ui/compute/*`, `/ui/remote/ec2/*`, `/ui/remote/k8s/*`; SSH bastion under
  `/ui/compute/bastion/*` + `/api/browser-ssh/*` + `/ui/remote/ssh-keys/*`; VNC under
  `/api/vnc/session*`; devtools at `/broadcast-devtools`). The earlier draft's bare
  prefixes (`/agents/*`, `/infra/*`, `/bastion/*`, `/vnc/*`, `/devtools/*`) were wrong
  and `/infra/*` does not exist at all. No category needs a "no backend surface found"
  row. Dev-host downtime is irrelevant to classification since the checked-in OpenAPI
  index/spec under `reference/` is authoritative.

## 14. Acceptance Criteria

AC-1. A decision record is committed at
`android/docs/decisions/AND-405-scope-admin-agents-infra.md` (or the confirmed ADR
location, aliased), with status, date, deciders, and an AND-405 reference. (FR-1,
FR-7) — **backlog: "Decision recorded in repo."**

AC-2. The record marks all six categories — full administration, agents/bots fleet,
compute/k8s/EC2, SSH bastion, VNC, devtools — as out of scope for mobile, each with
a rationale. (FR-2)

AC-3. The record contains an Exceptions section that is explicit — either a
concrete list or the literal "None". (FR-3)

AC-4. The record contains a classification/evidence table mapping each category to
a backend route prefix and/or `frontend/src/api/endpoints/*` file, or marks it "no
backend surface found". (FR-4)

AC-5. The Android backlog reflects the exclusions: no open implementation tickets
exist for the excluded categories; any such tickets are closed/`wont-do` with an
AND-405 link, and the E53 epic links the record. (FR-5) — **backlog: "backlog
reflects exclusions."**

AC-6. The record states the enforcement posture (no routes / nav / Hilt API
clients; deep-links resolve to a safe "not available on mobile" state) and names
the downstream owning ticket. (FR-6)

AC-7. The PR diff contains documentation and backlog changes only — no Kotlin
module, Retrofit interface, or navigation route for any excluded category.
(Testing 7)

## 15. Definition of Done

- Decision record file created, populated per FR-2..FR-7, and committed on a branch
  off `android-port`, merged via PR.
- Record status is `Accepted` with date `2026-06-05`, deciders named, AND-405 linked.
- Exceptions resolved (R1): either an agreed list or an explicit "None".
- Backlog updated: affected tickets closed/`wont-do` with AND-405 links; E53 epic
  links the record (AC-5 evidence captured in the PR description).
- ADR location confirmed (R3); path aliased if the canonical location differs from
  the proposed `android/docs/decisions/`.
- Classification table spot-checked against `/openapi.json` and/or
  `frontend/src/api/endpoints/*` by the reviewer; absent categories marked rather
  than invented.
- PR reviewed and approved by the Android lead and a product stakeholder; diff
  confirmed to contain no implementation code for excluded surfaces.
- A note is added pointing the navigation/deep-link guard ticket at AND-405 as the
  source of the "not available on mobile" requirement.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources rooted
at `reference/` unless noted: `openapi.index.txt` (endpoint index),
`openapi.pretty.json` (full schemas), `src/...` (frontend reference app).

1. **Claim:** Full administration surface exists on the backend.
   **VERDICT: Verified (and quantified).** ~170 routes:
   `GET/POST /admin/*` (12, e.g. `POST /admin/roles/grant`, `POST /admin/impersonation/start`),
   `/ui/admin/*` (158, e.g. `GET /ui/admin/ad-platform/accounts`), `/v1/admin/*`.
   **Source:** `openapi.index.txt` (`/admin/`, `/ui/admin/`, `/v1/admin/`); FE
   `src/api/endpoints/adminRoles.ts`, `adminImpersonation.ts`, `adminCompute.ts`,
   `adminAdPlatform.ts`.

2. **Claim (CORRECTED):** Agents/bots fleet is reachable at `/agents/*`.
   **VERDICT: Corrected.** No `/agents/*` route exists. Real prefix is `/ui/agent/*`
   (e.g. `GET /ui/agent/fleet/status`, `POST /ui/agent/fleet/start-all`,
   `POST /ui/agent/orchestrator/create-worker`); bots under separate routes.
   **Source:** `openapi.index.txt` (`/ui/agent/fleet/`, `/ui/agent/orchestrator/`);
   FE `src/api/endpoints/agentFleet.ts`, `agentOrchestrator.ts`, `bots.ts`.

3. **Claim (CORRECTED):** Compute/k8s/EC2 lives under `/infra/*` and/or `/compute/*`.
   **VERDICT: Corrected.** `/infra/*` does NOT exist (0 routes). Bare `/compute/*`
   does not exist either. Real prefixes: `/ui/compute/*` (security-groups, monitoring,
   connection-profiles), `/ui/remote/ec2/*` (e.g. `POST /ui/remote/ec2/instances/{id}/terminate`),
   `/ui/remote/k8s/*` (e.g. `GET /ui/remote/k8s/pods`), `/v1/admin/compute/*`.
   **Source:** `openapi.index.txt` (`/ui/compute/`, `/ui/remote/ec2/`, `/ui/remote/k8s/`,
   `/v1/admin/compute/`); FE `src/api/endpoints/ec2.ts`, `k8s.ts`, `computeBilling.ts`.

4. **Claim (CORRECTED):** SSH bastion is at `/bastion/*`.
   **VERDICT: Corrected.** No `/bastion/*` prefix. Real surface:
   `/ui/compute/bastion/paths*` (e.g. `POST /ui/compute/bastion/paths/{id}/resolve`),
   `/api/browser-ssh/{config,health,protocol}`, `/browser-ssh`, plus SSH key mgmt at
   `/ui/remote/ssh-keys/*` and recordings at `/ui/compute/ssh-recordings/*`.
   **Source:** `openapi.index.txt` (`/ui/compute/bastion/`, `/api/browser-ssh/`,
   `/ui/remote/ssh-keys/`); FE `src/api/endpoints/sshBastion.ts`, `sshKeys.ts`,
   `sshSessionRecording.ts`.

5. **Claim (CORRECTED):** VNC is at `/vnc/*` (or "n/a").
   **VERDICT: Corrected.** It is NOT "n/a" and not bare `/vnc/*`. Real surface:
   `/api/vnc/session`, `/api/vnc/session/{id}`, `/api/vnc/session/{id}/transfer-fallback`.
   **Source:** `openapi.index.txt` (`/api/vnc/session`); FE `src/api/endpoints/vnc.ts`.

6. **Claim (CORRECTED):** Devtools is at `/devtools/*`.
   **VERDICT: Corrected.** No `/devtools/*` prefix; the matching route is
   `/broadcast-devtools`. **Source:** `openapi.index.txt` (`/broadcast-devtools`);
   FE `src/api/endpoints/devtools.ts`.

7. **Claim:** Web auth = `ui_csrf` cookie echoed as `X-CSRF-Token`, refresh on 401.
   **VERDICT: Verified (refined).** `client.ts` reads cookie `ui_csrf` and sets header
   `X-CSRF-Token`; on 401 (only if previously authenticated) it calls
   `POST /ui/session/refresh` once and retries the original request.
   **Source:** `src/api/client.ts` (lines ~119-224: `getCookie("ui_csrf")`,
   `headers.set("X-CSRF-Token", csrf)`, `refreshSession()` -> `/ui/session/refresh`).

8. **Claim:** Backend error shape for validation is FastAPI-standard.
   **VERDICT: Verified.** 422 responses use `HTTPValidationError` =
   `{ detail: ValidationError[] }`; auth failures return `{ detail: string }`.
   **Source:** `openapi.pretty.json` components.schemas `HTTPValidationError`
   (line ~37133) and `ValidationError` (line ~80337); `src/api/client.ts`
   `normalizeErrorDetail(body.detail, ...)`.

9. **Claim:** The dev backend host is `http://18.222.237.167:8000` (plaintext/unreliable).
   **VERDICT: Unverified-assumption.** Not derivable from the OpenAPI or frontend
   sources provided (no base-URL constant matched in `reference/`). Treated as an
   environment fact carried from the ticket/program context, not verified here.

10. **Claim:** The downstream nav/deep-link guard that renders "not available on mobile"
    is owned by AND-022 (and telemetry pathway AND-052).
    **VERDICT: Unverified-assumption.** Cross-ticket ownership; not checkable against
    OpenAPI/frontend. Cited as a planning reference only.

11. **Claim (framework, scope-prevention):** Excluded categories get no Retrofit
    interfaces / Hilt-bound clients / Navigation-Compose destinations in the Android app.
    **VERDICT: Unverified-assumption (forward requirement).** No Android source exists
    yet to inspect; this is the decision being recorded, enforced by review (AC-7), not
    a current-state fact. Stack choices (Kotlin/Compose/Hilt/Retrofit) are program
    conventions — framework ref: https://developer.android.com/jetpack/compose ,
    https://developer.android.com/training/dependency-injection/hilt-android .

### Corrections made

- **§4.1 classification table & §4 FR-4 example prefixes:** replaced invented bare
  prefixes (`/admin/*`-only, `/agents/*`, `/infra/*`, `/compute/*`, `/bastion/*`,
  `/vnc/*`, `/devtools/*`) with the verified real prefixes (`/ui/admin/*`+`/admin/*`+
  `/v1/admin/*`, `/ui/agent/*`, `/ui/compute/*`+`/ui/remote/ec2/*`+`/ui/remote/k8s/*`,
  `/ui/compute/bastion/*`+`/api/browser-ssh/*`+`/ui/remote/ssh-keys/*`, `/api/vnc/session*`,
  `/broadcast-devtools`), each with the corresponding `src/api/endpoints/*.ts` file.
- **`/infra/*` removed:** it does not exist in the backend; the table now says so.
- **§13 R5:** changed from "Open — does the backend expose all six?" to "Resolved":
  all six categories verified present, with route counts/prefixes.
- **§8 CSRF:** refined "refresh on 401" to name the actual endpoint
  `POST /ui/session/refresh` and the single-retry behavior, marked Verified.
- **VNC:** corrected the "n/a or /vnc/*" hedge — VNC surface definitively exists.

### Open assumptions

- **Dev host `18.222.237.167:8000`** (claim 9): environment detail, not present in the
  provided `reference/` sources; cannot be verified here.
- **Cross-ticket ownership AND-022 / AND-052** (claim 10): planning references outside
  the verifiable OpenAPI/frontend scope.
- **Android-side enforcement** (claim 11): no Android code exists yet; the no-route /
  no-client guarantee is the decision itself, enforceable only at review time.
- **Backlog state** (FR-5 / AC-5): the issue tracker is not part of the provided
  sources, so "no open implementation tickets for excluded categories" is asserted as
  a to-be-done backlog edit, not verified here.

## 17. Test Plan

This is a documentation/scope chore with no shippable code, so most cases are
review/verification gates against the authoritative sources and the artifact, plus a
small set of forward-looking instrumented cases that protect the decision once the
Android app exists (these run later but are specified here so the enforcement contract
is testable). Test targets: **JVM** (local JVM/Robolectric), **emulator test35**
(API 35 x86_64 AVD), **device A15** (Samsung Galaxy A15 5G, SM-A156U, API 34, arm64,
serial R5CX821TA9R). Doc/review cases are **manual**.

- **TC-AND-405-01** — Type: manual (doc review). Target: artifact + `reference/openapi.index.txt`.
  Precond: decision record drafted. Steps: confirm all six categories
  (administration, agents/bots fleet, compute/k8s/EC2, SSH bastion, VNC, devtools) are
  each listed as "out of scope for mobile" with a 1-2 line rationale. Expected: six
  rows present, none missing. **Traces: AC-2.**

- **TC-AND-405-02** — Type: contract (manual evidence check vs OpenAPI). Target:
  `openapi.index.txt` / `openapi.pretty.json`. Precond: §4.1 table populated. Steps:
  for each of the six rows, grep the cited prefix in the index and confirm >=1 matching
  route; confirm `/infra/*` is NOT cited (0 routes). Expected: every cited prefix
  resolves to real endpoints; no invented prefixes (`/agents/*`, `/bastion/*`, `/vnc/*`,
  `/devtools/*`, `/infra/*`) remain. **Traces: AC-4.**

- **TC-AND-405-03** — Type: contract (manual evidence check vs frontend). Target:
  `src/api/endpoints/`. Precond: §4.1 table populated. Steps: for each category confirm
  the named FE file exists (`adminRoles.ts`, `agentFleet.ts`, `ec2.ts`/`k8s.ts`,
  `sshBastion.ts`, `vnc.ts`, `devtools.ts`). Expected: all referenced files exist.
  **Traces: AC-4.**

- **TC-AND-405-04** — Type: manual (doc review). Target: artifact. Precond: record
  drafted. Steps: confirm the Exceptions section is non-empty — an explicit list or the
  literal "None". Expected: section present and explicit; blank/absent fails.
  **Traces: AC-3.**

- **TC-AND-405-05** — Type: manual (doc review). Target: artifact. Precond: record
  drafted. Steps: confirm metadata block has status, decision date, deciders, and an
  AND-405 reference; post-merge status is `Accepted`. Expected: all metadata present.
  **Traces: AC-1.**

- **TC-AND-405-06** — Type: manual (doc review). Target: artifact + ADR location.
  Precond: file committed. Steps: confirm file at
  `android/docs/decisions/AND-405-scope-admin-agents-infra.md` (or confirmed ADR
  location, with path aliased). Expected: file exists at the agreed path.
  **Traces: AC-1.**

- **TC-AND-405-07** — Type: manual (backlog review). Target: issue tracker (E53/M8).
  Precond: backlog edits applied. Steps: search backlog for
  admin/agents/compute/k8s/ec2/bastion/vnc/devtools; verify no OPEN implementation
  ticket remains; any found are closed/`wont-do` with an AND-405 link; E53 epic links
  the record. Expected: zero open implementation tickets for excluded categories.
  **Traces: AC-5.**

- **TC-AND-405-08** — Type: manual (doc review). Target: artifact §7. Precond: record
  drafted. Steps: confirm the enforcement posture is stated (no routes / nav / Hilt API
  clients; deep-links resolve to a safe "not available on mobile" state) and the
  downstream owning ticket is named. Expected: enforcement section present and complete.
  **Traces: AC-6.**

- **TC-AND-405-09** — Type: unit (JVM). Target: JVM (PR-diff lint / module graph
  assertion). Precond: PR open. Steps: assert the diff introduces no Kotlin module
  named `feature-admin|feature-agents|feature-infra` and no `*Api` Retrofit interface
  for an excluded surface (`AdminApi`, `AgentsApi`, `InfraApi`, `BastionApi`, `VncApi`).
  Expected: assertion passes (diff is docs/backlog only). Runs on JVM, no device.
  **Traces: AC-7.**

- **TC-AND-405-10** — Type: instrumented/e2e. Target: **device A15** (physical, API 34,
  arm64). Precond: app installed; deep-link guard (AND-022) implemented. Steps: fire a
  deep link to an excluded surface verified to exist, e.g.
  `adb shell am start -W -a android.intent.action.VIEW -d "<scheme>://ui/admin/roles/audit"`
  and similarly for `ui/compute/bastion/paths`, `api/vnc/session`. Expected: app shows
  the "Not available on the mobile app" terminal state, makes NO network call to an
  excluded client, and does NOT crash/ANR/show blank. MUST run on the physical device to
  exercise real intent dispatch + arm64/API-34 behavior. **Traces: AC-6, AC-7.**

- **TC-AND-405-11** — Type: instrumented (flaky-host/offline). Target: emulator
  **test35**. Precond: app installed; airplane mode or dev host down. Steps: fire the
  same excluded deep links offline. Expected: same safe terminal state, no crash, no
  hung network attempt — the guard does not depend on connectivity. Emulator is
  sufficient (no real-hardware dependency). **Traces: AC-6.**

- **TC-AND-405-12** — Type: Compose-UI + accessibility. Target: emulator **test35**.
  Precond: deep-link terminal screen implemented. Steps: render the "Not available on
  the mobile app" screen; assert via Compose test + TalkBack/accessibility checks that
  the message has a content description, sufficient contrast, and >=48dp touch target on
  any action (e.g. "Go back"). Expected: screen is announced by TalkBack and passes
  touch-target/contrast checks. **Traces: AC-6.** (Forward note: localizable string per
  §9.)

- **TC-AND-405-13** — Type: contract/MockWebServer. Target: JVM. Precond: none.
  Steps: stand up MockWebServer returning a 422 `HTTPValidationError`
  (`{ "detail": [ ... ] }`) and a 401 `{ "detail": "Authentication required" }` for an
  excluded path; assert the app has NO Retrofit client wired to call it (the request is
  never issued). Expected: no outbound request to excluded paths; error shapes are
  modeled only for in-scope surfaces. Validates the negative contract. **Traces: AC-7.**

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (record committed, metadata, AND-405 ref) | TC-05, TC-06 |
| AC-2 (all six categories out of scope + rationale) | TC-01 |
| AC-3 (explicit Exceptions section) | TC-04 |
| AC-4 (classification/evidence table verifiable) | TC-02, TC-03 |
| AC-5 (backlog reflects exclusions; epic links record) | TC-07 |
| AC-6 (enforcement posture / safe deep-link state) | TC-08, TC-10, TC-11, TC-12 |
| AC-7 (PR diff: no impl code for excluded surfaces) | TC-09, TC-10, TC-13 |
