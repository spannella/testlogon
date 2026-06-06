---
id: AND-405
title: "Scope decision: admin/agents/infra"
milestone: M8
epic: E53
priority: P1
size: S
status: draft
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
categories to their evidence in the codebase/OpenAPI (e.g., route prefixes such as
`/admin/*`, `/agents/*`, `/infra/*` or the corresponding `frontend/src/api/endpoints/*`
files), so a future reader can verify the classification rather than trust it.
Where a category does not exist in the current backend, the row states "no backend
surface found (as of <date>)".

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
The following are OUT OF SCOPE for com.testlogon.android:
| # | Category            | Backend surface (evidence)        | Rationale            |
|---|---------------------|-----------------------------------|----------------------|
| 1 | Full administration | /admin/* ; frontend .../admin*.ts | desktop-class task   |
| 2 | Agents/bots fleet   | /agents/*                         | low mobile usage     |
| 3 | Compute/k8s/EC2     | /infra/* , /compute/*             | ops workflow         |
| 4 | SSH bastion         | /bastion/* (if present)           | security/form-factor |
| 5 | VNC                 | n/a or /vnc/*                     | not a mobile UX      |
| 6 | Devtools            | /devtools/* (if present)          | internal tooling     |

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
  The cookie-based UI session (`ui_csrf` echoed as `X-CSRF-Token`, refresh on 401)
  governs only the in-scope user-facing surfaces.
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
- **R5 (Open):** Does the backend currently expose all six categories, or only
  some? Rows for absent categories must say "no backend surface found (as of
  2026-06-05)" rather than invent paths; dev-host downtime may force reliance on
  cached/frontend evidence.

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
