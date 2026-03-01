# Newsfeed Markdown + Rich Text Implementation Tickets

This backlog translates `docs/newsfeed-markdown-richtext-support-plan.md` into concrete implementation tickets with dependencies and acceptance criteria.

## Conventions

- Priority: `P0` (must-have), `P1` (important), `P2` (nice-to-have)
- Size: `S` (~0.5–1 day), `M` (~1–3 days), `L` (~3–5 days)
- Type: `Backend`, `Frontend`, `API`, `Data`, `Security`, `Ops`, `QA`

---

## Epic A — Contracts and Content Model

### NFR-001 — Finalize versioned content envelope for posts/comments
- **Type:** API / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Define canonical fields for plain, markdown, and rich content while preserving legacy compatibility.
- **Deliverables:**
  - Contract update for `body_plain`, `body_markdown`, `body_rich`, `body_format`, `body_version`.
  - Backward-compatibility policy for `body` legacy string field.
- **Acceptance criteria:**
  - Contract examples include `plain`, `markdown`, and `rich` payloads.
  - Legacy `body: string` request/response compatibility is documented and approved.
- **Dependencies:** none

### NFR-002 — Implement backend request/response model support
- **Type:** Backend / API
- **Priority:** P0
- **Size:** L
- **Description:** Extend create/edit/get post and comment models to accept and return rich content fields.
- **Deliverables:**
  - Pydantic model updates for post/comment create/edit.
  - Serialization updates to include format-aware fields and legacy `body`.
- **Acceptance criteria:**
  - Existing clients using `body` continue to pass unchanged.
  - New clients can submit/read markdown and rich payloads.
- **Dependencies:** NFR-001

### NFR-003 — Add schema/version validation rules
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** M
- **Description:** Enforce payload limits and schema validity for rich content.
- **Deliverables:**
  - Validation for max text length, node depth/count, and allowed `body_format` values.
  - Error response contract for invalid payloads.
- **Acceptance criteria:**
  - Invalid schema payloads return deterministic 4xx errors.
  - Limits are configurable via settings and covered by tests.
- **Dependencies:** NFR-001

---

## Epic B — Security and Sanitization

### NFR-101 — Introduce markdown sanitization pipeline
- **Type:** Security / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Convert markdown to safe renderable output using strict sanitization.
- **Deliverables:**
  - Sanitizer allowlist for tags/attributes.
  - URL protocol policy (`https`, optional `mailto`; block dangerous schemes).
- **Acceptance criteria:**
  - Script/event-handler injection attempts are stripped or rejected.
  - Sanitizer policy is centrally defined and unit-tested.
- **Dependencies:** NFR-001

### NFR-102 — Validate rich JSON node schema
- **Type:** Security / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Enforce structural constraints for rich editor JSON payloads.
- **Deliverables:**
  - Rich content schema validator.
  - Rejection path for unsupported node types/attributes.
- **Acceptance criteria:**
  - Unsupported/raw HTML nodes are rejected by default.
  - Validation failures are observable with reason codes.
- **Dependencies:** NFR-001

### NFR-103 — Locked content masking for all formats
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** S
- **Description:** Ensure locked posts never leak markdown or rich payloads in responses.
- **Deliverables:**
  - Serializer masking for `body_plain`, `body_markdown`, `body_rich` under lock conditions.
- **Acceptance criteria:**
  - Locked views expose only placeholder content.
  - Regression tests prove no format-specific bypass.
- **Dependencies:** NFR-002

---

## Epic C — Frontend Authoring UX

### NFR-201 — Add markdown editor mode with preview
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Replace plain textarea-only flow with markdown mode + preview for create/edit post/comment.
- **Deliverables:**
  - Markdown mode toggle and preview panel.
  - API payload wiring with `body_format = markdown`.
- **Acceptance criteria:**
  - Users can compose markdown and preview rendered output before submit.
  - Existing plain text flow remains available behind fallback.
- **Dependencies:** NFR-002, NFR-101

### NFR-202 — Add rich-text editor mode (WYSIWYG)
- **Type:** Frontend
- **Priority:** P1
- **Size:** L
- **Description:** Integrate a rich-text editor supporting core formatting tools.
- **Deliverables:**
  - Toolbar actions: bold, italic, links, lists, quote, code.
  - API payload wiring with `body_format = rich` and structured JSON.
- **Acceptance criteria:**
  - Rich content round-trips through create/edit/get without losing structure.
  - Validation errors are surfaced clearly in the UI.
- **Dependencies:** NFR-002, NFR-102, NFR-201

### NFR-203 — Format-aware create/edit forms for comments
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Bring markdown/rich capabilities to comment create/edit with parity to posts.
- **Deliverables:**
  - Updated comment input/edit components.
  - Compatibility handling for legacy comment bodies.
- **Acceptance criteria:**
  - Comment editor supports chosen format and saves correctly.
  - Existing comments still display/edit safely.
- **Dependencies:** NFR-201

---

## Epic D — Rendering and Fallbacks

### NFR-301 — Build shared rich content renderer
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Implement one renderer used by post cards and comments.
- **Deliverables:**
  - `RichContentRenderer` with format switch (`plain`, `markdown`, `rich`).
  - Typography and spacing standards for feed consistency.
- **Acceptance criteria:**
  - Same renderer is used in post and comment surfaces.
  - Render failures fallback to safe plain text.
- **Dependencies:** NFR-201, NFR-202

### NFR-302 — Add truncation/expand behavior for long formatted content
- **Type:** Frontend
- **Priority:** P1
- **Size:** S
- **Description:** Preserve feed readability with expand/collapse support for long rich content.
- **Deliverables:**
  - Character/line threshold policy.
  - Expand/collapse UX and accessibility labels.
- **Acceptance criteria:**
  - Truncated content can be expanded without losing formatting.
  - Collapsed view does not break layout across formats.
- **Dependencies:** NFR-301

### NFR-303 — Legacy fallback rendering and migration read-path
- **Type:** Frontend / Backend
- **Priority:** P0
- **Size:** S
- **Description:** Ensure old records and old clients continue to function during rollout.
- **Deliverables:**
  - Read-path fallback from format fields to legacy `body`.
  - Client fallback to `body_plain` when unsupported format encountered.
- **Acceptance criteria:**
  - Legacy rows render correctly without migration prerequisites.
  - No regressions for plain text posts/comments.
- **Dependencies:** NFR-002, NFR-301

---

## Epic E — Data Migration and Backfill

### NFR-401 — Define no-downtime migration strategy
- **Type:** Data / Backend
- **Priority:** P0
- **Size:** S
- **Description:** Formalize read/write ordering to avoid cutover downtime.
- **Deliverables:**
  - Migration runbook with phases: dual-read, dual-write, cleanup.
- **Acceptance criteria:**
  - Plan supports safe deploy with mixed client versions.
  - Rollback steps are documented.
- **Dependencies:** NFR-002

### NFR-402 — Optional backfill for derived plain fields
- **Type:** Data / Ops
- **Priority:** P2
- **Size:** M
- **Description:** Backfill `body_plain` / default `body_format` on older records for consistency.
- **Deliverables:**
  - Backfill script and dry-run mode.
  - Progress metrics + retry behavior.
- **Acceptance criteria:**
  - Backfill can run incrementally and idempotently.
  - Data integrity checks report zero malformed rows.
- **Dependencies:** NFR-401

---

## Epic F — Testing and Quality Gates

### NFR-501 — Backend test coverage for formats and validation
- **Type:** QA / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Add unit/integration tests for plain/markdown/rich create-edit-get paths.
- **Deliverables:**
  - Tests for valid payloads across formats.
  - Tests for invalid schema/size/depth and sanitizer rejection.
- **Acceptance criteria:**
  - Test suite covers all format combinations and failure paths.
  - Locked-content masking test cases pass.
- **Dependencies:** NFR-002, NFR-101, NFR-102, NFR-103

### NFR-502 — Frontend component tests for editor and renderer
- **Type:** QA / Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add tests for editor state transitions and renderer output.
- **Deliverables:**
  - Tests for markdown preview and rich editor actions.
  - Snapshot/DOM tests for rendered content and fallback behavior.
- **Acceptance criteria:**
  - Core formatting features covered by component tests.
  - Fallback behavior verified for unsupported/invalid format data.
- **Dependencies:** NFR-201, NFR-202, NFR-301

### NFR-503 — E2E tests for author and viewer journeys
- **Type:** QA
- **Priority:** P1
- **Size:** M
- **Description:** Validate end-to-end post/comment create/edit/render behavior for markdown and rich formats.
- **Deliverables:**
  - New e2e scenarios for feed post/comment format workflows.
- **Acceptance criteria:**
  - Author publish + viewer render passes for markdown and rich.
  - Malicious payload attempts are rendered safely and do not execute.
- **Dependencies:** NFR-501, NFR-502

---

## Epic G — Rollout, Flags, and Observability

### NFR-601 — Add feature flags for markdown and rich text
- **Type:** Backend / Frontend / Ops
- **Priority:** P0
- **Size:** S
- **Description:** Gate features independently for safe rollout.
- **Deliverables:**
  - `newsfeed_markdown_enabled`
  - `newsfeed_richtext_enabled`
- **Acceptance criteria:**
  - Flags can be toggled independently per environment.
  - Disabled flags preserve legacy behavior.
- **Dependencies:** NFR-002, NFR-201

### NFR-602 — Instrument content-format telemetry
- **Type:** Ops / Backend / Frontend
- **Priority:** P1
- **Size:** S
- **Description:** Track adoption and failure rates by format.
- **Deliverables:**
  - Metrics for create/edit by format.
  - Validation/sanitization reject counters.
  - Renderer fallback/error counters.
- **Acceptance criteria:**
  - Dashboards show format adoption trend and top errors.
  - Alerts configured for sanitizer/renderer error spikes.
- **Dependencies:** NFR-601

### NFR-603 — Execute phased rollout and post-launch review
- **Type:** Ops / QA
- **Priority:** P1
- **Size:** M
- **Description:** Roll out to internal users, then cohorts, then broad release with checkpoints.
- **Deliverables:**
  - Rollout checklist and go/no-go criteria.
  - Post-launch report with incidents, adoption, and follow-ups.
- **Acceptance criteria:**
  - Each phase has explicit success criteria before progression.
  - Launch review completed with action items tracked.
- **Dependencies:** NFR-503, NFR-602

---

## Suggested execution order

1. Epic A (contracts/models) + Epic B (security foundations)
2. Epic C (authoring) + Epic D (rendering/fallback)
3. Epic F (test hardening)
4. Epic G (flags/telemetry/rollout)
5. Epic E optional backfill as needed

## Milestone definition of done

- Markdown and rich text create/edit/render flows work for posts and comments.
- Legacy plain-text compatibility remains intact.
- Sanitization and schema validation protections are enforced and tested.
- Feature-flagged rollout completed with production telemetry and documented sign-off.
