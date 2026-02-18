# File Preview Plan — Ticket Breakdown

This ticket set maps directly to `docs/file-preview-plan.md` and is ordered to reduce risk/dependencies.

---

## Milestone 0 — Foundation & contracts

### FP-001: Add preview capability contract to file metadata
**Scope**
- Add `preview_kind`, `preview_supported`, `preview_reason` to file info/list/shared-info responses.
- Keep backward compatibility for existing consumers.

**Acceptance criteria**
- Fields appear on `/v1/fs/list`, `/v1/fs/info`, `/v1/fs/shared-list`, `/v1/fs/shared-info` payloads.
- Existing clients that ignore new fields continue working.

**Dependencies**
- None.

---

### FP-002: Implement server-side preview type normalization utility
**Scope**
- Add canonical mapping from extension + content-type to:
  - `image|pdf|word|csv|excel|text|none`.
- Ensure deterministic behavior for ambiguous MIME values.

**Acceptance criteria**
- Utility returns stable `preview_kind` for supported target formats.
- Unknown types resolve to `none` with reason.

**Dependencies**
- FP-001.

---

### FP-003: Preview limits configuration model
**Scope**
- Add settings:
  - `FILEMGR_PREVIEW_MAX_BYTES`
  - `FILEMGR_PREVIEW_TEXT_MAX_LINES`
  - `FILEMGR_PREVIEW_TABLE_MAX_ROWS`
  - `FILEMGR_PREVIEW_TABLE_MAX_COLS`
  - `FILEMGR_PREVIEW_PARSE_TIMEOUT_SECONDS`

**Acceptance criteria**
- Settings configurable via environment.
- Safe defaults documented.

**Dependencies**
- None.

---

### FP-004: Enforce encrypted-file preview denial invariants
**Scope**
- Verify and harden all preview paths to reject encrypted files.
- Ensure `preview_reason=encrypted` is returned via metadata contract.

**Acceptance criteria**
- Encrypted files cannot be previewed inline (owned/shared).
- Download/decrypt flows remain unaffected.

**Dependencies**
- FP-001.

---

## Milestone 1 — Observability & governance

### FP-010: Add preview metrics and helpers
**Scope**
- Add counters/histograms:
  - `filemgr_preview_attempts_total{kind,outcome,reason}`
  - `filemgr_preview_latency_seconds{kind}`
  - `filemgr_preview_bytes_total{kind}`
  - `filemgr_preview_fallback_total{kind,reason}`

**Acceptance criteria**
- Metrics emitted on success/fallback/error.
- Labels are low-cardinality and documented.

**Dependencies**
- FP-001, FP-002.

---

### FP-011: Add preview audit/log dimensions
**Scope**
- Add structured audit/log fields:
  - `preview_kind`, `preview_supported`, `preview_reason`, `is_encrypted`.

**Acceptance criteria**
- Fields queryable in logs for owned and shared preview attempts.

**Dependencies**
- FP-001, FP-002.

---

### FP-012: Preview dashboard and alerts
**Scope**
- Dashboard panels:
  - success rate by kind,
  - p95 preview latency by kind,
  - fallback rate by reason.
- Alert on error/fallback spikes.

**Acceptance criteria**
- Dashboard JSON/runbook committed.
- Alert thresholds reviewed with ops.

**Dependencies**
- FP-010, FP-011.

---

## Milestone 2 — Frontend preview framework

### FP-020: Build preview dispatcher component
**Scope**
- Add central dispatcher that routes by `preview_kind` to renderer components.
- Add `UnsupportedPreview` fallback surface.

**Acceptance criteria**
- Dispatcher handles all target preview kinds and explicit fallback reasons.

**Dependencies**
- FP-001.

---

### FP-021: Add shared preview UI contract parity
**Scope**
- Ensure shared views consume the same preview capability fields.
- Keep encrypted/shared restrictions consistent.

**Acceptance criteria**
- Shared preview action behavior matches owned behavior by kind.

**Dependencies**
- FP-020, FP-004.

---

### FP-022: Add parse worker scaffold for heavy formats
**Scope**
- Introduce worker channel for CSV/Excel/Word parsing.
- Add progress + cancellation messages.

**Acceptance criteria**
- Worker can be invoked from dispatcher and canceled cleanly.

**Dependencies**
- FP-020.

---

## Milestone 3 — Renderers (high-value first)

### FP-030: PDF preview renderer
**Scope**
- Integrate PDF renderer with paging and zoom.

**Acceptance criteria**
- Users can view multipage PDFs and zoom in/out.
- Graceful fallback for oversized/failed parse.

**Dependencies**
- FP-020.

---

### FP-031: Image preview renderer
**Scope**
- Fast image render with fit and zoom controls.

**Acceptance criteria**
- Supports common image MIME types and large-image fallback.

**Dependencies**
- FP-020.

---

### FP-032: Text/code renderer with syntax highlighting
**Scope**
- Render escaped text with line numbers.
- Add syntax highlighting by extension/MIME hint.

**Acceptance criteria**
- No HTML/script execution possible.
- Highlighting works for common languages.

**Dependencies**
- FP-020.

---

## Milestone 4 — Table/document formats

### FP-040: CSV table preview renderer
**Scope**
- Parse CSV to table with delimiter detection and header-row toggle.
- Apply row/column limits and truncation messaging.

**Acceptance criteria**
- Users can preview CSV data in tabular form with deterministic fallbacks.

**Dependencies**
- FP-020, FP-022, FP-003.

---

### FP-041: Excel preview renderer (`.xlsx`)
**Scope**
- Parse workbook and render selected sheet as table.
- Include sheet selector and virtualization.

**Acceptance criteria**
- Handles multi-sheet workbooks.
- Large sheets remain responsive due to virtualization.

**Dependencies**
- FP-040, FP-022.

---

### FP-042: Word preview renderer (`.docx`)
**Scope**
- Convert/render `.docx` content for preview.
- `.doc` remains fallback-only initially.

**Acceptance criteria**
- `.docx` renders readable output.
- `.doc` shows explicit unsupported + download CTA.

**Dependencies**
- FP-020, FP-022.

---

## Milestone 5 — Guardrails and hardening

### FP-050: Preview guardrail enforcement end-to-end
**Scope**
- Enforce byte/row/col/time budgets in backend and UI handling.
- Standardize fallback reasons/messages.

**Acceptance criteria**
- Oversized/time-limited cases never crash UI; always show deterministic fallback.

**Dependencies**
- FP-003, FP-030..FP-042.

---

### FP-051: CSP and security review for preview flows
**Scope**
- Review and tighten CSP for preview rendering contexts.
- Verify no dynamic script execution paths introduced.

**Acceptance criteria**
- Security checklist completed and approved.

**Dependencies**
- FP-030..FP-042.

---

### FP-052: Accessibility pass for preview components
**Scope**
- Keyboard navigation, labels, focus management, table semantics.

**Acceptance criteria**
- Meets internal a11y checklist; no critical issues.

**Dependencies**
- FP-030..FP-042.

---

## Milestone 6 — Testing and release gate

### FP-060: Backend unit tests for preview classification + limits
**Scope**
- Add tests for mapping matrix and guardrail behavior.

**Acceptance criteria**
- High coverage of type mapping and rejection/fallback logic.

**Dependencies**
- FP-001..FP-004.

---

### FP-061: Frontend unit tests for dispatcher/renderers
**Scope**
- Test renderer selection and fallback behavior.
- Add security tests for escaped text rendering.

**Acceptance criteria**
- All preview kinds covered in unit tests.

**Dependencies**
- FP-020, FP-030..FP-042.

---

### FP-062: Integration tests for owned + shared preview flows
**Scope**
- End-to-end preview behavior for each supported type.
- Validate encrypted preview rejection in owned/shared contexts.

**Acceptance criteria**
- Integration suite demonstrates expected success and fallback paths.

**Dependencies**
- FP-021, FP-030..FP-042.

---

### FP-063: Performance tests for large CSV/XLSX/PDF
**Scope**
- Measure time-to-first-preview and memory envelope.

**Acceptance criteria**
- Meets defined p95 targets or provides approved exceptions.

**Dependencies**
- FP-040, FP-041, FP-030.

---

### FP-064: Preview release gate checklist
**Scope**
- Add machine-checkable release checklist for preview DoD:
  - supported formats complete,
  - encrypted-file restrictions verified,
  - metrics/dashboard live,
  - test suites green,
  - security review signed off.

**Acceptance criteria**
- Release gate script/checklist blocks promotion on missing criteria.

**Dependencies**
- FP-010..FP-063.

---

## Suggested sprint sequencing

### Sprint 1
- FP-001, FP-002, FP-003, FP-004, FP-010, FP-011

### Sprint 2
- FP-020, FP-021, FP-022, FP-030, FP-031, FP-032

### Sprint 3
- FP-040, FP-041, FP-042, FP-050

### Sprint 4
- FP-051, FP-052, FP-060, FP-061, FP-062, FP-063, FP-064

---

## Mapping back to plan doc
- Product requirements: FP-030..FP-042
- Security/privacy: FP-004, FP-050, FP-051
- Backend contract: FP-001..FP-003
- Frontend architecture: FP-020..FP-022
- Observability: FP-010..FP-012
- Rollout/testing/DoD: FP-060..FP-064
