# File Preview Expansion Plan

## Goal
Provide secure, performant previews for:
- PDF
- Microsoft Word documents (`.docx` first; `.doc` optional/fallback)
- Images
- CSV files as tables
- Excel files as tables (`.xlsx` first; `.xls` optional/fallback)
- Text/code files with syntax highlighting

---

## Product Requirements

### Supported preview experiences
1. **PDF**
   - In-app viewer with page navigation and zoom.
   - Optional text selection/search.

2. **Word docs**
   - Render `.docx` to HTML in preview pane.
   - For unsupported/legacy `.doc`, show clear fallback message and download option.

3. **Images**
   - Fast inline render with fit/zoom controls.
   - Respect existing encrypted-file preview restrictions.

4. **CSV as table**
   - Parse to rows/columns and show table preview.
   - Include delimiter detection (comma, tab, semicolon) and header-row toggle.

5. **Excel as table**
   - Parse `.xlsx` in browser, show sheet selector + table.
   - Limit rows/columns rendered at once (virtualized table).

6. **Text/code files**
   - Render plaintext with line numbers.
   - Syntax highlighting by extension / MIME hint.
   - Safe rendering only (no HTML execution).

---

## Security & Privacy Constraints

1. **Encrypted files remain non-previewable server-side**
   - Keep existing behavior: encrypted files require download + local decrypt.
   - Preview endpoints must continue returning unsupported for encrypted nodes.

2. **No active content execution**
   - Never execute macros/scripts from Office docs.
   - For text previews, escape HTML and render as text only.

3. **Size-based safeguards**
   - Introduce max preview bytes and row/column caps for CSV/Excel/text.
   - Add timeout budget for parse/render.

4. **CSP hardening for preview routes**
   - Ensure strict `Content-Security-Policy` for preview containers.

5. **Audit/telemetry**
   - Track preview attempts/outcomes by type and fallback reason.

---

## Technical Design

## 1) Backend contract

### Keep current API shape, extend metadata and capability flags
- Existing endpoints can remain primary (`/preview`, `/thumbnail`, `/info` etc.).
- Add normalized preview capability fields in file info/list payloads:
  - `preview_kind`: `image|pdf|word|csv|excel|text|none`
  - `preview_supported`: `true|false`
  - `preview_reason`: optional (`encrypted`, `unsupported_type`, `too_large`, ...)

### Authoritative MIME/type normalization
- Add server utility to map extension + content_type -> `preview_kind`.
- Prefer server decision to avoid inconsistent client behavior.

### Data delivery model by kind
- **image/pdf/text/csv**: stream raw bytes to client preview path.
- **word/excel**: stream bytes; parse/render in frontend worker (Phase 1).
- Optional future optimization: server-side document conversion service.

---

## 2) Frontend preview architecture

### Preview dispatcher
Create a single preview dispatcher component:
- Input: file metadata + fetch URL.
- Routes to specialized renderers:
  - `PdfPreview`
  - `ImagePreview`
  - `CsvTablePreview`
  - `ExcelTablePreview`
  - `WordPreview`
  - `CodePreview`
  - `UnsupportedPreview`

### Parsing/rendering libraries (suggested)
- PDF: `pdf.js`
- DOCX: `mammoth` (HTML conversion)
- XLSX/CSV: `xlsx` + lightweight table model
- Syntax highlighting: `highlight.js` or `prismjs`

### Worker offload
- Parse heavy formats (`xlsx`, `csv` large files, maybe docx) in Web Worker.
- Emit progress and support cancellation.

### Table UX (CSV/Excel)
- Virtualized grid for performance.
- Sheet selector for Excel.
- Preview sample limits with message like:
  - “Showing first 5,000 rows of 120,000.”

---

## 3) Limits and guardrails

Add configurable settings (backend + frontend-aligned):
- `FILEMGR_PREVIEW_MAX_BYTES` (default: `10485760` = 10 MiB)
- `FILEMGR_PREVIEW_TEXT_MAX_LINES` (default: `5000`)
- `FILEMGR_PREVIEW_TABLE_MAX_ROWS` (default: `5000`)
- `FILEMGR_PREVIEW_TABLE_MAX_COLS` (default: `200`)
- `FILEMGR_PREVIEW_PARSE_TIMEOUT_SECONDS` (default: `10`)

Behavior:
- If over limits, show structured fallback with download CTA.
- Never crash preview pane; always provide deterministic error/fallback copy.

---

## 4) Observability and SLOs

Add metrics/audit fields:
- `filemgr_preview_attempts_total{kind,outcome,reason}`
- `filemgr_preview_latency_seconds{kind}`
- `filemgr_preview_bytes_total{kind}`
- `filemgr_preview_fallback_total{kind,reason}`

Label cardinality rules (for stable metrics):
- `kind` is constrained to `image|pdf|word|csv|excel|text|none`.
- `outcome` is constrained to `success|fallback|error`.
- `reason` is constrained to small enums like `none|encrypted|unsupported_type|not_enabled|unknown`.

Log dimensions:
- `preview_kind`
- `preview_supported`
- `preview_reason`
- `is_encrypted`

Dashboards:
- Preview success rate by type.
- P95 preview open latency by type.
- Fallback/error rate by reason.

---

## 5) Rollout Phases

## Phase A — Foundation (1 sprint)
- Add backend preview-kind normalization and capability fields.
- Add preview limits config and server-side checks.
- Add observability primitives and baseline dashboards.

## Phase B — High-value renderers (1 sprint)
- Implement PDF, image, text/code preview renderers.
- Add syntax highlighting and safe text rendering.
- Add unit tests + route tests for capability flags.

## Phase C — Table formats (1 sprint)
- Implement CSV table renderer (delimiter detection, header toggle).
- Implement Excel table renderer with sheet selection.
- Add worker parsing + virtualization.

## Phase D — Word docs (1 sprint)
- Implement DOCX preview renderer.
- Add robust fallback handling for unsupported DOC or parse errors.

## Phase E — Hardening & polish (ongoing)
- Performance tuning on large files.
- Accessibility (keyboard nav, screen-reader labels).
- UX copy and support playbook for fallback cases.

---

## Testing Plan

## Backend tests
- MIME/extension -> preview kind normalization matrix.
- Encrypted file preview blocked behavior remains enforced.
- Size/timeout/guardrail rejection behavior.
- Capability field serialization in list/info/shared-info endpoints.

## Frontend unit tests
- Dispatcher selects correct renderer by `preview_kind`.
- CSV/Excel parser behavior and truncation states.
- Text/code rendering escapes HTML and highlights safely.
- Error/fallback component behavior per reason.

## Frontend integration tests
- Open preview for each supported type from file table.
- Shared file preview behavior consistent with permissions.
- Encrypted file shows download/decrypt guidance (no inline preview).

## Performance tests
- Large CSV/XLSX open time and memory profile.
- Worker parse cancellation and retry reliability.

---

## Definition of Done
- Users can preview PDF, images, CSV tables, Excel tables, DOCX, and text/code files.
- Encrypted files are still blocked from inline preview and require decrypt/download flow.
- Preview guardrails prevent oversized/expensive previews from degrading the app.
- Preview behavior is observable (success/fallback/error/latency) with dashboards.
- Existing preview functionality remains backward compatible.
