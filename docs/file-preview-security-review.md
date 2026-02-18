# File Preview Security Review (FP-051)

This checklist captures CSP and client-side script-execution review for preview flows (`/v1/fs/preview`, `/v1/fs/shared-preview`, thumbnails, and the FilePreview renderer matrix).

## Scope Reviewed

- Preview renderers: image, pdf, text, csv, excel, parquet, docx, unsupported fallback.
- Security headers middleware and default CSP policy.
- Frontend rendering paths for dynamic script execution risks.

## Checklist

- [x] **CSP tightened for preview contexts**
  - `script-src 'self'`
  - `object-src 'none'`
  - `frame-src 'self' blob:`
  - `worker-src 'self' blob:`
  - `form-action 'self'`
  - `media-src 'self' blob:`

- [x] **No new dynamic script execution paths**
  - No `dangerouslySetInnerHTML` introduced in preview renderer paths.
  - Text/code/docx preview output is rendered as text nodes (`<pre>/<code>/<span>`), not injected HTML.

- [x] **Deterministic fallback reasons**
  - Guardrail fallbacks mapped to explicit reasons: `too_large`, `parse_timeout`, `parse_failed`, `unsupported_type`, `legacy_word_unsupported`, `encrypted`.

- [x] **Preview guardrails do not crash UI**
  - Oversized/timeout/error paths return fallback surfaces with download CTA.

## Approval

- Status: **Approved**
- Approver: **security-review-board**
- Date: **2026-02-18**
- Tracking ticket: **FP-051**
