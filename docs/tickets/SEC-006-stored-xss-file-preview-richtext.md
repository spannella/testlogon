# SEC-006: Stored XSS (file preview inline HTML/SVG, rich-text fallback)

**Ticket**: SEC-006 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (item 6)

## Problem
- 👤 **File-manager preview serves dangerous types inline**: `app/routers/filemanager.py`
  preview/shared-preview serve `text/html` and `image/svg+xml` with
  `Content-Disposition: inline` (`is_previewable()` returns true for all `text/*`).
  Upload `malicious.html`/SVG → open `GET /v1/fs/preview?path=…` (or a shared
  preview) → JS executes **in the app origin** → session/CSRF-token theft, actions
  as the victim.
- **Rich-text fallback XSS**: `frontend/src/pages/feed/MarkdownComposer.tsx:~134`
  `richDocToHtml(doc, fallback)` interpolates the `body_plain` fallback **unescaped**
  into HTML that is rendered via `dangerouslySetInnerHTML` (RichContentRenderer) when
  `body_rich` is empty.
- **Aggravator**: the access token is mirrored into `localStorage["auth-store"]`, so
  any XSS = token theft (not just cookie, which is httpOnly).

## Fix
- Preview: exclude `text/html`, `text/xml`, `image/svg+xml` (and anything non-safe)
  from `is_previewable`; serve all non-image/non-pdf user files as
  `Content-Disposition: attachment`; set a restrictive `Content-Type`/`X-Content-Type-Options: nosniff`.
- `richDocToHtml`: HTML-escape the fallback (mirror `markdownHtmlFromProps`’s escaping).
- Consider not persisting the access token in localStorage (keep it cookie-only) to
  shrink XSS blast radius; add a CSP.

## Testing
E2E/unit: uploading an HTML/SVG file and hitting preview returns `attachment` (no
inline script execution); a post with `body_rich` empty + `body_plain`
`<img onerror=…>` renders escaped text, not executed markup.
