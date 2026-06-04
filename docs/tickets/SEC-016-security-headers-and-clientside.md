# SEC-016: Security Headers Not Applied (clickjacking/CSP) + Client-Side Hardening

**Ticket**: SEC-016 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 3)

## Problem
- **Security-headers middleware is defined but never registered** —
  `app/main.py:348-356` defines `_security_headers_middleware` (X-Frame-Options,
  CSP, X-Content-Type-Options nosniff, Referrer-Policy) but it is **not added** to the
  app → every response ships **without** these → **clickjacking** (no frame-ancestors/
  X-Frame-Options), MIME sniffing, no CSP (XSS blast-radius). HSTS also absent.
- **Client-side** (frontend/src): SW `postMessage` handler with **no `event.origin`
  check** (`lib/swMessageHandler.ts`); several `target="_blank"` links with
  `rel="noreferrer"` but **missing `noopener`** (reverse tabnabbing) — KycScreening…,
  AgentPrList, SyndicateProfilePage; `RichContentRenderer` renders backend
  `bodyMarkdownHtml` via `dangerouslySetInnerHTML` trusting backend sanitization
  (defense-in-depth: add DOMPurify); client SSO URL assigned to `window.location`
  unvalidated (`Login.tsx`).

## Fix
- **Register** the security-headers middleware (`app.middleware("http")(...)`) with a
  sane CSP, `X-Frame-Options: DENY`/`frame-ancestors 'none'`, `nosniff`,
  `Referrer-Policy`, and HSTS in prod.
- Add `rel="noopener noreferrer"` to all external `target=_blank`; add `event.origin`
  check to SW message handler; client-side-sanitize `bodyMarkdownHtml` (or assert
  backend-sanitized); validate SSO URL is https + expected host before redirect.

## Testing
Responses include the headers; an attempt to iframe a sensitive page is blocked;
SW ignores cross-origin messages; external links carry noopener.
