# Newsfeed Markdown + Rich Text Support Plan

## Current baseline

- Post and comment payloads are plain text (`body: string`) in the current API and frontend types.
- Create/edit UX uses textareas, and renderers display plain text with whitespace preservation.
- Backend serializers include some legacy handling where `body` might be a dict, but that is not a first-class rich-content contract.

## Goals

- Support **Markdown authoring and rendering**.
- Support **Rich Text (WYSIWYG) authoring and rendering**.
- Keep backward compatibility for existing plain-text posts/comments.
- Ship safely with sanitization, validation, and incremental rollout controls.

## 1) Define a versioned content model

Introduce a content envelope for posts and comments:

- `body_plain: string` (required fallback; used for search/safety/fallback rendering)
- `body_markdown?: string`
- `body_rich?: object` (editor-native JSON structure)
- `body_format: "plain" | "markdown" | "rich"`
- `body_version: number` (schema version)

Design choice:

- **Markdown canonical** if portability/interoperability is most important.
- **Rich JSON canonical** if fidelity in WYSIWYG editing is most important.

Either way, always derive and persist `body_plain`.

## 2) Evolve backend contracts with compatibility

For create/edit post and comment endpoints:

- Continue accepting legacy `body: string` requests.
- Add optional richer payload fields (format + rich/markdown content).
- Add response fields for richer content while preserving legacy `body`.

Validation rules:

- Max payload size and text length.
- Allowed format checks and schema validation for rich JSON.
- Content normalization (trim, canonicalization).

Serializer behavior:

- On read, return content in requested/stored format + fallback plain text.
- Continue returning legacy `body` during transition.

Locked-content behavior:

- Ensure all format variants are masked consistently for locked posts.

## 3) Security and sanitization hardening

Implement an explicit sanitization pipeline:

- Markdown -> sanitized HTML (strict allowlist of tags/attrs).
- Rich JSON -> validated node schema (disallow arbitrary/raw HTML nodes by default).
- URL protocol allowlist (`https`, optional `mailto`) and block dangerous protocols.

Add abuse controls:

- Max nesting depth and node count.
- Limits for embeds/links/mentions per post/comment.

Add security tests for XSS and injection edge cases.

## 4) Frontend authoring experience (incremental)

Replace/augment textarea flows in:

- Create post
- Edit post
- Create comment
- Edit comment

Phased UI:

1. **Phase A:** Markdown mode with preview toggle.
2. **Phase B:** Rich-text WYSIWYG mode (toolbar for bold/italic/link/list/code/quote).
3. **Phase C:** Enhancements (mentions, inline embeds, slash commands).

Fallback behavior:

- If a format is unsupported on client, render `body_plain`.

## 5) Rendering architecture

Create a shared `RichContentRenderer` used for:

- Feed post body
- Comment body

Responsibilities:

- Render by `body_format` (`plain`, `markdown`, `rich`).
- Use sanitized output only.
- Keep typography, spacing, and truncation behavior consistent.
- Graceful fallback to plain text if parsing/rendering fails.

## 6) Data migration strategy

No hard cutover required:

- Existing records with `body` remain readable as `plain`.
- On edit by new clients, write new content envelope fields.

Optional backfill:

- Populate derived `body_plain` and `body_format` defaults on legacy rows for analytics/search consistency.

Operational runbook:

- Use `docs/newsfeed-rich-content-migration-runbook.md` for the no-downtime phased rollout (`dual-read`, `dual-write`, `cleanup`) and rollback playbook.

## 7) Testing strategy

Backend:

- Create/edit/get for each content format.
- Legacy compatibility tests (`body` only).
- Validation failure tests (bad schema/oversized payload).
- Sanitization/XSS regression tests.
- Locked post/comment masking tests.

Frontend:

- Editor input + preview tests.
- Rendering snapshots for markdown/rich/plain variants.
- Fallback rendering tests.

E2E:

- Create markdown post/comment and verify rendering.
- Create rich-text post/comment and verify rendering.
- Edit preserves formatting.
- Malicious content does not execute.

## 8) Rollout and observability

Feature flags:

- `newsfeed_markdown_enabled`
- `newsfeed_richtext_enabled`

Rollout stages:

1. Internal staff only.
2. Small creator cohort.
3. Gradual percentage rollout.
4. Full rollout after stability/security checks.

Metrics and monitoring:

- Adoption by content format.
- Sanitizer rejection counts and top failure reasons.
- Renderer error rates.
- Client-side fallback usage rates.

## 9) Suggested implementation sequence

1. Finalize API/content schema RFC (1-2 days).
2. Backend model + validation + serializer compatibility (2-4 days).
3. Markdown editor/render support (2-3 days).
4. Rich-text editor/render support (4-8 days).
5. Security hardening and regression test pass (2-4 days).
6. Feature-flag rollout + telemetry review (ongoing).

## Definition of done

- Legacy plain-text clients continue to work.
- Markdown and rich-text clients can create/edit/render safely.
- Sanitization and validation protections are in place and tested.
- Rollout is controlled by flags with observability dashboards in place.
