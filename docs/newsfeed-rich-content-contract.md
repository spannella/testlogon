# Newsfeed Rich Content Contract (NFR-001)

This document defines the canonical content envelope for posts/comments and the legacy compatibility policy.

## Canonical envelope

Each post/comment body supports the following fields:

- `body_plain: string` — required fallback/plain representation.
- `body_markdown?: string` — optional markdown source.
- `body_rich?: object` — optional rich-text document JSON.
- `body_format: "plain" | "markdown" | "rich"` — selected source format.
- `body_version: number` — envelope schema version (current: `1`).

## Legacy compatibility policy

- The legacy `body: string` field remains accepted in create/edit requests.
- The legacy `body: string` field remains present in responses.
- For backward compatibility, `body` always maps to the plain fallback representation (`body_plain`).
- New clients should send the canonical envelope and may continue to include `body` during transition.

## Validation rules (contract level)

- At least one of `body`, `body_plain`, `body_markdown`, `body_rich` must be present.
- If `body_format = "markdown"`, `body_markdown` is required.
- If `body_format = "rich"`, `body_rich` is required.
- If `body_rich` is provided, a plain fallback (`body_plain` or legacy `body`) is required.

---

## Request examples

### 1) Legacy/plain request

```json
{
  "body": "Legacy plain text post",
  "visibility": "followers"
}
```

### 2) Markdown request

```json
{
  "body_plain": "Hello world",
  "body_markdown": "# Hello world",
  "body_format": "markdown",
  "body_version": 1
}
```

### 3) Rich-text request

```json
{
  "body_plain": "Hello rich world",
  "body_rich": {
    "type": "doc",
    "content": [
      {
        "type": "paragraph",
        "content": [{ "type": "text", "text": "Hello rich world" }]
      }
    ]
  },
  "body_format": "rich",
  "body_version": 1
}
```

## Response example

```json
{
  "post_id": "post_123",
  "author_id": "user_abc",
  "created_at": "2026-01-01T00:00:00+00:00",
  "body": "Hello world",
  "body_plain": "Hello world",
  "body_markdown": "# Hello world",
  "body_rich": null,
  "body_format": "markdown",
  "body_version": 1
}
```


## Error response contract

Invalid content payloads are rejected with HTTP `422` and deterministic validation message prefixes:

- `invalid_content_payload:` for missing/invalid field combinations and text length limit failures.
- `invalid_content_schema:` for malformed `body_rich` JSON shape or rich tree constraint failures.

Examples:

- `invalid_content_payload: body_markdown is required when body_format is markdown`
- `invalid_content_schema: body_rich node count exceeds max (500)`


## Markdown sanitization policy

Markdown input is converted to sanitized HTML on write and exposed as `body_markdown_html` in responses.

Allowlist (centrally defined in backend):

- Tags: `p`, `br`, `strong`, `em`, `code`, `pre`, `blockquote`, `ul`, `ol`, `li`, `a`
- Attributes: `a[href|rel|target]`

URL protocol policy for links:

- Allowed: `https`, `mailto`
- Blocked/rejected: everything else (including `javascript:`)

Any raw HTML/script/event-handler injection payloads are escaped (rendered as text) or stripped from link rendering.


## Rich JSON schema policy

Rich payloads (`body_rich`) are validated against a strict allowlist. By default, unsupported nodes and raw HTML/script-like nodes are rejected.

Allowed node types:

- `doc`, `paragraph`, `text`, `heading`, `blockquote`, `bulletList`, `orderedList`, `listItem`, `codeBlock`, `hardBreak`

Allowed mark types:

- `bold`, `italic`, `code`, `link`

Allowed mark URL protocols:

- `https`, `mailto`

Validation failures include deterministic reason codes in the error message prefix:

- `invalid_content_schema:unsupported_node_type:`
- `invalid_content_schema:unsupported_node_attr:`
- `invalid_content_schema:unsafe_link_protocol:`
- `invalid_content_schema:node_limit_exceeded:`
- `invalid_content_schema:depth_limit_exceeded:`

Server logs also include `reason_code` for observability.
