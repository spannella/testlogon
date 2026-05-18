# NFD-001 Decision Record — Draft Post Scope and UX Behavior

Status: Accepted
Owner: Feed Product + Feed Engineering
Last Updated: 2026-04-27
Related Tickets: `NFD-001`, `NFD-002`, `NFD-202`, `NFD-203`, `NFD-204`, `NFD-205`

## Purpose

Define the canonical behavior for newsfeed post drafts so backend/frontend implementations are consistent and testable.

## Decisions

### 1) Save model: manual save + autosave

- **Current behavior:** explicit **Save draft** plus debounced autosave for in-progress changes.
- Autosave uses retry/backoff for transient errors and pauses in explicit conflict mode when stale-version (`409`) responses occur.
- Manual save remains the primary explicit user action and conflict recovery path.

Rationale:
- Preserves user control with manual save while reducing accidental data loss through autosave.
- Conflict-aware autosave prevents retry storms and prompts explicit user recovery when the server version has changed.

### 2) Draft lifecycle and state model

A draft can be in one of these client-visible states:
- `idle` (loaded but unchanged)
- `dirty` (unsaved local changes)
- `saving`
- `save_error`
- `autosave_retrying`
- `autosave_offline`
- `autosave_conflict` (stale version detected; autosave paused until reload/manual intervention)

Publish behavior:
- Publishing from a draft creates a normal feed post through existing publish pipeline.
- On successful publish, the draft is deleted by default (keep-copy support is optional and non-MVP).

### 3) Draft payload parity with composer

Draft payload must preserve all values needed to restore the composer:
- body fields (`body`, `body_plain`, `body_markdown`, `body_rich`, `body_format`, `body_version`)
- attached post media references (`image_urls`, `file_paths`)
- lock settings (`unlock_price_cents`)

MVP excludes comment drafts.

### 4) List ordering, limits, and pagination

- Draft list is sorted by `updated_at DESC`.
- MVP page size: `20`.
- MVP hard per-user draft cap: `50`.
- When cap is reached, API returns a typed quota error and UI shows actionable guidance.

### 5) Empty, loading, and error UX states

Draft list panel must support:
- **Loading:** skeleton rows while list query resolves.
- **Empty:** message with guidance to save current content.
- **Error:** retry affordance plus concise failure reason.

Save/load/delete actions must show success and failure toasts.

### 6) Overwrite/update semantics

- Saving when no draft is currently loaded creates a new draft.
- Saving when a draft is currently loaded updates that same draft (`PATCH`).
- Loading a different draft while local state is `dirty` requires confirmation before discarding unsaved changes.

### 7) Offline behavior

- If network is unavailable, draft save attempts fail fast with clear error messaging.
- Local-only fallback for server drafts is **not** part of MVP server-backed draft behavior.
- Existing offline **post queue** behavior for publishing remains unchanged.

### 8) Cross-device expectations

- Drafts are server-backed and tied to the authenticated user.
- A draft saved on device A must be list/loadable on device B after refresh.

### 9) Security and ownership expectations

- Users can only read/update/delete their own drafts.
- Attachment references in drafts are validated for ownership at save and publish time.
- Draft content should follow existing content validation constraints wherever applicable.

### 10) Telemetry baseline

Track these events at minimum:
- `draft_save_success`
- `draft_save_fail`
- `draft_load_success`
- `draft_delete_success`
- `draft_publish_success`
- `draft_publish_fail`

Detailed telemetry enrichment is tracked by `NFD-402`.

## Non-goals

- Comment draft support.
- Real-time collaborative draft editing.
- Keep-copy-on-publish UX.

## Acceptance Checklist (for NFD-001)

- [x] Manual-save + autosave behavior documented.
- [x] Draft state model and transition expectations defined.
- [x] Clear empty/loading/error UX requirements documented.
- [x] Update-vs-create semantics and unsaved-change behavior documented.
- [x] Quota/ordering defaults documented.
- [x] Security and cross-device expectations documented.


## Draft List UX States (Normative)

| State | Trigger | UI Requirements | User Action |
|---|---|---|---|
| Loading | Draft list query in flight | Render 2–3 skeleton rows with disabled action buttons. | None |
| Empty | Query succeeds with zero drafts | Show "No saved drafts yet" and guidance to click **Save draft**. | Continue editing and save |
| Ready | Query succeeds with items | Show list sorted by `updated_at DESC` with `Load` and `Remove` controls per row. | Load/remove any draft |
| Error | Query fails or times out | Show inline error banner with concise reason and **Retry** button. | Retry fetch |

Additional rules:
- Save/Delete actions must optimistically disable their initiating button until request settles.
- Toast feedback is required for save/load/delete success and failure paths.

## Interaction Spec (Create, Load, Overwrite, Delete)

### Create draft
1. User has no active loaded draft and clicks **Save draft**.
2. Client submits `CreateDraftPostRequest`.
3. On success, draft list refreshes and new row appears at top.

### Load draft
1. User clicks **Load** on a draft row.
2. Composer state is replaced with that draft payload.
3. Draft context is set to `active_draft_id` for future updates.

### Overwrite/update existing draft
1. User edits a loaded draft (`active_draft_id` present) and clicks **Save draft**.
2. Client sends `UpdateDraftPostRequest` for the same draft id.
3. On success, `updated_at` changes and draft moves to top of list.

### Delete draft
1. User clicks **Remove** on a draft row.
2. Client calls delete endpoint for that draft id.
3. On success, row is removed without a full page reload.

### Unsaved changes when switching drafts
- If local state is `dirty` and user attempts to load another draft, show confirm dialog:
  - **Keep editing** (cancel load)
  - **Discard and load** (proceed)

## Draft-to-Publish Flow (Normative)

1. User loads (or creates) a draft and clicks **Post**.
2. If loaded draft has unsaved local edits, client performs pre-publish draft save first.
3. Publish uses standard post creation pipeline via publish-from-draft endpoint.
4. If publish conflicts with a stale draft version, client reloads latest draft and prompts user to review before retry.
5. On publish success, draft is deleted by default (MVP behavior).
6. On publish failure, draft remains intact for retry/edit.

## Conflict Recovery UX (Normative)

- Save conflict (`409`) during manual/pre-publish save:
  - Show conflict toast.
  - Auto-reload latest draft and show follow-up success/failure toast.
- Autosave conflict (`409`):
  - Set autosave state to `autosave_conflict` and pause further autosave scheduling.
  - Show inline message and **Reload latest** action in composer metadata panel.
- Publish conflict (`409`):
  - Show conflict toast.
  - Auto-reload latest draft and require user review before retrying publish.

## Product Sign-off

- Product owner approval: **Recorded** (2026-03-25)
- Design owner approval: **Recorded** (2026-03-25)
- Engineering owner approval: **Recorded** (2026-03-25)

Sign-off notes:
- Edge cases reviewed: empty-body + attachments, lock-price drafts, and unsaved-change flow.
- The interaction spec above is the source of truth for NFD-001 acceptance.
