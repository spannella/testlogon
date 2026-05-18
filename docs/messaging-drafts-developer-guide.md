# Messaging Drafts Developer Guide (MSGD-018)

## Overview

Messaging drafts provide explicit save/load/remove behavior for conversation-scoped text drafts.

Core components:
- Backend service: `app/services/messaging_drafts.py`
- API routes: `app/routers/messaging.py`
- Frontend hook: `frontend/src/pages/messages/useConversationDrafts.ts`
- Composer integration: `frontend/src/pages/messages/ComposeBar.tsx`

## Data flow summary

1. User clicks **Save draft** in composer.
2. Frontend writes optimistic local draft (`localStorage`).
3. Frontend attempts server create/update; on failure, local draft remains.
4. List/load/remove operations prefer local immediacy with server reconciliation.

## Feature gating

Backend gate vars:
- `MESSAGING_DRAFTS_MODE`
- `MESSAGING_DRAFTS_KILL_SWITCH`
- `MESSAGING_DRAFTS_ENABLED_USER_IDS`
- `MESSAGING_DRAFTS_ENABLED_TENANT_IDS`

Frontend gate vars:
- `VITE_MESSAGING_DRAFTS_ENABLED`
- `VITE_MESSAGING_DRAFTS_KILL_SWITCH`

## Known technical limitations

- Drafts are **text-only** (attachments/scheduling metadata are not persisted as drafts).
- Client fallback is browser-local; local-only drafts do not sync across devices.
- Last-write-wins reconciliation is timestamp-based and may override older local edits.

## Offline and cross-device behavior

- Offline/API-failure path keeps local drafts usable.
- Server-saved drafts can appear across sessions/devices after successful sync.
- If save never reached server, draft remains single-device local.

## Observability

- Backend metrics:
  - `messaging_draft_operations_total`
  - `messaging_draft_operation_duration_seconds`
  - `messaging_draft_fallback_total`
- Frontend analytics events are metadata-only (`messaging:draft-analytics`).

## Development checklist

- Update API contract docs for any route/schema changes.
- Preserve no-plaintext rule for logs/telemetry.
- Add/adjust tests in backend + frontend suites.
- Verify rollout gate behavior before enabling broadly.
