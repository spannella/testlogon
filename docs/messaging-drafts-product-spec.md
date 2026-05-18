# Messaging Drafts v1 — Product Requirements & Scope Lock

## Document metadata
- **Feature:** Messaging Drafts (conversation-scoped)
- **Version:** v1.0
- **Status:** Approved for implementation
- **Owner:** Product / Messaging
- **Last updated:** 2026-04-05

## 1) Problem statement
Users frequently start writing a message and need to pause before sending. Without drafts, partially written content is lost during navigation, refresh, or context switches. The goal of v1 is to provide a lightweight and predictable draft experience that lets users save, load, and remove in-progress text drafts per conversation.

## 2) Goals
1. Enable explicit **Save draft** behavior for in-progress text.
2. Ensure drafts are scoped to a single conversation and never leak across conversations.
3. Provide simple **Load** and **Remove** actions in composer UI.
4. Keep behavior predictable across refresh and navigation.

## 3) Scope lock

### In scope (v1)
- Text-only drafts.
- Conversation-scoped draft storage and retrieval.
- Explicit save action from composer.
- Load selected draft into composer.
- Remove selected draft from draft list.
- Persistence across refresh in the same browser profile.
- Desktop and mobile web support.

### Out of scope (v1)
- Attachment drafts (images, videos, files, audio).
- Scheduled-send draft metadata persistence.
- Encrypted payload/password persistence for drafts.
- Cross-device/cloud sync.
- Collaborative/shared drafts.
- Auto-save while typing.

## 4) Functional behavior contract

### 4.1 Save draft
- User clicks **Save draft**.
- If input is empty/whitespace-only: do not save; show validation feedback.
- If input has content: create a new draft entry for current conversation.
- Newest draft appears first in list.
- System enforces max drafts per conversation (v1 cap = 20).

### 4.2 Load draft
- User clicks **Load** for a specific draft row.
- Composer text is **replaced** with selected draft text (not appended).
- Composer receives focus after load.
- Draft remains in list after load until explicitly removed.

### 4.3 Remove draft
- User clicks **Remove** for a specific draft row.
- Draft is deleted immediately from storage and UI.
- Removal persists after refresh.

### 4.4 Overwrite/replace semantics
- Saving does **not** mutate existing rows; each save creates a new draft record.
- Loading a draft replaces current compose text.
- Removing affects only selected draft row.

### 4.5 Conversation isolation
- Drafts are isolated per conversation key.
- Switching conversation must show only that conversation’s drafts.
- No cross-conversation leakage is allowed.

## 5) Data model (v1)

### Client-side draft shape
```json
{
  "id": "draft-<timestamp>",
  "text": "string",
  "saved_at": 1712345678901
}
```

### Storage namespace
- Key format: `messaging:drafts:<conversationId>`
- Value format: JSON array of draft objects sorted newest-first in runtime view.

### Defensive rules
- Malformed JSON or malformed row entries are ignored safely.
- Parsing failures must not break composer render path.

## 6) Platform behavior

### Desktop web
- Save button visible in composer controls.
- Saved drafts list visible in composer region when drafts exist.
- Load/Remove actions accessible via button controls.

### Mobile web
- Same behavior and ordering as desktop.
- Controls remain keyboard/screen-reader accessible.
- Layout may adapt responsively, but behavior must remain identical.

## 7) Privacy and security constraints
- Draft content is user-generated message text and may contain sensitive information.
- v1 stores drafts locally in browser storage for that user/browser profile only.
- Draft content must not be sent to backend in v1.
- Draft text must not be logged in client analytics payloads.
- Draft telemetry (if emitted) must be metadata-only (event type/count/timestamps), never raw text.

## 8) Retention policy (v1)
- Drafts persist until user removes them or browser storage is cleared.
- Maximum retained drafts per conversation: 20.
- Oldest drafts are truncated when cap is exceeded.

## 9) Cross-device expectations
- v1 is **single-device/browser-profile only**.
- Users should not expect drafts to appear on another device/browser/session.
- Cross-device sync is deferred to post-v1 server-backed roadmap.

## 10) Rollout constraints
- Feature rollout controlled by product rollout plan and UI release process.
- If critical issues are detected, UI controls can be hidden/disabled via feature flag pathway (if present in environment).
- No backend migration dependency is required for v1 local-only behavior.

## 11) UX copy requirements (v1 baseline)
- Empty save attempt: clear validation message indicating text is required.
- Successful save: positive confirmation toast.
- Errors: non-blocking error toast with retry guidance.

## 12) Non-goals / explicit exclusions
- No guarantee of persistence in private browsing modes.
- No guaranteed persistence when browser storage quotas are exceeded.
- No message scheduling state persistence in drafts.
- No encryption credential caching for draft content.

## 13) Acceptance checklist for MSGD-001
- Product spec explicitly documents save/load/remove behavior and replace semantics.
- Empty draft handling is explicitly defined.
- In-scope vs out-of-scope boundaries are explicit.
- Desktop/mobile expectations are defined.
- Privacy constraints and non-goals are explicit.
