# Messaging Drafts QA Test Plan

## Objectives

Validate draft functionality, fallback behavior, isolation, and rollout-gate correctness.

## Test matrix

### Functional

1. Save non-empty draft -> appears in saved list.
2. Save empty draft -> rejected with user-facing error.
3. Load draft -> composer text is replaced.
4. Remove draft -> draft disappears immediately.

### Conversation scope

1. Save in Conversation A.
2. Switch to Conversation B.
3. Verify A draft is not visible in B.

### Refresh/session behavior

1. Save draft.
2. Reload page.
3. Verify draft is still available.

### Offline/failure fallback

1. Simulate create/list API failure.
2. Verify local draft remains accessible.
3. Verify no app crash and expected UX messaging.

### Feature gates

1. Backend `MESSAGING_DRAFTS_MODE=disabled` -> API returns controlled rejection.
2. Frontend `VITE_MESSAGING_DRAFTS_KILL_SWITCH=true` -> draft controls hidden/no-op.

### Security/privacy checks

1. Confirm no draft plaintext in telemetry payloads.
2. Confirm cross-user get/delete are denied.
3. Validate TTL retention behavior in service-level tests.

## Regression checks

- Sending normal messages still works with drafts present.
- Reply/attachments flows are unaffected by draft UI.

## Exit criteria

- All critical functional and isolation scenarios pass.
- No P1/P2 defects open for draft behavior.
- Rollout-gate and rollback checks pass in staging.
