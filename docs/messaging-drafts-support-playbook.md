# Messaging Drafts Support Playbook

## Scope

Troubleshooting customer reports for missing drafts, stale drafts, and sync conflicts.

## Quick triage questions

1. Which conversation was the draft saved in?
2. Was the user offline / on unstable network at save time?
3. Is issue on same device/browser or different device?
4. Approximate timestamp of save/load/remove action?

## Common issues and resolutions

### 1) Missing draft

Possible causes:
- Saved in a different conversation.
- Saved only locally, then user switched device/browser profile.
- Draft was removed manually.
- Feature currently disabled by rollout gate.

Actions:
- Verify conversation ID context.
- Check rollout flag status for tenant/environment.
- Ask user to return to original device/browser if save likely remained local.

### 2) Stale draft shown

Possible causes:
- Last-write-wins reconciliation chose newer server timestamp over local older edit.
- User loaded an older draft row.

Actions:
- Confirm the selected draft row timestamp/order.
- Ask user to save latest text again to create fresh newest draft.

### 3) Sync conflict across devices

Possible causes:
- Concurrent edits in multiple sessions.
- One session offline, syncing later.

Actions:
- Explain timestamp-based conflict policy (last-write-wins).
- Recommend copying critical text before loading/removing drafts during conflict.

## Escalation triggers

Escalate to engineering if:
- Draft text appears in logs/telemetry payloads.
- Cross-user draft access suspected.
- Reproducible data-loss pattern after successful server save.

## Evidence to collect

- User ID / tenant ID
- Conversation ID
- Operation timestamps (save/load/remove)
- Device/browser info
- Network conditions at incident time
- Relevant API status codes (if available)

## Customer-safe messaging

- Acknowledge impact and explain conversation-scoped behavior.
- Clarify local vs synced draft expectations.
- Provide concrete recovery steps (open original conversation/device, resave draft).
