# Release Notes: Messaging Drafts

## What’s new

You can now explicitly save, load, and remove message drafts from the message composer.

## User-visible behavior

- **Save draft** stores your current message draft for that conversation.
- **Load** replaces the composer text with the selected saved draft.
- **Remove** deletes that draft from your saved list.

## Known limitations

- Drafts currently support **text only**.
- Drafts saved only locally (for example during offline/auth failure) are not available on other devices.
- A draft list is conversation-scoped; drafts do not carry across conversations.

## Offline and cross-device expectations

- If the server is temporarily unavailable, drafts are still saved locally in the browser.
- Once server sync succeeds, drafts can be available across sessions/devices for that account.
- If a local draft was never synced, it remains device/browser-profile specific.

## Privacy and security

- Draft text is not included in analytics event payloads.
- Draft endpoints remain subject to conversation membership and ownership checks.
