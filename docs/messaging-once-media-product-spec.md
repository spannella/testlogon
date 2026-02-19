# Messaging Once-Media Product Specification (MOM-001)

## Status
- **Ticket:** MOM-001
- **State:** Draft for approval
- **Owners:** Product, Messaging Backend, Messaging Clients
- **Related docs:**
  - `docs/messaging-once-media-plan.md`
  - `docs/messaging-once-media-tickets.md`

## Objective
Define final product behavior for one-time-consumption media in messaging:
- View-once images
- View-once videos
- Listen-once audio messages

This spec locks policy-level behavior so backend and client implementations remain consistent.

---

## 1) Canonical policy decisions

### 1.1 Media type policy mapping
| Media type | Policy label in UI | Consumption policy | Allowed plays/opens |
|---|---|---|---|
| Image | View once | `view_once` | 1 open |
| Video | View once | `view_once` | 1 play session |
| Audio message | Listen once | `listen_once` | 1 play session |

### 1.2 Consumption trigger by type
- **Image:** marked consumed when recipient successfully opens the full image viewer.
- **Video:** marked consumed when playback starts (first successful media start event).
- **Audio:** marked consumed when playback starts (first successful media start event).

Rationale: start-based marking avoids exploit windows where users repeatedly attempt playback without consuming state transition.

### 1.3 Sender and recipient visibility
- **Sender sees:**
  - `Sent` → `Delivered` (existing behavior)
  - `Opened once` for image/video
  - `Listened once` for audio
- **Recipient sees:**
  - `View once` / `Listen once` badge while pending
  - `Opened` / `Listened` consumed placeholder after consume
  - No replay affordance after consume

### 1.4 Backup and restore policy
- Once-media metadata may be included in encrypted message backup.
- Media payload and keys for consumed once-media are **not** restored as replayable content.
- If a message is already consumed before restore, it must remain consumed after restore.

### 1.5 Forwarding, saving, and sharing
- Forwarding once-media as once-media is disallowed in phase 1.
- Save/export/share actions are disabled for pending once-media when platform policy allows.
- Platform limitations (e.g., screenshots on unsupported OS versions) are documented as non-guaranteed controls.

---

## 2) Group-chat semantics

### 2.1 Per-recipient consume model
- Consumption is tracked per recipient.
- In groups, each recipient receives one independent open/play allowance.
- One member consuming does not consume for other recipients.

### 2.2 Sender receipts in groups
- Sender can see aggregate state (e.g., `3/8 opened`, `2/8 listened`).
- Sender cannot re-open recipient content after sending.

### 2.3 Late joiners and membership changes
- New members added after message send do not receive historical once-media unless existing message visibility rules already expose it.
- Removed members lose access per normal authorization rules; no special once-media exception.

---

## 3) Interrupted playback/open and retry behavior

### 3.1 Image open flow
- If full image viewer opens successfully, message is consumed.
- If open fails before viewer render completes (e.g., network/token failure), remain pending and allow retry.

### 3.2 Video/audio playback flow
- If first playback start event succeeds, message is consumed immediately.
- If media fetch fails before playback start, remain pending and allow retry.
- If playback is interrupted after successful start, message remains consumed.

### 3.3 Multi-device conflict handling
- First successful consume transition wins.
- Concurrent opens/plays on other devices must resolve to consumed/expired response.

---

## 4) 1:1 and group edge-case behavior matrix

| Scenario | 1:1 expected behavior | Group expected behavior |
|---|---|---|
| Recipient opens pending once-image | Consumed for recipient; no replay | Consumed only for that recipient |
| Recipient starts pending once-video | Consumed for recipient at play start | Consumed only for that recipient |
| Recipient starts pending listen-once audio | Consumed for recipient at play start | Consumed only for that recipient |
| Network fails before open/play starts | Remains pending; retry allowed | Remains pending per affected recipient |
| Playback interrupted after start | Remains consumed | Remains consumed for affected recipient |
| Two recipient devices open concurrently | One successful consume; other sees consumed/expired | Same per recipient identity across devices |
| App restore after consume | Shows consumed state; no replay | Shows consumed state for consumed recipients |
| Sender views receipt state | Binary opened/listened receipt | Aggregate opened/listened count |

---

## 5) Approval checklist

Approval is complete when all below are checked by owners:

- [ ] Product approval (policy and UX language)
- [ ] Backend approval (consume semantics and race behavior)
- [ ] Client approval (UI states and playback/open triggers)
- [ ] Security approval (backup/restore + anti-export constraints)

## 6) Out-of-scope for MOM-001
- API schema implementation details (MOM-002)
- Feature flag and kill-switch implementation (MOM-003)
- Persistence and endpoint code changes (MOM-010+)
