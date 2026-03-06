# noVNC Browser Widget Implementation Plan

## Goal
Add a browser-based VNC widget using noVNC where users can enter VNC connection information and launch an in-browser remote desktop session, with support for clipboard copy/paste and capability-driven file transfer (including drag-and-drop where available).

## Recommended Architecture

## Architecture Decision Record
- See `docs/novnc-architecture-decision-record.md` for approved trust boundaries, sequence diagrams, bridge placement/scaling decisions, target-selection policy, and canonical error taxonomy.

Use a three-hop connection model:

1. Browser widget (noVNC client)
2. Backend API endpoint that mints a short-lived session token and returns connection metadata
3. WebSocket-to-VNC bridge (`websockify` or equivalent) connected to target VNC server (`host:port`)

This keeps target infrastructure controlled and avoids exposing raw VNC endpoints directly to browsers.

## Phase 1: MVP Viewer
### Frontend
Create a “Remote Desktop” widget/page with:
- Inputs: `host`, `port`, `password` (or target selection), optional display/session name
- Actions: `Connect`, `Disconnect`, `Fullscreen`, `Ctrl+Alt+Del`
- Viewer container for noVNC canvas
- Connection status area (`connecting`, `connected`, `failed`)

### Backend
Add session bootstrap endpoint:
- `POST /api/vnc/session`
  - Validates authentication and authorization to the target
  - Returns:
    - `session_id`
    - `ws_url`
    - short-lived token / signed connect params
    - `expires_at`
    - capability flags (optional in MVP, required later)

Add teardown endpoint:
- `DELETE /api/vnc/session/{session_id}`

## Phase 2: Clipboard Copy/Paste
Implement clipboard support with a small side panel:
- Local clipboard text area + “Send to remote” action
- “Read from remote” action where protocol/server allows
- Optional auto-sync toggle (gated by permissions and browser capability)

### UX and Security Notes
- Browser clipboard APIs may require explicit user gesture.
- Show clear disabled state when clipboard is unsupported by remote server.
- Enforce size limits and sanitize error handling for large clipboard payloads.

## Phase 3: File Transfer + Drag and Drop (Capability-Driven)
File transfer support varies significantly across VNC server implementations.

### Capability Negotiation
Return server/session capability flags from backend:
- `clipboard: boolean`
- `file_transfer: boolean`
- `drag_drop_upload: boolean`

### Frontend Behavior
- Show upload and drag-drop controls only when capabilities are true.
- Provide explicit fallback messaging when unsupported.

### Fallback Strategy
For environments without native VNC file transfer:
- Offer out-of-band transfer flow (SFTP/SCP/object storage upload)
- Keep UX consistent by presenting this as an alternative transfer path

## Security Requirements
- Never persist plaintext VNC credentials
- Prefer backend-managed secrets over user-supplied passwords where possible
- Use short-lived session tokens (1–5 minute connect TTL)
- Enforce strict per-target authorization
- Rate-limit session creation
- Require TLS/WSS for browser transport
- Audit log connect/disconnect/session failures

## Operational Requirements
- Idle timeout and max session duration
- Deterministic proxy/session cleanup on disconnect
- Metrics: session starts/stops, error categories, host-level failure rate
- Structured logs with session and user correlation IDs

## Testing Plan
### Backend
- Unit tests for token issuance, expiry, and authorization checks
- Integration test for create-session → connect bridge → teardown

### Frontend
- UI tests for connect/disconnect flows
- Clipboard behavior tests (supported vs unsupported)
- Capability-gated rendering tests for file upload/drag-drop controls

### Security/Resilience
- Expired token rejection
- Unauthorized target access rejection
- Proxy timeout and host unreachable handling
- Rate-limit verification

## Rollout Plan
1. **Phase A (MVP):** connect/disconnect + stable viewer + core controls
2. **Phase B:** clipboard support
3. **Phase C:** file transfer + drag/drop where supported, with fallback transfer path
4. **Phase D:** policy controls, richer audit/reporting, optional session recording

## Suggested Deliverables
- Backend API routes + service logic for VNC session brokering
- Frontend noVNC widget/page and connection form
- Capability model and feature-gated UI controls
- Security guardrails, logging, and metrics
- Test coverage across API, UI, and failure scenarios


## Security Runbook

Operational controls and incident response procedures for VNC security hardening are documented in `docs/vnc-security-runbook.md`.

- Observability and alerting: see `docs/vnc-observability-runbook.md` for metrics, dashboard panels, trace spans, and failure-rate alerts.
- Rollout and operational readiness: see `docs/vnc-rollout-operational-readiness.md` for phased cohort gates, kill switches, rollback steps, and tabletop validation.
