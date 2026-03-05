# VNC Security Runbook (VNC-012)

## Purpose
Operational runbook for security controls enforced by the brokered noVNC control plane.

## Controls

### 1) Authorization guardrails
- Session bootstrap is authorized by **target policy** and **caller role**.
- Allowed policy entries:
  - `*` (allow all)
  - explicit user subject (e.g. `user-123`)
  - role entries (e.g. `role:admin`, `role:root`)
- Unauthorized attempts return `403` with `VNC_AUTH_UNAUTHORIZED`.

### 2) Session bootstrap rate limiting
- Rate limit is enforced per `(user_sub, target_id)` tuple.
- Config:
  - `VNC_BOOTSTRAP_RATE_LIMIT_COUNT` (default `10`)
  - `VNC_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- Limit exceeded returns `429` with `VNC_RATE_LIMITED`.

### 3) TLS/WSS enforcement
- In non-dev environments (`APP_ENV` / `ENV` not in `dev`, `local`, `test`), VNC WebSocket bridge URL **must** be `wss://`.
- Misconfiguration is blocked at runtime with `500` and `VNC_TLS_REQUIRED`.

### 4) Idle timeout and max session duration
- Session policy is returned in bootstrap response as `timeout_policy`:
  - `idle_timeout_seconds`
  - `max_session_duration_seconds`
  - `warning_seconds`
- Expired sessions are closed deterministically with bridge/store cleanup and timeout telemetry.
- Config:
  - `VNC_SESSION_IDLE_TIMEOUT_SECONDS` (default `300`)
  - `VNC_SESSION_MAX_DURATION_SECONDS` (default `3600`)
  - `VNC_SESSION_TIMEOUT_WARNING_SECONDS` (default `60`)

## Audit events

### `vnc_session_bootstrap`
- Emitted on success and failure.
- Correlation fields:
  - `target_id`
  - `session_id` (success)
  - `error_code` (failure)
  - `user_role`

### `vnc_transfer_fallback_requested`
- Emitted on success and failure.
- Correlation fields:
  - `session_id`
  - `method` (success)
  - `expires_at` (success)
  - `error_code` (failure)

### `vnc_session_terminated`
- Emitted when idle/max-duration cleanup force-terminates a session.
- Correlation fields:
  - `session_id`
  - `target_id`
  - `reason` (`idle_timeout` or `max_duration`)
  - `error_code` (`VNC_SESSION_TERMINATED`)
  - `duration_seconds`

## Incident triage quick steps
1. Check audit stream for `vnc_session_bootstrap` failures by `error_code`.
2. If `VNC_RATE_LIMITED`, verify client retry behavior and check for abusive bursts.
3. If `VNC_TLS_REQUIRED`, inspect target inventory `ws_url` and migrate to `wss://`.
4. If repeated `VNC_AUTH_UNAUTHORIZED`, validate target policy and user role mapping.

## Safe rollback / mitigation
- Temporarily reduce exposure by tightening target `allowed_users` to admin-only role entries.
- Lower risk during abuse by reducing `VNC_BOOTSTRAP_RATE_LIMIT_COUNT` and/or increasing window.
- Do **not** disable TLS enforcement in production; fix `ws_url` to `wss://` instead.
