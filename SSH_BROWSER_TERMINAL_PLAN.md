# Browser SSH Terminal Plan (xterm.js + WebSocket)

## 1) Goals and scope
- Provide an in-browser SSH terminal using **xterm.js** for rendering and UX.
- Use a backend WebSocket server as a bridge between browser and SSH sessions.
- Support authentication with:
  - Password
  - Private key (optional passphrase)
- Allow users to enter target:
  - Host
  - Port
  - Username
- Provide reliable copy/paste behavior for desktop browsers.
- Keep credentials secure and avoid logging secrets.

## 2) High-level architecture
- **Frontend (Web app)**
  - Connection form: host, port, username, auth mode (password/private key), credential fields.
  - Terminal view powered by xterm.js.
  - WebSocket client that sends user keystrokes and receives terminal output.
- **Backend (WebSocket + SSH gateway)**
  - Authenticates/validates incoming session requests.
  - Opens an SSH connection to the requested host via SSH client library.
  - Creates an interactive shell (PTY) and relays byte streams bidirectionally:
    - Browser -> WebSocket -> SSH stdin
    - SSH stdout/stderr -> WebSocket -> browser terminal
- **Optional control plane**
  - Session limits, auditing metadata, observability, and policy controls.

## 3) Suggested technology choices
- **Frontend**
  - xterm.js
  - xterm addons:
    - `@xterm/addon-fit` (resize)
    - `@xterm/addon-web-links` (URL support)
    - Optional `@xterm/addon-clipboard` depending on browser strategy
- **Backend options**
  - Node.js: `ssh2` + `ws` (or `socket.io` if needed)
  - Go: `golang.org/x/crypto/ssh` + Gorilla WebSocket
  - Python: `paramiko`/`asyncssh` + FastAPI/WebSocket
- Prefer one runtime that your team already operates in production.

## 4) Protocol design (browser <-> websocket)
Define a small JSON envelope with explicit message types. Example:
- `connect`:
  - payload: `{ host, port, username, authType, password? privateKey? passphrase? }`
- `input`:
  - payload: `{ data: "...raw input bytes/base64..." }`
- `resize`:
  - payload: `{ cols, rows }`
- `signal` (optional):
  - payload: `{ name: "SIGINT" }`
- `output` (server -> client):
  - payload: `{ data: "..." }`
- `status` / `error`:
  - payload: human-readable state updates

Implementation notes:
- Prefer binary frames for throughput, or JSON+base64 for simplicity.
- Include server-side validation and strict schema checks.

## 5) Authentication flows
### A) Password
1. User selects password mode.
2. Frontend sends password only over WSS.
3. Backend uses SSH password auth and never stores plaintext credentials.

### B) Private key
1. User pastes private key (or uploads local key file for in-memory use only).
2. Optional passphrase field.
3. Frontend sends key material over WSS to backend.
4. Backend parses key and uses public-key auth.

Security expectations:
- Never persist password/key unless explicitly required and encrypted with KMS/HSM.
- Zero sensitive logs (mask fields, redact payloads).
- Clear sensitive variables from memory when session ends (best effort).

## 6) UX plan
- **Connection form**
  - Fields: host, port (default 22), username, auth method toggle.
  - Dynamic auth fields:
    - Password input (masked)
    - Private key textarea/file input + passphrase
  - “Connect” and “Disconnect” buttons.
- **Terminal panel**
  - xterm.js instance with cursor blink and proper theme.
  - Auto-fit on container/window resize.
- **Session feedback**
  - Inline status: connecting, connected, disconnected, error.
  - Optional reconnect prompt.

## 7) Copy/paste support strategy
- Enable native selection in xterm.js for copy.
- Add keyboard bindings:
  - Linux/Windows: Ctrl+Shift+C / Ctrl+Shift+V
  - macOS: Cmd+C / Cmd+V
- Add context menu actions for Copy/Paste as fallback.
- Use Clipboard API when available; provide graceful fallback for restricted browsers.
- Normalize pasted text (`\r\n` handling) before sending input to SSH.

## 8) Terminal/PTY behavior details
- Request PTY with sane defaults (e.g., `xterm-256color`).
- Send `resize` events whenever terminal dimensions change.
- Preserve UTF-8 and binary-safe transport.
- Handle control sequences and backpressure; avoid buffering unbounded output.

## 9) Security hardening checklist
- WSS only (TLS everywhere).
- AuthN/AuthZ for who can open SSH sessions (app login, RBAC, tenancy rules).
- Allowlist/denylist for reachable hosts and ports.
- Rate limiting and per-user/session quotas.
- Idle and absolute session timeouts.
- CSRF/origin checks and strict CORS for WS handshake.
- CSP headers on frontend.
- Optional: record audit metadata (who, when, host, duration) without recording secrets.

## 10) Reliability and observability
- Structured logs with session IDs (no credential content).
- Metrics:
  - active sessions
  - connect success/failure rate
  - session duration
  - bytes in/out
- Health checks for websocket tier.
- Graceful cleanup on disconnect, browser close, and backend restarts.

## 11) Delivery phases
1. **Phase 1: MVP**
   - Host/port/user form
   - Password auth
   - xterm display + interactive shell
   - basic copy/paste
2. **Phase 2: Key auth + UX polish**
   - Private key/passphrase support
   - Better error states and reconnect UX
   - robust resize behavior
3. **Phase 3: Security + scale**
   - RBAC, host policies, rate limits, timeouts
   - metrics/dashboarding
   - horizontal scaling and sticky/session strategy if needed
4. **Phase 4: Enterprise controls (optional)**
   - audit events
   - session recording (policy-dependent)
   - SSO integration

## 12) Testing plan
- **Unit tests**
  - Message schema validation
  - SSH auth mode selection logic
- **Integration tests**
  - Spawn test SSH server/container and verify interactive command execution.
  - Validate resize behavior and session teardown.
- **E2E tests**
  - Browser test: connect, run commands, copy output, paste command, disconnect.
- **Security tests**
  - Input fuzzing on host/port/user fields
  - Ensure secret redaction in logs
  - WS origin/CORS checks

## 13) Open decisions to finalize early
- Backend runtime (Node/Go/Python).
- Whether direct user-supplied targets are allowed or must be policy-restricted.
- Whether to support file upload for key material or paste-only.
- Whether sessions are ephemeral-only or auditable/recorded.
