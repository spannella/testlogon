# Security Hardening and Break-Glass Runbook

## Purpose
This runbook operationalizes root/admin security controls so operations and security teams can:
- manage root account lifecycle safely,
- enforce privileged action throttling,
- stream privileged events to SIEM/monitoring,
- execute incident response for compromised privileged sessions.

## Root account lifecycle and recovery controls

### 1) Provisioning
- Configure immutable root subject via `ROOT_USER_SUB`.
- Restrict root login sources:
  - `ROOT_LOGIN_ALLOWED_IPS` and/or
  - `ROOT_LOGIN_LOCAL_ONLY=true`.
- Enforce trusted proxy boundaries with `TRUSTED_PROXY_CIDRS`.
- Require root MFA enrollment before root login.

### 2) Normal operation
- Root login must use dedicated endpoint (`/auth/root/login`).
- Root session/token TTLs must remain shorter than normal sessions:
  - `ROOT_SESSION_TTL_SECONDS`
  - `ROOT_ACCESS_TOKEN_TTL_SECONDS`
  - `ROOT_REFRESH_TOKEN_TTL_SECONDS`.

### 3) Rotation and recovery
- Quarterly rotate root credentials and re-validate MFA factors.
- Confirm backup/recovery codes are sealed in approved secret-storage vault.
- Validate `ROOT_USER_SUB` mapping before each release and after IdP migrations.

### 4) Decommissioning
- Revoke all active root sessions.
- Rotate all secrets touched by root in previous 90 days.
- Re-issue admin grants using root role-management workflow with reasons.

## Privileged action rate limiting

The platform applies privileged action throttling via:
- `ADMIN_ACTION_MAX_PER_WINDOW` (default `120`)
- `ADMIN_ACTION_WINDOW_SECONDS` (default `900`)

Applied to:
- Admin role grants/revokes.
- Admin impersonation start/stop.

## Monitoring dashboards

Create dashboards with these minimum panels:

### Authentication and privileged controls
- `root_login_start` / `root_login_denied`
- `admin_role_granted` / `admin_role_revoked`
- `admin_impersonation_start` / `admin_impersonation_stop`
- `role_required` and `root_network_restricted` denials
- `Too many privileged actions` (HTTP 429) counts

### Session risk and containment
- Active root sessions count (target: near-zero steady-state)
- Active impersonation sessions count + age distribution
- Revoked privileged sessions over time
- New privileged source IPs by day

### Billing/file privileged access (forensics)
- Privileged billing writes with `viewed_as_admin=true`
- File access with `actor_sub`, `target_user_sub`, `file_path`
- Bulk operation correlation ids

## SIEM hooks

Enable SIEM forwarding for privileged audit events:
- `SIEM_WEBHOOK_ENABLED=true`
- `SIEM_WEBHOOK_URL=https://<siem-ingest-endpoint>`
- Optional HMAC signing: `SIEM_WEBHOOK_SECRET`
- `SIEM_ROOT_ADMIN_EVENTS_ONLY=true` (recommended)

SIEM payload includes:
- `event`, `ts`, `user_sub`
- `actor_sub`, `effective_sub` (when present)
- full normalized audit payload (`payload`)

## Operational checks (weekly)
- Verify root login source restrictions still match approved CIDRs.
- Verify SIEM ingestion freshness (<5 minutes delay).
- Review all root/admin grants/revokes and impersonation starts/stops.
- Validate no unresolved 429 spikes for privileged routes.

## Approval workflow
- Security owner signs runbook updates.
- Ops owner confirms monitor/dashboard health checks.
- Platform owner confirms env vars are deployed in all environments.

## Root CLI operational procedures

For step-by-step break-glass execution guidance (including approvals/escalation points, CLI-vs-API decision criteria, and evidence capture checklists), use:
- `docs/root-cli-operator-runbook.md`

Treat that runbook as the primary operational playbook for `rootctl` incident actions.

## SES/SNS notification endpoint hardening (PLATFORM-002 / GAP-0319)

The SES delivery-notification receiver `POST /internal/ses/notifications`
(`app/routers/ses_notifications.py`) ingests AWS SNS push messages for email
bounce/complaint/delivery events. A forged bounce/complaint can suppress all
outbound email (password reset, MFA, alerts) to any address, so this endpoint
requires **two** independent controls:

1. **SNS signature verification (application layer, primary)** — every SNS
   message is RSA-signed. The endpoint verifies the signature
   (`app/services/sns_signature.py`) before acting on any payload. The
   `SigningCertURL` is SSRF-guarded (must be `https://sns.<region>.amazonaws.com/...`)
   and the certificate is fetched, cached, and used to verify SignatureVersion 1
   (SHA1) and 2 (SHA256). Verification is gated by
   `SES_SNS_SIGNATURE_VERIFICATION_ENABLED` (default **True/on**). Leave it ON
   in all environments that receive real SNS traffic; only disable it in local
   dev/test where no real SNS subscription exists. `SubscriptionConfirmation`
   messages are auto-confirmed by fetching `SubscribeURL` (same AWS-host SSRF
   guard) only after signature verification passes.

2. **Network restriction (infrastructure, defence-in-depth)** — the
   `/internal/*` path family must additionally be restricted to intra-VPC /
   security-group traffic:
   - ALB listener rule: route `/internal/*` only to a private target group; the
     public listener must return 404 for `/internal/ses/notifications`.
   - Security group on the FastAPI task: allow port 8000 only from the ALB SG
     and the published AWS **SNS** IP ranges
     (`https://ip-ranges.amazonaws.com/ip-ranges.json`, `service: SNS`). No
     direct internet exposure of port 8000.
   - Dev: gate/remove the `/internal` Vite proxy so the browser has no path to
     `/internal/*` (does not affect backend-to-backend dev-stack calls).

Both layers are required. Signature verification stops forged payloads from any
peer (including a compromised internal service); network controls reduce the
attack surface and stop probing. Alert if `403` responses to
`/internal/ses/notifications` exceed ~5/min (misconfigured subscription or
probing attack).
