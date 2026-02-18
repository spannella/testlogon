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
