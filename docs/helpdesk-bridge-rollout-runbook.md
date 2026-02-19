# Helpdesk bridge mode rollout and rollback runbook (HB-020)

This runbook describes how to stage `helpdesk_bridge` routing safely by tenant/group and how to roll back immediately without a deploy.

## Feature flags

The messaging router reads these environment-backed controls at request time:

- `HELPDESK_BRIDGE_MODE`
  - `enabled`: allow all `helpdesk_bridge` conversation starts.
  - `disabled`: block all `helpdesk_bridge` conversation starts.
  - `internal`: allow only groups listed in `HELPDESK_BRIDGE_INTERNAL_GROUP_IDS`.
  - `selective`: allow groups in `HELPDESK_BRIDGE_ENABLED_GROUP_IDS` OR users whose tenant is in `HELPDESK_BRIDGE_ENABLED_TENANT_IDS`.
- `HELPDESK_BRIDGE_INTERNAL_GROUP_IDS`
  - Comma-separated group IDs used when `HELPDESK_BRIDGE_MODE=internal`.
  - Default: `helpdesk-internal`.
- `HELPDESK_BRIDGE_ENABLED_GROUP_IDS`
  - Comma-separated group IDs used when `HELPDESK_BRIDGE_MODE=selective`.
- `HELPDESK_BRIDGE_ENABLED_TENANT_IDS`
  - Comma-separated tenant IDs used when `HELPDESK_BRIDGE_MODE=selective`.

When blocked, API returns HTTP 403 with code `helpdesk_bridge_mode_disabled`.

## Staged rollout plan

1. **Pilot (internal only)**
   - Set:
     - `HELPDESK_BRIDGE_MODE=internal`
     - `HELPDESK_BRIDGE_INTERNAL_GROUP_IDS=<internal-helpdesk-group-ids>`
   - Validate internal operators can create helpdesk bridge conversations.
2. **Selective expansion**
   - Set `HELPDESK_BRIDGE_MODE=selective`.
   - Add initial canary groups in `HELPDESK_BRIDGE_ENABLED_GROUP_IDS`.
   - Optionally add canary tenants in `HELPDESK_BRIDGE_ENABLED_TENANT_IDS`.
3. **Full enablement (optional)**
   - Set `HELPDESK_BRIDGE_MODE=enabled` once KPIs and alerting are healthy.

## Rollback (no deploy)

If routing regressions are detected:

1. Set `HELPDESK_BRIDGE_MODE=disabled` in runtime config/secrets.
2. Reload service configuration per environment procedure.
3. Confirm new helpdesk bridge starts fail with HTTP 403 + `helpdesk_bridge_mode_disabled`.
4. Existing conversations continue to function with stored routing state; this is a creation gate rollback only.

## Post-change verification checklist

- Attempt a `helpdesk_bridge` start from an allowed and disallowed group.
- Confirm disallowed requests return code `helpdesk_bridge_mode_disabled`.
- Confirm allowed requests still fan out helpdesk alerts and create virtual `helpdesk_group:*` participant.
