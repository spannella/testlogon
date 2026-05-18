# Apple CalDAV Configuration Flags

This document defines environment-backed settings for Apple Calendar integration and their default values.

## Global and provider enablement

- `CALENDAR_INTEGRATIONS_ENABLED` (default: `1`)
  - Global switch for all calendar integrations.
  - If disabled (`0`/`false`), no provider is registered.

- `APPLE_CALDAV_ENABLED` (default: `0`)
  - Apple CalDAV provider switch.
  - Only used when `CALENDAR_INTEGRATIONS_ENABLED` is enabled.

## Endpoint and request behavior

- `APPLE_CALDAV_BASE_URL` (default: `https://caldav.icloud.com`)
- `APPLE_CALDAV_CONNECT_TIMEOUT_SECONDS` (default: `5`)
- `APPLE_CALDAV_READ_TIMEOUT_SECONDS` (default: `10`)
- `APPLE_CALDAV_RETRY_MAX_ATTEMPTS` (default: `3`)

## Polling defaults

- `APPLE_CALDAV_POLL_INTERVAL_SECONDS` (default: `300`)
- `APPLE_CALDAV_POLL_JITTER_SECONDS` (default: `30`)
- `APPLE_CALDAV_POLL_BATCH_SIZE` (default: `50`)
- `APPLE_CALDAV_OUTBOX_PROCESS_LIMIT` (default: `200`)

## Table names

- `CALENDAR_CONNECTIONS_TABLE_NAME` (default: `calendar_connections`)
- `CALENDAR_CONNECTION_SECRETS_TABLE_NAME` (default: `calendar_connection_secrets`)
- `EXTERNAL_CALENDARS_TABLE_NAME` (default: `external_calendars`)
- `EXTERNAL_EVENT_LINKS_TABLE_NAME` (default: `external_event_links`)
- `CALENDAR_SYNC_RUNS_TABLE_NAME` (default: `calendar_sync_runs`)

## Disable behavior matrix

1. `CALENDAR_INTEGRATIONS_ENABLED=0`
   - No providers are registered, regardless of provider-specific flags.
2. `CALENDAR_INTEGRATIONS_ENABLED=1` and `APPLE_CALDAV_ENABLED=0`
   - Apple provider is registered in disabled mode and fails fast for operations.
3. `CALENDAR_INTEGRATIONS_ENABLED=1` and `APPLE_CALDAV_ENABLED=1`
   - Apple provider is enabled and available.

## Rollout runbook reference

- Deployment runbook: `docs/runbooks/apple-caldav-rollout-runbook.md`
- Dashboard spec: `docs/dashboards/calendar-sync-ops-dashboard.json`
- Alert rules: `docs/alerts/calendar-sync-health-alerts.yml`

## Pre-launch environment verification checklist

- [ ] All table name env vars are set explicitly per environment.
- [ ] `CALENDAR_CONNECTION_SECRETS_TABLE_NAME` is backed by encryption-at-rest and correct IAM/KMS grants.
- [ ] `CALENDAR_INTEGRATIONS_ENABLED` and `APPLE_CALDAV_ENABLED` values are set for the intended rollout phase.
- [ ] Timeout/retry/polling values are reviewed against expected provider and workload characteristics.
