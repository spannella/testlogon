# Google Drive Mount Observability Runbook (GDM-051)

## Ownership

- **Service owner:** `platform-filemanager`
- **Primary on-call:** `platform-filemanager-oncall`
- **Escalation:** `infra-sre`

## Metrics

- `filemgr_mount_operation_duration_seconds{provider,operation}`
- `filemgr_mount_transfer_bytes_total{provider,direction,operation}`
- `filemgr_mount_api_errors_total{provider,operation,status_code,reason}`
- `filemgr_mount_refresh_attempts_total{provider,outcome,reason}`

## Dashboard

- Dashboard JSON: `docs/dashboards/google-drive-mount-ops-dashboard.json`
- Import into Grafana folder: `FileManager / Mounts`

## Alerts and thresholds

### 1) Elevated 401/403/429 rates (warning/critical)

```promql
sum(rate(filemgr_mount_api_errors_total{provider="google_drive",status_code=~"401|403|429"}[10m]))
```

- Warning: `> 0.2` for `15m`
- Critical: `> 1.0` for `15m`
- Owner: `platform-filemanager-oncall`

### 2) p95 mounted latency regression (warning/critical)

```promql
histogram_quantile(0.95, sum(rate(filemgr_mount_operation_duration_seconds_bucket{provider="google_drive"}[5m])) by (le, operation))
```

- Warning: any operation `> 1.5s` for `15m`
- Critical: any operation `> 3.0s` for `15m`
- Owner: `platform-filemanager-oncall`

### 3) Upload failure spikes (warning/critical)

```promql
sum(rate(filemgr_mount_api_errors_total{provider="google_drive",operation="upload"}[10m]))
```

- Warning: `> 0.1` for `10m`
- Critical: `> 0.5` for `10m`
- Owner: `platform-filemanager-oncall`

## Triage checklist

1. Confirm feature flag state (`FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED`) for impacted environment.
2. Check dashboard panel for 401/403/429 splits.
3. For 401/403 spikes, inspect `provider_oauth_refresh` audit events and `filemgr_mount_refresh_attempts_total` failure reasons.
4. For 429 spikes, inspect retry/backoff panel and Google API quota usage.
5. For upload spikes, validate resumable vs simple mode behavior and compare to recent deploy.
6. If critical threshold persists >30m, execute rollback guardrail:
   - disable mounts feature flag,
   - communicate impact in incident channel,
   - open follow-up ticket with metric snapshots.
