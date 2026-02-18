# File Manager Encryption Observability (Dashboards & Alerts)

This document defines dashboard panels and alert ideas for encryption-path reliability and adoption.

## New Metrics

- `filemgr_encryption_events_total{event,encrypted,reason}`
  - `event=upload` tracks encrypted/unencrypted upload mix.
  - `event=download_attempt` tracks encrypted download attempts.
  - `event=decrypt_failure` tracks client decrypt failures by `reason`.
  - `event=remembered_password_used` tracks remembered password usage (opt-in signal).

## Dashboard Panels

### 1) Encrypted upload adoption rate

```promql
sum(rate(filemgr_encryption_events_total{event="upload", encrypted="true"}[5m]))
/
clamp_min(sum(rate(filemgr_encryption_events_total{event="upload"}[5m])), 1)
```

### 2) Encrypted download attempt volume

```promql
sum(rate(filemgr_encryption_events_total{event="download_attempt", encrypted="true"}[5m]))
```

### 3) Decrypt failure rate (encrypted path)

```promql
sum(rate(filemgr_encryption_events_total{event="decrypt_failure"}[5m]))
/
clamp_min(sum(rate(filemgr_encryption_events_total{event="download_attempt", encrypted="true"}[5m])), 1)
```

### 4) Decrypt failures by reason

```promql
sum by (reason) (rate(filemgr_encryption_events_total{event="decrypt_failure"}[15m]))
```

Expected reasons:
- `wrong_password`
- `corrupted_metadata`
- `crypto_error`

### 5) Remembered-password usage rate (opt-in)

```promql
sum(rate(filemgr_encryption_events_total{event="remembered_password_used"}[15m]))
/
clamp_min(sum(rate(filemgr_encryption_events_total{event="download_attempt", encrypted="true"}[15m])), 1)
```

## Alert Recommendations

### Alert: decrypt failure spike

- Condition:

```promql
(
  sum(rate(filemgr_encryption_events_total{event="decrypt_failure"}[10m]))
  /
  clamp_min(sum(rate(filemgr_encryption_events_total{event="download_attempt", encrypted="true"}[10m])), 1)
) > 0.15
```

- For: `15m`
- Severity: warning

### Alert: persistent corrupted metadata failures

- Condition:

```promql
sum(rate(filemgr_encryption_events_total{event="decrypt_failure", reason="corrupted_metadata"}[15m])) > 0.1
```

- For: `30m`
- Severity: critical

### Alert: encryption adoption regression

- Condition:

```promql
(
  sum(rate(filemgr_encryption_events_total{event="upload", encrypted="true"}[1h]))
  /
  clamp_min(sum(rate(filemgr_encryption_events_total{event="upload"}[1h])), 1)
) < 0.02
```

- For: `2h`
- Severity: info

## SLO Mapping

- Encryption-path reliability SLI:
  - `1 - decrypt_failure_rate`
- Distinguishes encrypted-path failures from generic download errors by using:
  - encrypted `download_attempt`
  - `decrypt_failure` reason categories
