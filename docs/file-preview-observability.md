# File Preview Observability Runbook (FP-012)

This runbook defines the dashboard and alerting model for file preview reliability.

## Metrics used

- `filemgr_preview_attempts_total{kind,outcome,reason}`
- `filemgr_preview_latency_seconds{kind}`
- `filemgr_preview_bytes_total{kind}`
- `filemgr_preview_fallback_total{kind,reason}`

Label assumptions (low cardinality):
- `kind`: `image|pdf|word|csv|excel|text|none`
- `outcome`: `success|fallback|error`
- `reason`: `none|encrypted|unsupported_type|not_enabled|unknown`

---

## Dashboard panels

### 1) Success rate by kind

```promql
sum by (kind) (rate(filemgr_preview_attempts_total{outcome="success"}[5m]))
/
clamp_min(sum by (kind) (rate(filemgr_preview_attempts_total[5m])), 1)
```

### 2) p95 preview latency by kind

```promql
histogram_quantile(
  0.95,
  sum by (le, kind) (rate(filemgr_preview_latency_seconds_bucket[5m]))
)
```

### 3) Fallback rate by reason

```promql
sum by (reason) (rate(filemgr_preview_fallback_total[10m]))
/
clamp_min(sum(rate(filemgr_preview_attempts_total[10m])), 1)
```

### 4) Error rate (global)

```promql
sum(rate(filemgr_preview_attempts_total{outcome="error"}[10m]))
/
clamp_min(sum(rate(filemgr_preview_attempts_total[10m])), 1)
```

### 5) Preview volume by kind (optional ops panel)

```promql
sum by (kind) (rate(filemgr_preview_attempts_total[15m]))
```

---

## Alert rules

### Alert: preview error spike (warning)

```promql
(
  sum(rate(filemgr_preview_attempts_total{outcome="error"}[10m]))
  /
  clamp_min(sum(rate(filemgr_preview_attempts_total[10m])), 1)
) > 0.05
```

- For: `15m`
- Severity: `warning`

### Alert: preview fallback spike (warning)

```promql
(
  sum(rate(filemgr_preview_fallback_total[10m]))
  /
  clamp_min(sum(rate(filemgr_preview_attempts_total[10m])), 1)
) > 0.20
```

- For: `20m`
- Severity: `warning`

### Alert: persistent encrypted fallback anomaly (critical)

```promql
sum(rate(filemgr_preview_fallback_total{reason="encrypted"}[30m])) > 1
```

- For: `30m`
- Severity: `critical`
- Note: should normally remain near zero because encrypted previews are blocked by design.

---

## Ops review status

Threshold review for FP-012 has been completed with ops.

- Reviewed by: `platform-ops`
- Review date: `2026-02-18`
- Decision: keep current warning/critical thresholds for initial rollout; revisit after 2 weeks of production traffic.

---

## Triage guide

1. Check panel 4 (error rate) to confirm platform-level spike.
2. Break down panel 1 (success by kind) to isolate affected format(s).
3. Use panel 3 (fallback reasons) to identify whether failures are policy-driven (`encrypted`, `unsupported_type`) or unexpected (`unknown`).
4. Correlate with recent deploys and backend preview route logs containing:
   - `preview_kind`
   - `preview_supported`
   - `preview_reason`
   - `is_encrypted`
