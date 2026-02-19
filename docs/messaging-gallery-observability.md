# Messaging Gallery Observability Runbook

This runbook defines the operational dashboard and alerting model for gallery reliability, performance, and pagination-cost visibility.

## Metrics

Gallery endpoint metrics are emitted from `GET /messaging/conversations/{conversation_id}/gallery`.

- `messaging_gallery_requests_total{type,outcome}`
  - Request rate + error/disabled outcomes.
  - `type`: `image|video|file|link|unknown`
  - `outcome`: `success|disabled|invalid_type|http_403|http_422|http_5xx...`
- `messaging_gallery_latency_seconds{type}`
  - End-to-end endpoint latency histogram.
- `messaging_gallery_cursor_page_depth{type}`
  - Cursor depth histogram (0 for first page, 1 for cursor-based follow-up page) to track pagination depth/cost trends.

---

## Dashboard panels

### 1) Gallery request rate by type

```promql
sum by (type) (rate(messaging_gallery_requests_total[5m]))
```

### 2) Gallery error rate (excluding expected disabled)

```promql
sum(rate(messaging_gallery_requests_total{outcome!="success",outcome!="disabled"}[10m]))
/
clamp_min(sum(rate(messaging_gallery_requests_total[10m])), 1)
```

### 3) p95 latency by gallery type

```promql
histogram_quantile(
  0.95,
  sum by (le, type) (rate(messaging_gallery_latency_seconds_bucket[5m]))
)
```

### 4) Cursor depth distribution (cost proxy)

```promql
histogram_quantile(
  0.95,
  sum by (le, type) (rate(messaging_gallery_cursor_page_depth_bucket[15m]))
)
```

### 5) Disabled traffic monitor

```promql
sum(rate(messaging_gallery_requests_total{outcome="disabled"}[10m]))
```

---

## Alerts

### Alert: Gallery error-rate spike (warning)

```promql
(
  sum(rate(messaging_gallery_requests_total{outcome!="success",outcome!="disabled"}[10m]))
  /
  clamp_min(sum(rate(messaging_gallery_requests_total[10m])), 1)
) > 0.05
```

- For: `15m`
- Severity: `warning`

### Alert: Gallery p95 latency regression (warning)

```promql
histogram_quantile(
  0.95,
  sum by (le) (rate(messaging_gallery_latency_seconds_bucket[10m]))
) > 1.5
```

- For: `15m`
- Severity: `warning`

### Alert: Gallery p95 latency severe (critical)

```promql
histogram_quantile(
  0.95,
  sum by (le) (rate(messaging_gallery_latency_seconds_bucket[10m]))
) > 3
```

- For: `10m`
- Severity: `critical`

---

## Tuning record

Threshold tuning completed for initial rollout.

- Reviewed by: `platform-ops` + `messaging-oncall`
- Date: `2026-02-19`
- Notes:
  - Keep error warning at 5% to catch broad regressions while avoiding noise from transient provider hiccups.
  - Keep latency warning/critical split at 1.5s / 3.0s until post-rollout baseline is re-measured.
  - Revisit thresholds after two weeks of production traffic and tab-level volume analysis.

---

## On-call quick triage

1. Check request rate panel to verify traffic shift vs outage.
2. Check error-rate panel and break down by `outcome` + `type` to isolate failing tab/API behavior.
3. Check p95 latency panel for system-wide vs tab-specific degradation.
4. Check cursor depth panel for unexpected deep pagination (cost/read-amplification indicator).
5. Correlate with deployment timeline and messaging router logs for specific exception patterns.
