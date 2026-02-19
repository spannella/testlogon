# Media Preview Alerting Runbook (MP-052)

## Dashboard
- Primary dashboard: `docs/dashboards/media-preview-ops-dashboard.json`.
- Ops review status: **reviewed with ops** for v1 thresholds below.

## Alert Rules (recommended)

### 1) Sustained preview generation failure
- **Signal:** `filemgr_preview_jobs_total{outcome=~"failed|dead_letter"}`
- **Expr:**
  - `sum(rate(filemgr_preview_jobs_total{outcome=~"failed|dead_letter"}[10m])) / clamp_min(sum(rate(filemgr_preview_jobs_total[10m])), 1) > 0.20`
- **For:** `15m`
- **Severity:** `critical`
- **Action:**
  1. Inspect `filemgr_preview_job_failed` logs for `preview_reason` spikes.
  2. Verify ffmpeg/ffprobe availability and worker runtime limits.
  3. Check storage write failures and signed/CDN URL policy.

### 2) Preview backlog saturation
- **Signal:** `filemgr_preview_queue_depth`
- **Expr:** `sum(filemgr_preview_queue_depth) > 250`
- **For:** `20m`
- **Severity:** `warning`
- **Action:**
  1. Scale preview worker concurrency.
  2. Check dead-letter and retry rates in `filemgr_preview_jobs_total`.
  3. Validate upload throughput and storage latency.

### 3) Hover playback failure spike
- **Signal:** `filemgr_preview_hover_play_failures_total`
- **Expr:**
  - `sum(rate(filemgr_preview_hover_play_failures_total[10m])) / clamp_min(sum(rate(filemgr_preview_hover_play_starts_total[10m])), 1) > 0.05`
- **For:** `15m`
- **Severity:** `warning`
- **Action:**
  1. Break down by `reason` label.
  2. Validate hover clip URL delivery and MIME correctness.
  3. Confirm client autoplay/reduced-motion behavior and browser compatibility.

## Label cardinality guardrails
- Only use bounded enum labels: `media_type`, `artifact`, `outcome`, `reason`.
- Do **not** add per-user, path, file-id, or job-id labels.
