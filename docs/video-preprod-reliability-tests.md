# Video pre-production reliability tests (VWD-020)

This document defines the pre-production failure scenarios, expected behavior, baseline metrics, and release gate thresholds.

## Scenarios

### 1) Input failover
- **Trigger:** Primary ingest input loss (encoder/process/network kill).
- **Expected behavior:** Pipeline fails over to backup input; playback resumes without sustained outage.
- **Recovery objective:** `recover_ms <= 15000`.
- **Quality guardrails:**
  - `max_rebuffer_ms <= 4000`
  - `dropped_segments <= 3`

### 2) DRM key/license outage
- **Trigger:** Simulated key service outage / license provider 5xx burst.
- **Expected behavior:** Controlled degradation while preserving session continuity where possible; no prolonged hard-fail loops.
- **Recovery objective:** `recover_ms <= 20000`.
- **Guardrails:**
  - `license_5xx_rate <= 0.05`
  - `stale_key_serve_seconds <= 120`

### 3) CDN behavior under origin stress
- **Trigger:** Origin error burst + cache pressure.
- **Expected behavior:** Edge cache absorbs transient origin instability; manifests/segments recover within threshold.
- **Recovery objective:** `recover_ms <= 30000`.
- **Guardrails:**
  - `origin_5xx_rate <= 0.02`
  - `edge_hit_ratio >= 0.85`
  - `manifest_stale_seconds <= 30`

## Baseline metrics template

Create a JSON report with this structure (example values shown):

```json
{
  "input_failover": {
    "recover_ms": 8200,
    "max_rebuffer_ms": 1500,
    "dropped_segments": 1
  },
  "key_outage": {
    "recover_ms": 12600,
    "license_5xx_rate": 0.031,
    "stale_key_serve_seconds": 40
  },
  "cdn_behavior": {
    "recover_ms": 14500,
    "origin_5xx_rate": 0.009,
    "edge_hit_ratio": 0.91,
    "manifest_stale_seconds": 12
  }
}
```

## Execution

```bash
./scripts/video/preprod_reliability_checks.sh /path/to/reliability_report.json
```

Exit codes:
- `0`: all thresholds passed
- `1`: one or more scenario thresholds failed
- `2`: malformed or missing input report
