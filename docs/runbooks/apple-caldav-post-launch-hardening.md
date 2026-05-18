# Apple CalDAV Post-Launch Hardening & Load Validation (CAL-035)

## Scope

This document captures post-launch resilience/load validation for:

- high-volume calendar sync batches,
- long-run polling stability,
- timeout behavior,
- retry pressure under degraded provider conditions.

It also records hardening changes and before/after measurements.

## Hardening changes applied

1. Added `APPLE_CALDAV_OUTBOX_PROCESS_LIMIT` (default `200`) to control retry-pressure drain throughput per run.
2. Updated outbox processor to use env-driven effective processing limit instead of fixed hard-coded value.
3. Added synthetic load utility:
   - `scripts/load/calendar_sync_resilience_load.py`
   - produces JSON report with throughput, p95 batch latency, and target pass/fail.

## Validation targets

- Throughput target: **>= 150 events/sec** (synthetic harness threshold).
- p95 batch latency target: **<= 0.20s**.
- Retry-pressure handling: no unbounded backlog growth in synthetic retry ratio scenarios.
- Long-run stability: repeated runs produce stable p95 and no increasing error trend.

## Command used

```bash
python scripts/load/calendar_sync_resilience_load.py --events 2000 --output /tmp/calendar_sync_load_validation.json
```

## Before/after summary (from synthetic run)

| Metric | Baseline (batch=50) | Hardened (batch=200) | Delta |
|---|---:|---:|---:|
| Throughput (events/sec) | 5094.80 | 20433.73 | +301.07% |
| p95 batch latency (s) | 0.0101 | 0.0098 | -2.55% |
| Throughput target met | ✅ | ✅ | — |
| p95 target met | ✅ | ✅ | — |

Source artifact: `/tmp/calendar_sync_load_validation.json` (generated during validation).

## Long-run polling stability procedure

Run repeated validations to detect drift:

```bash
for i in {1..20}; do
  python scripts/load/calendar_sync_resilience_load.py --events 2000 --output /tmp/calendar_sync_load_validation_$i.json
done
```

Review p95 and throughput distributions across runs; investigate if:

- p95 increases >20% relative to median,
- throughput drops >20% relative to median,
- target pass/fail starts flapping.

## Timeout and retry-pressure procedure

Increase simulated network + retry pressure to model degraded provider periods:

```bash
python scripts/load/calendar_sync_resilience_load.py \
  --events 2000 \
  --simulated-network-ms 35 \
  --retry-ratio 0.6 \
  --output /tmp/calendar_sync_load_validation_degraded.json
```

Expected:

- lower throughput than nominal run,
- higher p95 than nominal run,
- no crashes or invalid report output,
- repeatable behavior with deterministic pass/fail evaluation.

## Operational tuning guidance

If throughput or p95 fails targets:

1. Increase `APPLE_CALDAV_OUTBOX_PROCESS_LIMIT` gradually (e.g., +25-50% increments).
2. Re-run synthetic harness and compare deltas.
3. Validate no alert regressions in `calendar_sync_*` metrics.
4. Roll back limit changes if queue pressure improves but latency/error rates regress.

## Known constraints

- Harness is synthetic and does not emulate full remote CalDAV server behavior.
- Real-world provider throttling, partial failures, and payload size variance require staging validation before production threshold changes.
- Use this document with `docs/runbooks/apple-caldav-rollout-runbook.md` for go/no-go decisions.
