# Jira Sync Observability Dashboards & Alerts

## Objective

Define production observability for Jira sync pipeline across:

- webhook ingestion throughput/replay/auth health,
- mirror freshness and latency,
- outbound + inbound sync success/failure rates,
- conflict rate and backlog,
- queue depth/age and worker saturation.

This document also defines default alert thresholds aligned to an SLO/error-budget model.

---

## SLO / Error Budget Baseline

### Service Level Objectives (monthly)

- **Sync processing availability SLO**: 99.5%
  - Budget: 0.5% failed terminal sync operations (inbound + outbound combined).
- **Webhook acceptance SLO**: 99.9%
  - Budget: 0.1% non-auth, non-replay webhook failures.
- **Freshness SLO** (mirror/inbound):
  - P95 mirror lag < 10m
  - P99 mirror lag < 30m

### Error budget burn guidance

- **Fast-burn page**: projected exhaustion in < 24h
- **Slow-burn ticket**: projected exhaustion in < 7d

---

## Required Metrics

> Metric names below map to existing counters/histograms where possible and define new ones where needed.

### Webhook

- `jira_webhook_requests_total{event_type, workspace_id, result}`
- `jira_webhook_auth_failures_total{workspace_id, reason}`
- `jira_webhook_replay_deduplicated_total{workspace_id}`
- `jira_webhook_enqueue_failures_total{workspace_id}`
- `jira_webhook_processing_latency_seconds{workspace_id}` (histogram)

### Outbound / Inbound sync

- `jira_sync_events_total{direction, result, workspace_id, error_code}`
- `jira_sync_latency_seconds{direction, workspace_id}` (histogram)
- `jira_sync_terminal_failures_total{direction, workspace_id, error_code}`
- `jira_sync_retryable_failures_total{direction, workspace_id, error_code}`
- `jira_conflicts_detected_total{workspace_id}`
- `jira_conflicts_resolved_total{workspace_id, action}`
- `jira_conflicts_open_gauge{workspace_id}`

### Queue / worker

- `jira_queue_depth{queue, workspace_id}`
- `jira_queue_oldest_age_seconds{queue, workspace_id}`
- `jira_worker_process_seconds{worker_type}` (histogram)
- `jira_worker_errors_total{worker_type, error_code, workspace_id}`

### Mirror

- `jira_mirror_backfill_progress{workspace_id, project_key}`
- `jira_mirror_incremental_lag_seconds{workspace_id, project_key}`
- `jira_mirror_imported_issues_total{workspace_id, project_key}`

---

## Dashboard Design

## 1) Executive Health Dashboard

Panels:

- Overall success rate (inbound+outbound)
- Webhook acceptance rate
- Open conflict count
- Queue depth (inbound/outbound)
- P95 sync latency

Filters (required drill-down dimensions):

- `workspace_id`
- `direction` (`inbound`, `outbound`, `conflict_resolution`)
- time window

## 2) Webhook Operations Dashboard

Panels:

- Throughput by event type
- Auth failures by reason
- Replay dedup count
- Enqueue failures
- Processing latency distribution

Filters:

- `workspace_id`
- `event_type`

## 3) Sync Reliability Dashboard

Panels:

- Success/retryable/terminal outcomes by direction
- Top error codes
- Retry volume trend
- Sync latency P50/P95/P99
- Failed operations by workspace

Filters:

- `workspace_id`
- `direction`
- `error_code`

## 4) Conflict Management Dashboard

Panels:

- New conflicts per hour
- Open conflict backlog
- Resolution actions (`keep_internal` vs `keep_jira`)
- Time-to-resolution percentile

Filters:

- `workspace_id`
- `action`

## 5) Queue + Worker Capacity Dashboard

Panels:

- Queue depth over time
- Oldest message age
- Worker processing latency
- Worker errors by code

Filters:

- `queue`
- `workspace_id`
- `worker_type`

---

## Alert Rules (Default Thresholds)

## P1 (Paging)

1. **Webhook auth failure spike**
   - Condition: auth failures > 5% of webhook requests for 10m (workspace-level or global).
2. **Queue stuck**
   - Condition: queue oldest age > 900s for 10m.
3. **Terminal sync failure spike**
   - Condition: terminal failure rate > 2% for 15m.
4. **Error budget fast burn**
   - Condition: 2h burn rate > 14x budget.

## P2 (Paging/High-priority ticket depending hours)

1. **Conflict spike**
   - Condition: conflicts detected > 3x 7-day baseline for 30m.
2. **Mirror lag breach**
   - Condition: P95 incremental lag > 15m for 30m.
3. **Webhook enqueue failures**
   - Condition: > 1% enqueue failures for 15m.

## P3 (Ticket)

1. **Slow burn**
   - Condition: 24h burn rate > 2x budget.
2. **Backfill stalled**
   - Condition: no backfill progress update for 60m during active backfill.

---

## Alert Routing & Ownership

- Primary owner: Ticketing/Jira integration team.
- Secondary owner: Platform/on-call SRE.
- Routing keys:
  - P1 -> Pager + incident channel
  - P2 -> Pager (business hours) + ticket
  - P3 -> ticket only

---

## Runbook Hooks for Alerts

Each alert should include links to:

1. Jira sync rollout runbook (`docs/jira-sync-rollout-runbook.md`)
2. Relevant dashboard with workspace pre-filter
3. Top failing error-code panel
4. Admin kill-switch endpoint instructions

---

## Validation Checklist Before Enabling Alerts

- [ ] Metrics present in staging and production.
- [ ] Workspace and direction labels populated.
- [ ] Dashboard variables support `workspace_id` and `direction`.
- [ ] Synthetic test verifies each alert path.
- [ ] Alert noise reviewed for at least one pilot week.

---

## Change Management

Any threshold changes must include:

- rationale tied to SLO/error budget,
- before/after false-positive and missed-incident analysis,
- approval from service owner + on-call lead.

