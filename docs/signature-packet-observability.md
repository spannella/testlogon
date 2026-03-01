# Signature Packet Observability (SFP-062)

## Metrics

### Lifecycle funnel
- `signature_packet_events_total{event_type=*}`
  - Produced from append-only packet events.
  - Funnel checkpoints:
    - `packet_created`
    - `packet_sent`
    - `signer_completed`
    - `packet_completed`
    - `packet_finalized`

### Render reliability and latency
- `signature_packet_render_jobs_total{outcome,reason}`
  - success/failure job outcomes and failure reason split.
- `signature_packet_render_duration_seconds{outcome}`
  - render latency histogram for success + failure paths.

## Dashboard
- File: `docs/dashboards/signature-packet-ops-dashboard.json`
- Grafana UID: `signature-packet-ops`
- Panels:
  - lifecycle funnel by event type
  - render failures by reason
  - render p95 latency
  - stuck packet proxy trend (24h)

### Availability in target environments
- The dashboard JSON is committed to repo and should be imported by monitoring bootstrap in each target environment.
- Recommended folder mapping in Grafana: `Ops / Signature Packets`.

## Alerts

### Paging alerts (P1)
1. **Render failures spike**
   - Expr: `sum(rate(signature_packet_render_jobs_total{outcome="failed"}[10m])) > 0`
   - For: `15m`
2. **Render latency regression**
   - Expr: `histogram_quantile(0.95, sum by (le) (rate(signature_packet_render_duration_seconds_bucket{outcome="success"}[10m]))) > 30`
   - For: `15m`

### Ticket alerts (non-paging)
1. **Stuck packet proxy sustained**
   - Expr: `clamp_min(sum(increase(signature_packet_events_total{event_type=~"packet_sent|signer_completed"}[24h])) - sum(increase(signature_packet_events_total{event_type="packet_completed"}[24h])), 0) > 25`
   - For: `60m`
2. **Finalize failure reason drift**
   - Expr: top failure reason rate > baseline for 2h.

## Ownership and escalation
- **Primary owner**: Backend Signatures team (`#team-signatures-oncall`).
- **Secondary owner**: Platform Reliability (`#team-platform-reliability`).
- **Escalation path**:
  1. Page primary on-call.
  2. If unresolved for 30 minutes, escalate to Platform Reliability manager on-call.
  3. If customer-impacting and unresolved for 60 minutes, declare SEV incident and engage Incident Commander.

## Support/debug workflow
1. Query `GET /v1/signature-packets/{packet_id}/events`.
2. Validate event chronology (`created_at`) and actor transitions.
3. Correlate with render metrics (`*_render_jobs_total`, `*_render_duration_seconds`) for failures/latency.
