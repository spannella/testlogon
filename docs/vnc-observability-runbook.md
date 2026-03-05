# VNC Observability Runbook (VNC-013)

## Metrics

The VNC backend exports these Prometheus metrics:

- `vnc_session_events_total{action,outcome,target_id,error_code}`
  - `action=start|stop`
  - Tracks session bootstrap and teardown outcomes by target and error code.
- `vnc_session_duration_seconds{target_id,outcome}`
  - Histogram for session active duration.
- `vnc_bridge_failures_total{target_id,error_code}`
  - Counter for bridge connect/setup failures.

### Suggested dashboard panels

1. **Session start success rate (5m)**
   - `sum(rate(vnc_session_events_total{action="start",outcome="success"}[5m])) / sum(rate(vnc_session_events_total{action="start"}[5m]))`
2. **Top start failure reasons by target**
   - `topk(10, sum by (target_id,error_code) (rate(vnc_session_events_total{action="start",outcome="failure"}[15m])))`
3. **Bridge failures by target**
   - `sum by (target_id,error_code) (rate(vnc_bridge_failures_total[15m]))`
4. **Session duration p95**
   - `histogram_quantile(0.95, sum by (le,target_id) (rate(vnc_session_duration_seconds_bucket[15m])))`

### Alerts

- **High bootstrap failure rate**
  - Trigger when start failure ratio is > 20% for 10 minutes.
- **Bridge failure spike**
  - Trigger when `rate(vnc_bridge_failures_total[5m])` exceeds baseline threshold per environment.

## Structured logging fields

VNC API/service logs include these correlation fields:

- `correlation_id`
- `session_id`
- `target_id`
- `user_sub`
- `error_code` (on failure)

Use `correlation_id` + `session_id` to stitch API bootstrap, bridge connect, and teardown events in log search.

## Tracing

The backend emits trace spans (when OpenTelemetry is configured):

- `vnc.api.bootstrap`
- `vnc.bootstrap`
- `vnc.bridge_connect`
- `vnc.api.teardown`

Each span includes VNC-prefixed attributes (e.g., `vnc.session_id`, `vnc.target_id`, `vnc.correlation_id`) for end-to-end tracking.
