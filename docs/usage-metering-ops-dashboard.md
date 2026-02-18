# Usage Metering Ops Dashboard & Alerts (OPS-001)

This runbook defines operational metrics, dashboard panels, and alert thresholds for the new messaging/newsfeed usage dimensions.

## Metrics published

The metering pipeline now emits period-aware counters for ops segmentation and anomaly detection:

- `usage_metering_events_by_period_total{event_type,source,outcome,period_id}`
- `usage_metering_bytes_by_period_total{event_type,source,period_id}`
- `usage_surface_units_total{source_family,dimension,period_id}`
- `usage_surface_transfer_bytes_total{source_family,direction,period_id}`

These are emitted alongside existing metering counters/histograms.

## Source family mapping

- `filemanager`: all non-messaging/newsfeed metering sources.
- `messaging`: `messaging_*` sources and `messaging_send`.
- `newsfeed`: `newsfeed_*` sources and `newsfeed_post`.

## Dashboard panels

Recommended dashboard sections (period-aware):

1. **Metering event health**
   - Applied vs duplicate vs error (`usage_metering_events_by_period_total`) by `source` and `period_id`.
2. **Transfer volume by surface**
   - Upload/download bytes (`usage_surface_transfer_bytes_total`) split by `source_family` and `direction`.
3. **Unit usage by surface**
   - Message sends / post publishes (`usage_surface_units_total`) split by `source_family`.
4. **Pipeline reliability**
   - Existing `usage_metering_pipeline_errors_total` and `usage_metering_pipeline_duration_seconds`.

## Alerts

Define at least the following threshold alerts:

1. **Metering error spike**
   - Trigger when `usage_metering_events_by_period_total{outcome="error"}` rate exceeds baseline by >3x for 10m.
2. **Messaging transfer spike**
   - Trigger when `usage_surface_transfer_bytes_total{source_family="messaging",direction="upload"}` 15m rate exceeds weekly p95 by >2x.
3. **Newsfeed transfer spike**
   - Trigger when `usage_surface_transfer_bytes_total{source_family="newsfeed",direction="download"}` 15m rate exceeds weekly p95 by >2x.
4. **Unexpected unit surge**
   - Trigger when `usage_surface_units_total{dimension="message_send"}` or `usage_surface_units_total{dimension="post_publish"}` 30m rate exceeds expected growth envelope.

## Period filtering

All new ops counters include `period_id` (`YYYY-MM`) so dashboards can be filtered for current and historical billing periods directly.
