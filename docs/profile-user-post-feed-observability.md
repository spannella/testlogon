# Profile Feed Observability (PUF-301)

This document captures metrics/log fields added for profile-mode feed requests on `GET /feed`.

## Metrics

All metrics are emitted with `mode` label (`profile` when `author_id` is present, otherwise `global`).

- `newsfeed_feed_requests_total{mode,outcome}`
  - request volume and success/error rates.
- `newsfeed_feed_latency_seconds{mode,outcome}`
  - end-to-end route latency.
- `newsfeed_feed_errors_total{mode,error_type}`
  - error reasons (`validation`, `http_###`, `unhandled`).
- `newsfeed_feed_filter_usage_total{mode,filter_name}`
  - observed filter usage (`q`, `from`, `to`, `has_media`).
- `newsfeed_feed_page_depth{mode}`
  - number of DDB pages scanned to fulfill each request.

## Structured logs

`app.routers.newsfeed` emits `event=newsfeed_feed_query` records with:

- `mode`, `viewer_id`, `author_id`
- `limit`, `cursor_present`, `page_depth`, `item_count`, `has_next_cursor`
- sanitized query metadata under `query`:
  - `has_q`, `q_length`, `has_from`, `has_to`, `has_media`
- `outcome` and `error_type` for failures

## Suggested dashboard panels

If your environment has dashboards, add:

1. **Profile feed throughput**
   - `sum(rate(newsfeed_feed_requests_total{mode="profile"}[5m]))`
2. **Profile feed p95 latency**
   - `histogram_quantile(0.95, sum(rate(newsfeed_feed_latency_seconds_bucket{mode="profile",outcome="success"}[5m])) by (le))`
3. **Profile feed error rate by error_type**
   - `sum(rate(newsfeed_feed_errors_total{mode="profile"}[5m])) by (error_type)`
4. **Profile filter usage breakdown**
   - `sum(rate(newsfeed_feed_filter_usage_total{mode="profile"}[15m])) by (filter_name)`
5. **Profile pagination depth p95**
   - `histogram_quantile(0.95, sum(rate(newsfeed_feed_page_depth_bucket{mode="profile"}[15m])) by (le))`
