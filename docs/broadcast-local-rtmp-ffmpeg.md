# BRD-010/012 Local RTMP + ffmpeg + MinIO + Cache Proxy Pipeline

This stack provides local ingest + processing for broadcast development.

## Services
- `rtmp` (`alfg/nginx-rtmp`)
  - Ingest endpoint: `rtmp://localhost:1935/live/<stream_key>`
  - Health/stat endpoint: `http://localhost:8088/healthz` and `http://localhost:8088/stat`
- `ffmpeg-worker` (`jrottenberg/ffmpeg`)
  - Reads RTMP input from nginx-rtmp.
  - Produces ABR HLS renditions and applies watermark overlay.
  - Auto-restarts processing loop so pipeline recovers after restarts without manual intervention.
- `hls-origin` (`nginx`)
  - Serves generated HLS outputs at `http://localhost:8089/hls/<stream_key>/master.m3u8`
- `cache-proxy` (`nginx`)
  - CloudFront-like local cache in front of origin.
  - Verifies signed query token (`md5` + `expires`) before serving playback.
  - Playback base URL: `http://localhost:8090/hls/<stream_key>/master.m3u8?...`
- `minio` + `minio-init`
  - Local S3-compatible archive store.
  - Bucket defaults to `broadcast-archive`.
- `archive-sync` (`minio/mc`)
  - Mirrors local archive output from ffmpeg worker into MinIO under session prefix.

## Run
```bash
docker compose -f docker-compose.broadcast-local.yml up -d
```

## OBS publish target
- URL: `rtmp://localhost:1935/live`
- Stream key: `devstream` (or `BROADCAST_STREAM_KEY` override)

## Verify output
- Origin playback (unsigned): `http://localhost:8089/hls/devstream/master.m3u8`
- Rendition playlists:
  - `/hls/devstream/v0.m3u8`
  - `/hls/devstream/v1.m3u8`
  - `/hls/devstream/v2.m3u8`

## Verify signed playback through cache proxy
1. Mint playback URL from API (requires authenticated app session):
   - `POST /broadcast/sessions/{session_id}/playback-url`
2. Open returned `playback_url` (host defaults to `http://localhost:8090`).
3. Cache behavior:
   - Response headers include `X-Cache-Status` (`MISS`, then `HIT` on repeat).
   - `cache-proxy` access logs emit `cache=<status>`.

## Verify MinIO archive persistence
- MinIO API: `http://localhost:9000`
- MinIO Console: `http://localhost:9001`
- Default credentials: `minioadmin / minioadmin`
- Objects are mirrored to:
  - `s3://broadcast-archive/sessions/<stream_key>/...`

## BRD-016 archive policy automation
- Helper script: `scripts/check_broadcast_archive_policy.py`
- Script behavior:
  - applies lifecycle retention policy tagged as `retention=broadcast`
  - validates bucket policy includes archive write permissions (`s3:PutObject`)
- Session API exposure:
  - `GET /broadcast/sessions/{session_id}` includes `s3_archive_prefix` in output metadata.

## BRD-017 CloudFront playback auth model
- Session API returns CloudFront-style playback URL:
  - `GET /broadcast/sessions/{session_id}` -> `cloudfront_playback_url`
- Signed URL model:
  - playback URL query params include `cf_token` and `cf_expires`
  - validation endpoint: `GET /broadcast/playback/verify?path=...&cf_token=...&cf_expires=...`
- Security/cache defaults are captured in provider snapshot metadata:
  - `cache_policy_id`
  - `response_headers_policy_id`
  - optional WAF ACL + geo allowlist attachment points

## BRD-018 health polling + drift detection
- Reconciler worker:
  - startup task: `start_broadcast_reconciler_task`
  - polling interval via `BROADCAST_RECONCILER_INTERVAL_SECONDS` (default 30s)
- Drift rules:
  - compares desired session status vs provider `status()` response
  - if mismatch persists longer than `BROADCAST_DRIFT_SLA_SECONDS`, session is transitioned to `error`
- Stale-session recovery:
  - sessions stuck in `provisioning`/`stopping` longer than `BROADCAST_STALE_SESSION_SECONDS` are transitioned to `error`
- Reconciler writes flags into `provider_state_snapshot`:
  - `last_reconciled_at`, `desired_state`, `actual_state`, `drift_detected`, `stale_detected`

## BRD-019 metrics, dashboards, and alerting
- Metrics emitted with provider dimension (`local|aws`):
  - `broadcast_provision_latency_seconds`
  - `broadcast_session_actions_total` (`action=start|stop`, `result=success|failure`)
  - `broadcast_input_loss_total`
  - `broadcast_output_errors_total`
  - `broadcast_drift_incidents_total`
- Dashboard template:
  - `docs/dashboards/broadcast-health-dashboard.json`
- Alert thresholds/routing:
  - `docs/alerts/broadcast-health-alerts.yml`
  - rules route to `nonprod-oncall` for smoke verification in non-prod.

## BRD-020 incident runbooks
- On-call incident runbook:
  - `docs/broadcast-live-incident-runbook.md`
- Postmortem template:
  - `docs/templates/broadcast-postmortem-template.md`
- Includes:
  - class-specific triage and mitigation/rollback steps (ingest failure, no playback, DRM key issues, watermark issues)
  - escalation matrix and universal triage checklist
  - prevention action tracking structure for postmortems

## BRD-021 contract/integration test suite
- API contract tests:
  - `tests/contract/test_broadcast_api_contract.py`
  - snapshot fixture: `tests/fixtures/broadcast_api_contract_snapshot.json`
- Shared provider contract tests:
  - `tests/contract/test_broadcast_provider_contract_shared.py`
- CI workflow gate:
  - `.github/workflows/broadcast-contract-tests.yml`
  - PRs touching broadcast contracts/providers fail fast on breaking API/provider changes.

## BRD-022 end-to-end local pipeline harness
- E2E harness script:
  - `scripts/e2e/broadcast_local_e2e.py`
- Synthetic media/expected markers:
  - `assets/broadcast-synthetic/expected-output-markers.txt`
- Assertions performed:
  - starts local stack
  - pushes synthetic RTMP input
  - validates watermark signal in generated segment
  - checks encrypted HLS marker (`#EXT-X-KEY`)
  - verifies archive output files exist
- Artifacts/logs:
  - `tmp/broadcast-e2e-artifacts/report.json`
  - copied playlist/raw analysis files in same folder for triage
- Optional nightly/manual CI workflow:
  - `.github/workflows/broadcast-local-e2e-nightly.yml`

## BRD-013 local debug/ops page
- UI page: `http://localhost:8000/broadcast-devtools`
- API status endpoint: `GET /internal/broadcast-dev/status`
- Guard rails:
  - available only when `DEV_MODE=1` and `BROADCAST_DEVTOOLS_ENABLED=1`
  - requires authenticated UI session with `admin` or `root` role
- Polling cadence: every 5s from page JavaScript.
- Shows:
  - ingest health status (`rtmp` health endpoint)
  - signed manifest URL
  - discovered stream keys under local HLS root
  - transcoder log tail (`tmp/broadcast-logs/ffmpeg-worker.log`)
  - archive object list (`tmp/broadcast-archive/**`)

## Watermark scaling rules
The ffmpeg filter graph uses:
- `scale='min(220,iw*110)':-1` on watermark asset
- `overlay=W-w-24:H-h-24` placement (bottom-right with 24px margins)

This keeps watermark sizing bounded and consistent across 1080p/720p/480p outputs.

## Stream key to output mapping
- Ingest key: `<stream_key>` from `rtmp://localhost:1935/live/<stream_key>`
- Output directory: `./tmp/broadcast-hls/<stream_key>/`

## Restart behavior
`ffmpeg-worker` runs a retry loop that:
1. starts transcode when input is available,
2. restarts automatically on process exit,
3. avoids manual repair after container restarts.
