# Video Broadcasting Plan (RTMP Ingest → AWS Elemental + DRM + HLS + Recording)

## 1) Goals
- Let creators configure an outbound RTMP stream from the app.
- Send RTMP ingest to AWS Elemental MediaLive.
- Apply watermark overlay in the live pipeline.
- Apply DRM for HLS playback.
- Deliver outputs to:
  - Amazon S3 for durable recording/archive.
  - AWS Elemental MediaPackage for HLS origin packaging.
  - Amazon CloudFront as global CDN in front of MediaPackage.
- Provide a local developer environment with host-local equivalents for every stage.

## 2) Target Architecture (Production)
1. **Control plane (this app)**
   - Adds a “Broadcast Profiles” domain model and APIs.
   - Creates/updates/deletes broadcast sessions and status.
   - Stores stream key references in secure secret storage.

2. **Ingest path**
   - Broadcaster software (OBS, vMix, etc.) pushes RTMP to a per-channel ingest endpoint.
   - Route RTMP into MediaLive input (RTMP_PUSH or Link-compatible equivalent based on account policy).

3. **Live processing (MediaLive)**
   - Video/audio transcoding ladder for adaptive bitrate.
   - Watermark overlay via MediaLive channel settings (static PNG/alpha positioning).
   - SCTE/metadata pass-through if future ad insertion is desired.

4. **Packaging and DRM**
   - MediaLive output to MediaPackage channel.
   - MediaPackage endpoint configured for HLS and DRM (e.g., SPEKE-compatible key provider).
   - Playback clients fetch HLS manifests/segments via CloudFront.

5. **Recording/Archive**
   - Parallel MediaLive output group writes HLS/TS (or CMAF variant as required) to S3.
   - Lifecycle policies move recordings to lower-cost classes and eventual retention expiry.

6. **CDN**
   - CloudFront distribution with MediaPackage origin.
   - Optional origin access controls, token auth, geo restrictions, and WAF.

## 3) App-Level Workstreams

### A. Data model and API
- Add entities:
  - `broadcast_profile` (name, region, rendition preset, watermark asset, drm_policy_id).
  - `broadcast_session` (profile_id, status, ingest_url, stream_key_ref, started_at, stopped_at).
  - `broadcast_output` (session_id, mediapackage_endpoint, cloudfront_playback_url, s3_archive_prefix).
- Add APIs:
  - `POST /broadcast/profiles`
  - `POST /broadcast/sessions`
  - `POST /broadcast/sessions/{id}/start`
  - `POST /broadcast/sessions/{id}/stop`
  - `GET /broadcast/sessions/{id}`
- Add state machine:
  - `draft -> provisioning -> ready -> live -> stopping -> stopped -> error`

### B. AWS orchestration service
- New service layer module to orchestrate:
  - MediaLive input + channel creation (or channel reuse strategy).
  - MediaPackage channel + endpoint configuration.
  - CloudFront distribution binding (or shared distribution path strategy).
  - S3 archive path provisioning and lifecycle tagging.
- Use idempotency keys and persisted correlation IDs.
- Capture AWS ARNs and endpoint URLs in DB.

### C. Secrets and security
- Store stream keys and DRM credentials in AWS Secrets Manager (or SSM Parameter Store with KMS).
- Never persist raw keys in app DB logs.
- IAM least-privilege roles for MediaLive/MediaPackage/S3/CloudFront operations.
- Add audit logs for create/start/stop/delete actions.

### D. Observability
- Capture health/status from AWS APIs on a polling cadence (or event-driven if EventBridge used).
- Metrics:
  - Time to provision, session uptime, start failure rates.
  - Input loss alarms, output errors, drift between desired and actual state.
- Alerts via CloudWatch alarms + app-level incident surfacing.

## 4) DRM Design
- Integrate MediaPackage DRM using SPEKE key provider.
- Support at least one DRM scheme initially (FairPlay/Widevine/PlayReady selection based on client matrix).
- Issue playback authorization tokens (JWT or signed cookies) and enforce at CloudFront.
- Define key rotation interval and document player compatibility constraints.

## 5) Watermark Strategy
- Start with static channel watermark image per profile.
- Define safe-area presets and output-resolution aware scaling.
- Future phase: dynamic watermark text/ID burn-in (would require a more advanced processing tier).

## 6) Dev Environment (Host-Local Equivalents)

### Objectives
- No AWS dependency for day-to-day feature development.
- Local stack mimics control-plane contracts and happy-path lifecycle.

### Local components
1. **RTMP ingest**
   - Use local `nginx-rtmp` (or SRS) container for RTMP server.
   - OBS pushes to `rtmp://localhost:1935/live/<stream_key>`.

2. **Transcode + watermark**
   - Use `ffmpeg` worker container reading RTMP and producing ABR HLS outputs.
   - Apply watermark overlay filter (`overlay`) from local image assets.

3. **DRM simulation**
   - For local dev, use AES-128 HLS encryption + local mock key server.
   - Keep interface compatible with future SPEKE integration (same control contract, mocked provider).

4. **Package/origin**
   - Serve local HLS output from filesystem-backed origin service (e.g., simple Nginx).
   - Simulate MediaPackage endpoint URLs via a local routing prefix.

5. **Recording sink**
   - Use local MinIO bucket as S3 equivalent.
   - Persist archive renditions under a session-based prefix.

6. **CDN equivalent**
   - Use local reverse proxy cache (Nginx/Varnish) to mimic CloudFront behavior.
   - Enable token check middleware to simulate signed playback access.

7. **Control plane simulation**
   - Add a `BROADCAST_PROVIDER=local|aws` switch.
   - `local` provider spins up pipeline jobs and returns synthetic ARNs/endpoint IDs.

### Local developer UX
- One command boot (`docker compose up`) that starts:
  - rtmp server, transcoder worker, key server mock, origin server, minio, cache proxy.
- Provide seeded example profile + test stream key.
- Add a debug page showing:
  - ingest status, transcoder logs, manifest URL, archive object listing.

## 7) Delivery Phases

### Phase 0 — Discovery/ADR (1 sprint)
- Finalize AWS service limits, quota requests, regions, cost model.
- Decide DRM provider and player support matrix.
- Produce architecture decision record (ADR).

### Phase 1 — Control plane skeleton (1 sprint)
- Add DB tables, APIs, state machine, and local provider stub.
- No real media flow yet; mocked lifecycle only.

### Phase 2 — Local media pipeline (1–2 sprints)
- Implement RTMP ingest + ffmpeg watermark + HLS + MinIO recording.
- Add local tokenized playback and key-server mock.

### Phase 3 — AWS integration MVP (2 sprints)
- Implement MediaLive + MediaPackage provisioning and teardown.
- Add S3 archive output and CloudFront playback URL generation.
- Add operational alarms and error handling.

### Phase 4 — DRM production hardening (1 sprint)
- SPEKE integration, key rotation, client QA matrix validation.
- Security review and incident runbooks.

### Phase 5 — Scale/reliability (ongoing)
- Channel reuse optimization, autoscaling orchestration workers.
- Cost controls, rightsizing renditions, archive lifecycle tuning.

## 8) Risks and Mitigations
- **Provisioning latency**: pre-warm/reuse channels for near-instant go-live.
- **Cost spikes**: enforce max concurrent sessions and idle channel shutdown.
- **DRM playback fragmentation**: maintain explicit device/player compatibility matrix.
- **Watermark quality issues**: test per rendition and define baseline visual QA checks.
- **Local/prod drift**: keep common orchestration interfaces and contract tests.

## 9) Definition of Done (MVP)
- Creator can create/start/stop a broadcast from the app.
- RTMP ingest accepted and visible in status dashboard.
- Live HLS playback available through CloudFront URL.
- Watermark visible on stream.
- DRM-protected playback works on at least target player set.
- Recording objects available in S3 with retention policy tags.
- Local dev stack reproduces end-to-end flow without AWS access.
