# Video Encoding, Watermarking, and DRM Plan

Related implementation tickets: `docs/video-encoding-watermark-drm-implementation-tickets.md`.

## 1) Goals and non-goals

### Goals
- Provide a production-grade pipeline for ingest, transcoding, packaging, watermarking, and DRM using **AWS Elemental MediaLive**.
- Provide a low-cost, open-source local development environment that mirrors production behavior closely enough for feature work and integration tests.
- Standardize outputs for ABR playback (HLS + DASH), player integration, entitlement checks, and key/license lifecycle.
- Support both static watermark overlays and forensic watermark insertion strategy where feasible.

### Non-goals
- Building a proprietary encoder.
- Replacing cloud DRM license providers in production.
- Achieving bit-exact parity between local dev outputs and MediaLive outputs.

---

## 2) Target architecture

### Production (AWS)
1. **Ingest**
   - RTMP/SRT contribution input into MediaLive input.
   - Event metadata arrives via API (asset ID, tenant ID, watermark policy, DRM policy).

2. **Live processing**
   - MediaLive channel generates ABR ladders.
   - MediaLive applies graphic watermark (logo/text) via output overlays where required.
   - Output as CMAF/HLS (and DASH if required) to MediaPackage or S3 origin path.

3. **Packaging and DRM**
   - Use MediaPackage (or equivalent packager) to apply SPEKE-based DRM key exchange.
   - Encrypt outputs for Widevine/FairPlay/PlayReady policies.
   - CDN (CloudFront) in front of origin.

4. **Playback authorization**
   - App backend issues short-lived signed playback URLs and license JWT/claims.
   - Player requests manifest/segments + license from DRM endpoints.

5. **Observability**
   - CloudWatch metrics/alarms for channel health, input loss, output errors, and key errors.

### Local dev (open-source)
1. **Ingest emulator**
   - NGINX-RTMP or SRT listener container for local contribution streams.

2. **Encoding and watermarking**
   - FFmpeg service produces ABR renditions and overlays watermark (`drawtext` or `overlay` filter).

3. **Packaging and serving**
   - Shaka Packager (or GPAC) container creates HLS/DASH outputs.
   - Optional CENC clear-key mode for DRM workflow simulation.
   - NGINX static origin serves manifests and media segments.

4. **License simulation**
   - For development/testing only, use clear-key or a mock license service to exercise client DRM code paths.

5. **Parity approach**
   - Keep a shared pipeline contract (input metadata schema, rendition profile names, manifest path conventions).

---

## 3) Implementation phases

### Phase 0 — Design and contracts (1 week)
- Define pipeline API contract:
  - Input spec: codec, frame rate, resolution, audio layout.
  - Policy spec: watermark mode, DRM profile, retention.
- Define canonical ABR ladders (e.g., 1080p/720p/540p/360p).
- Document playback URL and entitlement model.
- Produce threat model for content and key leakage.

### Phase 1 — Local open-source stack MVP (1–2 weeks)
- Add `docker-compose.video.local.yml` with services:
  - `ingest` (nginx-rtmp or srt-live-server)
  - `transcoder` (ffmpeg)
  - `packager` (shaka-packager)
  - `origin` (nginx)
  - `license-mock` (lightweight API)
- Add sample scripts:
  - `scripts/video/push_sample_stream.sh`
  - `scripts/video/package_vod.sh`
- Produce encrypted (or clear-key) HLS/DASH sample outputs and validate in reference player.

### Phase 2 — Production MediaLive baseline (1–2 weeks)
- Provision IaC modules (Terraform/CloudFormation) for:
  - MediaLive inputs/channels
  - MediaPackage channels/endpoints
  - CloudFront distribution + origin access controls
  - IAM roles and KMS keys
- Create baseline channel templates for core ABR profiles.
- Connect app backend job orchestration to start/stop event channels.

### Phase 3 — Watermark policy support (1 week)
- Static watermark:
  - Define branding assets per tenant/environment.
  - Add watermark placement presets (top-right, bottom-left, opacity, safe margins).
- Dynamic watermark text:
  - Add template variables (`tenant`, `session`, `timestamp`) for local dev FFmpeg overlay.
  - Mirror policy semantics in MediaLive configuration.

### Phase 4 — DRM hardening (1–2 weeks)
- Integrate production DRM provider via SPEKE-compatible key server.
- Enforce per-content keys and key rotation policy.
- Add offline playback policy decisions (if needed).
- Add renewal/revocation handling and failure-path UX.

### Phase 5 — Operations and rollout (1 week)
- Add dashboards and alerts.
- Run load and failover tests (input disconnect, origin latency, key server failure).
- Create runbooks for on-call:
  - channel restart
  - input source failover
  - key server fallback
- Gradual rollout: internal tenants -> pilot -> general availability.

---

## 4) Repository changes proposed

1. `docs/video/` (new)
   - `architecture.md`
   - `drm-policies.md`
   - `watermark-policies.md`
   - `runbook.md`
2. `infra/` additions for AWS MediaLive/MediaPackage/CDN.
3. `scripts/video/` helper scripts for local stream push, packaging, and validation.
4. Local compose file dedicated to video stack to keep current app compose lean.

---

## 5) Suggested local toolchain

- **FFmpeg**: transcode + watermark overlay.
- **Shaka Packager**: DASH/HLS generation + CENC packaging.
- **NGINX / NGINX-RTMP**: ingest + origin.
- **MinIO (optional)**: local object storage parity with S3 flows.
- **Reference player**: Shaka Player or Video.js for quick playback validation.

---

## 6) Compatibility and player requirements

- H.264/AAC baseline for broad compatibility; consider HEVC/AV1 as opt-in.
- CMAF segments preferred to reduce packaging divergence.
- DRM support matrix:
  - Chrome/Android: Widevine
  - Safari/iOS/tvOS: FairPlay
  - Edge/Windows TV ecosystems: PlayReady
- Ensure CORS and HTTPS constraints are matched between local and prod for license calls.

---

## 7) Security model

- No long-lived media URLs; use signed short-lived tokens.
- Separate content encryption keys by asset or channel.
- Use KMS/HSM-backed key custody in production.
- Mask secrets in logs and disable verbose DRM logging in production.
- Gate admin pipeline actions with RBAC and audit trails.

---

## 8) Testing strategy

### Local CI checks
- Verify manifest generation for HLS and DASH.
- Validate segment continuity and bitrate ladder presence.
- Validate watermark visibility with simple frame snapshot checks.
- Validate mock license flow and player startup path.

### Pre-production checks
- MediaLive input failover test.
- DRM license outage behavior test.
- CDN cache/key rotation propagation test.
- Player startup latency and rebuffering baseline.

---

## 9) Risks and mitigations

- **Risk:** Local stack diverges from MediaLive behavior.
  - **Mitigation:** define strict pipeline contracts and acceptance tests shared by both environments.
- **Risk:** DRM integration complexity and vendor lock-in.
  - **Mitigation:** isolate DRM adapter behind internal service interface.
- **Risk:** Watermark requirements evolve (forensic vs visible).
  - **Mitigation:** separate watermark policy layer from encoding profile definitions.

---

## 10) First sprint backlog (actionable)

1. Draft pipeline contract schema (`asset`, `renditions`, `watermark`, `drm`).
2. Stand up local compose stack with FFmpeg + Shaka Packager + NGINX.
3. Add one end-to-end sample stream -> packaged output -> browser playback.
4. Add watermark policy config and one dynamic watermark example.
5. Scaffold AWS IaC for MediaLive + MediaPackage in non-prod account.
6. Add observability baseline dashboards and health alarms.

This gives a practical path: fast local iteration on open-source tooling, while production uses AWS MediaLive and managed packaging/DRM capabilities.
