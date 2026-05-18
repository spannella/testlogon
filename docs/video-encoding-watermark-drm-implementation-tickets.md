# Video Encoding, Watermarking, and DRM — Implementation Tickets

This ticket set maps to `docs/VIDEO_ENCODING_WATERMARK_DRM_PLAN.md` and is sequenced to deliver local developer velocity first, then production hardening and rollout.

---

## Epic A — Contracts, architecture baseline, and policy definitions

### VWD-001 — Finalize pipeline contract schema (asset/renditions/watermark/drm)
- **Status:** ✅ Implemented (2026-03-24)
- **Type:** Backend / Platform
- **Priority:** P0
- **Size:** M
- **Description:** Define canonical request/event schema for ingest jobs and live channel runs.
- **Deliverables:**
  - JSON schema (or Pydantic/OpenAPI model) for `asset`, `renditions`, `watermark`, `drm`.
  - Validation rules for required fields, supported codecs, and policy enums.
  - Versioning strategy (`contract_version`) and backward compatibility notes.
- **Acceptance criteria:**
  - Contract stored in repo and referenced by app/backend services.
  - Invalid payloads fail fast with deterministic error messages.
  - Contract examples exist for local-dev and production workflows.
- **Dependencies:** None.

### VWD-002 — Define canonical ABR ladder profiles and naming
- **Status:** ✅ Implemented (2026-03-24)
- **Type:** Video Platform
- **Priority:** P0
- **Size:** S
- **Description:** Standardize rendition ladder profiles and naming to keep local/prod outputs aligned.
- **Deliverables:**
  - Baseline ladder profile (1080p/720p/540p/360p) with bitrate and GOP settings.
  - Naming convention for variants, manifests, and output path prefixes.
- **Acceptance criteria:**
  - Ladder profiles approved and documented.
  - Same profile names used in local scripts and AWS templates.
- **Dependencies:** VWD-001.

### VWD-003 — Author watermark policy spec (static + dynamic)
- **Status:** ✅ Implemented (2026-03-24)
- **Type:** Product / Security / Video Platform
- **Priority:** P0
- **Size:** S
- **Description:** Define watermark policy model and rendering constraints.
- **Deliverables:**
  - Policy fields for mode, placement, opacity, margins, and template vars.
  - Tenant-specific asset policy for logos and fallback behavior.
- **Acceptance criteria:**
  - Policy supports static logo + dynamic text scenarios.
  - Policy is consumable by local FFmpeg workflow and MediaLive config.
- **Dependencies:** VWD-001.

### VWD-004 — Author DRM policy spec and entitlement contract
- **Status:** ✅ Implemented (2026-03-25)
- **Type:** Security / Backend
- **Priority:** P0
- **Size:** M
- **Description:** Define DRM profiles and playback entitlement payload contract.
- **Deliverables:**
  - DRM profile matrix for Widevine/FairPlay/PlayReady.
  - Entitlement token claim spec (asset, tenant, ttl, device/session fields).
  - Key rotation and per-content-key policy.
- **Acceptance criteria:**
  - Profile policy is documented and testable.
  - License request/response contract is defined for player integration.
- **Dependencies:** VWD-001.

---

## Epic B — Local open-source dev stack MVP

### VWD-005 — Add `docker-compose.video.local.yml` for ingest/transcode/package/origin
- **Status:** ✅ Implemented (2026-03-25)
- **Type:** DevEx / Infra
- **Priority:** P0
- **Size:** M
- **Description:** Create local stack to run end-to-end video workflows without AWS.
- **Deliverables:**
  - Compose services: `ingest`, `transcoder`, `packager`, `origin`, `license-mock`.
  - Internal network + mounted volumes for media artifacts and configs.
  - Healthchecks and startup docs.
- **Acceptance criteria:**
  - `docker compose -f docker-compose.video.local.yml up` boots all services.
  - Origin serves manifests/segments from generated outputs.
- **Dependencies:** VWD-001, VWD-002.

### VWD-006 — Implement local ingest emulator (RTMP/SRT)
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** Video Platform
- **Priority:** P0
- **Size:** M
- **Description:** Provide contribution input endpoint and stream routing for local tests.
- **Deliverables:**
  - NGINX-RTMP or SRT service config.
  - Route from ingest stream key to transcoder input.
- **Acceptance criteria:**
  - Sample stream can be pushed and accepted reliably.
  - Input loss/reconnect behavior is documented.
- **Dependencies:** VWD-005.

### VWD-007 — Implement FFmpeg ABR transcoding pipeline with watermark overlay
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** Video Platform
- **Priority:** P0
- **Size:** L
- **Description:** Create reproducible transcoding job for ladder outputs and watermark application.
- **Deliverables:**
  - FFmpeg profile scripts/config for ABR outputs.
  - Watermark filters (`overlay`/`drawtext`) mapped to policy contract.
- **Acceptance criteria:**
  - Generated outputs include all expected renditions.
  - Watermark appears at expected placement/opacity for configured policy.
- **Dependencies:** VWD-002, VWD-003, VWD-006.

### VWD-008 — Implement local packaging for HLS + DASH (CMAF)
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** Video Platform
- **Priority:** P0
- **Size:** M
- **Description:** Package transcoded outputs into playback-ready manifests/segments.
- **Deliverables:**
  - Shaka Packager (or GPAC) config for HLS + DASH.
  - Manifest path conventions matching contract.
- **Acceptance criteria:**
  - Both HLS and DASH manifests generate successfully.
  - Variants align with canonical ladder names and metadata.
- **Dependencies:** VWD-007.

### VWD-009 — Add local clear-key/mock-license flow for DRM path testing
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** Security / DevEx
- **Priority:** P1
- **Size:** M
- **Description:** Simulate DRM handshake locally to validate player and entitlement paths.
- **Deliverables:**
  - Mock license service or clear-key mode support.
  - Sample entitlement token generation for local playback.
- **Acceptance criteria:**
  - Player can request license and start protected playback in local env.
  - Failure paths (expired/invalid token) are testable.
- **Dependencies:** VWD-004, VWD-005, VWD-008.

### VWD-010 — Add helper scripts for local stream push and packaging workflows
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** DevEx
- **Priority:** P1
- **Size:** S
- **Description:** Provide one-command local demo/test scripts.
- **Deliverables:**
  - `scripts/video/push_sample_stream.sh`
  - `scripts/video/package_vod.sh`
  - Optional `scripts/video/validate_manifests.sh`
- **Acceptance criteria:**
  - New developers can run documented scripts to produce and play sample output.
- **Dependencies:** VWD-006, VWD-007, VWD-008.

---

## Epic C — Production AWS MediaLive/MediaPackage baseline

### VWD-011 — Scaffold IaC for MediaLive inputs and channels
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** Infra / Platform
- **Priority:** P0
- **Size:** L
- **Description:** Provision reusable AWS resources for live ingest and transcoding.
- **Deliverables:**
  - Terraform/CloudFormation modules for MediaLive input + channel templates.
  - IAM roles/policies for MediaLive execution.
- **Acceptance criteria:**
  - Non-prod environment can create/destroy channels reliably via IaC.
  - Channel templates support canonical ABR ladder.
- **Dependencies:** VWD-002.

### VWD-012 — Provision MediaPackage endpoints and SPEKE DRM integration hooks
- **Status:** ✅ Implemented (2026-03-26)
- **Type:** Infra / Security
- **Priority:** P0
- **Size:** L
- **Description:** Add managed packaging and DRM key exchange baseline.
- **Deliverables:**
  - MediaPackage channels/endpoints for HLS/DASH.
  - SPEKE integration settings and key provider config placeholders.
- **Acceptance criteria:**
  - Packaged endpoints produce encrypted manifests in non-prod.
  - Key exchange path is validated in integration tests/staging checks.
- **Dependencies:** VWD-004, VWD-011.

### VWD-013 — Provision CloudFront + origin access controls + TLS
- **Status:** ✅ Implemented (2026-04-04)
- **Type:** Infra
- **Priority:** P0
- **Size:** M
- **Description:** Put CDN in front of packaging origin with secure access.
- **Deliverables:**
  - Distribution config, cache policies, signed URL/cookie strategy.
  - Origin access control and TLS cert wiring.
- **Acceptance criteria:**
  - Playback manifests/segments are only reachable through approved access path.
  - Cache headers align with segment and key rotation requirements.
- **Dependencies:** VWD-012.

### VWD-014 — Integrate backend orchestration for channel lifecycle
- **Type:** Backend / Platform
- **Priority:** P1
- **Size:** M
- **Description:** Connect app service layer to create/start/stop event channels.
- **Deliverables:**
  - Job handlers for channel lifecycle operations.
  - Idempotency and retry logic for AWS API calls.
- **Acceptance criteria:**
  - Operators can trigger channel lifecycle from backend workflow safely.
  - Duplicate requests do not create duplicate channels/resources.
- **Dependencies:** VWD-011.

---

## Epic D — Watermarking and DRM hardening

### VWD-015 — Implement tenant branding asset management
- **Type:** Backend / Product
- **Priority:** P1
- **Size:** M
- **Description:** Manage and validate tenant watermark assets and policy assignment.
- **Deliverables:**
  - Storage and metadata model for watermark assets.
  - Admin API/UI hooks for uploading/assigning watermark assets.
- **Acceptance criteria:**
  - Tenants can define default watermark profile.
  - Invalid assets (size/format) are rejected with clear errors.
- **Dependencies:** VWD-003.

### VWD-016 — Implement dynamic watermark variables in local + production configs
- **Type:** Video Platform
- **Priority:** P1
- **Size:** M
- **Description:** Support templated watermark text fields (tenant/session/timestamp).
- **Deliverables:**
  - Variable interpolation logic in local FFmpeg pipeline.
  - Equivalent policy mapping in MediaLive configuration path.
- **Acceptance criteria:**
  - Dynamic values render correctly in output samples.
  - Unsupported variables fail validation before job start.
- **Dependencies:** VWD-003, VWD-007, VWD-011.

### VWD-017 — Integrate production DRM license provider and key rotation
- **Type:** Security / Infra
- **Priority:** P1
- **Size:** L
- **Description:** Replace mock path with production-grade DRM provider integration.
- **Deliverables:**
  - Provider integration module and secrets management wiring.
  - Rotation configuration and operational controls.
- **Acceptance criteria:**
  - End-to-end protected playback succeeds for at least one profile per DRM family.
  - Key rotation exercises complete with no playback regressions.
- **Dependencies:** VWD-012, VWD-004.

### VWD-018 — Implement playback entitlement issuance and validation
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** M
- **Description:** Issue short-lived playback entitlements and enforce policy checks.
- **Deliverables:**
  - Entitlement token endpoint/service.
  - Validation middleware and token claims enforcement.
- **Acceptance criteria:**
  - Expired/invalid token paths are rejected deterministically.
  - Token TTL and audience constraints are enforced.
- **Dependencies:** VWD-004.

---

## Epic E — Observability, QA, and rollout readiness

### VWD-019 — Add local CI checks for manifests, ladder continuity, watermark presence
- **Type:** QA / DevEx
- **Priority:** P0
- **Size:** M
- **Description:** Automate local validation checks for generated artifacts.
- **Deliverables:**
  - CI scripts for HLS/DASH manifest validation.
  - Basic frame-snapshot watermark assertion.
  - Segment continuity and ladder completeness checks.
- **Acceptance criteria:**
  - CI fails on missing renditions, invalid manifests, or absent watermark.
- **Dependencies:** VWD-007, VWD-008.

### VWD-020 — Add pre-production reliability tests (input failover, key outage, CDN behavior)
- **Type:** QA / SRE
- **Priority:** P1
- **Size:** M
- **Description:** Validate high-risk runtime failure scenarios before rollout.
- **Deliverables:**
  - Test scenarios and scripts for input failover and key service outages.
  - Observed baseline metrics and pass/fail thresholds.
- **Acceptance criteria:**
  - Failure scenarios have documented expected behavior and recovery times.
- **Dependencies:** VWD-012, VWD-013, VWD-017.

### VWD-021 — Build dashboards and alerts for channel/key/playback health
- **Type:** SRE / Platform
- **Priority:** P1
- **Size:** M
- **Description:** Add operational visibility for live events and DRM health.
- **Deliverables:**
  - CloudWatch dashboards/alarms for channel state, input loss, output errors, key errors.
  - Alert routing and escalation policy.
- **Acceptance criteria:**
  - On-call receives actionable alerts with runbook links.
- **Dependencies:** VWD-011, VWD-012.

### VWD-022 — Publish runbooks and staged rollout checklist
- **Type:** SRE / Product / Platform
- **Priority:** P1
- **Size:** S
- **Description:** Document operations and phased tenant rollout gates.
- **Deliverables:**
  - Runbooks for channel restart, input failover, key fallback.
  - Rollout checklist (internal -> pilot -> GA) and rollback criteria.
- **Acceptance criteria:**
  - Support/on-call can execute critical actions without tribal knowledge.
- **Dependencies:** VWD-020, VWD-021.

---

## Suggested delivery slices

### Slice 1 (MVP local parity)
- VWD-001, VWD-002, VWD-003, VWD-005, VWD-006, VWD-007, VWD-008, VWD-010, VWD-019

### Slice 2 (production baseline)
- VWD-004, VWD-011, VWD-012, VWD-013, VWD-014, VWD-018, VWD-021

### Slice 3 (hardening + rollout)
- VWD-009, VWD-015, VWD-016, VWD-017, VWD-020, VWD-022
