# Video Pipeline Contract Versioning Strategy (VWD-001)

Active contract version: `2026-03-video-pipeline-v1`

## Compatibility policy

- **Minor additive fields:** accepted by consumers for 90 days before being marked required.
- **New major versions:** old major remains accepted for at least 180 days after new major release.
- **Breaking enum/value changes:** require a new `contract_version`.

## Runtime reference

- `app/services/video_pipeline_contract_service.py` exposes `contract_capabilities_snapshot()` for backend services to discover active/supported versions and compatibility policy.
- `app/services/video_pipeline_contract_service.py` exposes `validate_video_pipeline_job()` to validate and normalize incoming payloads with deterministic errors.


## Contract artifacts

- Request schema: `docs/video-pipeline-contract-v1.json`
- Event schema: `docs/video-pipeline-event-contract-v1.json`
- Request/event examples: `docs/video-pipeline-contract-examples.md`
