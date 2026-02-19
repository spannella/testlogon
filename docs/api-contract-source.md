# API contract source of truth

The canonical API contract source for this repository is:

- `docs/swagger.json` (FastAPI OpenAPI artifact)

For messaging changes, treat this file as the source of truth for request and response shapes. Frontend endpoint payloads and TypeScript models must match this contract.

## Workflow (temporary)

1. Update backend models/routes.
2. Regenerate/update `docs/swagger.json` from FastAPI OpenAPI.
3. Align frontend API client/types with the canonical schema.
4. Run `tests/test_messaging_contract_drift.py`.

For once-media contract planning and implementation details, see:

- `docs/messaging-once-media-api-contract.md`
- `docs/messaging-once-media-schema-v1.json`
