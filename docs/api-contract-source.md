# API contract source of truth

The canonical API contract source for this repository is:

- `docs/swagger.json` (FastAPI OpenAPI artifact)

For messaging and projects changes, treat this file as the source of truth for request and response shapes. Frontend endpoint payloads and TypeScript models must match this contract.

Companion docs:
- `docs/project-api-contract.md` (human-readable projects endpoint examples)

## Workflow (temporary)

1. Update backend models/routes.
2. Regenerate/update `docs/swagger.json` from FastAPI OpenAPI.
3. Align frontend API client/types with the canonical schema.
4. Run `tests/test_messaging_contract_drift.py`.
