# Google Calendar Testing Strategy (GCAL-023)

## Coverage layers
- **Unit:** OAuth, token refresh/expiry handling, mapper transforms, conflict classification.
- **Integration:** mocked Google API flows for token-expiry refresh and incremental syncToken invalidation fallback.
- **E2E:** user journey simulation for connect → map → manual sync in API-level e2e tests, plus Playwright calendar spec in CI.

## New deterministic fixtures
- `tests/fixtures/google_calendar/token_expiry_case.json`
- `tests/fixtures/google_calendar/sync_token_invalidation_case.json`

## CI jobs
- `.github/workflows/google-calendar-tests.yml`
  - backend regression suite job
  - frontend Playwright calendar e2e job

## Critical path assertions
- Connection setup and callback succeed under feature gate.
- Mapping creation persists expected associations.
- Incremental sync falls back to full import when sync token is invalid.
- Token expiry forces refresh before API request.
- Manual sync endpoint succeeds and returns metrics payload.
