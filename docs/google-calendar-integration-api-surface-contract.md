# Google Calendar Integration API Surface Contract (GCAL-017)

Endpoints:
- `GET /ui/calendar/integrations/google/status`
  - rollout state + connection health fields.
- `GET /ui/calendar/integrations/google/calendars`
  - provider calendar list with mapped internal calendar context.
- `POST /ui/calendar/integrations/google/mappings`
  - create internal↔Google calendar mapping (owner validation enforced by mapping service).
- `POST /ui/calendar/integrations/google/sync/run`
  - manual sync trigger (`incremental` or `full`) with rate limiting + audit event emission.

Authz/gating:
- All endpoints require UI session + Google feature gate.
- Mapping creation requires owner permission on the target internal calendar.

Operational behavior:
- Manual sync trigger is rate-limited via privileged action limiter.
- Manual runs are audit logged with mode/processed/error metrics.
