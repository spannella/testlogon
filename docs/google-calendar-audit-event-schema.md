# Google Calendar Audit Event Schema (GCAL-022)

## Purpose
Defines normalized audit payload fields for Google Calendar integration lifecycle and compliance review.

## Required fields
- `event` (string)
- `user_sub` (string)
- `ts` (unix timestamp, from core audit pipeline)
- `outcome` (`success|failure|info|warning|error`)
- `actor_sub` (string)
- `target_type` (string)
- `target_id` (string)
- `integration` = `google_calendar`
- `compliance_domain` = `calendar_sync`

## Event families
- Connection lifecycle:
  - `google_calendar_connect_start`
  - `google_calendar_connect_callback`
  - `google_calendar_connected`
  - `google_calendar_disconnect`
  - `google_calendar_disconnected`
- Mapping lifecycle:
  - `google_calendar_mapping_created`
  - `google_calendar_mapping_reactivated`
  - `google_calendar_mapping_unmapped`
- Sync lifecycle:
  - `google_calendar_manual_sync_run`
  - `google_calendar_sync_error`
  - `google_calendar_sync_conflict`
  - `google_calendar_sync_dead_lettered`

## Sensitive-data guardrails
Audit payload sanitization redacts keys containing markers such as:
- `token`
- `secret`
- `password`
- `authorization`
- `ciphertext`
- `nonce`
- `aad`
- `kms`

Any matching field value is recorded as `[REDACTED]`.
