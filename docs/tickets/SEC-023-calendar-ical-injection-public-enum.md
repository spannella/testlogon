# SEC-023: iCal Injection + Public-Event Enumeration + Booking Abuse

**Ticket**: SEC-023 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 4)

## Problem
- **iCal property injection**: `app/routers/calendar.py:2048-2074` builds
  `SUMMARY:{name}` / `DESCRIPTION:{...}` without RFC-5545 escaping. A `\r\n` in the
  event name/description injects arbitrary iCal properties (e.g. `ATTACH:` to malware,
  `VALARM`) into the `.ics`, on both the authed and public `/ical` endpoints; also
  CSV/formula-injection risk when opened in a spreadsheet.
- **Public-event enumeration / no auth**: `GET /calendar/public/event/{calId}/{eventId}`
  (`:2079-2109`) returns full event detail with **no authorization check and no rate
  limit** → enumerate events/calendars by id, leaking titles/times/attendee info.
- **Booking endpoints**: `/booking/{link_id}` + `/reserve` (`:1946-2043`) have **no
  rate limiting** (spam/double-book/DoS), and `reserve_booking_slot` references an
  **undefined `ctx`** at `:2043` → 500 / unhandled exception (functional + DoS).

## Fix
- Add an `escape_ics_value()` (escape `\ , ; \r \n`) and apply to every iCal property
  (SUMMARY, DESCRIPTION, LOCATION, etc.).
- Gate public event access on an explicit `is_public`/share flag; add per-IP rate
  limiting + (optional) unguessable share tokens instead of raw ids.
- Fix the `ctx` reference in `reserve_booking_slot` (use `user_sub=None` for anon);
  rate-limit booking GET/reserve per link + per IP.

## Testing
pytest/E2E: an event named `X\r\nATTACH:http://evil` produces an escaped single
SUMMARY line; public event for a non-public calendar → 403; booking reserve succeeds
(no NameError) and is rate-limited.
