# SEC-005: Broken Access Control / IDOR Cluster

**Ticket**: SEC-005 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (HIGH — broken access control)

## Problem
Multiple endpoints trust an `id`/`user_sub` from the request instead of the
authenticated subject (or the correct admin scope):
- 👤 **Activity-feed forgery** `app/routers/activity_feed.py:148` — `POST /feed/record`
  takes `user_id` from the body → any user injects feed entries for anyone.
- 👤 **Achievements** `app/routers/achievements.py:228` — read any user's badges/points by id.
- 🛡️ **KYC masked PII unscoped** `app/routers/kyc_cases.py:1557` — *any* admin reads
  masked PII for *any* case (the decrypt path uses `_is_scoped_admin_for_case`, the
  masked path doesn't).
- 🛡️ **Impersonation audit scan** `app/routers/admin_impersonation.py:192` — any
  `auth_support` admin scans **all** impersonations platform-wide / by arbitrary actor.
- 🛡️ **Admin compute quotas** `admin_compute.py:158`, **invoices** `invoices.py:97`,
  **job-retry** `admin_jobs.py:90` — any admin reads/acts on any user by id; some
  **unaudited**.
- **Signature packet final-PDF** `app/routers/signature_packets.py:858` — a signer who
  hasn't signed can download the completed PDF; no completion check + no download rate limit.

## Fix
- User endpoints: force the subject to `ctx.user_sub` (activity record, achievements)
  or verify ownership before returning/mutating.
- Admin endpoints: enforce the correct scope **and** per-case/assignment scoping
  (`_is_scoped_admin_for_case` for KYC masked PII; scope impersonation audit to self
  or ROOT; gate quotas/invoices on `billing_support`); add `audit_event` to every
  cross-user admin read/action (job-retry, invoices, quotas).
- Signature final-PDF: require signer `status == completed` (or owner); rate-limit.

## Testing
pytest: user A cannot record activity / read achievements / read PII as user B;
unassigned/insufficient-scope admin gets 403 on masked PII / impersonation audit /
quotas; non-completed signer cannot fetch final PDF; cross-user admin actions emit audit.
