# Impersonation audit log silently empty when actor has many sessions

## Symptom
GET /admin/impersonation/audit returns items:[] even right after a successful
POST /admin/impersonation/start — the audit trail of who impersonated whom
appears empty.

## Root cause
Impersonation records live in the shared T.sessions table (pk=user_sub) alongside
every regular login session. impersonation_audit ran a SINGLE capped read
(T.sessions.query(...).query Limit=500 / scan Limit=500) and filtered in-memory
for purpose==impersonation. A busy actor accumulates thousands of login sessions
(the dev root had 1905), so the handful of impersonation rows fall OUTSIDE the
first 500-item page (DDB returns items in key order, not time order) and are never
seen -> audit returns nothing. Compliance-relevant: the impersonation audit trail
is incomplete on any heavily-used admin/root account in prod too.

## Fix
Paginate the underlying query/scan (ExclusiveStartKey loop, keeping only
impersonation rows, safety-capped at 100 pages) so all impersonation records in
the requested window are collected regardless of how many unrelated sessions
exist. See impersonation_audit_pagination.patch.

## Prod-mirror status: PENDING (running-server-affecting, compliance)
Apply on prod (/home/ubuntu/testlogon) via SSM, restart uvicorn, verify a fresh
impersonation-start appears in GET /admin/impersonation/audit.

## e2e impact
admin-roles 'impersonation audit log returns the start events'.
