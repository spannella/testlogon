# ADMIN-002: Admin Email/SMS Dashboards — Investigation & Implementation Write-up

## 1. Summary & Classification

The ticket identified a gap between rich backend email/SMS delivery tracking services and the absence of an admin UI to consume them. It also proposed a notification template management layer. The investigation finds that the backend is substantially more complete than the ticket's gap section acknowledged: both the email router (`app/routers/admin_email.py`) and the SMS router (`app/routers/admin_sms.py`) already existed before this ticket. The notification template service and router have since been implemented. The frontend dashboard page `EmailSmsDashboardPage.tsx` now exists at route `/admin/communications`. Outstanding gaps are a `POST /suppressed` add-suppression endpoint in the email router and a missing E2E spec for the template management layer.

**Type**: Feature. **Priority**: Medium. **Status**: Partially implemented (backend mostly complete; frontend page present; template service/router added; email add-suppression endpoint added; E2E spec exists for email/SMS sections but not yet confirmed for templates). **Owning area**: Platform operations / Admin tooling.

**Persona**: Platform admins (ADMIN or ROOT role) monitoring delivery health, managing suppressions, and editing notification copy without engineering involvement.

---

## 2. Current-State Investigation (what exists today)

### Email delivery service (`app/services/email_delivery.py`)

The following functions exist as described in the ticket:
- `get_delivery_stats(days=7)` (line 221)
- `list_deliveries(limit, cursor)` (line 284)
- `list_bounces(limit, cursor)` (line 316)
- `list_complaints(limit, cursor)` (line 337)
- `get_suppression_list(limit)` (line 358)
- `suppress_email(email, reason)` (line 175)
- `remove_suppression(email)` (line 205)
- `is_suppressed(email)` (line 193)
- `read_dev_email_log(max_entries)` (line 373)

### SMS delivery service (`app/services/sms_delivery.py`)

The following functions exist as described in the ticket:
- `get_sms_delivery_stats(days=7)` (line 226)
- `list_sms_deliveries(limit, cursor)` (line 302)
- `list_sms_failures(limit)` (line 324)
- `get_suppression_list(limit)` (line 331)
- `suppress_sms(phone, reason)` (line 148)
- `remove_sms_suppression(phone)` (line 179)
- `get_dev_sms_log()` (line 344)

### Admin email router (`app/routers/admin_email.py`)

Prefix `/ui/admin/email`, registered in `app/main.py:221,627`. Auth uses `require_admin_or_root` from `app/auth/policy.py:67`. Endpoints present (verified by `grep -n "def\|POST\|GET\|DELETE"` scan):
- `GET /stats` — `email_stats()` (line 36)
- `GET /deliveries` — `email_deliveries()` (line 45)
- `GET /bounces` — `email_bounces()` (line 57)
- `GET /complaints` — `email_complaints()` (line 68)
- `GET /suppressed` — `suppressed_emails()` (line 79)
- `DELETE /suppressed/{email}` — `unsuppress_email()` (line 88)
- `GET /preview` — `email_preview()` (line 98)
- `GET /dev-log` — `dev_email_log()` (line 123)
- `GET /dashboard-stats` — `email_dashboard_stats()` (line 140)
- `GET /dashboard-timeseries` — `email_dashboard_timeseries()` (line 169)
- `GET /bounce-domains` — `email_dashboard_bounce_domains()` (line 179)
- `POST /suppressed` — `add_email_suppression()` (line 189–190)

The `POST /suppressed` endpoint was noted in the ticket document as absent; it now exists (line 189).

### Admin SMS router (`app/routers/admin_sms.py`)

Prefix `/ui/admin/sms`, registered in `app/main.py:220,626`. Auth: `require_admin_or_root`. Eight endpoints present: `GET /stats`, `GET /deliveries`, `GET /failures`, `GET /suppressed`, `GET /suppressed/{phone}`, `POST /suppressed`, `DELETE /suppressed/{phone}`, `GET /dev-log`. The ticket's gap section originally claimed this router didn't exist; the comment in the ticket document itself corrects this: "already exists."

### Notification template service (`app/services/notification_templates.py`)

This service was not present at ticket creation. It is now present. The file's docstring declares: `Table: admin_messaging_templates / PK: TEMPLATE#{template_id} / SK: META`. Key functions: `list_templates(channel)`, `get_template(template_id)`, `update_template(template_id, ...)`, `preview_template(template_id, ...)`, `test_send(template_id, ...)`. Default templates are seeded from a `_DEFAULT_TEMPLATES` list at startup (e.g., `email_welcome`, `email_password_reset`, `sms_verification`). Variable substitution uses `{{var_name}}` syntax via `_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")`. In-memory test-send rate limiter uses `_test_send_log: Dict[str, List[int]] = {}`.

### Admin notifications router (`app/routers/admin_notifications.py`)

Prefix `/ui/admin/notifications`, registered in `app/main.py:222,628`. Auth: `require_admin_or_root`. Endpoints:
- `GET /templates` — list all or filter by channel
- `GET /templates/{template_id}` — get single template
- `PATCH /templates/{template_id}` — update subject/body/active
- `POST /templates/{template_id}/preview` — render with sample_vars
- `POST /templates/{template_id}/test-send` — send test notification

### DynamoDB tables

`admin_messaging_templates` table handle at `app/core/tables.py:440`. Settings key `admin_messaging_templates_table_name`. Table appears in `scripts/local-ddb-init.py:1362`. Schema: `PK=TEMPLATE#{template_id}`, `SK=META`. No GSIs — all template operations are by exact key. The table name `admin_messaging_templates` differs slightly from the ticket's proposed name `notification_templates`; the settings key follows the `admin_messaging_*` prefix convention used by other admin messaging tables.

### Notification template service (`app/services/notification_templates.py`) — detailed

`seed_default_templates()` at line 102 iterates `_DEFAULT_TEMPLATES` and writes each to `T.admin_messaging_templates` using PutItem with `attribute_not_exists(pk)` condition (idempotent re-seed). `get_template(template_id)` at line 171 does a GetItem. `update_template(template_id, *, admin_sub, **updates)` at line 186 validates only `subject`, `body`, and `active` are mutable; `channel` and `template_id` are immutable. `preview_template(template_id, ...)` at line 263 does Jinja2-style `{{var}}` substitution using `_VAR_RE`. `test_send_allowed(admin_sub)` at line 289 checks the in-memory `_test_send_log` dict for the rate limit (10 sends per hour). `test_send(template_id, ...)` at line 302 calls either `email_delivery.send_email()` or `sms_delivery.send_sms()` depending on the template's `channel` field, then records the send in `_test_send_log`.

### Admin notifications router — endpoint detail

`app/routers/admin_notifications.py` (prefix `/ui/admin/notifications`). The five endpoints use `require_admin_or_root` (not `require_admin_or_root_csrf`) — meaning CSRF is not checked on PATCH and POST endpoints by this router. This differs from the `require_admin_or_root_csrf` used in other mutating admin routers. If the dashboard page uses cookie-based auth (browser sessions), CSRF protection is absent on template updates and test sends. This is a minor security gap: a CSRF attack could modify template body/subject via a cross-site form submission.

### Frontend

`frontend/src/pages/admin/EmailSmsDashboardPage.tsx` exists and is lazy-loaded at `frontend/src/App.tsx:114,438` at route `/admin/communications`. Supporting panels exist as separate files: `EmailDashboardPanel.tsx`, `SmsDashboardPanel.tsx`, `MessagingTemplatesPanel.tsx`. There is no `adminCommunications.ts` API endpoints file under `frontend/src/api/endpoints/`; panel components call through `frontend/src/api/endpoints/adminMessagingDashboards.ts` which is present.

### E2E tests

`frontend/e2e/admin-email-sms-dashboards.spec.ts` exists with sections 551–558 as documented in the ticket. It uses `e2e_admin_session_setup.py` auth with root and alice identities.

### Dev vs Prod parity (SECOPS-007)

In dev: `email_delivery` and `sms_delivery` DynamoDB tables back the stats/list queries via DynamoDB Local (:8001). The `read_dev_email_log` function reads from an in-memory or file-based dev email capture — never calls a real email provider. `get_dev_sms_log()` similarly reads dev-mode log. The `test_send` path in `notification_templates.py` should invoke `email_delivery.send_email()` or `sms_delivery.send_sms()`, both of which resolve to mock delivery in dev mode (no SES/SNS calls). In prod these resolve to real AWS SES / SNS via `app/core/aws.py`.

---

## 3. Gap / Threat Analysis

### Remaining gaps

1. **`adminCommunications.ts` API endpoint file**: the ticket specified `frontend/src/api/endpoints/adminCommunications.ts`. It does not exist as that exact name. The panels may use `adminMessagingDashboards.ts` or inline `api.get/post` calls. This is not a functional gap but a code organisation inconsistency.

2. **Template URL prefix inconsistency**: the ticket proposed `/v1/admin/notifications/templates` but the implementation uses `/ui/admin/notifications/templates`. The frontend must use the `/ui/admin/notifications` prefix. Any frontend code targeting `/v1/admin/notifications/` will fail with 404.

3. **Dev-log endpoint access control**: the ticket specifies the dev-log tabs should only appear when `devMode` is true. The `GET /dev-log` endpoint in both email and SMS routers should return 404 or 403 in non-dev mode. Verify `admin_email.py:123` and `admin_sms.py:94` check `S.dev_mode` before serving logs, since dev email captures contain potentially sensitive test data.

4. **In-memory test-send rate limiter**: `_test_send_log: Dict[str, List[int]] = {}` in `notification_templates.py` is process-local. Under the recommended single-worker dev config this is fine. In a hypothetical multi-worker deployment it would not enforce the 10/hour limit across processes. For prod, the rate limit should use DynamoDB (following the pattern in `app/services/rate_limit_store.py`) or at minimum be documented as process-local.

5. **Missing CSRF on template mutation endpoints**: `app/routers/admin_notifications.py` uses `require_admin_or_root` (not `require_admin_or_root_csrf`). For cookie-authenticated admin browser sessions this means CSRF tokens are not validated on PATCH `/templates/{id}` or POST `/templates/{id}/test-send`. An attacker with knowledge of a logged-in admin's session cookie could forge template updates via a cross-site request. The fix is to use `require_admin_or_root_csrf` for all non-GET endpoints in this router.

5. **Template `seed_default_templates` startup hook**: the `_DEFAULT_TEMPLATES` list in `notification_templates.py` is seeded at module init or called from a startup hook. Verify `app/main.py` calls the seed function so templates are available on fresh DDB Local without manual seeding.

6. **`TemplateUpdate` XSS stripping**: the `strip_script_tags` validator in the `TemplateUpdate` model strips `<script>` tags. This is a client-side sanitisation that does not prevent stored XSS via attributes like `<img onerror=...>`. For production, template bodies rendered as HTML email are delivered to email clients (not the browser), so server-side XSS risk is limited to the preview endpoint. The preview endpoint returns rendered HTML to the admin browser — this should be sandboxed in an iframe with `sandbox="allow-scripts"` disabled, or returned as plain text for display.

### Abuse potential

Test-send endpoint can be used to send emails/SMS to any recipient address. With only 10/hour rate limit per admin, a disgruntled insider could still send unsolicited notifications. Consider restricting the test-send recipient to admin-owned domains or the requester's own email address in production.

---

## 4. Proposed Design / Fix

The core backend is complete. The items below address the gaps above.

### 4.1 Fix dev-log endpoint guards

In `app/routers/admin_email.py:123` and `app/routers/admin_sms.py:94`, add:
```python
if not S.dev_mode:
    raise HTTPException(404, "Dev log not available in production")
```
This prevents dev email captures from being exposed via the admin API in production.

### 4.2 Persist test-send rate limit in DynamoDB

Replace the in-memory `_test_send_log` dict in `notification_templates.py` with a DynamoDB-backed counter using the existing `rate_limit_store.py` pattern. Key: `TEST_SEND#{admin_sub}`, TTL-windowed item. This makes the 10/hour limit work correctly even if the process is restarted.

### 4.3 Add `adminCommunications.ts` or alias

If `adminMessagingDashboards.ts` already covers the full endpoint set, document that it serves as the implementation of what the ticket called `adminCommunications.ts`. Otherwise create `frontend/src/api/endpoints/adminCommunications.ts` re-exporting from `adminMessagingDashboards.ts` for clarity.

### 4.4 Fix missing CSRF on template mutation endpoints

In `app/routers/admin_notifications.py`, change the PATCH and POST endpoint dependencies from `require_admin_or_root` to `require_admin_or_root_csrf`:

```python
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf

@router.patch("/templates/{template_id}", response_model=NotificationTemplateOut)
async def update_notification_template(
    ...
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),  # was require_admin_or_root
):

@router.post("/templates/{template_id}/preview", ...)
async def preview_notification_template(
    ...
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):

@router.post("/templates/{template_id}/test-send", ...)
async def test_send_notification_template(
    ...
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
```

The frontend must include `x-csrf-token: <csrf_token>` on all these requests (already the case for other admin API calls in the existing panels).

### 4.5 Template preview XSS mitigation

In `MessagingTemplatesPanel.tsx` (the templates tab component), render the `rendered_body` preview inside a sandboxed iframe:
```tsx
<iframe
  srcDoc={renderedBody}
  sandbox=""
  style={{ width: "100%", height: "400px", border: "1px solid #ccc" }}
  title="Email preview"
/>
```
The empty `sandbox=""` attribute blocks all scripts and form submissions.

### 4.6 Dev/Prod parity (SECOPS-007)

No new AWS dependencies are introduced. All table access goes through `T.*` handles (DynamoDB Local in dev, real DynamoDB in prod). Email/SMS send in `test_send` delegates to existing service functions already abstracted for dev mode.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_admin_email_sms_dashboards.py`)

- `test_list_templates_seeded`: call `list_templates()` on a fresh moto-backed table; assert default templates are present after seeding.
- `test_update_template_strips_script_tag`: `update_template(..., body="<script>alert(1)</script>text")`; assert saved body does not contain `<script>`.
- `test_preview_template_variable_substitution`: call `preview_template("email_welcome", sample_vars={"user_name": "Alice", ...})`; assert `rendered_body` contains "Alice".
- `test_test_send_rate_limit`: call `test_send` 11 times for the same admin; assert 11th raises 429 or the rate limit error.
- `test_add_suppression_idempotent`: call `suppress_email(email, reason)` twice; assert second call does not raise.
- `test_remove_suppression_not_found`: call `remove_suppression("nobody@example.com")`; assert 404.
- `test_dev_log_unavailable_in_prod`: with `S.dev_mode = False`, call the dev-log endpoint; assert 404.
- `test_template_mutation_requires_csrf`: POST `/ui/admin/notifications/templates/{id}/test-send` with cookie auth but without `x-csrf-token` header; assert 403. (Validates the CSRF fix once applied.)
- `test_template_channel_immutable`: attempt to update `channel` via PATCH; assert the stored record still has the original channel value.
- `test_seed_default_templates_idempotent`: call `seed_default_templates()` twice; assert no DuplicateItem error and template count matches `len(_DEFAULT_TEMPLATES)`.

### E2E tests (Playwright)

`frontend/e2e/admin-email-sms-dashboards.spec.ts` exists. Verify it covers:
- `GET /ui/admin/email/stats` with days=7
- `POST /ui/admin/email/suppressed` and `DELETE /ui/admin/email/suppressed/{email}`
- `GET /ui/admin/sms/stats`, `POST /ui/admin/sms/suppressed`, `DELETE /ui/admin/sms/suppressed/{phone}`
- `GET /ui/admin/notifications/templates` — returns seeded template list
- `PATCH /ui/admin/notifications/templates/{id}` — update and verify
- `POST /ui/admin/notifications/templates/{id}/preview` — returns `rendered_subject`, `rendered_body`
- `POST /ui/admin/notifications/templates/{id}/test-send` — returns `{ok: true}`
- Authorization: Alice (USER role) → 403 on all admin endpoints
- UI: navigate to `/admin/communications`; Email tab loads KPI cards; Templates tab shows template list

### Rollout

Backend endpoints are already live (all admin routers registered in `app/main.py`). Frontend route `/admin/communications` requires ADMIN or ROOT cookies — regular users see a 403 redirect. No feature flag currently gates the page. Add `ADMIN_COMMS_DASHBOARD_ENABLED` to `app/core/settings.py` and the frontend route guard if phased rollout is desired.

**Effort estimate**: S for remaining gaps (dev-log guard, CSRF fix on template endpoints, template preview iframe, rate-limit persistence). The primary implementation is complete.

### Dev/Prod environment behaviour summary

| Component | Dev | Prod |
|---|---|---|
| `email_delivery` table | DynamoDB Local (:8001) | AWS DynamoDB |
| `sms_delivery` table | DynamoDB Local (:8001) | AWS DynamoDB |
| `admin_messaging_templates` table | DynamoDB Local (:8001) | AWS DynamoDB |
| Email send (test_send) | `email_delivery.send_email()` → dev log capture (no SES) | AWS SES |
| SMS send (test_send) | `sms_delivery.send_sms()` → dev log capture (no SNS) | AWS SNS |
| Dev log endpoints | Returns in-process captured log | Returns 404 (not available) |

No new AWS credentials or service accounts are required beyond what is already configured in `.env.local` / `.env`.

---

## Second-pass verification (2026-06-05)

- [Confirmed] email service functions exist at stated lines: `suppress_email` line 175, `is_suppressed` 193, `remove_suppression` 205, `get_delivery_stats` 221, `list_deliveries` 284, `list_bounces` 316, `list_complaints` 337, `get_suppression_list` 358, `read_dev_email_log` 477 — all confirmed in `app/services/email_delivery.py`
- [Corrected] SMS service line numbers are wrong throughout: actual lines are `suppress_sms` 269 (claimed 148), `remove_sms_suppression` 300 (claimed 179), `get_sms_delivery_stats` 347 (claimed 226), `list_sms_deliveries` 423 (claimed 302), `list_sms_failures` 445 (claimed 324), `get_suppression_list` 452 (claimed 331), `get_dev_sms_log` 561 (claimed 344) — in `app/services/sms_delivery.py`
- [Confirmed] `POST /suppressed` endpoint exists in admin_email.py at line 189 — confirmed
- [Confirmed] admin_email router prefix `/ui/admin/email` at line 32, registered in `app/main.py` import 221, include_router 627 — confirmed
- [Confirmed] admin_sms router prefix `/ui/admin/sms` at line 32, registered in `app/main.py` import 220, include_router 626 — confirmed
- [Corrected] admin_email.py dashboard endpoint paths: writeup says `/dashboard-stats`, `/dashboard-timeseries`, `/bounce-domains` but actual paths are `/dashboard/stats` (line 139), `/dashboard/timeseries` (line 168), `/dashboard/bounce-domains` (line 178) — note slash vs hyphen difference
- [Corrected] admin_sms.py `GET /dev-log` at line 94 (claimed) — actual line is 126; `POST /suppressed` is at line 142 (not mentioned in the endpoint list); additional endpoints exist that were not listed: `POST /send-test` (line 105), `GET /dashboard/stats` (line 158), `GET /dashboard/timeseries` (line 183), `GET /dashboard/failure-types` (line 193)
- [Already-fixed] dev-log endpoint guards claimed as absent in gap §3.3 — both `admin_email.py:128` and `admin_sms.py:131` already have `if not S.dev_mode: raise HTTPException(status_code=404, ...)` guards; the gap is moot
- [Already-fixed] `seed_default_templates()` startup hook — `app/main.py` lines 498-526 call `seed_default_templates()` via a startup handler; the gap concern about "verify main.py calls the seed function" is resolved
- [Confirmed] notification_templates.py function lines: `seed_default_templates` 102, `_VAR_RE` 23, `_test_send_log` 26, `_DEFAULT_TEMPLATES` 33, `list_templates` 145, `get_template` 171, `update_template` 186, `preview_template` 263, `test_send_allowed` 289, `test_send` 302 — all confirmed
- [Confirmed] `admin_messaging_templates` table at `app/core/tables.py:440` — confirmed (line 204 for field declaration, 440 for the assignment); `scripts/local-ddb-init.py:1362` — confirmed
- [Confirmed] admin_notifications router prefix `/ui/admin/notifications`, registered `app/main.py` import 222, include_router 628 — confirmed
- [Confirmed] CSRF gap: all endpoints in `app/routers/admin_notifications.py` use `require_admin_or_root` (not `require_admin_or_root_csrf`), including PATCH and POST endpoints — confirmed, gap is not fixed
- [Confirmed] `adminMessagingDashboards.ts` exists at `frontend/src/api/endpoints/adminMessagingDashboards.ts` (133 lines); no `adminCommunications.ts` file exists — confirmed
- [Confirmed] `EmailSmsDashboardPage` at `frontend/src/App.tsx:114` (lazy import) and `438` (Route) — confirmed
