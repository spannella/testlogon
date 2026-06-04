# PLATFORM-006: Email Delivery Production Config — Investigation & Implementation Write-up

> Type: feature / hardening | Priority: High | Status: Substantially implemented (email_delivery service, admin routers, and DDB table exist; send_alert_email still uses old silent-failure pattern)

## 1. Summary & Classification

Email delivery existed in the codebase but was disabled by default (`ALERTS_EMAIL_ENABLED` defaults to `"0"`, `app/core/settings.py:186`) and had no feedback loop. `send_alert_email()` in `app/services/alerts.py` (line 458) creates a new `boto3.client("ses")` per call, swallows all exceptions silently with a bare `except Exception: pass`, and returns `None` always — callers have no way to know whether the email was sent. PLATFORM-006 fixes the silent failure, adds SES MessageId tracking, implements a suppression list for hard bounces and spam complaints, and builds an admin dashboard for delivery health monitoring. The SES SNS notification webhook (`/internal/ses/notifications`) receives bounce, complaint, and delivery events from AWS.

- **Type**: Feature / hardening / observability
- **Priority**: High
- **User personas affected**: all users with email alerts configured; platform admins; operations teams managing SES sender reputation
- **Cross-references**: SECOPS-007 (dev/prod parity — dev mode logs to file, prod sends via SES, same code path controlled by `S.dev_mode`; DDB Local in dev), PLATFORM-007 (SMS production follows the same delivery-tracking pattern)

---

## 2. Current-State Investigation

### 2.1 send_alert_email() — current implementation

`app/services/alerts.py:458–478` (current state, verified with `sed`):

```python
def send_alert_email(to_emails: List[str], subject: str, body_text: str) -> None:
    if not to_emails:
        return
    if S.dev_mode:
        # ... writes to .logs/dev/emails.log ...
        return
    if not S.alerts_email_enabled or not S.alerts_from_email:
        return
    try:
        import boto3
        ses = boto3.client("ses")              # new client per call — no connection reuse
        ses.send_email(
            Source=S.alerts_from_email,
            Destination={"ToAddresses": to_emails},
            Message={"Subject": {"Data": subject[:120]},
                     "Body": {"Text": {"Data": body_text[:8000]}}},
        )
    except Exception:
        pass                                   # silent failure — no log, no metric, no retry
```

Three problems are immediately apparent:
1. `boto3.client("ses")` creates a new HTTP connection on every call (~50 ms overhead).
2. `except Exception: pass` means SES rejections (`MessageRejected`, `MailFromDomainNotVerifiedException`, quota exceeded) disappear silently.
3. The function returns `None` always — callers cannot distinguish success from failure.

The alert fanout in `app/services/alerts.py` (approximately lines 753, 765, 791) calls `send_alert_email()` three times under different template branches, and the entire email section is additionally wrapped in its own `except Exception: pass` (verified around line 670). This creates a double silent-failure envelope.

### 2.2 Module-level SES client (aws.py) — unused by alerts.py

`app/core/aws.py:11–19` creates a module-level SES client `ses` when `S.ses_from_email` is set:
```python
ses = None
if S.ses_from_email:
    ses = _boto3_client("ses", region_name=S.aws_region or "us-east-1",
                        endpoint_url=S.aws_endpoint_url or None)
```

However, `send_alert_email()` ignores this and creates its own per-call client. The fix is to use a `_get_ses_client()` singleton that checks `aws.py`'s `ses` first and initialises it lazily if None.

### 2.3 Email settings (app/core/settings.py)

| Setting | Line | Default | Notes |
|---|---|---|---|
| `ses_from_email` | 179 | `""` | Triggers module-level client creation in aws.py |
| `alerts_from_email` | 185 | `""` | Source address for `send_email()` |
| `alerts_email_enabled` | 186 | `"0"` | **Disabled by default** |
| `alerts_email_max_per_window` | 187 | `20` | Rate limit bucket via `_bucket_limit()` |
| `alerts_email_window_seconds` | 188 | `3600` | 1-hour window |
| `dev_email_log` | 246 | `.logs/dev/emails.log` | Dev mode output file |
| `devtools_email_log_path` | 249 | same | Dev Tools UI discovery path |
| `notification_email_templates_enabled` | 1314 | `True` | Enable NOTIFY-001 HTML templates |

### 2.4 Email template system

`app/services/alert_email_templates.py` (165 lines total):
- `_wrap_html()` (line 16–39): responsive HTML email template with inline CSS, 560px container
- Five template functions covering messaging, payments, subscriptions, refunds, security
- `_TEMPLATE_MAP` (line 122–147): maps 12 event type strings to the 5 template functions
- `render_alert_email_template(event_type, details)` (line 150–165): dispatcher

These templates exist but the functions do not currently pass an `html_body` parameter to `send_alert_email()`. The improved function signature should accept `html_body: str = ""` as a keyword argument.

### 2.5 What now exists (substantially implemented)

- `app/services/email_delivery.py` — delivery tracking, suppression list, admin queries (confirmed present)
- `app/routers/admin_email.py` — admin monitoring endpoints (confirmed present, registered in `main.py:221–222, 627–629`)
- `app/routers/ses_notifications.py` — SES SNS webhook receiver (confirmed present)
- `app/core/tables.py:203, 439` — `email_delivery` table handle and initialisation
- Pydantic models for email delivery stats/bounces/complaints in `app/models.py`

### 2.6 What is NOT yet done

- `send_alert_email()` (`alerts.py:458`) is still the old implementation with silent failure — the ticket-designed improved version with `_get_ses_client()`, logging, `record_email_sent()`, and suppression check has not been applied to the actual function.
- The alert fanout's double `except Exception: pass` wrapper has not been removed.
- `app/metrics.py` additions for `EMAIL_SENT`, `EMAIL_FAILED`, `EMAIL_BOUNCED`, `EMAIL_COMPLAINED`, `EMAIL_SUPPRESSED` counters may not yet exist.

---

## 3. Gap / Threat Analysis

### 3.1 Sender reputation risk (SES suspension)

AWS SES will suspend sending access if:
- **Bounce rate** > 5% (hard threshold; warning at 2%)
- **Complaint rate** > 0.1%

Without bounce tracking, the platform continues emailing invalid addresses, accumulating bounces. Without complaint handling, users who mark emails as spam continue receiving them. Both lead to SES account suspension — blocking all email delivery for all users.

The `is_suppressed(email)` check in `email_delivery.py` before the SES call prevents re-sending to hard-bounced or complained-about addresses. The `record_email_bounce()` function auto-suppresses permanent bounces; `record_email_complaint()` suppresses all complainants.

### 3.2 Silent failure masking security events

`send_alert_email()` is called for security alerts (login from new device, MFA changes, password resets). If the SES call fails — due to quota exhaustion, domain verification expiry, or a regional outage — the user never receives the security alert. The silent `except Exception: pass` means operations teams have no visibility into the failure. The fix is to log at `exception()` level and increment `email_failed_total`.

### 3.3 Rate-limited emails produce no feedback

`can_send_alert_channel(user_sub, "email")` at `app/services/rate_limit.py:321–323` returns `False` silently when the per-user limit is exceeded. The admin dashboard should expose rate-limited drops so operations can distinguish legitimate rate limiting from quota exhaustion.

### 3.4 SNS notification endpoint security

`POST /internal/ses/notifications` is an unauthenticated endpoint (must be — SNS cannot authenticate). It should only be reachable from AWS SNS IP ranges, enforced via security group or WAF. Without this restriction, an attacker could POST a crafted bounce notification to suppress any email address. For staging with no WAF, restrict the endpoint to VPC-only traffic.

### 3.5 Admin unsuppression abuse

`DELETE /ui/admin/email/suppressed/{email}` removes an address from the suppression list, re-enabling delivery. If an admin removes a suppressed address that complained (spam report), the next email delivery will generate a new complaint, degrading SES reputation. Admin audit logging for this action is strongly recommended.

### 3.6 Code sites that must change

| File | Change |
|---|---|
| `app/services/alerts.py:458–478` | Replace silent-failure `send_alert_email()` with logged, tracked version |
| `app/services/alerts.py:~670` | Remove outer `except Exception: pass` from email fanout |
| `app/metrics.py` | Add `EMAIL_SENT`, `EMAIL_FAILED`, `EMAIL_BOUNCED`, `EMAIL_COMPLAINED`, `EMAIL_SUPPRESSED` counters |
| `app/services/email_delivery.py` | Confirmed present — verify `is_suppressed()`, `record_email_sent()`, `record_email_bounce()` functions |
| `app/routers/ses_notifications.py` | Confirmed present — handles SNS subscription confirmation + bounce/complaint events |
| `app/routers/admin_email.py` | Confirmed present — admin stats/bounces/complaints/suppressed endpoints |
| `scripts/local-ddb-init.py` | Add `email_delivery` table with ByStatus GSI and `attr_types={"created_at": "N"}` |
| `frontend/src/pages/admin/EmailDeliveryPage.tsx` | New — admin dashboard |
| `frontend/src/App.tsx` | Add `/admin/email` route |

---

## 4. Proposed Design / Fix

### 4.1 Improved send_alert_email()

```python
_ses_client = None

def _get_ses_client():
    global _ses_client
    if _ses_client is None:
        import boto3
        _ses_client = boto3.client("ses", region_name=S.aws_region or "us-east-1",
                                   endpoint_url=S.aws_endpoint_url or None)
    return _ses_client

def send_alert_email(to_emails: List[str], subject: str, body_text: str,
                     *, html_body: str = "") -> Optional[str]:
    if not to_emails:
        return None
    if S.dev_mode:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for addr in to_emails:
            _write_dev_log(S.dev_email_log, f"[{ts}] TO={addr}\nSubject: {subject}\n{body_text}\n\n")
        return f"dev-{now_ts()}"

    if not S.alerts_email_enabled or not S.alerts_from_email:
        return None

    if S.email_suppression_enabled:
        from app.services.email_delivery import is_suppressed
        to_emails = [e for e in to_emails if not is_suppressed(e)]
    if not to_emails:
        return None

    try:
        ses = _get_ses_client()
        body: Dict[str, Any] = {"Text": {"Data": body_text[:8000], "Charset": "UTF-8"}}
        if html_body:
            body["Html"] = {"Data": html_body[:50000], "Charset": "UTF-8"}
        resp = ses.send_email(
            Source=S.alerts_from_email,
            Destination={"ToAddresses": to_emails},
            Message={"Subject": {"Data": subject[:120], "Charset": "UTF-8"}, "Body": body},
        )
        message_id = resp.get("MessageId", "")
        from app.services.email_delivery import record_email_sent
        record_email_sent(to_emails, subject, message_id)
        EMAIL_SENT.inc(len(to_emails))
        logger.info("Email sent: message_id=%s, to=%s", message_id, to_emails)
        return message_id
    except Exception as exc:
        from app.services.email_delivery import record_email_failure
        record_email_failure(to_emails, subject, str(exc))
        EMAIL_FAILED.inc(len(to_emails))
        logger.exception("Email send failed: to=%s, error=%s", to_emails, str(exc)[:200])
        return None
```

### 4.2 DDB email_delivery table schema

```python
TableDef(
    "email_delivery", "pk", "sk",
    gsi=[{"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"}],
    attr_types={"created_at": "N"},   # CRITICAL for numeric GSI sort key
    ttl_attribute="ttl_epoch",
)
```

Item patterns:
- `PK: EMAIL#{address}` / `SK: SENT#{ts}#{msg_id}` — successful send record (90-day TTL)
- `PK: EMAIL#{address}` / `SK: BOUNCE#{ts}#{msg_id}` — bounce event (1-year TTL)
- `PK: EMAIL#{address}` / `SK: COMPLAINT#{ts}#{msg_id}` — complaint event (1-year TTL)
- `PK: SUPPRESS#{address}` / `SK: STATUS` — suppression record (no TTL — permanent until admin removes)

### 4.3 SES SNS notification flow

```
SES event (bounce/complaint/delivery)
    │
    ▼ AWS publishes to SNS topic ses-delivery-notifications
    │
    ▼ SNS HTTPS push to POST /internal/ses/notifications
    │
    ▼ ses_notifications.py receives and parses SNS envelope
    │
    ├── Type=SubscriptionConfirmation → GET SubscribeURL to confirm
    ├── Type=Notification/Bounce → record_email_bounce() → suppress hard bounces
    ├── Type=Notification/Complaint → record_email_complaint() → suppress all
    └── Type=Notification/Delivery → log + increment metric
```

The endpoint always returns HTTP 200 to prevent SNS retry storms, even if internal processing fails.

### 4.4 Prometheus metrics

```python
# app/metrics.py — add after existing counters (~line 95)
EMAIL_SENT     = Counter("email_sent_total", "Emails successfully sent via SES")
EMAIL_FAILED   = Counter("email_failed_total", "Email send failures")
EMAIL_BOUNCED  = Counter("email_bounced_total", "SES bounces", ["bounce_type"])
EMAIL_COMPLAINED = Counter("email_complained_total", "SES complaints")
EMAIL_SUPPRESSED = Counter("email_suppressed_total", "Emails skipped (suppressed)", ["reason"])
```

The `noop` pattern for non-production (`app/metrics.py:26–55`) means these counters are harmless when Prometheus is not configured.

### 4.5 Admin endpoints (app/routers/admin_email.py — confirmed exists)

Uses `require_admin_or_root` from `app/auth/policy.py` (line 67):

- `GET /ui/admin/email/stats?days=7` — delivery stats (sent, bounced, complained, failed, suppressed, rates)
- `GET /ui/admin/email/bounces?limit=50` — paginated bounce list
- `GET /ui/admin/email/complaints?limit=50` — paginated complaint list
- `GET /ui/admin/email/suppressed?limit=50` — suppression list
- `DELETE /ui/admin/email/suppressed/{email}` — remove suppression (admin override)

### 4.6 Dev/Prod parity (SECOPS-007)

- In dev (`S.dev_mode = True`): `send_alert_email()` writes to `.logs/dev/emails.log` via `_write_dev_log()`. Returns `f"dev-{now_ts()}"` as a fake MessageId so callers can log it.
- In prod: real SES call; returns actual SES MessageId.
- Suppression check (`is_suppressed()`): calls DDB in both modes — DDB Local in dev, production DDB in prod.
- SES notification endpoint: registered in both dev and prod; in dev it can be tested by POSTing directly to `POST /internal/ses/notifications` with a crafted SNS payload (see `curl` examples in the ticket).
- The `email_delivery` DDB table is created by `scripts/local-ddb-init.py` for dev; Terraform/CloudFormation for prod.
- `ALERTS_EMAIL_ENABLED` defaults to `"0"` in `.env.local.example` (dev email is disabled; use dev log for testing). Staging sets `ALERTS_EMAIL_ENABLED=1` after SES domain verification.

### 4.7 Staging SES setup checklist

1. Verify sender domain in SES console (adds DKIM CNAME records to DNS)
2. Add SPF TXT record: `v=spf1 include:amazonses.com ~all`
3. Add DMARC TXT record: `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com`
4. Create SNS topic `ses-delivery-notifications` in the same region
5. Configure SES to publish Bounce + Complaint + Delivery events to the topic
6. Subscribe `https://staging.example.com/internal/ses/notifications` to the SNS topic
7. First POST to the endpoint will be a `SubscriptionConfirmation` — the endpoint auto-fetches `SubscribeURL`
8. Request SES production access (exit sandbox) before sending to non-verified addresses

### 4.8 Alternatives considered

- **SNS directly for email delivery**: SES over SNS would add an extra hop. Rejected — SES direct API is simpler and already used by `aws.py`.
- **SQS for async email delivery**: Would decouple email sending from the alert path, preventing slow SES calls from blocking alert writes. Deferred for high-volume scenarios; the current synchronous path is acceptable at the expected alert rates (< 100/day per user).
- **Third-party email service (SendGrid, Mailgun)**: Would add an external dependency and billing relationship. Rejected — SES is already the AWS-native choice.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (tests/test_email_delivery.py)

| # | Test | What to assert |
|---|---|---|
| 1 | `test_send_logs_failure_not_silent` | `logger.exception()` called when `ses.send_email()` raises |
| 2 | `test_send_returns_message_id` | Mock SES returns MessageId; function returns it |
| 3 | `test_send_disabled_returns_none` | `alerts_email_enabled=False` → `None` |
| 4 | `test_ses_client_reused` | `_get_ses_client()` returns same object on second call |
| 5 | `test_record_sent_writes_ddb` | DDB item with `status="sent"`, `message_id`, `to_email` |
| 6 | `test_bounce_suppresses_hard` | Permanent bounce → `SUPPRESS#{email}` item created |
| 7 | `test_bounce_skips_transient` | Transient bounce → no SUPPRESS item |
| 8 | `test_complaint_suppresses_all` | Complaint → SUPPRESS item for each recipient |
| 9 | `test_is_suppressed_true_after_suppress` | `suppress_email()` + `is_suppressed()` → True |
| 10 | `test_is_suppressed_fails_open` | DDB error in `is_suppressed()` → returns False |
| 11 | `test_send_skips_suppressed_addresses` | Suppressed email not in SES `Destination.ToAddresses` |
| 12 | `test_ses_notification_bounce_200` | POST bounce JSON → 200; bounce recorded in DDB |
| 13 | `test_ses_notification_complaint_200` | POST complaint JSON → 200; complaint + suppression recorded |
| 14 | `test_ses_notification_subscription_confirm` | POST SubscriptionConfirmation → 200 (without network call in test) |
| 15 | `test_admin_stats_requires_admin_role` | Alice (USER) → 403 |
| 16 | `test_admin_unsuppress_removes_record` | DELETE → `is_suppressed()` returns False |

All use moto-mocked DDB via `tests/conftest.py`.

### 5.2 Playwright E2E tests (frontend/e2e/email-delivery.spec.ts)

18 tests across 4 sections:

- Section 1 (6): Delivery API — stats endpoint returns `sent/bounced/complained`; `days=30` parameter; bounces list; complaints list; suppressed list; non-admin gets 403.
- Section 2 (4): SES notification webhook — POST bounce JSON → 200; complaint → 200; delivery → 200; SNS subscription confirmation → 200.
- Section 3 (3): Suppression — unsuppress an address; unsuppress idempotent (unknown address → 200); suppressed list reflects change.
- Section 4 (5): Admin UI — page loads with "Email Delivery" heading; stats cards show sent/bounced/complained; bounce rate percentage visible; bounce table headers; complaint table headers.

Auth: root identity for admin tests; `injectAuth(page, "root")` + CSRF header.

### 5.3 Manual verification of dev-mode email logging

```bash
# In dev mode (DEV_MODE=1, ALERTS_EMAIL_ENABLED=0):
# Trigger a security alert (e.g., login from new IP) and verify:
cat .logs/dev/emails.log   # should show [timestamp] TO=... entries
```

### 5.4 Staging verification

```bash
# After enabling ALERTS_EMAIL_ENABLED=1 in staging:
curl -s -b cookies.txt -H "x-csrf-token: $CSRF" \
  https://staging.example.com/ui/admin/email/stats?days=1
# After sending a test alert email:
# Verify "sent" count increments
# Trigger a bounce by sending to bounce-test address (SES provides simulator: bounce@simulator.amazonses.com)
# Verify bounce appears in /ui/admin/email/bounces and address in /ui/admin/email/suppressed
```

### 5.5 Observability and alerts

| Alert | Condition | Severity |
|---|---|---|
| Bounce rate > 2% | `email_bounced_total / email_sent_total > 0.02` (1h rate) | Warning |
| Complaint rate > 0.05% | `email_complained_total / email_sent_total > 0.0005` (1h rate) | Critical |
| Email failures | `rate(email_failed_total[5m]) > 0` | Warning |
| SES client errors | Any `email_failed_total` increment | Immediate investigation |

### 5.6 Rollout plan

| Phase | Action | Risk |
|---|---|---|
| 1 | Deploy improved `send_alert_email()` with logging + tracking | Low — same external behaviour; dev_mode path unchanged |
| 2 | Deploy `email_delivery` DDB table + `ses_notifications` router | Low — no-op until SES is configured |
| 3 | Enable `ALERTS_EMAIL_ENABLED=1` in staging; configure SES | Medium — real emails sent in staging; SES sandbox limits to verified addresses |
| 4 | Subscribe SNS notification endpoint; verify bounce/complaint handling | Medium — test with SES simulator addresses |
| 5 | Enable in production; request SES production access (exit sandbox) | High — real user emails; monitor bounce/complaint rates daily for first week |

**Rollback**: Set `ALERTS_EMAIL_ENABLED=0`. All email delivery stops; DDB records and suppression list preserved.

**Effort**: M (8–10 days as estimated; infrastructure largely in place, primary remaining work is `send_alert_email()` refactor + metrics + SES staging setup).
