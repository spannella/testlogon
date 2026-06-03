# ADMIN-002: Admin Email/SMS Dashboards

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Dependencies**: Email delivery (`email_delivery.py` — see `app/services/email_delivery.py`), SMS delivery (`sms_delivery.py` — see `app/services/sms_delivery.py`), admin email router (`admin_email.py` — see `app/routers/admin_email.py`, prefix `/ui/admin/email`, registered in `app/main.py:162,439`), admin SMS router (`admin_sms.py` — see `app/routers/admin_sms.py`, prefix `/ui/admin/sms`, registered in `app/main.py:161,438`), admin auth (`auth/policy.py` — see `app/auth/policy.py`)
<!-- NOTE: `require_admin_session` does not exist in auth/deps.py. The admin email and SMS routers use `require_admin_or_root` from `app/auth/policy.py:67`. -->

---

## 1. Overview & Motivation

### The Gap

The platform sends emails and SMS messages for notifications, verification codes, password resets, and alerts. The backend has comprehensive delivery tracking services:

- **Email** (`email_delivery.py`): `record_email_sent`, `record_email_bounce`, `record_email_complaint`, `get_delivery_stats`, `list_deliveries`, `list_bounces`, `list_complaints`, `get_suppression_list`, `suppress_email`, `remove_suppression`
- **SMS** (`sms_delivery.py`): `record_sms_sent`, `record_sms_failure`, `get_sms_delivery_stats`, `list_sms_deliveries`, `list_sms_failures`, `get_suppression_list`, `suppress_sms`, `remove_sms_suppression`
- **Admin email router** (`admin_email.py`): Stats, deliveries, bounces, complaints, suppression management, template preview, dev log

However, there is no admin-facing dashboard UI that visualizes these metrics. The API endpoints exist but are not consumed by any frontend page. Admins must use raw API calls or the Swagger UI to check delivery health. There is also no notification template management UI.
<!-- NOTE: An SMS admin router DOES already exist at app/routers/admin_sms.py (prefix /ui/admin/sms, registered in app/main.py:161,438). It provides stats, deliveries, failures, suppression CRUD, and dev log endpoints using require_admin_or_root auth. The claim "no SMS admin router" is incorrect. -->

### Why This Is Needed

1. **Delivery monitoring**: If the email provider starts silently dropping messages (e.g., due to IP reputation), admins need to see delivery rates plummet in real-time — not discover it days later when users complain about missing verification codes.

2. **Bounce management**: Email bounces degrade sender reputation. A dashboard showing bounce trends helps admins identify problematic user cohorts (e.g., typo-heavy domains) and clean the list proactively.

3. **Suppression management**: Users who mark emails as spam or whose addresses bounce must be suppressed. Admins need to view, add, and remove suppressions — currently possible only via API calls.

4. **SMS cost visibility**: SMS messages cost money per segment. A dashboard showing daily SMS volume, segment counts, and failure rates helps manage SMS spending.

5. **Template management**: Notification templates (email subjects, body HTML, SMS text) are currently hardcoded or stored in template files. An admin UI for viewing and editing templates reduces engineering involvement for copy changes.

6. **Test send**: Before changing a template, admins need to send a test notification to verify formatting — currently impossible without code changes.

### User Stories

- As a **platform admin**, I want to see email delivery rates over time so I can detect delivery issues early.
- As a **platform admin**, I want to view bounce and complaint details so I can identify problematic addresses.
- As a **platform admin**, I want to manage the email suppression list so I can suppress or unsuppress addresses.
- As a **platform admin**, I want to see SMS delivery statistics so I can monitor SMS spending.
- As a **platform admin**, I want to view and edit notification templates so I can update copy without engineering.
- As a **platform admin**, I want to send a test notification so I can verify template formatting.

### Architecture After This Change

```
Admin Communications Dashboard (/admin/communications)
│
├── Email Tab
│   ├── KPI Cards
│   │   ├── Total Sent (7d)
│   │   ├── Delivery Rate %
│   │   ├── Bounce Rate %
│   │   └── Complaint Rate %
│   │
│   ├── Delivery Chart (line, daily)
│   │   ├── Sent
│   │   ├── Delivered
│   │   ├── Bounced
│   │   └── Complained
│   │
│   ├── Bounce Drilldown
│   │   ├── Bounce type distribution (hard/soft)
│   │   ├── Top bouncing domains
│   │   └── Recent bounces table
│   │
│   ├── Complaint Drilldown
│   │   ├── Recent complaints table
│   │   └── Complaint source (FBL provider)
│   │
│   └── Suppression List
│       ├── Search/filter
│       ├── Add suppression
│       └── Remove suppression
│
├── SMS Tab
│   ├── KPI Cards
│   │   ├── Total Sent (7d)
│   │   ├── Delivery Rate %
│   │   ├── Failure Rate %
│   │   └── Total Segments
│   │
│   ├── Delivery Chart (line, daily)
│   │
│   ├── Failure Drilldown
│   │   ├── Error type distribution
│   │   └── Recent failures table
│   │
│   └── SMS Suppression List
│
├── Templates Tab
│   ├── Template list (email + SMS)
│   ├── Template editor (name, subject, body)
│   ├── Preview (rendered HTML / plain text)
│   └── Test send button
│
└── Dev Log Tab (dev mode only)
    ├── Recent dev-mode emails
    └── Recent dev-mode SMS
```

### Architecture & Data Flow

```
┌─────────────┐    ┌─────────────────┐    ┌────────────────────┐
│   Admin UI   │───▶│  FastAPI Router  │───▶│  DynamoDB Tables   │
│  (React +    │    │  admin_email.py  │    │  email_delivery    │
│   shadcn/ui) │    │  admin_sms.py    │    │  sms_delivery      │
│              │    │  admin_notif.py  │    │  notification_tmpl  │
└──────┬───────┘    └────────┬────────┘    └────────────────────┘
       │                     │
       │   GET /stats        │   get_delivery_stats()
       │   GET /deliveries   │   list_deliveries()
       │   GET /bounces      │   list_bounces()
       │   POST /suppressed  │   suppress_email()
       │                     │
       ▼                     ▼
┌─────────────┐    ┌─────────────────┐
│  React Query │    │  Service Layer   │
│  useQuery()  │    │  email_delivery  │
│  useMutation │    │  sms_delivery    │
│              │    │  notif_templates │
└─────────────┘    └─────────────────┘

Request Flow — Email Stats:
  Browser → GET /v1/admin/email/stats?days=7
         → require_admin_or_root (cookie auth + CSRF check)
         → get_delivery_stats(days=7)
         → DynamoDB Query: PK=EMAIL_STATS, SK between date range
         → aggregate sent/delivered/bounced/complained
         → return EmailStatsOut JSON

Request Flow — Template Test Send:
  Browser → POST /v1/admin/notifications/templates/{id}/test-send
         → require_admin_or_root (CSRF enforced)
         → notification_templates.test_send(id, recipient, sample_vars)
         → render template with sample_vars
         → email_delivery.send_email() or sms_delivery.send_sms()
         → record as test_send in delivery log
         → return {ok: true, channel: "email", recipient: "admin@test.local"}
```

---

## 2. Current State Analysis

### 2.1 Email Delivery Service (`app/services/email_delivery.py`)

Key functions (verified):
- `get_delivery_stats(days=7)` (line 221): Returns counts for sent, delivered, bounced, complained, failed
- `list_deliveries(limit, cursor)` (line 284): Paginated delivery list
- `list_bounces(limit, cursor)` (line 316): Paginated bounce list
- `list_complaints(limit, cursor)` (line 337): Paginated complaint list
- `get_suppression_list(limit)` (line 358): Suppressed addresses
- `suppress_email(email, reason)` (line 175): Add to suppression list
- `remove_suppression(email)` (line 205): Remove from suppression list
- `is_suppressed(email)` (line 193): Check suppression status
- `read_dev_email_log(max_entries)` (line 373): Dev mode log

### 2.2 SMS Delivery Service (`app/services/sms_delivery.py`)

Key functions (verified):
- `get_sms_delivery_stats(days=7)` (line 226): SMS delivery statistics
- `list_sms_deliveries(limit, cursor)` (line 302): SMS delivery list
- `list_sms_failures(limit)` (line 324): SMS failure list
- `get_suppression_list(limit)` (line 331): Suppressed phone numbers
- `suppress_sms(phone, reason)` (line 148): Add to suppression
- `remove_sms_suppression(phone)` (line 179): Remove suppression
- `get_dev_sms_log()` (line 344): Dev mode log

### 2.3 Admin Email Router (`app/routers/admin_email.py`)

Existing endpoints (prefix `/ui/admin/email`, auth: `require_admin_or_root` from `app/auth/policy.py:67`):
- `GET /stats` (line 26): Email statistics — `email_stats()`
- `GET /deliveries` (line 35): Delivery list — `email_deliveries()`
- `GET /bounces` (line 47): Bounce list — `email_bounces()`
- `GET /complaints` (line 58): Complaint list — `email_complaints()`
- `GET /suppressed` (line 69): Suppression list — `suppressed_emails()`
- `DELETE /suppressed/{email}` (line 78): Remove suppression — `unsuppress_email()`
- `GET /preview` (line 88): Template preview — `email_preview()`
- `GET /dev-log` (line 113): Dev email log — `dev_email_log()`

### 2.3b Admin SMS Router (`app/routers/admin_sms.py`)

<!-- NOTE: This router already exists, contrary to the Gap section claim. -->
Existing endpoints (prefix `/ui/admin/sms`, auth: `require_admin_or_root` from `app/auth/policy.py:67`, registered in `app/main.py:161,438`):
- `GET /stats` (line 24): SMS statistics — `sms_stats()`
- `GET /deliveries` (line 33): SMS delivery list — `sms_deliveries()`
- `GET /failures` (line 45): SMS failure list — `sms_failures()`
- `GET /suppressed` (line 56): Suppression list — `suppressed_list()`
- `GET /suppressed/{phone}` (line 65): Check suppression — `check_suppression()`
- `POST /suppressed` (line 74): Add suppression — `suppress_phone()`
- `DELETE /suppressed/{phone}` (line 84): Remove suppression — `unsuppress_phone()`
- `GET /dev-log` (line 94): Dev SMS log — `dev_log()`

### 2.4 Email Templates (`app/services/alert_email_templates.py`)

Template functions for different notification types (see `app/services/alert_email_templates.py` — file exists). Templates are Python functions returning HTML strings — not yet stored in DDB for dynamic editing.

### 2.5 Gaps

1. No admin dashboard UI for email delivery metrics
2. No admin dashboard UI for SMS delivery metrics
3. ~~No SMS admin router (only email has one)~~ — **CORRECTED**: An SMS admin router already exists at `app/routers/admin_sms.py` with 8 endpoints (see section 2.3b above)
4. No notification template management UI
5. No test send functionality (send test notification to specific address)
6. No delivery rate charts over time
7. No bounce/complaint drilldown visualizations

---

## 3. Technical Design

### 3.1 SMS Admin Router: `app/routers/admin_sms.py`

<!-- NOTE: This router already exists at app/routers/admin_sms.py with prefix /ui/admin/sms (line 20), registered in app/main.py:161,438. It already has 8 endpoints using require_admin_or_root. The paths below should use /ui/admin/sms/ prefix (not /v1/admin/sms/) to match the existing implementation. -->

Existing endpoints (already implemented):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/sms/stats` | `require_admin_or_root` | SMS delivery stats (line 24) |
| GET | `/ui/admin/sms/deliveries` | `require_admin_or_root` | SMS delivery list (line 33) |
| GET | `/ui/admin/sms/failures` | `require_admin_or_root` | SMS failure list (line 45) |
| GET | `/ui/admin/sms/suppressed` | `require_admin_or_root` | Suppression list (line 56) |
| GET | `/ui/admin/sms/suppressed/{phone}` | `require_admin_or_root` | Check suppression (line 65) |
| POST | `/ui/admin/sms/suppressed` | `require_admin_or_root` | Add suppression (line 74) |
| DELETE | `/ui/admin/sms/suppressed/{phone}` | `require_admin_or_root` | Remove suppression (line 84) |
| GET | `/ui/admin/sms/dev-log` | `require_admin_or_root` | Dev SMS log (line 94) |

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / GSI | Query Type | Example |
|---------------|-------|-----|----------|------------|---------|
| Get email stats by period | `email_delivery` | `EMAIL_STATS` | SK between `DATE#2026-05-22` and `DATE#2026-05-29` | Query (range) | 7-day delivery stats aggregation |
| List email deliveries (paginated) | `email_delivery` | `EMAIL_DELIVERY` | SK descending, Limit=50 | Query (paginated) | Recent 50 deliveries with cursor |
| List bounces by date | `email_delivery` | `EMAIL_BOUNCE` | SK descending | Query | Recent bounces for bounce drilldown |
| List complaints | `email_delivery` | `EMAIL_COMPLAINT` | SK descending | Query | Recent complaints for complaint drilldown |
| Get suppression list | `email_delivery` | `EMAIL_SUPPRESSED` | SK begins_with `ADDR#` | Query (scan) | All suppressed email addresses |
| Check single suppression | `email_delivery` | `EMAIL_SUPPRESSED` | SK = `ADDR#{email}` | GetItem | Is this email suppressed? |
| Add suppression | `email_delivery` | `EMAIL_SUPPRESSED` | SK = `ADDR#{email}` | PutItem | Suppress spam@test.local |
| Remove suppression | `email_delivery` | `EMAIL_SUPPRESSED` | SK = `ADDR#{email}` | DeleteItem | Unsuppress false positive |
| Get SMS stats by period | `sms_delivery` | `SMS_STATS` | SK between date range | Query (range) | 7-day SMS delivery stats |
| List SMS deliveries | `sms_delivery` | `SMS_DELIVERY` | SK descending, Limit=50 | Query (paginated) | Recent SMS deliveries |
| List SMS failures | `sms_delivery` | `SMS_FAILURE` | SK descending | Query | Recent SMS failures |
| SMS suppression CRUD | `sms_delivery` | `SMS_SUPPRESSED` | SK = `PHONE#{phone}` | GetItem/PutItem/DeleteItem | Manage phone suppressions |
| List templates | `notification_templates` | `TEMPLATE#{id}` | SK = `META` | Scan (all templates) | All notification templates |
| Get single template | `notification_templates` | `TEMPLATE#{id}` | SK = `META` | GetItem | Template by ID |
| Update template | `notification_templates` | `TEMPLATE#{id}` | SK = `META` | UpdateItem | Update body/subject |

### 3.3 Template Management

**Template storage table**: `notification_templates`

```python
TableDef(
    name="notification_templates",
    pk="pk", sk="sk",
    gsis=[],
)
```

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `TEMPLATE#{template_id}` |
| `sk` | S | `META` |
| `template_id` | S | Unique template ID (e.g., `email_welcome`, `sms_verification`) |
| `channel` | S | `"email"` or `"sms"` |
| `name` | S | Human-readable name |
| `subject` | S | Email subject line (email only) |
| `body` | S | Template body (HTML for email, plain text for SMS) |
| `variables` | L | List of available template variables (e.g., `{{user_name}}`) |
| `active` | BOOL | Whether template is active |
| `updated_at` | N | Last update timestamp |
| `updated_by` | S | Admin who last updated |

### 3.4 Template Management Service: `app/services/notification_templates.py`
<!-- NOTE: app/services/notification_templates.py does not exist yet — new implementation required. The notification_templates DDB table also does not exist in scripts/local-ddb-init.py and must be created. No notification_templates_table_name setting exists in app/core/settings.py, and no table handle in app/core/tables.py. -->

```python
"""Notification template management (ADMIN-002).

CRUD for email and SMS notification templates.
Supports template preview and test send.
"""

def list_templates(
    *, channel: str = None
) -> List[Dict[str, Any]]:
    """List all notification templates."""
    ...

def get_template(template_id: str) -> Dict[str, Any]:
    """Get template by ID."""
    ...

def update_template(
    template_id: str, *, admin_sub: str, **updates
) -> Dict[str, Any]:
    """Update template content.

    Only subject and body are editable by admins.
    template_id and channel are immutable.
    """
    ...

def preview_template(
    template_id: str, *, sample_vars: Dict[str, str] = None
) -> Dict[str, Any]:
    """Render template with sample variables for preview."""
    ...

def test_send(
    template_id: str, *, recipient: str, admin_sub: str,
    sample_vars: Dict[str, str] = None
) -> Dict[str, Any]:
    """Send a test notification to a specific recipient.

    Uses the template's channel (email or SMS) to determine
    delivery method. Logs as a test send.
    """
    ...

def seed_default_templates() -> None:
    """Seed default templates from alert_email_templates.py.

    Called once at initialization to populate DDB from
    hardcoded templates.
    """
    ...
```

### 3.5 Template & Test Send Router
<!-- NOTE: app/routers/admin_notifications.py does not exist yet — new implementation required. -->

Extend admin email router or create new combined router:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/notifications/templates` | `require_admin_or_root` | List templates |
| GET | `/v1/admin/notifications/templates/{id}` | `require_admin_or_root` | Get template |
| PATCH | `/v1/admin/notifications/templates/{id}` | `require_admin_or_root` | Update template |
| POST | `/v1/admin/notifications/templates/{id}/preview` | `require_admin_or_root` | Preview template |
| POST | `/v1/admin/notifications/templates/{id}/test-send` | `require_admin_or_root` | Test send |

### 3.6 API Request/Response Examples

**GET /ui/admin/email/stats?days=7**
<!-- NOTE: The actual router prefix is /ui/admin/email (see admin_email.py:22), not /v1/admin/email. All email admin API paths below should use /ui/admin/email/. -->

```json
// Request
GET /ui/admin/email/stats?days=7
Cookie: ui_session=...; ui_access_token=...; ui_csrf=...
x-csrf-token: <csrf_token>

// Response 200
{
  "sent": 4521,
  "delivered": 4389,
  "bounced": 87,
  "complained": 12,
  "failed": 33,
  "delivery_rate": 97.08,
  "bounce_rate": 1.92,
  "complaint_rate": 0.27,
  "period_days": 7
}
```

**GET /ui/admin/email/deliveries?limit=5**

```json
// Response 200
{
  "items": [
    {
      "delivery_id": "del_a1b2c3d4e5f6",
      "recipient": "user@example.com",
      "subject": "Your verification code",
      "template_id": "email_verification",
      "status": "delivered",
      "sent_at": 1748500000,
      "delivered_at": 1748500003,
      "provider_response": "250 OK"
    }
  ],
  "next_cursor": "eyJsYXN0X2tleS..."
}
```

**GET /ui/admin/email/bounces?limit=5**

```json
// Response 200
{
  "items": [
    {
      "bounce_id": "bnc_f7g8h9i0j1k2",
      "recipient": "bad_address@typo.com",
      "bounce_type": "hard",
      "bounce_subtype": "permanent",
      "diagnostic": "550 5.1.1 User unknown",
      "bounced_at": 1748499800,
      "original_subject": "Welcome to the platform"
    }
  ],
  "next_cursor": null
}
```

**POST /ui/admin/email/suppressed**
<!-- NOTE: The existing admin_email.py does not have a POST endpoint for adding suppressions. Only DELETE /suppressed/{email} exists. A POST endpoint would need to be added. -->

```json
// Request
{
  "address": "spam@test.local",
  "reason": "repeated spam complaints"
}

// Response 200
{
  "ok": true,
  "address": "spam@test.local",
  "reason": "repeated spam complaints",
  "suppressed_at": 1748500100,
  "suppressed_by": "root.admin@testdev.local"
}
```

**DELETE /ui/admin/email/suppressed/spam@test.local**

```json
// Response 200
{
  "ok": true,
  "address": "spam@test.local",
  "removed_at": 1748500200
}
```

**GET /ui/admin/sms/stats?days=7**

```json
// Response 200
{
  "sent": 1283,
  "delivered": 1204,
  "failed": 79,
  "total_segments": 1547,
  "delivery_rate": 93.84,
  "failure_rate": 6.16,
  "period_days": 7
}
```

**GET /ui/admin/sms/failures?limit=5**

```json
// Response 200
{
  "items": [
    {
      "failure_id": "smf_k3l4m5n6o7p8",
      "phone": "+15559876543",
      "error_type": "invalid_number",
      "error_message": "The number is not a valid mobile number",
      "attempted_at": 1748499600,
      "template_id": "sms_verification",
      "segments": 1
    }
  ],
  "next_cursor": null
}
```

**GET /v1/admin/notifications/templates**

```json
// Response 200
[
  {
    "template_id": "email_welcome",
    "channel": "email",
    "name": "Welcome Email",
    "subject": "Welcome to {{platform_name}}!",
    "body": "<h1>Welcome, {{user_name}}!</h1><p>Thanks for joining...</p>",
    "variables": ["user_name", "platform_name", "login_url"],
    "active": true,
    "updated_at": 1748400000,
    "updated_by": "root.admin@testdev.local"
  },
  {
    "template_id": "sms_verification",
    "channel": "sms",
    "name": "SMS Verification Code",
    "subject": null,
    "body": "Your verification code is {{code}}. Expires in {{expires_minutes}} minutes.",
    "variables": ["code", "expires_minutes"],
    "active": true,
    "updated_at": 1748400000,
    "updated_by": null
  }
]
```

**PATCH /v1/admin/notifications/templates/email_welcome**

```json
// Request
{
  "subject": "Welcome aboard, {{user_name}}!",
  "body": "<h1>Hey {{user_name}},</h1><p>We're excited to have you...</p>"
}

// Response 200
{
  "template_id": "email_welcome",
  "channel": "email",
  "name": "Welcome Email",
  "subject": "Welcome aboard, {{user_name}}!",
  "body": "<h1>Hey {{user_name}},</h1><p>We're excited to have you...</p>",
  "variables": ["user_name", "platform_name", "login_url"],
  "active": true,
  "updated_at": 1748500300,
  "updated_by": "root.admin@testdev.local"
}
```

**POST /v1/admin/notifications/templates/email_welcome/preview**

```json
// Request
{
  "sample_vars": {
    "user_name": "Alice",
    "platform_name": "TestPlatform",
    "login_url": "https://app.example.com/login"
  }
}

// Response 200
{
  "template_id": "email_welcome",
  "channel": "email",
  "rendered_subject": "Welcome aboard, Alice!",
  "rendered_body": "<h1>Hey Alice,</h1><p>We're excited to have you...</p>",
  "missing_vars": []
}
```

**POST /v1/admin/notifications/templates/email_welcome/test-send**

```json
// Request
{
  "recipient": "admin@test.local",
  "sample_vars": {
    "user_name": "TestAdmin",
    "platform_name": "TestPlatform",
    "login_url": "https://app.example.com/login"
  }
}

// Response 200
{
  "ok": true,
  "template_id": "email_welcome",
  "channel": "email",
  "recipient": "admin@test.local",
  "sent_at": 1748500400
}
```

### 3.7 Pydantic Models (`app/models.py`)

```python
class EmailStatsOut(BaseModel):
    sent: int
    delivered: int
    bounced: int
    complained: int
    failed: int
    delivery_rate: float = Field(ge=0.0, le=100.0)
    bounce_rate: float = Field(ge=0.0, le=100.0)
    complaint_rate: float = Field(ge=0.0, le=100.0)
    period_days: int = Field(ge=1, le=365)

    @field_validator("delivery_rate", "bounce_rate", "complaint_rate", mode="before")
    @classmethod
    def round_rates(cls, v):
        if isinstance(v, (int, float)):
            return round(float(v), 2)
        return v

class SmsStatsOut(BaseModel):
    sent: int
    delivered: int
    failed: int
    total_segments: int
    delivery_rate: float = Field(ge=0.0, le=100.0)
    failure_rate: float = Field(ge=0.0, le=100.0)
    period_days: int = Field(ge=1, le=365)

    @field_validator("delivery_rate", "failure_rate", mode="before")
    @classmethod
    def round_rates(cls, v):
        if isinstance(v, (int, float)):
            return round(float(v), 2)
        return v

class SuppressionAdd(BaseModel):
    address: str = Field(min_length=1, max_length=320)
    reason: str = Field(default="manual", max_length=200)

    @field_validator("address", mode="before")
    @classmethod
    def normalize_address(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v

class TemplateOut(BaseModel):
    template_id: str
    channel: str
    name: str
    subject: Optional[str] = None
    body: str
    variables: List[str]
    active: bool
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None

class TemplateUpdate(BaseModel):
    subject: Optional[str] = Field(default=None, max_length=200)
    body: Optional[str] = Field(default=None, max_length=10000)
    active: Optional[bool] = None

    @field_validator("body", mode="before")
    @classmethod
    def strip_script_tags(cls, v):
        """Prevent executable scripts in template body."""
        if isinstance(v, str):
            import re
            return re.sub(r"<script[^>]*>.*?</script>", "", v, flags=re.DOTALL | re.IGNORECASE)
        return v

class TemplatePreviewRequest(BaseModel):
    sample_vars: Dict[str, str] = Field(default_factory=dict)

class TemplateTestSend(BaseModel):
    recipient: str = Field(min_length=1, max_length=320)
    sample_vars: Dict[str, str] = Field(default_factory=dict)

    @field_validator("recipient", mode="before")
    @classmethod
    def normalize_recipient(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v
```

### 3.8 Error Handling Matrix

| Scenario | HTTP Status | Error Message | Recovery Action |
|----------|-------------|---------------|-----------------|
| Non-admin user accesses any endpoint | 403 | "Forbidden: admin role required" | Redirect to login or escalate role |
| Invalid `days` parameter (< 1 or > 365) | 422 | "days must be between 1 and 365" | Correct the query parameter |
| Suppression address is empty | 422 | "address must have at least 1 character" | Provide a valid email/phone |
| Suppression address too long (> 320 chars) | 422 | "address must have at most 320 characters" | Shorten the address |
| Duplicate suppression add | 200 | Idempotent — returns existing record | No action needed |
| Remove non-existent suppression | 404 | "Address not found in suppression list" | Verify the address spelling |
| Template not found | 404 | "Template not found: {template_id}" | Check template ID exists |
| Template body too long (> 10000 chars) | 422 | "body must have at most 10000 characters" | Shorten the template body |
| Template body contains `<script>` tags | 200 | Tags silently stripped by validator | Re-check body after save |
| Test send to invalid email format | 422 | "Invalid email format" | Provide a valid email address |
| Test send rate limit exceeded (> 10/hr) | 429 | "Too many test sends. Limit: 10 per hour." | Wait and retry |
| SMS suppression phone format invalid | 422 | "Phone must be in E.164 format (+1234567890)" | Provide E.164 formatted number |
| Template preview with missing variables | 200 | Response includes `missing_vars` array | Provide all required sample_vars |
| DynamoDB read timeout on stats query | 500 | "Internal server error" | Retry request; check DDB health |
| Dev log endpoint in non-dev mode | 404 | "Dev log not available in production" | Only accessible in dev mode |

### 3.9 Frontend: Communications Dashboard

**Route**: `/admin/communications` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/communications/CommunicationsDashboard.tsx`

#### Frontend Component Tree

```
CommunicationsDashboard
├── Tabs (shadcn/ui)
│   ├── TabsTrigger "Email"
│   ├── TabsTrigger "SMS"
│   ├── TabsTrigger "Templates"
│   └── TabsTrigger "Dev Log" (conditional: devMode)
│
├── TabsContent "email"
│   ├── KpiCardRow
│   │   ├── KpiCard (title="Sent (7d)", value={emailStats.sent})
│   │   ├── KpiCard (title="Delivery Rate", value, variant="default")
│   │   ├── KpiCard (title="Bounce Rate", value, variant="warning")
│   │   └── KpiCard (title="Complaint Rate", value, variant="danger")
│   ├── DeliveryChart (data={emailDeliveries})
│   ├── div.grid
│   │   ├── BounceTable (data={bounces}, onLoadMore)
│   │   └── ComplaintTable (data={complaints}, onLoadMore)
│   └── SuppressionSection
│       ├── SuppressionSearchBar (onSearch)
│       ├── AddSuppressionDialog (onAdd)
│       └── SuppressionTable (data={suppressions}, onRemove)
│
├── TabsContent "sms"
│   ├── SmsKpiCardRow
│   │   ├── KpiCard (title="Sent (7d)")
│   │   ├── KpiCard (title="Delivery Rate")
│   │   ├── KpiCard (title="Failure Rate", variant="danger")
│   │   └── KpiCard (title="Total Segments")
│   ├── SmsDeliveryChart (data={smsDeliveries})
│   ├── SmsFailureTable (data={smsFailures}, onLoadMore)
│   └── SmsSuppressionSection
│       ├── AddSmsSuppressionDialog (onAdd)
│       └── SmsSuppressionTable (data, onRemove)
│
├── TabsContent "templates"
│   ├── TemplateList (templates, onEdit, onPreview, onTestSend)
│   ├── TemplateEditDialog (template, onSave, open, onOpenChange)
│   ├── TemplatePreviewDialog (template, renderedHtml, open)
│   └── TestSendDialog (template, onSend, open, onOpenChange)
│
└── TabsContent "dev-log" (conditional)
    ├── DevEmailLog (entries={devEmails})
    └── DevSmsLog (entries={devSms})
```

#### TypeScript Props Interfaces

```typescript
interface KpiCardProps {
  title: string;
  value: string | number;
  variant?: "default" | "warning" | "danger";
  changePercent?: number;
  icon?: React.ComponentType;
}

interface DeliveryChartProps {
  data: Array<{
    date: string;
    sent: number;
    delivered: number;
    bounced: number;
    complained: number;
  }>;
  loading?: boolean;
}

interface BounceTableProps {
  data: Array<{
    bounce_id: string;
    recipient: string;
    bounce_type: "hard" | "soft";
    diagnostic: string;
    bounced_at: number;
  }>;
  onLoadMore?: () => void;
  hasMore?: boolean;
}

interface SuppressionTableProps {
  data: Array<{
    address: string;
    reason: string;
    suppressed_at: number;
    suppressed_by?: string;
  }>;
  onRemove: (address: string) => void;
}

interface TemplateListProps {
  templates: TemplateOut[];
  onEdit: (template: TemplateOut) => void;
  onPreview: (template: TemplateOut) => void;
  onTestSend: (template: TemplateOut) => void;
}

interface TemplateEditDialogProps {
  template: TemplateOut | null;
  onSave: (id: string, updates: TemplateUpdate) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface TestSendDialogProps {
  template: TemplateOut | null;
  onSend: (id: string, data: TemplateTestSend) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}
```

```tsx
<Tabs defaultValue="email">
  <TabsList>
    <TabsTrigger value="email">Email</TabsTrigger>
    <TabsTrigger value="sms">SMS</TabsTrigger>
    <TabsTrigger value="templates">Templates</TabsTrigger>
    {devMode && <TabsTrigger value="dev-log">Dev Log</TabsTrigger>}
  </TabsList>

  <TabsContent value="email">
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Sent (7d)" value={emailStats.sent} />
        <KpiCard title="Delivery Rate" value={`${emailStats.delivery_rate}%`} />
        <KpiCard title="Bounce Rate" value={`${emailStats.bounce_rate}%`} variant="warning" />
        <KpiCard title="Complaint Rate" value={`${emailStats.complaint_rate}%`} variant="danger" />
      </div>

      {/* Delivery chart */}
      <Card>
        <CardHeader><CardTitle>Email Delivery Trend</CardTitle></CardHeader>
        <CardContent><DeliveryChart data={emailDeliveries} /></CardContent>
      </Card>

      {/* Bounce and complaint tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle>Recent Bounces</CardTitle></CardHeader>
          <CardContent><BounceTable data={bounces} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Recent Complaints</CardTitle></CardHeader>
          <CardContent><ComplaintTable data={complaints} /></CardContent>
        </Card>
      </div>

      {/* Suppression management */}
      <Card>
        <CardHeader>
          <CardTitle>Email Suppression List</CardTitle>
          <Button size="sm" onClick={() => setShowAddSuppression(true)}>Add</Button>
        </CardHeader>
        <CardContent><SuppressionTable data={suppressions} onRemove={handleRemove} /></CardContent>
      </Card>
    </div>
  </TabsContent>

  <TabsContent value="sms">
    {/* Similar layout with SMS-specific stats */}
  </TabsContent>

  <TabsContent value="templates">
    <TemplateList
      templates={templates}
      onEdit={setEditTemplate}
      onPreview={handlePreview}
      onTestSend={handleTestSend}
    />
    <TemplateEditDialog template={editTemplate} onSave={handleSaveTemplate} />
    <TestSendDialog template={testSendTemplate} onSend={handleSendTest} />
  </TabsContent>
</Tabs>
```

### 3.10 Frontend API (`frontend/src/api/endpoints/adminCommunications.ts`)
<!-- NOTE: frontend/src/api/endpoints/adminCommunications.ts does not exist yet — new implementation required. Paths below corrected to use /ui/admin/ prefix to match existing routers. -->

```typescript
// Email — uses existing admin_email.py router (prefix /ui/admin/email)
export const getEmailStats = (params?: { days?: number }) =>
  client.get("/ui/admin/email/stats", { params });
export const getEmailDeliveries = (params?: { limit?: number }) =>
  client.get("/ui/admin/email/deliveries", { params });
export const getEmailBounces = (params?: { limit?: number }) =>
  client.get("/ui/admin/email/bounces", { params });
export const getEmailComplaints = (params?: { limit?: number }) =>
  client.get("/ui/admin/email/complaints", { params });
export const getEmailSuppressions = () =>
  client.get("/ui/admin/email/suppressed");
export const removeEmailSuppression = (email: string) =>
  client.delete(`/ui/admin/email/suppressed/${encodeURIComponent(email)}`);
export const addEmailSuppression = (data: { address: string; reason: string }) =>
  client.post("/ui/admin/email/suppressed", data);

// SMS — uses existing admin_sms.py router (prefix /ui/admin/sms)
export const getSmsStats = (params?: { days?: number }) =>
  client.get("/ui/admin/sms/stats", { params });
export const getSmsDeliveries = (params?: { limit?: number }) =>
  client.get("/ui/admin/sms/deliveries", { params });
export const getSmsFailures = (params?: { limit?: number }) =>
  client.get("/ui/admin/sms/failures", { params });
export const getSmsSuppressions = () =>
  client.get("/ui/admin/sms/suppressed");
export const addSmsSuppression = (data: { address: string; reason: string }) =>
  client.post("/ui/admin/sms/suppressed", data);
export const removeSmsSuppression = (phone: string) =>
  client.delete(`/ui/admin/sms/suppressed/${encodeURIComponent(phone)}`);

// Templates — new admin_notifications.py router (to be created)
export const listTemplates = (params?: { channel?: string }) =>
  client.get("/v1/admin/notifications/templates", { params });
export const getTemplate = (id: string) =>
  client.get(`/v1/admin/notifications/templates/${id}`);
export const updateTemplate = (id: string, data: TemplateUpdate) =>
  client.patch(`/v1/admin/notifications/templates/${id}`, data);
export const previewTemplate = (id: string, data: { sample_vars: Record<string, string> }) =>
  client.post(`/v1/admin/notifications/templates/${id}/preview`, data);
export const testSendTemplate = (id: string, data: TemplateTestSend) =>
  client.post(`/v1/admin/notifications/templates/${id}/test-send`, data);
```

---

## 4. Implementation Plan

### Phase 1: Backend — SMS Router (Days 1-2)

1. ~~**`app/routers/admin_sms.py`**: New router mirroring admin_email.py pattern, 7 endpoints.~~ — **Already exists** at `app/routers/admin_sms.py` with 8 endpoints (prefix `/ui/admin/sms`).
2. ~~**`app/main.py`**: Register SMS admin router.~~ — **Already registered** at `app/main.py:161,438`.
<!-- NOTE: Phase 1 is already complete. The SMS admin router exists and is registered. Skip to Phase 2. -->

### Phase 2: Backend — Template Management (Days 2-4)

3. **`scripts/local-ddb-init.py`**: Add `notification_templates` table.
4. **`app/core/settings.py`**: Add `notification_templates_table_name`.
5. **`app/core/tables.py`**: Add `notification_templates` table handle.
6. **`app/services/notification_templates.py`**: New file. Template CRUD, preview, test send.
7. **`app/routers/admin_notifications.py`**: New router with 5 endpoints.
8. **`app/main.py`**: Register notifications admin router.

### Phase 3: Backend Models (Day 4)

9. **`app/models.py`**: Add communication dashboard Pydantic models.

### Phase 4: Frontend (Days 5-8)

10. **`frontend/src/api/types.ts`**: Add TypeScript types.
11. **`frontend/src/api/endpoints/adminCommunications.ts`**: New file.
12. **`frontend/src/pages/admin/communications/CommunicationsDashboard.tsx`**: New page with email/SMS/templates tabs.
13. **`frontend/src/App.tsx`**: Add `/admin/communications` route.
14. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Communications" admin nav link.

### Phase 5: E2E Tests (Days 9-10)

15. **`frontend/e2e/admin-communications.spec.ts`**: 30 tests across 8 sections.

---

## 5. Observability

### 5.1 Metrics

| Metric Name | Type | Labels | Description |
|------------|------|--------|-------------|
| `admin_email_stats_requests_total` | counter | `admin_sub` | Times email stats endpoint was called |
| `admin_sms_stats_requests_total` | counter | `admin_sub` | Times SMS stats endpoint was called |
| `admin_suppression_add_total` | counter | `channel` (email/sms), `admin_sub` | Suppressions added by admins |
| `admin_suppression_remove_total` | counter | `channel`, `admin_sub` | Suppressions removed by admins |
| `admin_template_update_total` | counter | `template_id`, `admin_sub` | Template edits by admins |
| `admin_template_test_send_total` | counter | `channel`, `admin_sub` | Test sends triggered |
| `admin_template_preview_total` | counter | `template_id` | Template previews rendered |

### 5.2 Logging Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `admin_suppression_added` | INFO | `channel`, `address`, `reason`, `admin_sub` | Admin adds a suppression |
| `admin_suppression_removed` | INFO | `channel`, `address`, `admin_sub` | Admin removes a suppression |
| `admin_template_updated` | INFO | `template_id`, `channel`, `fields_changed`, `admin_sub` | Template content edited |
| `admin_template_test_sent` | INFO | `template_id`, `channel`, `recipient`, `admin_sub` | Test notification sent |
| `admin_template_test_rate_limited` | WARN | `admin_sub`, `count_in_window` | Admin hit test send rate limit |
| `admin_email_stats_queried` | DEBUG | `days`, `admin_sub` | Stats endpoint called |
| `admin_sms_stats_queried` | DEBUG | `days`, `admin_sub` | SMS stats endpoint called |

### 5.3 Alerting Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Email delivery rate drop | `delivery_rate < 90%` for 2 consecutive checks | HIGH | Notify platform admins via Slack/email |
| Bounce rate spike | `bounce_rate > 5%` for any 24h period | MEDIUM | Flag in dashboard, send admin alert |
| Complaint rate critical | `complaint_rate > 0.5%` for any 7d period | HIGH | Block further sends, notify admins |
| SMS failure rate spike | `failure_rate > 15%` for any 24h period | MEDIUM | Dashboard warning, check SMS provider |

---

## 6. Rollout Plan

### Phase 1: Backend Only (Feature Flag: `ADMIN_COMMS_DASHBOARD_ENABLED=false`)

| Step | Action | Validation |
|------|--------|------------|
| 1 | Deploy SMS admin router + notification template service | API tests pass; Swagger shows new endpoints |
| 2 | Seed default templates from `alert_email_templates.py` | `GET /v1/admin/notifications/templates` returns seeded templates |
| 3 | Run backend unit tests for new services | All template CRUD tests pass |

### Phase 2: Frontend (Feature Flag: `ADMIN_COMMS_DASHBOARD_ENABLED=true`)

| Step | Action | Validation |
|------|--------|------------|
| 4 | Deploy CommunicationsDashboard page | Route loads; tabs render |
| 5 | Wire email tab to existing admin_email endpoints | KPI cards show real stats |
| 6 | Wire SMS tab to new admin_sms endpoints | SMS stats display correctly |
| 7 | Wire templates tab to new admin_notifications endpoints | Template list, edit, preview all work |

### Phase 3: GA (Remove Feature Flag)

| Step | Action | Validation |
|------|--------|------------|
| 8 | Enable for all admin users | All 30 E2E tests pass |
| 9 | Monitor delivery rate alerts for false positives | Alert thresholds tuned |
| 10 | Remove feature flag, clean up conditional code | No regressions |

### Feature Flags Table

| Flag | Default | Purpose |
|------|---------|---------|
| `ADMIN_COMMS_DASHBOARD_ENABLED` | `false` | Gates visibility of `/admin/communications` route and sidebar link |
| `ADMIN_TEMPLATE_EDIT_ENABLED` | `true` | Allows template body/subject editing (can disable for read-only mode) |
| `ADMIN_TEST_SEND_ENABLED` | `true` | Allows test send functionality (can disable in production) |

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Endpoint | Target P50 | Target P99 | Notes |
|----------|-----------|-----------|-------|
| GET /email/stats | < 100ms | < 300ms | DDB query with date range filter |
| GET /email/deliveries | < 150ms | < 400ms | Paginated, Limit=50 |
| GET /email/bounces | < 150ms | < 400ms | Paginated |
| GET /email/suppressed | < 200ms | < 500ms | Scan with Limit |
| POST /email/suppressed | < 100ms | < 250ms | Single PutItem |
| DELETE /email/suppressed | < 100ms | < 250ms | Single DeleteItem |
| GET /sms/stats | < 100ms | < 300ms | DDB query with date range filter |
| GET /templates | < 100ms | < 250ms | Scan (small table, < 50 templates) |
| PATCH /templates/{id} | < 100ms | < 250ms | Single UpdateItem |
| POST /templates/{id}/preview | < 50ms | < 150ms | In-memory template rendering |
| POST /templates/{id}/test-send | < 500ms | < 2000ms | Includes external email/SMS send |

### 7.2 Caching Strategy

- **Email/SMS stats**: React Query `staleTime: 30_000` (30 seconds). Stats don't change frequently enough to justify real-time polling.
- **Delivery/bounce lists**: React Query `staleTime: 10_000` (10 seconds). Shorter stale time for lists that may update as new events arrive.
- **Suppression list**: React Query `staleTime: 60_000` (60 seconds). Suppressions change infrequently.
- **Template list**: React Query `staleTime: 120_000` (2 minutes). Templates change rarely.
- **No backend caching**: All reads go directly to DDB. Template rendering is in-memory (no cache needed).
- **Browser cache**: All responses include `Cache-Control: no-store` (PII in delivery logs).

### 7.3 Pagination

- **Delivery lists**: Cursor-based pagination using `LastEvaluatedKey` encoding from `app/core/cursor.py`. Default `limit=50`, max `limit=200`.
- **Bounce/complaint lists**: Same cursor pattern. Default `limit=50`.
- **Suppression list**: Non-paginated scan with `Limit=1000` (suppression lists are typically small). If list exceeds 1000, add cursor pagination.
- **Template list**: Non-paginated scan (template count < 50 expected).

---

## 8. Security Considerations

### 8.1 Role-Based Access
- All communication dashboard endpoints require ADMIN role
- Template editing requires ADMIN role (not ROOT — templates are operational, not financial)
- Test send limited to admin-owned email addresses to prevent abuse

### 8.2 Suppression Safety
- Removing a suppression re-enables delivery to that address/phone
- Suppression additions logged with admin identity and reason
- Auto-suppression from bounces/complaints cannot be removed without admin action

### 8.3 Template Security
- Template body must not include executable scripts (strip `<script>` tags)
- Template variables are auto-escaped to prevent XSS in rendered emails
- Test sends are rate-limited to 10 per hour per admin

### 8.4 PII in Delivery Logs
- Delivery logs contain email addresses and phone numbers (PII)
- Access restricted to ADMIN role
- Logs should not be cached in browser (Cache-Control: no-store)

---

## 9. E2E Test Plan

**Test file**: `frontend/e2e/admin-communications.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Charlie (admin)
- Seed email delivery records (5 sent, 1 bounced, 1 complained)
- Seed SMS delivery records (3 sent, 1 failed)
- Seed 2 notification templates (1 email, 1 SMS)

**Section 551: Email Stats & Deliveries API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves email delivery stats` | GET `/ui/admin/email/stats` as Root -> 200; `sent >= 5`, `delivery_rate` between 0 and 100, `bounce_rate >= 0` <!-- NOTE: actual prefix is /ui/admin/email, not /v1/admin/email --> |
| 2 | `Admin lists email deliveries` | GET `/v1/admin/email/deliveries?limit=10` -> 200; array with seeded deliveries |
| 3 | `Admin lists email bounces` | GET `/v1/admin/email/bounces` -> 200; array with at least 1 bounce entry |
| 4 | `Non-admin cannot access email stats` | GET as Alice -> 403 |

**Section 552: Email & SMS Suppression API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Admin views email suppression list` | GET `/v1/admin/email/suppressed` -> 200; returns array |
| 6 | `Admin adds email to suppression list` | POST `/v1/admin/email/suppressed` with `{address: "spam@test.local", reason: "spam"}` -> 200 or 201; re-GET list includes `spam@test.local` |
| 7 | `Admin removes email from suppression` | DELETE `/v1/admin/email/suppressed/spam@test.local` -> 200; re-GET list excludes it |
| 8 | `Admin views SMS suppression list` | GET `/v1/admin/sms/suppressed` -> 200; returns array |

**Section 553: SMS Stats & Failures API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Admin retrieves SMS delivery stats` | GET `/v1/admin/sms/stats` as Root -> 200; `sent >= 3`, `delivery_rate >= 0` |
| 10 | `Admin lists SMS deliveries` | GET `/v1/admin/sms/deliveries?limit=10` -> 200; array of delivery records |
| 11 | `Admin lists SMS failures` | GET `/v1/admin/sms/failures` -> 200; array with at least 1 failure |
| 12 | `Admin adds phone to SMS suppression` | POST `/v1/admin/sms/suppressed` with `{address: "+15551234567", reason: "opt-out"}` -> 200 or 201 |

**Section 554: Template Management API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Admin lists notification templates` | GET `/v1/admin/notifications/templates` as Root -> 200; array with 2 seeded templates |
| 14 | `Admin updates template body` | PATCH `/v1/admin/notifications/templates/{id}` with `{body: "Updated body"}` -> 200; re-GET shows updated body |
| 15 | `Admin previews template` | POST `/v1/admin/notifications/templates/{id}/preview` with `{sample_vars: {user_name: "Alice"}}` -> 200; response contains rendered HTML/text with "Alice" |
| 16 | `Admin sends test notification` | POST `/v1/admin/notifications/templates/{id}/test-send` with `{recipient: "admin@test.local"}` -> 200; response confirms send |

**Section 555: Input Validation & Edge Cases (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 17 | `Empty suppression address rejected` | POST with `{address: "", reason: "test"}` -> 422; validation error for min_length |
| 18 | `Template body with script tags stripped` | PATCH template with body containing `<script>alert(1)</script>` -> 200; re-GET body has no `<script>` tags |
| 19 | `Invalid days parameter rejected` | GET `/v1/admin/email/stats?days=0` -> 422; validation error |
| 20 | `Template update with empty subject allowed` | PATCH with `{subject: ""}` -> 200; subject cleared |

**Section 556: Concurrent Operations (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 21 | `Concurrent suppression add is idempotent` | POST same suppression twice concurrently; both return 200; list has exactly one entry |
| 22 | `Concurrent template updates last-write-wins` | Two PATCH requests with different bodies; final GET shows one of the bodies |
| 23 | `Stats query during active delivery` | Seed new delivery records, then immediately query stats; new records reflected |

**Section 557: Authorization Boundary Tests (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 24 | `Regular user cannot access SMS stats` | Alice GET `/v1/admin/sms/stats` -> 403 |
| 25 | `Regular user cannot add suppression` | Alice POST `/v1/admin/email/suppressed` -> 403 |
| 26 | `Regular user cannot update template` | Alice PATCH template -> 403 |

**Section 558: Communications Dashboard UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 27 | `Dashboard loads with Email tab active` | Root navigates to `/admin/communications`; "Email" tab is active; KPI cards visible |
| 28 | `SMS tab shows SMS-specific stats` | Click "SMS" tab; SMS KPI cards visible (Sent, Delivery Rate, Failure Rate, Segments) |
| 29 | `Templates tab lists templates` | Click "Templates" tab; at least 2 templates listed |
| 30 | `Suppression add dialog works` | Click "Add" button on suppression card; dialog opens; enter address and reason; submit; address appears in list |

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| ~~`app/routers/admin_sms.py`~~ | ~~SMS admin router~~ — **Already exists** with 8 endpoints |
| `app/services/notification_templates.py` | Template CRUD, preview, test send <!-- NOTE: does not exist yet --> |
| `app/routers/admin_notifications.py` | Template management router (5 endpoints) <!-- NOTE: does not exist yet --> |
| `frontend/src/api/endpoints/adminCommunications.ts` | API wrappers <!-- NOTE: does not exist yet --> |
| `frontend/src/pages/admin/communications/CommunicationsDashboard.tsx` | Dashboard page <!-- NOTE: does not exist yet --> |
| `frontend/e2e/admin-communications.spec.ts` | E2E tests (30 tests, sections 551-558) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add communication dashboard Pydantic models |
| `app/main.py` | Register `admin_notifications_router` only (`admin_sms_router` already registered at lines 161, 438) |
| `app/core/settings.py` | Add `notification_templates_table_name` <!-- NOTE: does not exist yet --> |
| `app/core/tables.py` | Add `notification_templates` table handle <!-- NOTE: does not exist yet --> |
| `scripts/local-ddb-init.py` | Add `notification_templates` table <!-- NOTE: does not exist yet --> |
| `frontend/src/api/types.ts` | Add communication TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/communications` route <!-- NOTE: route does not exist yet --> |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Communications" admin nav link |

## 12. Acceptance Criteria

1. Email stats dashboard shows sent, delivered, bounced, complained counts and rates
2. Email deliveries, bounces, and complaints listed with pagination
3. Email suppression list manageable (view, add, remove)
4. SMS stats dashboard shows sent, delivered, failed counts and rates
5. SMS deliveries and failures listed
6. SMS suppression list manageable
7. Notification templates listed, editable, and previewable
8. Test send delivers a notification to a specified address
9. Non-admin users receive 403 on all endpoints
10. All 30 E2E tests pass in `frontend/e2e/admin-communications.spec.ts`

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_notification_templates.py`

**Mock setup**: DynamoDB mocked via `moto`. Email sending mocked with `unittest.mock.patch("app.services.email_delivery.send_email")`. SMS sending mocked with `unittest.mock.patch("app.services.sms_delivery.send_sms")`.

**Fixtures**:
- `templates_table`: moto-backed `notification_templates` table with PK=`TEMPLATE#{id}`, SK=`META`
- `admin_session`: Fake session dict `{"user_sub": "root.admin@testdev.local", "role": "ROOT", "admin_profile": {...}}`
- `sample_email_template`: Pre-built email template dict with subject, body, variables
- `sample_sms_template`: Pre-built SMS template dict

**Test functions**:

| Function | What it tests |
|----------|---------------|
| `test_list_templates_returns_all` | `list_templates()` returns all seeded templates from DDB |
| `test_list_templates_filters_by_channel` | `list_templates(channel="email")` returns only email templates |
| `test_get_template_by_id` | `get_template("email_welcome")` returns correct template record |
| `test_get_template_not_found` | `get_template("nonexistent")` raises 404 |
| `test_update_template_body` | `update_template("email_welcome", body="new body")` persists change |
| `test_update_template_strips_script_tags` | Body with `<script>` tags has them removed by `TemplateUpdate` validator |
| `test_update_template_preserves_immutable_fields` | `channel` and `template_id` cannot be changed via update |
| `test_preview_template_renders_variables` | `preview_template("email_welcome", sample_vars={"user_name": "Alice"})` returns rendered HTML with "Alice" |
| `test_preview_template_reports_missing_vars` | Preview with incomplete vars returns `missing_vars` list |
| `test_test_send_email_calls_send_email` | `test_send("email_welcome", recipient="admin@test.local")` calls patched `send_email` with rendered content |
| `test_test_send_sms_calls_send_sms` | `test_send("sms_verification", recipient="+15551234567")` calls patched `send_sms` |
| `test_test_send_rate_limit` | 11th test send within 1 hour returns 429 |
| `test_seed_default_templates` | `seed_default_templates()` populates DDB from `alert_email_templates.py` functions |
| `test_suppression_add_idempotent` | Adding same address twice returns 200 both times, list has one entry |
| `test_suppression_remove_not_found` | Removing nonexistent address returns 404 |

**Test file**: `tests/test_admin_email_router.py` (existing router, add coverage)

| Function | What it tests |
|----------|---------------|
| `test_email_stats_returns_rates` | GET `/ui/admin/email/stats` returns `delivery_rate`, `bounce_rate`, `complaint_rate` as floats |
| `test_email_stats_invalid_days_returns_422` | `days=0` or `days=400` returns 422 |
| `test_email_deliveries_pagination` | Cursor-based pagination returns correct pages |
| `test_non_admin_gets_403` | USER role on email stats returns 403 |

### Integration Tests

**Test file**: `tests/test_admin_communications_integration.py`

Tests with real moto DynamoDB (no patching of DDB calls):

| Test | What it validates |
|------|-------------------|
| `test_template_crud_roundtrip` | Create template, update body, re-read, verify changes persisted |
| `test_template_preview_with_all_variables` | Seed template with 5 variables, preview with all provided, no `missing_vars` |
| `test_email_stats_aggregation_across_dates` | Seed delivery records across 7 dates, verify `get_delivery_stats(days=7)` aggregates correctly |
| `test_sms_stats_aggregation` | Seed SMS records, verify `get_sms_delivery_stats()` counts match |
| `test_suppression_lifecycle` | Add suppression, verify `is_suppressed()` returns True, remove, verify returns False |
| `test_test_send_with_real_template` | Seed template, call test_send, verify email_delivery.send_email was called with rendered content |

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/admin-communications.spec.ts`
**Sections**: 551-558 (30 tests) as detailed in section 9 above.

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for authorization boundary tests.

**CSRF handling**: All POST/PATCH/DELETE requests via `page.request` include `headers: { "x-csrf-token": sessions["root"].csrf_token }`.

**Setup/teardown**:
- `beforeAll`: Inject auth for Root and Alice. Seed email delivery records (5 sent, 1 bounced, 1 complained), SMS records (3 sent, 1 failed), and 2 notification templates via direct DDB writes.
- `afterAll`: Clean up seeded suppression entries and test templates.

**Negative tests**: 403 (non-admin on all endpoints), 404 (nonexistent template, nonexistent suppression removal), 422 (empty suppression address, invalid `days` param, template body > 10000 chars)

**Key selectors**:
- Email tab: `page.getByRole("tab", { name: /email/i })`
- SMS tab: `page.getByRole("tab", { name: /sms/i })`
- Templates tab: `page.getByRole("tab", { name: /templates/i })`
- KPI card: `page.locator("[data-testid='kpi-sent']")` or `page.getByText(/sent \(7d\)/i)`
- Suppression add button: `page.getByRole("button", { name: /add/i })` scoped within suppression card
- Template row: `page.getByText("Welcome Email")` in templates list

### Test Data Requirements

**DDB seed data**:
- `email_delivery` table: PK=`EMAIL_STATS`, SK=`DATE#2026-05-{dd}` records for 7 days; PK=`EMAIL_DELIVERY`, PK=`EMAIL_BOUNCE`, PK=`EMAIL_COMPLAINT` records
- `sms_delivery` table: PK=`SMS_STATS`, PK=`SMS_DELIVERY`, PK=`SMS_FAILURE` records
- `notification_templates` table: PK=`TEMPLATE#email_welcome`, SK=`META`; PK=`TEMPLATE#sms_verification`, SK=`META`

**Test user roles**:
- Root (ROOT): Full admin access to all endpoints
- Charlie (ADMIN): Admin access for section 557 authorization tests
- Alice (USER): Non-admin for 403 boundary tests

**Cleanup strategy**: Delete all seeded records in `afterAll` using known PKs/SKs. Suppression entries cleaned by DELETE endpoint calls.

### CI/Pipeline Considerations

- **Feature flag**: `ADMIN_COMMS_DASHBOARD_ENABLED=true` in `.env.local` for E2E tests
- **New DDB table**: `notification_templates` must be created in `scripts/local-ddb-init.py` before tests run
- **Serial execution**: Template tests (section 554) depend on seeded data from `beforeAll` — run in declared order
- **Retry safety**: Each test uses unique suppression addresses with timestamp suffix (`spam_${Date.now()}@test.local`) to avoid cross-retry collisions
- **Test send mocking**: In dev mode, `send_email` and `send_sms` write to dev log instead of sending real notifications — no external service dependency

---

## Dependencies & Merge Safety

### Depends On (upstream)

| Ticket / Component | What's needed | Status | Can work start before dependency merges? |
|-------------------|---------------|--------|------------------------------------------|
| `app/services/email_delivery.py` | Email stats, deliveries, bounces, complaints, suppression functions | **Implemented** (exists in codebase) | Yes — already merged |
| `app/services/sms_delivery.py` | SMS stats, deliveries, failures, suppression functions | **Implemented** (exists in codebase) | Yes — already merged |
| `app/routers/admin_email.py` | Existing admin email router (8 endpoints, prefix `/ui/admin/email`) | **Implemented** (registered in `main.py:162,439`) | Yes — already merged |
| `app/routers/admin_sms.py` | Existing admin SMS router (8 endpoints, prefix `/ui/admin/sms`) | **Implemented** (registered in `main.py:161,438`) | Yes — already merged |
| `app/auth/policy.py` | `require_admin_or_root` auth dependency | **Implemented** (exists in codebase) | Yes — already merged |
| `app/services/alert_email_templates.py` | Hardcoded templates to seed into DDB | **Implemented** (exists in codebase) | Yes — already merged |

All upstream dependencies are already implemented and merged. This ticket has no blocking dependencies.

### Depended On By (downstream)

| Ticket | What it needs from ADMIN-002 |
|--------|------------------------------|
| None identified | No other tickets reference ADMIN-002 as a dependency |

### Merge Strategy

**Classification**: **Independent**

This ticket is fully self-contained. It creates new service/router/frontend files and adds a new DDB table. No other in-flight tickets modify the same files or tables.

- **No cross-ticket conflicts**: The `notification_templates` table is unique to this feature; existing `admin_email.py` and `admin_sms.py` are read-only dependencies (not modified)
- **New DDB table**: `notification_templates` requires addition to `scripts/local-ddb-init.py`
- **Feature flag gated**: `ADMIN_COMMS_DASHBOARD_ENABLED` defaults to `false`
- **Safe to merge to main independently** at any time

### Merge Checklist

- [ ] **DDB tables**: Add `notification_templates` table to `scripts/local-ddb-init.py` (PK=`pk`, SK=`sk`, no GSIs)
- [ ] **Settings**: Add `notification_templates_table_name` to `app/core/settings.py` and `.env.local.example`; add `ADMIN_COMMS_DASHBOARD_ENABLED`, `ADMIN_TEMPLATE_EDIT_ENABLED`, `ADMIN_TEST_SEND_ENABLED` feature flags
- [ ] **Table handle**: Add `notification_templates` to `app/core/tables.py`
- [ ] **Router registration**: Register `admin_notifications_router` in `app/main.py` (existing `admin_email_router` and `admin_sms_router` already registered)
- [ ] **Frontend route**: Add `/admin/communications` route to `App.tsx` with admin role guard
- [ ] **Frontend sidebar**: Add "Communications" link in admin section of `Sidebar.tsx`
- [ ] **E2E tests**: All 30 tests in `frontend/e2e/admin-communications.spec.ts` pass
- [ ] **Unit tests**: All tests in `tests/test_notification_templates.py` pass
- [ ] **No breaking changes**: Existing admin email/SMS endpoints, frontend pages, and DDB records are unaffected
- [ ] **Template seeding**: `seed_default_templates()` runs at startup to populate DDB from `alert_email_templates.py`

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/email_delivery.py` | 33, 175, 193, 205, 221, 284, 316, 337, 358, 373 | Existing email delivery service with stats, CRUD, suppression, dev log |
| `app/services/sms_delivery.py` | 41, 148, 179, 226, 302, 324, 331, 344 | Existing SMS delivery service with stats, CRUD, suppression, dev log |
| `app/services/alert_email_templates.py` | — | Existing hardcoded email templates (Python functions returning HTML) |
| `app/routers/admin_email.py` | 22, 26-113 | Existing admin email router, prefix `/ui/admin/email`, 8 endpoints, auth: `require_admin_or_root` |
| `app/routers/admin_sms.py` | 20, 24-95 | Existing admin SMS router, prefix `/ui/admin/sms`, 8 endpoints, auth: `require_admin_or_root` |
| `app/auth/policy.py` | 63, 67, 84 | `require_root` (line 63), `require_admin_or_root` (line 67), `require_admin_scope` (line 84) |
| `app/main.py` | 161-162, 438-439 | Registration of `admin_sms_router` (line 161/438) and `admin_email_router` (line 162/439) |
| `app/services/notification_templates.py` | — | Does not exist yet — new implementation required |
| `app/routers/admin_notifications.py` | — | Does not exist yet — new implementation required |
| `frontend/src/api/endpoints/adminCommunications.ts` | — | Does not exist yet — new implementation required |
| `frontend/src/pages/admin/communications/` | — | Does not exist yet — new implementation required |
