# ADMIN-002: Admin Email/SMS Dashboards

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Dependencies**: Email delivery (`email_delivery.py`), SMS delivery (`sms_delivery.py`), admin email router (`admin_email.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

The platform sends emails and SMS messages for notifications, verification codes, password resets, and alerts. The backend has comprehensive delivery tracking services:

- **Email** (`email_delivery.py`): `record_email_sent`, `record_email_bounce`, `record_email_complaint`, `get_delivery_stats`, `list_deliveries`, `list_bounces`, `list_complaints`, `get_suppression_list`, `suppress_email`, `remove_suppression`
- **SMS** (`sms_delivery.py`): `record_sms_sent`, `record_sms_failure`, `get_sms_delivery_stats`, `list_sms_deliveries`, `list_sms_failures`, `get_suppression_list`, `suppress_sms`, `remove_sms_suppression`
- **Admin email router** (`admin_email.py`): Stats, deliveries, bounces, complaints, suppression management, template preview, dev log

However, there is no admin-facing dashboard UI that visualizes these metrics. The API endpoints exist but are not consumed by any frontend page. Admins must use raw API calls or the Swagger UI to check delivery health. There is also no SMS admin router (only email has one) and no notification template management UI.

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
         → require_admin_session (cookie auth + CSRF check)
         → get_delivery_stats(days=7)
         → DynamoDB Query: PK=EMAIL_STATS, SK between date range
         → aggregate sent/delivered/bounced/complained
         → return EmailStatsOut JSON

Request Flow — Template Test Send:
  Browser → POST /v1/admin/notifications/templates/{id}/test-send
         → require_admin_session (CSRF enforced)
         → notification_templates.test_send(id, recipient, sample_vars)
         → render template with sample_vars
         → email_delivery.send_email() or sms_delivery.send_sms()
         → record as test_send in delivery log
         → return {ok: true, channel: "email", recipient: "admin@test.local"}
```

---

## 2. Current State Analysis

### 2.1 Email Delivery Service (`app/services/email_delivery.py`)

Key functions:
- `get_delivery_stats(days=7)`: Returns counts for sent, delivered, bounced, complained, failed
- `list_deliveries(limit, cursor)`: Paginated delivery list
- `list_bounces(limit, cursor)`: Paginated bounce list
- `list_complaints(limit, cursor)`: Paginated complaint list
- `get_suppression_list(limit)`: Suppressed addresses
- `suppress_email(email, reason)`: Add to suppression list
- `remove_suppression(email)`: Remove from suppression list
- `is_suppressed(email)`: Check suppression status
- `read_dev_email_log(max_entries)`: Dev mode log

### 2.2 SMS Delivery Service (`app/services/sms_delivery.py`)

Key functions:
- `get_sms_delivery_stats(days=7)`: SMS delivery statistics
- `list_sms_deliveries(limit, cursor)`: SMS delivery list
- `list_sms_failures(limit)`: SMS failure list
- `get_suppression_list(limit)`: Suppressed phone numbers
- `suppress_sms(phone, reason)`: Add to suppression
- `remove_sms_suppression(phone)`: Remove suppression
- `get_dev_sms_log()`: Dev mode log

### 2.3 Admin Email Router (`app/routers/admin_email.py`)

Existing endpoints:
- `GET /stats`: Email statistics
- `GET /deliveries`: Delivery list
- `GET /bounces`: Bounce list
- `GET /complaints`: Complaint list
- `GET /suppressed`: Suppression list
- `DELETE /suppressed/{email}`: Remove suppression
- `GET /preview`: Template preview
- `GET /dev-log`: Dev email log

### 2.4 Email Templates (`app/services/alert_email_templates.py`)

Template functions for different notification types. Templates are Python functions returning HTML strings — not yet stored in DDB for dynamic editing.

### 2.5 Gaps

1. No admin dashboard UI for email delivery metrics
2. No admin dashboard UI for SMS delivery metrics
3. No SMS admin router (only email has one)
4. No notification template management UI
5. No test send functionality (send test notification to specific address)
6. No delivery rate charts over time
7. No bounce/complaint drilldown visualizations

---

## 3. Technical Design

### 3.1 SMS Admin Router: `app/routers/admin_sms.py`

Mirror the existing email admin router pattern for SMS:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/sms/stats` | `require_admin_session` | SMS delivery stats |
| GET | `/v1/admin/sms/deliveries` | `require_admin_session` | SMS delivery list |
| GET | `/v1/admin/sms/failures` | `require_admin_session` | SMS failure list |
| GET | `/v1/admin/sms/suppressed` | `require_admin_session` | Suppression list |
| POST | `/v1/admin/sms/suppressed` | `require_admin_session` | Add suppression |
| DELETE | `/v1/admin/sms/suppressed/{phone}` | `require_admin_session` | Remove suppression |
| GET | `/v1/admin/sms/dev-log` | `require_admin_session` | Dev SMS log |

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

Extend admin email router or create new combined router:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/notifications/templates` | `require_admin_session` | List templates |
| GET | `/v1/admin/notifications/templates/{id}` | `require_admin_session` | Get template |
| PATCH | `/v1/admin/notifications/templates/{id}` | `require_admin_session` | Update template |
| POST | `/v1/admin/notifications/templates/{id}/preview` | `require_admin_session` | Preview template |
| POST | `/v1/admin/notifications/templates/{id}/test-send` | `require_admin_session` | Test send |

### 3.6 API Request/Response Examples

**GET /v1/admin/email/stats?days=7**

```json
// Request
GET /v1/admin/email/stats?days=7
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

**GET /v1/admin/email/deliveries?limit=5**

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

**GET /v1/admin/email/bounces?limit=5**

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

**POST /v1/admin/email/suppressed**

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

**DELETE /v1/admin/email/suppressed/spam@test.local**

```json
// Response 200
{
  "ok": true,
  "address": "spam@test.local",
  "removed_at": 1748500200
}
```

**GET /v1/admin/sms/stats?days=7**

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

**GET /v1/admin/sms/failures?limit=5**

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

```typescript
// Email
export const getEmailStats = (params?: { days?: number }) =>
  client.get("/v1/admin/email/stats", { params });
export const getEmailDeliveries = (params?: { limit?: number }) =>
  client.get("/v1/admin/email/deliveries", { params });
export const getEmailBounces = (params?: { limit?: number }) =>
  client.get("/v1/admin/email/bounces", { params });
export const getEmailComplaints = (params?: { limit?: number }) =>
  client.get("/v1/admin/email/complaints", { params });
export const getEmailSuppressions = () =>
  client.get("/v1/admin/email/suppressed");
export const removeEmailSuppression = (email: string) =>
  client.delete(`/v1/admin/email/suppressed/${encodeURIComponent(email)}`);
export const addEmailSuppression = (data: { address: string; reason: string }) =>
  client.post("/v1/admin/email/suppressed", data);

// SMS
export const getSmsStats = (params?: { days?: number }) =>
  client.get("/v1/admin/sms/stats", { params });
export const getSmsDeliveries = (params?: { limit?: number }) =>
  client.get("/v1/admin/sms/deliveries", { params });
export const getSmsFailures = (params?: { limit?: number }) =>
  client.get("/v1/admin/sms/failures", { params });
export const getSmsSuppressions = () =>
  client.get("/v1/admin/sms/suppressed");
export const addSmsSuppression = (data: { address: string; reason: string }) =>
  client.post("/v1/admin/sms/suppressed", data);
export const removeSmsSuppression = (phone: string) =>
  client.delete(`/v1/admin/sms/suppressed/${encodeURIComponent(phone)}`);

// Templates
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

1. **`app/routers/admin_sms.py`**: New router mirroring admin_email.py pattern, 7 endpoints.
2. **`app/main.py`**: Register SMS admin router.

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
| 1 | `Admin retrieves email delivery stats` | GET `/v1/admin/email/stats` as Root -> 200; `sent >= 5`, `delivery_rate` between 0 and 100, `bounce_rate >= 0` |
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
| `app/routers/admin_sms.py` | SMS admin router (7 endpoints) |
| `app/services/notification_templates.py` | Template CRUD, preview, test send |
| `app/routers/admin_notifications.py` | Template management router (5 endpoints) |
| `frontend/src/api/endpoints/adminCommunications.ts` | API wrappers |
| `frontend/src/pages/admin/communications/CommunicationsDashboard.tsx` | Dashboard page |
| `frontend/e2e/admin-communications.spec.ts` | E2E tests (30 tests, sections 551-558) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add communication dashboard Pydantic models |
| `app/main.py` | Register `admin_sms_router` and `admin_notifications_router` |
| `app/core/settings.py` | Add `notification_templates_table_name` |
| `app/core/tables.py` | Add `notification_templates` table handle |
| `scripts/local-ddb-init.py` | Add `notification_templates` table |
| `frontend/src/api/types.ts` | Add communication TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/communications` route |
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
