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

### 3.2 Template Management

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

### 3.3 Template Management Service: `app/services/notification_templates.py`

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

### 3.4 Template & Test Send Router

Extend admin email router or create new combined router:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/notifications/templates` | `require_admin_session` | List templates |
| GET | `/v1/admin/notifications/templates/{id}` | `require_admin_session` | Get template |
| PATCH | `/v1/admin/notifications/templates/{id}` | `require_admin_session` | Update template |
| POST | `/v1/admin/notifications/templates/{id}/preview` | `require_admin_session` | Preview template |
| POST | `/v1/admin/notifications/templates/{id}/test-send` | `require_admin_session` | Test send |

### 3.5 Pydantic Models (`app/models.py`)

```python
class EmailStatsOut(BaseModel):
    sent: int
    delivered: int
    bounced: int
    complained: int
    failed: int
    delivery_rate: float
    bounce_rate: float
    complaint_rate: float
    period_days: int

class SmsStatsOut(BaseModel):
    sent: int
    delivered: int
    failed: int
    total_segments: int
    delivery_rate: float
    failure_rate: float
    period_days: int

class SuppressionAdd(BaseModel):
    address: str = Field(min_length=1, max_length=320)
    reason: str = Field(default="manual", max_length=200)

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

class TemplatePreviewRequest(BaseModel):
    sample_vars: Dict[str, str] = Field(default_factory=dict)

class TemplateTestSend(BaseModel):
    recipient: str = Field(min_length=1, max_length=320)
    sample_vars: Dict[str, str] = Field(default_factory=dict)
```

### 3.6 Frontend: Communications Dashboard

**Route**: `/admin/communications` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/communications/CommunicationsDashboard.tsx`

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

### 3.7 Frontend API (`frontend/src/api/endpoints/adminCommunications.ts`)

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

15. **`frontend/e2e/admin-communications.spec.ts`**: 16 tests across 4 sections.

---

## 5. E2E Test Plan

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

---

## 6. Security Considerations

### 6.1 Role-Based Access
- All communication dashboard endpoints require ADMIN role
- Template editing requires ADMIN role (not ROOT — templates are operational, not financial)
- Test send limited to admin-owned email addresses to prevent abuse

### 6.2 Suppression Safety
- Removing a suppression re-enables delivery to that address/phone
- Suppression additions logged with admin identity and reason
- Auto-suppression from bounces/complaints cannot be removed without admin action

### 6.3 Template Security
- Template body must not include executable scripts (strip `<script>` tags)
- Template variables are auto-escaped to prevent XSS in rendered emails
- Test sends are rate-limited to 10 per hour per admin

### 6.4 PII in Delivery Logs
- Delivery logs contain email addresses and phone numbers (PII)
- Access restricted to ADMIN role
- Logs should not be cached in browser (Cache-Control: no-store)

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/routers/admin_sms.py` | SMS admin router (7 endpoints) |
| `app/services/notification_templates.py` | Template CRUD, preview, test send |
| `app/routers/admin_notifications.py` | Template management router (5 endpoints) |
| `frontend/src/api/endpoints/adminCommunications.ts` | API wrappers |
| `frontend/src/pages/admin/communications/CommunicationsDashboard.tsx` | Dashboard page |
| `frontend/e2e/admin-communications.spec.ts` | E2E tests (16 tests, sections 551-554) |

## 8. Files to Modify

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

## 9. Acceptance Criteria

1. Email stats dashboard shows sent, delivered, bounced, complained counts and rates
2. Email deliveries, bounces, and complaints listed with pagination
3. Email suppression list manageable (view, add, remove)
4. SMS stats dashboard shows sent, delivered, failed counts and rates
5. SMS deliveries and failures listed
6. SMS suppression list manageable
7. Notification templates listed, editable, and previewable
8. Test send delivers a notification to a specified address
9. Non-admin users receive 403 on all endpoints
10. All 16 E2E tests pass in `frontend/e2e/admin-communications.spec.ts`
