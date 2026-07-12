# CRM Campaigns & Email Marketing — Extra Implementation Tickets

**Area**: Campaigns & Email Marketing
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T2] Campaigns & Email Marketing — 8 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Campaigns module supports multi-channel outreach (email, phone, mail, fax, SMS), a step-by-step campaign wizard, target lists, survey-linked campaigns, HTML email templates with `{{merge_field}}` substitution, CAN-SPAM / GDPR-compliant open-tracking pixels and one-click unsubscribe links, web-to-lead capture forms that create Contact/Lead records from public form submissions, and A/B (split) testing with per-variant open/click reporting.

testlogon's marketing campaign infrastructure is fully planned in MKT-001..MKT-014 (`docs/ofbiz/specs/`) but not yet implemented. The tickets below are layered **on top of** MKT-001..MKT-014 and assume that foundation will land first. Where a capability extends a specific MKT ticket the dependency is cited explicitly.

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag (default `"0"`, off) following the `cart_reminders_enabled` pattern at `app/core/settings.py:821`. With the flag off all new routes return 404 and all new background work is a no-op. Existing surfaces are byte-for-byte unchanged.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables use the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha — omitting this causes `ValidationException` at query time. No `if S.dev_mode` branches in service code.
- **Reuse existing primitives — never fork**:
  - Email delivery: `app/services/alerts.send_alert_email` (`alerts.py:459`) and `send_alert_email_html` (extended by CMP-002); HTML template wrapper `_wrap_html` at `app/services/alert_email_templates.py:16`.
  - Merge-field substitution: `_VAR_RE` pattern + `_render()` helper at `app/services/notification_templates.py:23,245`.
  - HMAC-signed tokens: `generate_recovery_link` pattern at `app/services/cart_reminders.py:214`; `_mark_token_consumed` conditional-put at `cart_reminders.py:198–211`.
  - Opt-out gate: `is_user_opted_out` at `app/services/cart_reminders.py:95`; opt-out preference CRUD at `cart_reminders.py:128` (`set_reminder_preference`).
  - A/B statistical significance: `ab_test_significance` at `app/services/ad_optimization.py:253`.
  - Audit events: `app/services/alerts.audit_event` at `alerts.py:644`.
  - Campaign send orchestration: `send_campaign` in `app/services/marketing_campaigns.py` (MKT-009).
  - Questionnaire lookup: `REPO.get_published_by_slug(slug)` in `app/services/questionnaires_repository.py:666`.
- **Planned upstream dependencies**: MKT-001..MKT-014 (`docs/ofbiz/specs/MKT-*.md`) deliver ContactLists, PartySegments, tracking codes, campaign models, and campaign-send orchestration. The CMP tickets below extend those specs. CMP-001 (non-email campaign types) and CMP-003 (HTML email templates) are prerequisites for several later tickets. Dependency order: CMP-001 → CMP-002 → CMP-003 → CMP-004 → CMP-005 → CMP-006 → CMP-007 → CMP-008.
- **Hermetic offline tests**: All pytest use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles per the project test-isolation pattern (see `tests/test_gap_0220_0221_ssh_stored_key.py` for the canonical form). No real AWS or network calls.

---

### CMP-001: Non-email campaign types (phone / mail / fax / SMS)

**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

SuiteCRM supports five campaign types: `email`, `phone`, `mail`, `fax`, `sms`. The planned `MarketingCampaignCreateIn` model in MKT-003 (`docs/ofbiz/specs/MKT-003.md:99–123`) has no `campaign_type` field — it encodes outreach channel implicitly via the send path. This ticket adds an explicit `campaign_type` field to the MKT-003 models and extends the MKT-009 send path to handle non-email channels.

**Model changes** (`app/models.py` — additive, in the MKT-003 marketing block after line 4927):

```python
CAMPAIGN_TYPES = {"email", "phone", "mail", "fax", "sms"}

# Extend MarketingCampaignCreateIn (MKT-003) — additive field with default:
campaign_type: str = Field(default="email", pattern=r"^(email|phone|mail|fax|sms)$")

# Add to MarketingCampaignOut:
campaign_type: str = "email"
```

Existing campaigns that predate this field default to `"email"` at read time via `item.get("campaign_type", "email")`. No data migration needed.

**Service changes** (`app/services/marketing_campaigns.py` — MKT-004 module):

- `create_campaign` persists `campaign_type` from the input model; existing campaigns without the field are handled via `.get("campaign_type", "email")`.
- `send_campaign` (MKT-009): when `campaign_type != "email"`, skip `send_alert_email` and instead write a send-log row with `channel=campaign_type` and `in_app_only=True` (in-app alert only, no email). Non-email channels produce an in-app alert via `write_alert` (alerts.py:356) with `event="marketing.campaign.{campaign_type}"` and a note that actual phone/mail/fax delivery is handled out-of-band. SMS channel additionally calls `app/services/alerts.send_sms_alert` if that service exists, otherwise falls back to in-app alert only.

**Router changes** (`app/routers/marketing_campaigns.py` — MKT-011 module):

- `POST /ui/marketing/campaigns` — `campaign_type` passes through from body to service unchanged.
- `GET /ui/marketing/campaigns` — accepts `?campaign_type=` filter; passes to `list_campaigns(owner_id, campaign_type=campaign_type)` which adds a `FilterExpression` on `campaign_type`.

**DynamoDB**: no new table. `campaign_type` is a plain attribute on the existing `MarketingCampaigns` table item (MKT-002). Adding a GSI on `campaign_type` is a future consideration; filtering is a post-query scan for MVP given small expected result sets per owner.

**Acceptance Criteria**
- `MarketingCampaignCreateIn(campaign_type="phone", ...)` passes model validation; `campaign_type="telegram"` raises `ValidationError`.
- `send_campaign(campaign_id, owner_id)` on a `campaign_type="phone"` campaign writes a send-log row with `channel="phone"` and does NOT call `send_alert_email`.
- `send_campaign` on a `campaign_type="email"` campaign behaves exactly as MKT-009 specifies (no regression).
- `GET /ui/marketing/campaigns?campaign_type=sms` returns only SMS campaigns for the caller.
- All new fields default to `"email"` so existing MKT-009 tests are unaffected.

**Dependencies**
- MKT-003 (model insert point), MKT-004 (`create_campaign`), MKT-009 (`send_campaign`), MKT-011 (router).
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).

---

### CMP-002: HTML email templates for campaigns with merge-field substitution

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

SuiteCRM lets admins create reusable HTML email templates with `{{merge_field}}` placeholders that are substituted per-recipient at send time. testlogon has a `{{var}}` substitution engine at `app/services/notification_templates.py:23,245` (`_VAR_RE`, `_render`) and an HTML wrapper at `app/services/alert_email_templates.py:16` (`_wrap_html`). This ticket introduces a `MarketingEmailTemplate` DynamoDB table for campaign-specific HTML templates and wires per-recipient merge-field substitution into the MKT-009 send path.

**DynamoDB table** (`scripts/local-ddb-init.py`):

```
Table: MarketingEmailTemplates  (env DDB_MARKETING_EMAIL_TEMPLATES, default "MarketingEmailTemplates")
PK: TMPL#{template_id}  SK: META
GSI ByOwnerCreatedAt: PK=owner_id (S), SK=created_at (N)
attr_types={"created_at": "N"}
```

Template row attributes: `template_id` (sha256[:16] of `owner_id|name`), `owner_id`, `name`, `subject_template` (str, `{{merge_fields}}`), `body_html_template` (str, HTML with `{{merge_fields}}`), `variables` (list[str] — parsed from template at save time using `_VAR_RE`), `status` (`draft`/`active`), `created_at` (N), `updated_at` (N).

Add `T.marketing_email_templates` handle in `app/core/tables.py` and `marketing_email_templates_table_name` in `app/core/settings.py` following the `_safe_table` pattern at `tables.py:65`.

**Pydantic models** (`app/models.py` — additive, in the MKT-003 block):

```python
class MarketingEmailTemplateCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    subject_template: str = Field(..., min_length=1, max_length=500)
    body_html_template: str = Field(..., min_length=1, max_length=50000)

class MarketingEmailTemplateOut(BaseModel):
    template_id: str
    owner_id: str
    name: str
    subject_template: str
    body_html_template: str
    variables: List[str] = []
    status: str = "draft"
    created_at: int = 0
    updated_at: int = 0
```

Also add `email_template_id: Optional[str] = None` to `MarketingCampaignCreateIn` / `MarketingCampaignUpdateIn` (MKT-003 additive extension) so a campaign can reference a template by ID.

**Service** (`app/services/marketing_email_templates.py`):

- `create_template(owner_id, data)` — parses `_VAR_RE.findall(subject + body)` for `variables`; deterministic `template_id = sha256(owner_id + "|" + name)[:16]`; conditional put (duplicate name per owner → 409).
- `get_template(owner_id, template_id)` — point lookup; ownership enforced.
- `list_templates(owner_id, limit, cursor)` — `ByOwnerCreatedAt` GSI.
- `render_template(template_item, merge_vars)` — delegates to `_render()` from `notification_templates.py:245`; returns `(rendered_subject, rendered_body_html)`.

**Send path extension** (`app/services/marketing_campaigns.py` — MKT-009 `_build_message_body`):

When `campaign.get("email_template_id")` is set and `campaign_type == "email"`:
1. Fetch template via `get_template(owner_id, email_template_id)`.
2. Build per-recipient `merge_vars = {"first_name": profile.first_name, "email": profile.email, "unsubscribe_url": ..., "platform_name": S.platform_name}`.
3. Call `render_template(template, merge_vars)` → `(subject, html_body)`.
4. Extend `send_alert_email` to accept an optional `html_body` argument (additive parameter, default `None`); when provided, send using SES `Html` body (in addition to the existing `Text` body); in dev mode, log the HTML body to `S.dev_email_log`. This change is isolated to `app/services/alerts.py:459–488` — add `body_html: Optional[str] = None` as a keyword-only parameter and branch on it for the SES `Message["Body"]` dict.

**Router** (`app/routers/marketing_campaigns.py` — MKT-011 extension):

```
POST /ui/marketing/email-templates          → create template (require_ui_session + flag gate)
GET  /ui/marketing/email-templates          → list templates (require_ui_session)
GET  /ui/marketing/email-templates/{id}     → get template (require_ui_session)
PATCH /ui/marketing/email-templates/{id}    → update template (require_ui_session + flag gate)
DELETE /ui/marketing/email-templates/{id}   → delete template (require_ui_session + flag gate)
POST /ui/marketing/email-templates/{id}/preview  → render with sample vars (require_ui_session)
```

**Acceptance Criteria**
- `POST /ui/marketing/email-templates` creates a template; `variables` list is auto-extracted from `{{first_name}}` etc. in subject and body.
- `POST .../preview` with `sample_vars={"first_name": "Alice"}` substitutes all `{{first_name}}` occurrences in the rendered output.
- `send_campaign` with `email_template_id` set calls `render_template` once per recipient and passes `html_body` to email delivery.
- `send_campaign` without `email_template_id` falls back to the MKT-009 plain-text body (no regression).
- Missing merge vars in `render_template` leave the `{{var}}` placeholder intact (not crash).
- Duplicate template name per owner returns 409.

**Dependencies**
- MKT-003 (model insert point), MKT-004 (`create_campaign` for `email_template_id` field), MKT-009 (`send_campaign` / `_build_message_body`), MKT-011 (router).
- CMP-001 (campaign_type guard — template only rendered when `campaign_type=="email"`).
- `app/services/notification_templates.py:245` (`_render` reuse).
- `app/services/alert_email_templates.py:16` (`_wrap_html` reuse).
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).

---

### CMP-003: Email open-tracking pixel

**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Add a CAN-SPAM/GDPR-standard 1×1 transparent GIF open-tracking pixel endpoint and wire it into the campaign email send path so every marketing email body gets a pixel URL that records an open event when the image is fetched by the recipient's mail client.

**DynamoDB**: no new table. Open events are appended as VISIT child rows on `T.tracking_codes` (MKT-010) using the same `TRACK#{code_slug}/VISIT#{ts}#{nonce}` scheme, with an extra `event_type="open"` attribute to distinguish from link-click visits. The campaign's linked `tracking_code` (from MKT-009) is reused as the attribution anchor. If no tracking code is linked to the campaign a synthetic per-send open-tracking code is created via `create_tracking_code` (MKT-010).

**Public endpoint** (`app/routers/marketing_campaigns.py` — public router, no auth):

```python
GET /ui/marketing/t/{code}/open.gif
```

Behavior:
1. Record open event: call `record_visit(code, event_type="open", ip_address=..., user_agent=...)` (extends MKT-010's `record_visit` to accept an `event_type` kwarg, defaulting to `"click"` for backward compatibility).
2. Return a minimal 1×1 transparent GIF as `Response(content=_TRANSPARENT_GIF, media_type="image/gif")`. The `_TRANSPARENT_GIF` constant is 43 bytes (`b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"`).
3. Set `Cache-Control: no-store, no-cache` and `Pragma: no-cache` response headers to prevent proxy caching.
4. Never 404 on unknown codes (silently skip `record_visit`); always return the GIF so broken tracking links do not cause broken-image icons in email clients.

The endpoint gate: even with `S.marketing_campaigns_enabled=False`, the redirect still returns the GIF but skips `record_visit` (matching the MKT-011 §5.1 pattern for the public visit redirect).

**Send path extension** (`app/services/marketing_campaigns.py` — MKT-009 `_build_message_body`):

When `campaign_type == "email"` and a `tracking_code` is available, append a pixel `<img>` tag to the HTML body returned by `_build_message_body`:

```html
<img src="{S.public_base_url}/ui/marketing/t/{tracking_code}/open.gif"
     width="1" height="1" alt="" style="display:none" />
```

For plain-text fallback bodies (no HTML template), no pixel is embedded (pixels require HTML).

**`record_visit` extension** (`app/services/tracking_codes.py` — MKT-010):

Add `event_type: str = "click"` keyword argument. VISIT row gains an `event_type` attribute. `record_order`, `link_promo_redemption` are unchanged. `list_visits_for_code(code_slug, event_type=None)` — add optional filter on `event_type` to separate opens from clicks in the attribution rollup (MKT-005).

**Acceptance Criteria**
- `GET /ui/marketing/t/test_code/open.gif` returns a 1×1 GIF with status 200, `Content-Type: image/gif`, `Cache-Control: no-store`.
- `record_visit` is called with `event_type="open"` and a VISIT row with `event_type="open"` is written to `T.tracking_codes`.
- Unknown `code` returns 200 GIF without DDB write.
- Campaign send with `tracking_code` set and an HTML template embeds the pixel `<img>` tag in the rendered body.
- `record_visit(code, event_type="click")` (existing call path) is unchanged.

**Dependencies**
- MKT-009 (`send_campaign` / `_build_message_body`), MKT-010 (`record_visit` extension, `T.tracking_codes`), MKT-011 (public router registration).
- CMP-002 (HTML template — pixel only embedded in HTML bodies).
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).

---

### CMP-004: Unsubscribe / opt-out link embedded in campaign emails

**Type:** Feature  **Priority:** P0  **Estimate:** 2d

**Description**

CAN-SPAM and GDPR require a one-click unsubscribe link in every marketing email. This ticket adds HMAC-signed unsubscribe URL generation (mirroring `generate_recovery_link` at `app/services/cart_reminders.py:214`) and a public one-click opt-out endpoint.

**Settings** (`app/core/settings.py` — additive):

```python
marketing_unsubscribe_secret: str = os.environ.get(
    "MARKETING_UNSUBSCRIBE_SECRET", ""
)  # Falls back to UI_ACCESS_TOKEN_SECRET when empty — same pattern as cart_recovery_link_secret
marketing_unsubscribe_ttl_days: int = int(os.environ.get("MARKETING_UNSUBSCRIBE_TTL_DAYS", "365"))
```

**Service** (`app/services/marketing_unsubscribe.py` — new file):

```python
def _unsub_secret() -> str:
    return S.marketing_unsubscribe_secret or S.ui_access_token_secret

def generate_unsubscribe_url(user_sub: str, campaign_id: str) -> str:
    """Mint a signed, time-limited, one-time-use unsubscribe URL.
    Token format: base64url(payload).base64url(sig)
    Payload: {"sub": user_sub, "cid": campaign_id, "exp": now + ttl, "jti": uuid4().hex}
    HMAC-SHA256 signature using _unsub_secret().
    Same scheme as generate_recovery_link (cart_reminders.py:214–166).
    """

def verify_unsubscribe_token(token: str) -> tuple[str, str]:
    """Verify token, raise HTTPException(400) on invalid/expired/replayed.
    Returns (user_sub, campaign_id).
    One-time-use: writes UNSUB#CONSUMED#{jti} to T.cart_reminder_config
    via attribute_not_exists conditional put (mirrors _mark_token_consumed
    at cart_reminders.py:198–211).
    """

def opt_out_user(user_sub: str) -> None:
    """Write the global opt-out row reusing set_reminder_preference(user_sub, opted_out=True)
    from app.services.cart_reminders:128. The same OPTOUT#USER#{sub}/META row
    used by cart reminders and MKT-007 is reused here — a single opt-out row
    suppresses all marketing channels (cart reminders, campaigns, and future channels).
    """
```

**Public endpoint** (`app/routers/marketing_campaigns.py` — public router, no auth):

```python
GET /ui/marketing/optout/{token}
```

Behavior:
1. Call `verify_unsubscribe_token(token)` → `(user_sub, campaign_id)`. On error (invalid/expired) → return `HTMLResponse` with "This unsubscribe link has expired. Please contact support." (plain HTTP 200 so mail clients don't show error icons).
2. Call `opt_out_user(user_sub)`.
3. Emit `audit_event("marketing.unsubscribe", user_sub, campaign_id=campaign_id)` (best-effort).
4. Return `HTMLResponse` with a simple "You have been unsubscribed from marketing emails." page (no redirect, to avoid redirect-loop risks with aggressive mail scanners).

**Send path extension** (`app/services/marketing_campaigns.py` — MKT-009 `_build_message_body` and `_try_send_one`):

- In `_try_send_one`, call `generate_unsubscribe_url(party_id, campaign_id)` and pass `unsubscribe_url` into `_build_message_body`.
- In `_build_message_body`, append the unsubscribe line to plain-text body: `"\n\nTo unsubscribe: {unsubscribe_url}"`.
- In CMP-002 HTML template rendering: add `unsubscribe_url` to the `merge_vars` dict so `{{unsubscribe_url}}` in HTML templates is substituted. Also append a default HTML footer: `<p style="font-size:11px;color:#999">To unsubscribe, <a href="{unsubscribe_url}">click here</a>.</p>` if the template body does not already contain `{{unsubscribe_url}}`.

**Acceptance Criteria**
- `generate_unsubscribe_url(sub, cid)` returns a URL containing `/ui/marketing/optout/`.
- `GET /ui/marketing/optout/{valid_token}` calls `opt_out_user`, writes the opt-out row, returns 200 HTML.
- Second visit with the same token returns 200 HTML "expired" message without calling `opt_out_user` again (one-time-use).
- Expired token (past `exp`) returns 200 HTML "expired" message.
- After opt-out, `is_user_opted_out(user_sub)` (cart_reminders.py:95) returns `True`.
- Campaign send includes the unsubscribe URL in both plain-text and HTML bodies.
- Opted-out users are not re-sent to (MKT-009 opt-out guard at `_try_send_one` already enforces this).

**Dependencies**
- MKT-009 (`send_campaign` / `_try_send_one`), MKT-011 (public router).
- CMP-002 (HTML template merge-vars for `{{unsubscribe_url}}`).
- `app/services/cart_reminders.set_reminder_preference` (opt-out write), `is_user_opted_out` (opt-out read), `_mark_token_consumed` pattern (cart_reminders.py:198).
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).

---

### CMP-005: Survey / questionnaire linked to campaign

**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

SuiteCRM allows a campaign to link to a Survey so recipients receive a survey URL in the campaign email. testlogon has a full questionnaire system with published slugs (`get_published_by_slug` at `app/services/questionnaires_repository.py:666`) and public submission endpoints (`app/routers/questionnaires.py`).

**Model changes** (`app/models.py` — additive in MKT-003 block):

Add `questionnaire_id: Optional[str] = None` to `MarketingCampaignCreateIn` and `MarketingCampaignUpdateIn`.

Add to `MarketingCampaignOut`: `questionnaire_id: Optional[str] = None`, `questionnaire_url: Optional[str] = None`.

**Service changes** (`app/services/marketing_campaigns.py`):

In `create_campaign`/`update_campaign` (MKT-004): when `questionnaire_id` is provided, call `REPO.get_questionnaire(questionnaire_id)` (via `DynamoQuestionnaireRepository` from `app/services/questionnaires_repository.py:41`) to verify it exists and is published. If not found or not published, raise `HTTPException(422, "questionnaire not found or not published")`.

In `get_campaign` (MKT-004): populate `questionnaire_url = f"{S.public_base_url}/questionnaires/public/{slug}"` where `slug = questionnaire_item["published_slug"]` when `questionnaire_id` is set.

In `send_campaign` (MKT-009) `_build_message_body`: when `campaign.get("questionnaire_id")` is set, add `survey_url` to the plain-text body (`"Please complete our survey: {questionnaire_url}"`) and expose it as a merge-field `{{survey_url}}` in the `merge_vars` dict passed to HTML template rendering (CMP-002).

**Acceptance Criteria**
- `POST /ui/marketing/campaigns` with `questionnaire_id=<published_id>` succeeds; `GET` returns `questionnaire_url`.
- `POST /ui/marketing/campaigns` with `questionnaire_id=<unpublished_id>` returns 422.
- Campaign send with linked questionnaire includes the survey URL in the plain-text email body.
- HTML template render (`{{survey_url}}`) substitutes the questionnaire URL.
- Campaign without `questionnaire_id` is unaffected.

**Dependencies**
- MKT-003 (model insert point), MKT-004 (`create_campaign`), MKT-009 (`send_campaign`), MKT-011 (router).
- CMP-002 (HTML template `merge_vars`).
- `app/services/questionnaires_repository.DynamoQuestionnaireRepository.get_questionnaire` and `get_published_by_slug`.
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).

---

### CMP-006: Web-to-lead capture form

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

SuiteCRM's web-to-lead feature provides a public POST endpoint that accepts form submissions, creates a Contact/Lead record, and optionally adds the submitter to a target list. testlogon has `T.contacts` at `app/core/tables.py:354` and a contacts router at `app/routers/contacts.py`. The LED-001..LED-004 tickets (`docs/suitecrm/CRM_LEADS_TICKETS.md`) build a `leads` table; this ticket reuses that foundation where available, falling back to creating a minimal contact entry when LED tickets are not yet deployed.

**Settings** (`app/core/settings.py` — additive):

```python
web_to_lead_enabled: bool = os.environ.get("WEB_TO_LEAD_ENABLED", "0") not in ("0", "false", "False")
web_to_lead_captcha_enabled: bool = os.environ.get("WEB_TO_LEAD_CAPTCHA_ENABLED", "0") not in ("0", "false", "False")
```

**DynamoDB**: no new table. Lead/contact captures are written to `T.leads` (LED-001) when `S.leads_enabled`, otherwise written as a minimal external contact record to a new `web_lead_captures` table (PK=`CAPTURE#{capture_id}` / SK=`META`, GSI `ByCampaignCreatedAt`: PK=`campaign_id`, SK=`created_at N`; `attr_types={"created_at": "N"}`). Add `T.web_lead_captures` handle and `web_lead_captures_table_name` setting.

**Pydantic models** (`app/models.py` — additive):

```python
class WebLeadCaptureIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=120)
    last_name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=254)
    phone: Optional[str] = Field(default=None, max_length=32)
    company: Optional[str] = Field(default=None, max_length=120)
    message: Optional[str] = Field(default=None, max_length=2000)
    campaign_id: Optional[str] = None   # when embedded as a campaign capture form
    contact_list_id: Optional[str] = None  # add to this list after capture
    honeypot: Optional[str] = None      # bot-trap field; non-empty → reject silently

class WebLeadCaptureOut(BaseModel):
    capture_id: str
    status: str = "received"
    created_at: int = 0
```

**Public endpoint** (no auth):

```python
POST /ui/marketing/leads/capture
```

Behavior:
1. `_require_web_lead_enabled()` — raises 404 when `S.web_to_lead_enabled` is off.
2. Honeypot check: if `body.honeypot` is non-empty, return `WebLeadCaptureOut(status="received")` without any writes (silent bot rejection, same response shape to avoid bot enumeration).
3. Write a capture row to `T.web_lead_captures` (or `T.leads` when `S.leads_enabled`).
4. If `body.contact_list_id` is provided and `S.marketing_campaigns_enabled` is on, call `add_member(list_id=body.contact_list_id, party_id=capture_id)` from MKT-007 (`app/services/marketing_lists.py`) — this adds the external email as a list member keyed on `capture_id` (not a platform `user_sub`; MKT-007 must support non-user party IDs).
5. Emit `audit_event("web_lead.captured", "anonymous", capture_id=capture_id, campaign_id=body.campaign_id)` (best-effort).
6. Return `WebLeadCaptureOut`.

**Admin endpoint** (require_admin_session):

```
GET /ui/admin/marketing/leads?campaign_id=&cursor=&limit=50
```

Lists web-lead captures, optionally filtered by `campaign_id`, using the `ByCampaignCreatedAt` GSI. Returns `{"captures": [...], "cursor": str|null, "count": int}`.

**Acceptance Criteria**
- `POST /ui/marketing/leads/capture` with valid body returns `{"status": "received", "capture_id": "..."}`.
- Non-empty `honeypot` returns `{"status": "received"}` without any DDB write.
- `contact_list_id` present and valid adds the capture to the contact list.
- Admin `GET /ui/admin/marketing/leads` returns the captured entries.
- Flag `WEB_TO_LEAD_ENABLED=0` → endpoint returns 404.
- No auth required on the capture endpoint.

**Dependencies**
- MKT-007 (`add_member`) when adding to a contact list.
- LED-001 (`T.leads`) when `S.leads_enabled` — graceful fallback to `T.web_lead_captures` otherwise.
- MKT-011 (router — public and admin registration).
- Feature flag: `S.web_to_lead_enabled` (new), `S.marketing_campaigns_enabled` (MKT-002 for list add).

---

### CMP-007: A/B (split) test for campaign email content

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

SuiteCRM supports split-testing campaign email content with per-variant open/click reporting. testlogon already has a two-proportion Z-test significance function at `app/services/ad_optimization.py:253` (`ab_test_significance`) that powers ad creative A/B tests. This ticket extends `MarketingCampaignCreateIn` with a `variants` list, splits the send audience across variants, and reports per-variant open/click rates using MKT-010 tracking code visit records.

**Model changes** (`app/models.py` — additive in MKT-003 block):

```python
class CampaignVariant(BaseModel):
    variant_id: str = ""          # assigned server-side (sha256[:8] of campaign_id+index)
    name: str = Field(..., min_length=1, max_length=80)
    email_template_id: Optional[str] = None   # CMP-002 template; overrides campaign-level template
    subject_override: Optional[str] = None    # overrides campaign name as subject
    weight: int = Field(default=1, ge=1, le=100)  # relative send weight

# Additive field on MarketingCampaignCreateIn / UpdateIn:
variants: Optional[List[CampaignVariant]] = None  # None = no A/B test; 2–5 variants

# Additive field on MarketingCampaignOut:
variants: List[CampaignVariant] = []
```

**Service changes** (`app/services/marketing_campaigns.py`):

`create_campaign` / `update_campaign` (MKT-004): validate `variants` list: 2–5 variants allowed; if `email_template_id` is set on a variant, verify the template exists (reusing CMP-002 `get_template`). Persist variants JSON on the campaign item.

`send_campaign` (MKT-009) `_resolve_audience` extension: when `campaign.get("variants")` is non-empty, assign each resolved `party_id` to a variant using weighted round-robin (deterministic: `hash(campaign_id + party_id) % total_weight` maps to variant index). Record `variant_id` on each send-log row in `T.marketing_send_log`.

`_build_message_body` / `_try_send_one`: use the variant's `email_template_id` (if set) and `subject_override` for that recipient. Variant-specific tracking codes: if the campaign has a `tracking_code`, append `_v{variant_index}` suffix to differentiate variant visit counts (create sub-codes via `create_tracking_code` on first send if they do not already exist).

**Attribution extension** (`app/services/marketing_campaigns.py` — `compute_attribution` from MKT-005):

Add `variant_stats: list[{variant_id, sent, opens, clicks, open_rate, click_rate}]` to `CampaignAttributionOut`. When variants exist, call `ab_test_significance(variant_a={"impressions": sent_a, "clicks": opens_a}, variant_b={"impressions": sent_b, "clicks": opens_b})` from `app/services/ad_optimization.py:253` to compute significance.

**Router** (`app/routers/marketing_campaigns.py` — MKT-011):

```
GET /ui/marketing/campaigns/{id}/ab-results
```

Returns per-variant stats and significance test results. Uses `require_ui_session` + ownership check.

**Acceptance Criteria**
- `MarketingCampaignCreateIn(variants=[{name:"A"}, {name:"B"}])` passes validation.
- More than 5 variants raises `ValidationError`.
- `send_campaign` with 2 variants splits the recipient list; each send-log row has `variant_id`.
- `GET .../ab-results` returns `variant_stats` with `significant: bool` from Z-test.
- `compute_attribution` on a non-variant campaign is unchanged.
- Variant with `email_template_id` referencing a non-existent template raises 422 on campaign create/update.

**Dependencies**
- MKT-003 (model insert point), MKT-004 (`create_campaign`), MKT-005 (`compute_attribution`), MKT-009 (`send_campaign`), MKT-010 (tracking codes), MKT-011 (router + `ab-results` endpoint).
- CMP-002 (HTML email templates — variant-specific templates).
- CMP-003 (open-tracking pixel — variant-specific tracking codes for open-rate measurement).
- `app/services/ad_optimization.ab_test_significance` (at `ad_optimization.py:253`).
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).

---

### CMP-008: Email personalization merge tags end-to-end

**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

This ticket ensures that the per-recipient merge-tag substitution introduced in CMP-002 is complete and consistent across all send paths: plain-text body fallback, HTML template body, subject line, and the A/B variant subject override. It also adds the standard SuiteCRM merge tags (`{{first_name}}`, `{{last_name}}`, `{{email}}`, `{{company}}`, `{{phone}}`) to the documented set, resolves them from the recipient's platform profile (`get_profile` at `app/services/profile.py:262`), and exposes a preview endpoint that takes a `campaign_id + sample_party_id` and renders the fully substituted email for that recipient.

**Model changes** (`app/models.py` — additive):

```python
class CampaignPreviewIn(BaseModel):
    sample_party_id: Optional[str] = None  # platform user_sub; if None use campaign owner's profile
    variant_id: Optional[str] = None       # which variant to preview; None = first/only

class CampaignPreviewOut(BaseModel):
    subject: str
    body_text: str
    body_html: Optional[str] = None
    unsubscribe_url: str
    merge_vars_used: List[str] = []
    merge_vars_missing: List[str] = []
```

**Service** (`app/services/marketing_campaigns.py` — MKT-009 extension):

Extract `_build_merge_vars(party_id: str, campaign_id: str) -> dict[str, str]` as a named helper callable from both `_try_send_one` and the preview endpoint:

```python
def _build_merge_vars(party_id: str, campaign_id: str) -> dict[str, str]:
    """Resolve standard merge tags for a recipient.
    Uses get_profile(party_id) from app/services/profile.py:262.
    Returns dict with keys: first_name, last_name, email, company, phone,
    unsubscribe_url, platform_name, survey_url (when questionnaire linked).
    """
```

All existing `_build_message_body` calls updated to use `_build_merge_vars`. The merge-var dict is passed into `render_template` (CMP-002) and the plain-text `_build_message_body` helper. Missing vars leave `{{var}}` in place (existing `_render` behavior from `notification_templates.py:245`).

**Router** (`app/routers/marketing_campaigns.py` — MKT-011):

```
POST /ui/marketing/campaigns/{id}/preview-email
Body: CampaignPreviewIn
Response: CampaignPreviewOut
Auth: require_ui_session + ownership
Flag gate: yes (mutating preview resolves profile data)
```

Behavior: fetch campaign, resolve sample profile, call `_build_merge_vars`, call `_build_message_body` + optionally `render_template`, collect `merge_vars_used` (vars that had values) and `merge_vars_missing` (vars left unresolved). Return `CampaignPreviewOut`. No DDB writes, no email sent.

**Acceptance Criteria**
- `POST .../preview-email` with a real `sample_party_id` returns a fully rendered subject and body with all standard merge tags substituted.
- `merge_vars_missing` lists any `{{var}}` that had no value.
- Plain-text body for a non-HTML-template campaign still substitutes `{{first_name}}` etc.
- HTML template body (CMP-002) substitutes the full merge-vars dict including `{{unsubscribe_url}}` (CMP-004) and `{{survey_url}}` (CMP-005).
- A/B variant subject_override (CMP-007) is also personalized when `variant_id` is provided.
- Campaign send (MKT-009) uses `_build_merge_vars` — no regression in existing send tests.

**Dependencies**
- MKT-009 (`_build_message_body`, `_try_send_one`), MKT-011 (router).
- CMP-002 (HTML template `render_template`), CMP-004 (`unsubscribe_url` in merge vars), CMP-005 (`survey_url` in merge vars), CMP-007 (variant subject personalization).
- `app/services/profile.get_profile` (at `profile.py:262`).
- `app/services/notification_templates._render` (at `notification_templates.py:245`).
- Feature flag: `S.marketing_campaigns_enabled` (MKT-002).
