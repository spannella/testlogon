# SuiteCRM → testlogon — Gap Analysis

Generated 2026-06-11 via a 15-area multi-agent gap analysis. Each SuiteCRM capability was checked against the live testlogon codebase AND the existing ticket/spec set.

**330 capabilities** → **HAVE 74 · PARTIAL 63 · PLANNED 30 · MISSING 145**. **157 follow-on tickets recommended** (the MISSING set + PARTIAL items needing real extension that aren't already covered by a planned ticket). Overlaps with planned work (OFBiz Party/CRM `PTY-*`, Marketing `MKT-*`, Catalog `PRD-*`, etc.) are marked PLANNED and are NOT re-ticketed.

## Summary by area

| Tier | Area | HAVE | PARTIAL | PLANNED | MISSING | → new tickets |
|---|---|---:|---:|---:|---:|---:|
| 1 | Accounts, Contacts & Relationships | 4 | 3 | 12 | 6 | **6** |
| 1 | Leads, Targets / Prospects & Target Lists | 0 | 3 | 3 | 11 | **13** |
| 1 | Opportunities, Sales Pipeline & Forecasts | 0 | 2 | 0 | 14 | **6** |
| 1 | Activities (Calls, Meetings, Tasks, Notes) & Calendar | 13 | 2 | 0 | 10 | **10** |
| 1 | Cases, Customer Support & Customer Portal | 10 | 5 | 1 | 12 | **17** |
| 2 | Email client, Inbound email & Email Templates | 5 | 2 | 2 | 9 | **10** |
| 2 | Campaigns & Email Marketing | 5 | 9 | 5 | 4 | **8** |
| 2 | Quotes, Products, Contracts & PDF Templates (AOS) | 6 | 9 | 5 | 9 | **5** |
| 2 | Invoices, Line Items & Multi-currency (AOS) | 10 | 5 | 2 | 9 | **12** |
| 3 | Knowledge Base | 0 | 0 | 0 | 12 | **12** |
| 3 | Reports & Dashboards (AOR + dashlets) | 6 | 3 | 0 | 10 | **8** |
| 3 | Workflow & Process Automation (AOW) | 4 | 3 | 0 | 8 | **9** |
| 3 | Security Suite, Studio & Admin | 6 | 7 | 0 | 8 | **14** |
| 4 | Projects, Project Tasks & Gantt | 0 | 1 | 0 | 13 | **12** |
| 4 | Events, Maps, Surveys, Documents & misc | 5 | 9 | 0 | 10 | **15** |
| | **TOTAL** | **74** | **63** | **30** | **145** | **157** |

## Scope tiers (for the build decision)

- **Tier 1 — Core CRM entities (clear fit)** — ~52 tickets
- **Tier 2 — Sales/Marketing/Email & financial CRM** — ~35 tickets
- **Tier 3 — Heavy platform engines (debatable fit)** — ~43 tickets
- **Tier 4 — Projects & misc (tangential)** — ~27 tickets

---

## Recommended tickets (the gaps)


### [T1] Accounts, Contacts & Relationships — 6 tickets

> The platform has a functional social-graph contacts surface and a full user address book, and has a comprehensive 15-ticket OFBiz Party/CRM buildout planned (PTY-001 through PTY-015) covering party CRUD, roles, bidirectional relationships, contact mechanisms, B2B org accounts, and frontend UI — but none of these tickets are yet implemented. Three capabilities SuiteCRM provides that are not covered by any planned ticket are: duplicate contact detection and merge, vCard import, and vCard export.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Account industry field | MISSING | Add industry (string picklist) and related business fields (website, phone, employee_count, annual_revenue) to PARTY_GROUP META row and CrmOrgAccountOut model;  |
| Account hierarchy (parent account / member organizations) | MISSING | Add PARENT_ORG relationship type to CrmRelationshipType and a parent_org_party_id accessor to the party service; expose in PTY-012 router and PTY-014 UI. |
| Reports-to hierarchy on Contacts (manager chain) | MISSING | Add REPORTS_TO to CrmRelationshipType enum (PTY-003) and expose bidirectional manager/report queries in the PTY-011 router. |
| Duplicate contact detection and merge | MISSING | New PTY-016 ticket: duplicate party detection (fuzzy name + email/phone match scoring) and merge-records endpoint that consolidates two party records, re-pointi |
| vCard import (import contacts from .vcf files) | MISSING | New PTY-017 ticket: vCard (.vcf) import endpoint that parses standard vCard fields (FN, EMAIL, TEL, ADR, ORG, TITLE) and creates CRM party + contact-mech record |
| vCard export (export a contact as a .vcf file) | MISSING | New PTY-018 ticket: GET /ui/party/parties/{party_id}/vcard endpoint returning a vCard 3.0/4.0 .vcf attachment built from the party's CrmPartyOut + contact mechs |

### [T1] Leads, Targets / Prospects & Target Lists — 13 tickets

> No dedicated Lead, Prospect, or Target-List module exists. Three MKT tickets cover static/dynamic contact lists and opt-out suppression (planned, not built). The Lead entity, web-to-lead conversion, lead status/source, lead conversion to Account+Contact+Opportunity, lead scoring, bulk import, duplicate merge, and drip sequencing are all absent and unplanned.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Lead record with status field (New, Assigned, In Process, Converted, Recycled, Dead) | MISSING | Create a Lead entity (status, source, assigned_to, description, contact fields) as a PERSON party subtype with role=LEAD in the PTY model, or as a standalone DD |
| Lead source tracking (Web Site, Cold Call, Email, Campaign, Trade Show, etc.) | MISSING | Add lead_source picklist field to the Lead entity ticket above; wire it into attribution rollup alongside MKT tracking codes. |
| Web-to-Lead form capture (embeddable HTML form that creates a Lead record on submission) | PARTIAL | Add a 'capture as lead' flag to questionnaire publish settings that, on anonymous submission, creates a Lead record in the planned PTY/Lead module. |
| Lead conversion to Account + Contact + Opportunity | MISSING | Design a lead-conversion workflow that creates a PARTY_GROUP (Account) + PERSON (Contact) + an Opportunity record, pending PTY module delivery. |
| Opportunity / Deal record (sales pipeline stage, close date, amount, probability) | MISSING | Implement an Opportunity / Deal module (pipeline stage SM, amount, close date, probability, linked party + lead) as a new DDB-backed service. |
| Target / Prospect record (light-weight pre-lead with email, no platform account required) | MISSING | Add PERSON parties that can exist without a platform user_sub (external email-only contacts) with a PROSPECT role, enabling campaign sends to non-users. |
| Bulk CSV import of Leads / Targets / Prospects | MISSING | Add a CSV import endpoint for contacts/leads/targets with field mapping, validation, and duplicate-check, landing records into the PTY party table or a Lead tab |
| Duplicate detection and merge for Leads / Contacts | MISSING | Implement duplicate detection (exact email/phone match on ContactMech) and a merge endpoint in the PTY party service, triggered on import and create. |
| Lead assignment / round-robin to users or queues | MISSING | Add assigned_user_id and assignment workflow to the Lead entity, with optional round-robin distribution configurable per team/queue. |
| Lead nurturing / drip campaign sequences tied to lead status | MISSING | Design a multi-step drip sequence engine (time-delayed steps, stop-on-reply, trigger on lead status change) as a campaign sequence type in the MKT module. |
| Lead scoring (point-based qualification score) | MISSING | Add a configurable point-based lead scoring engine (behaviour signals + profile criteria) and expose score on the Lead entity. |
| Activity log on Lead / Contact (calls, emails, meetings linked to the record) | PARTIAL | Extend activity_feed to support CRM-entity-scoped queries (by contact_id or lead_id) and add Call/Meeting/Note activity types linked to party records. |
| Contact / Lead search and filter (by source, status, assigned user, date range) | PARTIAL | Add filterable search to the contacts/party list endpoint (name prefix, role, status, created_at range) with GSI-backed query paths. |

### [T1] Opportunities, Sales Pipeline & Forecasts — 6 tickets

> The testlogon platform has no Opportunities, Sales Pipeline, or Forecasts functionality. Zero SuiteCRM capabilities in this area are implemented; two generic subsystems (activity feed, calendar) exist as partial foundations that could be extended once a core Opportunity entity is built. The PARTY_CRM_TICKETS.md backlog (PTY-001..PTY-015) plans a Party/Contact/B2B-Org model that is a prerequisite, but the Opportunity module, sales stage pipeline, win/loss tracking, forecast worksheets, quota management, and pipeline reports are all absent and unplanned.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Opportunity record (name, amount, close date, stage, probability, description) | MISSING | New SALES-001: Opportunity CRUD (name, amount, close_date, stage enum, probability, lead_source, description) backed by DynamoDB single-table, flag-gated, wired |
| Sales stage pipeline (e.g. Prospecting, Qualification, Proposal, Negotiation, Closed Won/Lost) | MISSING | New SALES-002: Configurable sales-stage list + Opportunity stage-transition API + Kanban view; depends on SALES-001. |
| Opportunity↔Contact roles (Decision Maker, Evaluator, Influencer, etc.) | MISSING | New SALES-003: Opportunity↔Contact role junction (role enum: decision_maker, evaluator, influencer, champion, etc.) via Party relationship layer; depends on SAL |
| Forecasts module — quota management per user/team | MISSING | New SALES-004: SalesQuota entity (user_sub, period_type, period_key, target_amount_cents) with CRUD admin API and per-user quota lookup. |
| Forecasts module — forecast worksheet (committed, best case, pipeline amounts per rep) | MISSING | New SALES-005: Forecast worksheet (category enum: committed/best_case/pipeline, override amount, period) per rep; depends on SALES-001 and SALES-004. |
| Pipeline report — opportunities by stage with amount and count | MISSING | New SALES-006: Pipeline report endpoint (opportunities grouped by stage, totals by amount/weighted amount) + frontend funnel chart; depends on SALES-001. |

### [T1] Activities (Calls, Meetings, Tasks, Notes) & Calendar — 10 tickets

> Calendar (events, recurrence, sharing, Google/Apple sync, booking links, conflict detection, iCal export, org team calendar) is robustly implemented. Call history logging exists but is scoped to platform voice/video calls with no CRM entity linking. Tasks, Notes (with attachments), meeting invitee RSVP workflow, calendar event reminders/alarms, and a unified CRM activity history timeline on records are all absent and unplanned.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Calendar: event attendees list stored on event | PARTIAL | Add per-attendee RSVP status (accepted/declined/tentative/no-response), invite-notification dispatch on event creation/update, and attendee-response endpoint PU |
| Calendar: meeting invitee accept/decline/tentative workflow | MISSING | Add RSVP endpoint (PUT /calendars/{id}/events/{id}/rsvp with status: accepted/declined/tentative), per-attendee response tracking on the event item, and notific |
| Calendar: event reminders/alarms (email/in-app, minutes-before) | MISSING | Add reminders list to EventCreateIn (array of {minutes_before, method: email/in_app}), a scheduler service that fires alerts via app/services/alerts.py at remin |
| Calendar: email invite notification to attendees on event create/update | MISSING | Wire create_event and update_event to dispatch invitation emails to attendees via app/services/alerts.py (or email_delivery.py), including ICS attachment. |
| Calls: call logging with subject, description, direction, duration, outcome | PARTIAL | Extend call history record with subject, description/notes, outcome, and optional linked_party_id (contact or Party from PARTY_CRM_TICKETS); add POST endpoint t |
| Calls: link call to CRM entity (contact, lead, account, opportunity) | MISSING | Add optional linked_entity_type/linked_entity_id fields to call records; surface call history on the Party detail view once PTY-011 ships. |
| Tasks: standalone task management (subject, status, priority, due date, assigned to) | MISSING | Create new CRM Tasks module: TaskCreateIn (subject, status, priority, due_date, assignee_sub, linked_entity_type/id), service, router /ui/crm/tasks, frontend pa |
| Notes: standalone note with free-text body and file attachment | MISSING | Create CRM Notes module: NoteCreateIn (body, file_attachment_key, linked_entity_type/id), service storing to DDB with S3 attachment reference, router /ui/crm/no |
| Activity history timeline on CRM record (contact/lead/account) | MISSING | Add CRM activity history service: aggregate calls, calendar events, tasks, notes linked to a party_id; expose GET /ui/party/{party_id}/activities returning a ch |
| Calendar: yearly recurrence frequency | MISSING | Add YEARLY to RecurrenceRule.freq enum and implement _expand_rrule YEARLY branch (simple: add 1 year to start date per occurrence). |

### [T1] Cases, Customer Support & Customer Portal — 17 tickets

> Testlogon has a solid internal ticketing core (create/assign/thread/status/boards/Jira sync) plus a live helpdesk messenger bridge. It lacks SLA enforcement on support tickets, ticket priority fields, file attachments on tickets, inbound email-to-ticket, a Knowledge Base, a Joomla-style customer self-service portal, CSAT surveys, and ticket merging/linking — all are genuinely missing with no planned tickets.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Case creation with subject, description, and sequential case number | PARTIAL | Add auto-increment human-readable case number (e.g. CASE-NNNN) generated at creation and exposed in TicketOut, for CRM parity. |
| Case priority field (Urgent/High/Medium/Low) | PARTIAL | Add a first-class priority field (urgent/high/medium/low) to CreateTicketReq and the ticket store, distinct from complexity labels. |
| Case email notifications to submitter and assigned agent | PARTIAL | Wire ticket alert events to a proper transactional email dispatch (SES) with templated subject/body for case notifications. |
| Case linked to Account (B2B organization) | MISSING | Add optional account_id / org_party_id field to tickets and a GSI for listing all cases for an organization. |
| Case linked to Contact | MISSING | Add optional contact_id linkage to the ticket store; surface it in TicketOut and add a GSI for per-contact case list. |
| Case file/attachment support | MISSING | Add a POST /{ticket_id}/attachments endpoint that accepts multipart uploads, stores to S3, and records attachment metadata on the ticket message or as a sub-ite |
| SLA management (response time targets, breach alerts, escalation rules) | MISSING | Add SLA tier config and per-ticket sla_due_at field; add background checker that marks breaches and emits escalation events. |
| Case escalation (manual and rule-based) | MISSING | Add POST /{ticket_id}/escalate endpoint that records an escalation event, increments escalation_level, and can re-assign to a senior agent. |
| Inbound email-to-ticket (email creates a case) | MISSING | Add inbound email-to-ticket: SES inbound rule → SNS → /internal/ses/inbound endpoint that parses From/Subject/Body and calls STORE.create_ticket, threading repl |
| Knowledge Base (articles, categories, case deflection suggestions) | MISSING | Build a Knowledge Base module: KB articles (title, body, category, tags), search, admin CRUD, and a 'suggested articles' endpoint at ticket creation for case de |
| Customer self-service portal (Joomla Portal / case submission without full account) | MISSING | Add a public-facing case-submission endpoint (no auth required, email-verified via token) and a portal page at /support/new for guest ticket submission. |
| Case merge / duplicate detection | MISSING | Add POST /tickets/{ticket_id}/merge with a target_ticket_id to copy messages and redirect future updates. |
| Case-to-case relationship / linked tickets | MISSING | Add a ticket_links sub-table (ticket_id, related_ticket_id, link_type: duplicate/blocks/relates_to) with GET/POST/DELETE endpoints. |
| Canned responses / reply templates for agents | MISSING | Add a TicketResponseTemplate resource (title, body, category) with CRUD for admins and a GET /tickets/response-templates for agent lookup during reply. |
| CSAT / customer satisfaction rating after case closure | MISSING | On ticket status → done, trigger a CSAT survey (reuse app/routers/questionnaires.py) sent to owner_sub, storing rating and optional comment on the ticket. |
| Ticket reporting and metrics (resolution time, volume, agent performance) | PARTIAL | Add a ticket analytics endpoint returning resolution time distribution, volume per period, and per-agent throughput beyond the current status-count summary. |
| Ticket watchers / CC (additional users notified of updates) | PARTIAL | Implement watcher add/remove endpoints (POST/DELETE /tickets/{id}/watchers) and persist watchers list on the ticket META row. |

### [T2] Email client, Inbound email & Email Templates — 10 tickets

> The platform has solid outbound transactional email infrastructure (SES delivery, bounce/complaint tracking, suppression list, system notification templates with variable substitution) but has no email client capabilities at all: no IMAP/SMTP per-user account connections, no inbox UI, no email threading, no email-to-record archiving, no user email signatures, and no HTML body delivery in SES calls (templates render HTML but the SES call sends it as plain text). Campaign email sending is planned (MKT-009) but not yet built, and neither open/click tracking nor per-campaign HTML templates are in scope for those tickets.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Per-user personal email accounts (IMAP/SMTP connection) | MISSING | Per-user IMAP/SMTP email account connections: store encrypted credentials, fetch/sync inbox via IMAP, send via personal SMTP. |
| Inbound group mailbox with auto-case / auto-lead creation | MISSING | Inbound group mailbox parser: poll a support email address, parse raw email, auto-create a support ticket and thread the replies. |
| Email composer / full email client UI (inbox, sent, drafts, folders) | MISSING | In-app email client UI: inbox list, thread view, compose/reply/forward, drafts, and folder sidebar for personal IMAP accounts. |
| Email threading and conversation view | MISSING | Email thread grouping (In-Reply-To / References header parsing) stored in DDB and surfaced in the email client UI. |
| Email archiving / relate-to-CRM-record | MISSING | Email archiving: allow users to relate an email message to a contact, ticket, or org record, stored as an email_history row on the target record. |
| Admin / platform outbound email settings (from-address, SES/SMTP configuration) | PARTIAL | Runtime admin UI to update outbound email from-address and toggle SES/SMTP, with change audit logging. |
| HTML email body in system notification templates | PARTIAL | Fix send_alert_email in app/services/alerts.py to pass html_body as SES Body.Html.Data when an HTML template is rendered. |
| User personal email signatures | MISSING | User personal email signature CRUD and auto-append to outgoing emails (requires per-user email account feature). |
| Campaign email tracking (opens, clicks, unsubscribes) | PLANNED | Extend MKT-009/MKT-010 to add open-tracking pixel and one-click unsubscribe link (CAN-SPAM / GDPR compliance) in campaign email bodies. |
| Marketing campaign email template (custom HTML body per campaign) | MISSING | Campaign-specific HTML email template: link a notification_template_id to a MarketingCampaign and render it with recipient merge vars on send. |

### [T2] Campaigns & Email Marketing — 8 tickets

> Core email delivery infrastructure (bounce/suppression/SES SNS) and in-app mass-message campaigns are fully built; the dedicated marketing campaign layer (contact lists, segments, tracker URLs, campaign-send) is entirely planned under MKT-001..MKT-014 but not yet implemented; email open-pixel tracking and web-to-lead are missing with no ticket.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Non-email campaigns (phone call / mail / fax campaign types) | MISSING | Add campaign_type enum (email, phone, mail, fax, sms) to the planned MKT-003 models and surface in the MKT-011 router so non-email outreach can be tracked. |
| Survey campaigns (link a questionnaire to a campaign) | PARTIAL | Add questionnaire_id optional field to MKT-003 MarketingCampaignCreateIn so a campaign can reference a published questionnaire slug and embed its URL in outboun |
| Email open tracking (1x1 pixel) | MISSING | Add a public GET /ui/marketing/t/{code}/open.gif pixel endpoint (records open event to tracking_codes table) and embed the pixel URL in campaign email bodies wh |
| Opt-out / unsubscribe link embedded in campaign emails | PARTIAL | Add unsubscribe URL generation (HMAC-signed, similar to cart recovery links) and a public GET /ui/marketing/optout/{token} endpoint; have MKT-009's send path ap |
| HTML email template library for campaigns | PARTIAL | Add a campaign email template CRUD (create/list/preview with {{merge_field}} substitution) as part of MKT-011/MKT-013 scope, or as a standalone MKT-015 ticket. |
| Email personalization / merge tags in campaign body | PARTIAL | Extend MKT-009 campaign send to substitute per-recipient merge fields ({{first_name}}, {{email}}, {{unsubscribe_url}}) into the email body before calling send_a |
| Web-to-lead capture form | MISSING | Add a public POST /ui/marketing/leads/capture endpoint that accepts form submissions, creates a contact/party record, optionally adds to a contact list, and rec |
| A/B (split) testing for email campaign content | PARTIAL | Add variant_bodies list to MarketingCampaignCreateIn (MKT-003) so MKT-009 can split-send variants across recipient cohorts and report per-variant open/click met |

### [T2] Quotes, Products, Contracts & PDF Templates (AOS) — 5 tickets

> SuiteCRM's Advanced OpenSales (AOS) area is almost entirely absent: the platform has a working product catalog with flat categories and stock management, auto-generated billing invoices (PDF + email), and a sophisticated KYC-domain PDF template engine with merge fields — but has no sales quote module, no CRM contract module, no quote-to-invoice or quote-to-contract conversion, no per-module generic PDF templates, and no quote line groups. Product depth features (category trees, variants, bundles, price lists, tiered pricing) are fully planned (PRD-001..016, OFB-019/020) but not yet built.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Sales Quotes — quote entity (header, status, expiry date, assigned user, billing/shipping address) | MISSING | New AOS-QUOTE-001: sales quote entity (header, stage, expiry, account/contact linkage, billing/shipping address, assigned user) — new DDB table + Pydantic model |
| Sales Quotes — multi-currency support (quote in non-USD currency with exchange rate) | PARTIAL | New AOS-CURRENCY-001: multi-currency quotes/invoices with configurable exchange rates — separate from AOS-QUOTE-001. |
| Invoices — standalone invoice record (invoice number, status, line items, tax, total, due date) | PARTIAL | New AOS-INV-001: standalone invoice CRUD (draft→sent→paid→overdue lifecycle, due_date, manual line-item editing, send-to-customer action). |
| Contracts — CRM contract record (contract name, account, start/end dates, value, status, renewal) | MISSING | New AOS-CONTRACT-001: CRM contract entity (name, account, number, start/end, value, status lifecycle, renewal notification) — new DDB table + router. |
| PDF Templates — per-module PDF template (admin creates a template for Quotes, Invoices, or Contracts with merge fields) | PARTIAL | New AOS-PDF-001: generalize kyc_document_templates.py into a module-agnostic PDF template engine for Quotes/Invoices/Contracts with configurable merge-field set |

### [T2] Invoices, Line Items & Multi-currency (AOS) — 12 tickets

> Core invoice generation, PDF, and email are fully built; tax is a single flat rate with no jurisdiction engine; multi-currency is a display-only planned spec (FIN-005) with no exchange-rate conversion at transaction time; B2B manual invoicing, payment terms, per-line tax, and CRM relationship linking are all absent.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Invoice line items (description, quantity, line amount) | PARTIAL | Add unit_price_cents field to InvoiceLineItemOut and persist it on creation so line items are self-describing (qty x unit_price = line_amount). |
| Invoice subtotal, tax, and grand total calculation | PARTIAL | Extend InvoiceOut/create_invoice to carry shipping_cents and discount_cents fields matching the ORD-008 adjustment model. |
| Invoice status lifecycle (Draft, Sent, Paid, Overdue, Void/Cancelled) | PARTIAL | Extend invoice status to Draft/Sent/Paid/Overdue/Void with transition endpoints; wire to AR aging (planned in OFB-015). |
| Manual invoice creation by admin or sales rep (B2B) | MISSING | Add POST /ui/admin/invoices with free-form buyer/seller/line-items/due-date payload for B2B manual invoicing. |
| Invoice payment terms and due date | MISSING | Add payment_terms and due_date fields to the invoice model; compute due_date = created_at + terms days; expose in PDF and list view. |
| Invoice billing address and shipping address | PARTIAL | Add billing_address (street, city, state, postal_code, country) struct to InvoiceOut and create_invoice payload. |
| Invoice void / cancel endpoint | MISSING | Add POST /ui/invoices/{number}/void endpoint that sets status=void and creates a reversal ledger entry. |
| Invoice PDF template customization / company branding | MISSING | Add admin-configurable PDF template fields (logo S3 key, company_name, footer_text) read by _render_invoice_lines to customize generated PDFs. |
| Currency conversion at transaction / charge time | MISSING | Add transactional currency conversion: on invoice creation store both original_amount_cents+currency and usd_amount_cents using current exchange rate; requires  |
| Named tax groups / multiple tax rates by jurisdiction | MISSING | Add a tax_rates table (name, rate_bps, country/jurisdiction) and allow assignment at line-item level; linked to OFB-013/014 GL Sales Tax Payable account. |
| Per-line-item tax rate assignment | MISSING | Add tax_rate_bps and tax_exempt fields to InvoiceLineItemOut; compute per-line tax and sum to invoice tax_cents. |
| Invoice-level discount line | PARTIAL | Pass applied promo discount_cents into create_invoice() and render it as a discount line in the PDF and InvoiceOut model. |

### [T3] Knowledge Base — 12 tickets

> No Knowledge Base module exists in testlogon; all 12 SuiteCRM KB capabilities are missing and unplanned.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Article CRUD with rich-text body | MISSING | AOK-001: KB article CRUD (DynamoDB table kb_articles; PK=ARTICLE#{id}; fields: title, body_html, status, author_sub, created_at, updated_at). |
| Article status lifecycle (Draft / Published / Expired) | MISSING | AOK-002: Article status lifecycle (draft → published → expired) with transition audit; gated by KNOWLEDGE_BASE_ENABLED feature flag. |
| Article file attachments | MISSING | AOK-003: KB article attachments — S3 upload + link to article record (reuse newsfeed upload pattern at app/routers/newsfeed.py:3117). |
| KB category tree (hierarchical categories) | MISSING | AOK-004: KB category tree service (parent_id, path materialization) — can share the PRD-004 pattern in docs/ofbiz/specs/PRD-004.md but on a separate kb_categori |
| Article ratings (helpful / not helpful) | MISSING | AOK-005: Article helpfulness rating (POST /kb/articles/{id}/rate, helpful:bool; aggregate helpful_count/not_helpful_count on article). |
| Article view counter | MISSING | AOK-006: Article view counter — atomic DynamoDB increment on GET /kb/articles/{id}; store view_count on article record. |
| Related articles linking | MISSING | AOK-007: Related articles — RELATED#{article_id}/ARTICLE#{target_id} rows on kb_articles table; GET /kb/articles/{id}/related returns list. |
| Portal publication (public / unauthenticated article browsing) | MISSING | AOK-008: Public KB portal — unauthenticated GET /public/kb/articles (list published) + GET /public/kb/articles/{id} + GET /public/kb/search?q= endpoints. |
| KB article full-text search | MISSING | AOK-009: KB full-text search — add _search_kb module to app/routers/search.py aggregator; token-index pattern mirrors existing message search. |
| KB article tags / keywords | MISSING | AOK-010: KB article tags field (list of normalized strings, indexed with TAG#{tag}/ARTICLE#{id} rows on kb_articles table; mirrors newsfeed tag pattern). |
| Article revision history / versioning | MISSING | AOK-011: KB article revision history — REVISION#{article_id}/REV#{ts} rows storing prior body snapshots; GET /kb/articles/{id}/revisions. |
| Admin KB management UI | MISSING | AOK-012: KB admin UI — frontend/src/pages/knowledge/ with article list, editor (rich text), category tree, publish/expire controls. |

### [T3] Reports & Dashboards (AOR + dashlets) — 8 tickets

> testlogon has several fixed purpose-built analytics dashboards (creator, financial, ads, KYC) and charting infrastructure (recharts), but entirely lacks the core SuiteCRM AOR capability: no user-defined report builder, no cross-entity query composer, no per-user configurable home dashlets, no saved searches, and no general-purpose scheduled report emails tied to custom reports. The gap is structural — the platform's analytics are hard-coded per domain rather than metadata-driven.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Custom report builder — select any module, choose fields, add conditions (filter rows) | MISSING | AOR-001: custom report builder — metadata-driven report entity (module, fields, conditions), DynamoDB-backed, creator/admin scope. |
| Report grouping (GROUP BY) and aggregate functions (SUM, AVG, COUNT, MIN, MAX) | MISSING | AOR-002: grouping and aggregate functions for the report builder (depends AOR-001). |
| Report charts (bar, line, pie) embedded in report output | PARTIAL | AOR-003: chart attachment to report definitions (bar/line/pie selectable per report, depends AOR-001). |
| Scheduled report delivery by email (cron-driven, send to recipient list) | PARTIAL | AOR-004: generalise scheduled report email delivery to cover custom AOR reports (depends AOR-001; can reuse audit_export_schedule patterns). |
| Per-user configurable Home dashboard with drag-and-drop dashlets | MISSING | DASH-001: per-user configurable home dashboard with dashlet registry (add/remove/reorder widgets, layout persisted in DynamoDB). |
| Saved Searches as dashlets (pin a list-view filter as a dashboard tile) | MISSING | DASH-002: named saved searches with dashlet tile rendering (depends DASH-001). |
| Pre-built dashlets: Recent Activities, Upcoming Calls/Meetings, My Leads, etc. | MISSING | DASH-003: standard dashlet catalogue (Recent Activity, Pipeline, Tickets, Calendar today, etc.) as selectable tiles for DASH-001. |
| CSV data export from tabular modules (billing ledger, contacts, questionnaire responses) | PARTIAL | Extend GET /ui/export/csv to cover additional modules (tickets, subscriptions, orders, contacts-crm) — low-effort extension of existing pattern. |

### [T3] Workflow & Process Automation (AOW) — 9 tickets

> The platform has solid time-based scheduling for content (unified scheduler: posts, file-shares, catalog sales) and narrow event-triggered automation (chat-bot keyword triggers, cart-abandonment staged reminders, webhook outbound delivery), but the core AOW concept — a user-configurable rule engine that watches any CRM record module, evaluates multi-field conditions, and fires modify-field / create-record / send-email actions on save or on a recurring schedule — does not exist and has no planned ticket.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Rule definition: apply to a target module / record type | MISSING | Add a configurable CRM workflow rule entity with a target_module field (contact, ticket, order, etc.) as the foundation for AOW-style automation. |
| Trigger: on-save (create or update record) | MISSING | Implement on-save workflow rule trigger: evaluate registered rules after any record write in target modules. |
| Trigger: scheduled (cron / time-based polling) | PARTIAL | Extend the unified scheduler to support recurring CRM workflow rules (scan target module records on cadence and evaluate conditions). |
| Trigger: time-elapsed since record field (e.g. 3 days after close date) | MISSING | Add a time-elapsed trigger type to the workflow rule engine: fire N hours/days after a specified record field value. |
| Condition evaluation: field comparison operators (equals, contains, greater-than, etc.) | MISSING | Build a condition evaluator supporting field/operator/value triples for CRM record fields (eq, neq, contains, gt, lt, is_empty). |
| Action: modify field (set a record field to a value) | MISSING | Implement a modify-field workflow action: given a module, record id, field name, and new value, apply the update as an action step. |
| Action: create related record (e.g. create Task, create Case) | MISSING | Implement a create-record workflow action: create a linked ticket, task, or contact record as a workflow action step. |
| Action: send email notification (template-based) | PARTIAL | Wire the existing template email infrastructure into the workflow rule engine as a 'send email' action step, callable from a configured rule. |
| Staged / drip reminder sequences tied to a record event | PARTIAL | Generalize the staged-reminder infrastructure into a configurable drip-sequence action type in the workflow rule engine. |

### [T3] Security Suite, Studio & Admin — 14 tickets

> testlogon has strong platform-admin primitives (scoped roles, audit export, job monitoring, email monitoring, billing config) but is entirely missing SuiteCRM's CRM-specific ACL layer (per-module CRUD/import/export/mass-update roles, record-level Security Groups, field-level ACL), Studio/Module Builder (custom fields, custom modules, relationship builder, layout editor, dropdown editor), and multi-currency admin. The scheduler exists but as a user-facing content scheduler, not an admin-configurable cron job manager.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| ACL Roles: per-module CRUD permission matrix (create/read/update/delete/export/import/mass-update per CRM module) | PARTIAL | Design and implement a per-module CRUD/import/export/mass-update ACL role matrix stored in DynamoDB, mapped onto the existing AdminScope/AdminProfile layer. |
| ACL Roles: role assignment to users and user groups | PARTIAL | Extend role grant to support multi-role assignment per user and allow security groups/user groups to carry an ACL Role that propagates to members. |
| Security Groups: record-level access control (users/groups can only see records they own or are assigned to) | MISSING | Implement CRM record-level Security Groups: a DynamoDB membership table linking record-id to group-id, enforced in list/get service calls on contacts, tickets,  |
| Field-level ACL: hide or read-only specific fields per role | MISSING | Build a field-level ACL metadata store and a response-model post-processor that nullifies or omits fields based on the caller's role/scope. |
| Admin: system-level audit log export (all entity changes across the platform, downloadable CSV/NDJSON/PDF) | PARTIAL | Add per-record field-change audit trail (old_value/new_value/field_name/record_type/record_id) as a new audit_adapters category and a write-path hook in the ser |
| Admin: scheduler / cron-job management UI (view, enable/disable, trigger background jobs) | PARTIAL | Add enable/disable toggle endpoints and a manual-trigger endpoint to the admin jobs API, with DDB-persisted job config so changes survive restarts. |
| Admin: email queue management (view queued outbound emails, retry bounced, manage suppressions) | PARTIAL | Implement an outbound email queue table with per-message status tracking and an admin retry/cancel endpoint. |
| Admin: global search configuration (enable/disable modules in search, set search weights/boost) | PARTIAL | Add an admin API to manage per-domain search inclusion and relevance weights, stored in DynamoDB and reloaded at runtime. |
| Admin: currency management (add currencies, set exchange rates, set default currency) | PARTIAL | Implement admin currency management: DynamoDB-backed currency table, exchange rate fetching/caching, and GET/POST/PATCH /ui/admin/currencies endpoints. |
| Studio: custom fields (add custom fields to existing modules without code changes) | MISSING | Build a Studio-like custom field registry: DynamoDB metadata table for field definitions per entity type, a runtime validation layer, and API endpoints to defin |
| Studio: custom modules (create new entity types via a builder UI without writing code) | MISSING | Implement a dynamic module builder: DynamoDB-backed entity type registry, generic CRUD router that serves any registered module, and admin UI for module definit |
| Studio: relationship builder (define custom relationships between modules — 1:1, 1:N, N:M) | MISSING | Build a relationship metadata registry allowing admins to define custom inter-module relationships, stored in DynamoDB and surfaced via generic relate-field end |
| Studio: layout editor (edit detail/edit/list/search view layouts per module) | MISSING | Implement a layout metadata store (DynamoDB) and a frontend layout renderer that reads field order/visibility from stored layout definitions per module/view typ |
| Studio: dropdown editor (add/edit/reorder options in picklist/enum fields) | MISSING | Build a dropdown editor service: DynamoDB table for named option lists, CRUD admin API at /ui/admin/dropdowns, and integration with custom fields. |

### [T4] Projects, Project Tasks & Gantt — 12 tickets

> The testlogon 'project' is a file-grouping layer (name, description, tags, tracked files with provider/status) not a CRM project management system. Zero SuiteCRM project management capabilities are present: no project tasks, no Gantt, no templates, no resource assignment, no task dependencies, no CRM relationships. The project record itself is partial (missing status, dates, priority). No tickets in any backlog cover these CRM project management gaps.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Project record (name, description, status, dates, priority) | PARTIAL | Extend ProjectModel and projects API with status, start_date, end_date, priority, and assigned_user fields to match SuiteCRM project header semantics. |
| Project tasks (duration, start/end dates, % complete, order) | MISSING | Implement ProjectTask model and CRUD service/API under /v1/projects/{id}/tasks with name, duration, start_date, end_date, percent_complete, task_order, descript |
| Project task dependencies (predecessor/successor links) | MISSING | Add predecessor_task_ids field to ProjectTask model and dependency-validation logic so dependent tasks cannot start before their predecessors are complete. |
| Project task resource assignment (assign task to user/contact) | MISSING | Add assigned_user_id to ProjectTask and project-level resources list (ProjectResource) supporting internal users and party/contact links. |
| Gantt chart view | MISSING | Implement a Gantt chart frontend component (e.g. using dhtmlx-gantt or react-gantt-task) consuming project tasks with start_date, duration, dependencies, and re |
| Project templates (reusable task structures) | MISSING | Implement ProjectTemplate model and API (POST/GET/PUT/DELETE /v1/project-templates) and a 'create from template' endpoint that clones the task structure into a  |
| Project milestones | MISSING | Add is_milestone boolean to ProjectTask model so milestone tasks render as diamond markers on the Gantt view and can be filtered/reported separately. |
| Project team members / multi-resource pool | MISSING | Implement a ProjectMember model and /v1/projects/{id}/members endpoints to add/remove users with roles (owner, member, viewer) feeding the Gantt resource rows. |
| Project to Contact relationships | MISSING | Add a ProjectContact join endpoint and subpanel to link Party/Contact records to projects, reusing the PTY PARTY_CRM_TICKETS party model once built. |
| Project to Account/Organization relationships | MISSING | Add account_id field (linking to PARTY_GROUP party) to ProjectModel and index so projects can be filtered and displayed under an organization account. |
| Project to Case/Ticket relationships | MISSING | Add project_id optional field to TicketModel and a bidirectional project-ticket link endpoint so support cases can be associated with a delivery project. |
| Project status workflow (planned/in-review/underway/completed/deferred) | MISSING | Add status field (draft/in_review/underway/completed/deferred) to ProjectModel with transition validation and audit_event emission on state changes. |

### [T4] Events, Maps, Surveys, Documents & misc — 15 tickets

> Surveys (questionnaire builder) and transactional SMS are fully built; Calendar booking and mobile/responsive UI are solid partial coverage; SuiteCRM-specific CRM Events management (invitee/delegate/capacity/waitlist), geocoded contact proximity search, document category/revision/expiration library, and iframe dashlets are all absent and unplanned.

| Capability | Status | Proposed ticket scope |
|---|---|---|
| Events module — invitee list management (add/remove/import invitees, send invitations) | MISSING | Add event invitee management: per-invitee invitation status, bulk import from contacts, invitation email via alerts.send_alert_email. |
| Events module — delegate/registration management (accept/decline, attendance check-in, delegate badge/certificate) | MISSING | Build event delegate/registration module: per-user registration, acceptance/decline workflow, attendance tracking, optional PDF certificate. |
| Events module — event capacity limits and waitlist | MISSING | Add max_attendance field to calendar events + waitlist queue with auto-promotion on cancellation. |
| Maps — geocode addresses for Contacts, Accounts, Leads | PARTIAL | Extend address geocoding (real Google Maps or OpenStreetMap Nominatim) to general contact/account address records, storing lat/lng for map rendering. |
| Maps — proximity/radius search on Contacts or Accounts | MISSING | Add radius/proximity search endpoint for contacts and accounts using stored lat/lng with Haversine formula. |
| Maps — map view (pin drop / visual map of records) | MISSING | Add map view page/dashlet rendering geocoded contact/account pins using a Leaflet or Google Maps embed. |
| Surveys — survey distribution (send link to contacts, email invitation) | PARTIAL | Add survey distribution endpoint that emails a link to a contact-list or segment using alerts.send_alert_email (mirrors mass_message_campaigns). |
| Surveys — survey reporting/analytics (completion rates, per-question answer distribution) | PARTIAL | Extend survey analytics to compute per-question answer frequency distributions for select/radio/multiselect types. |
| Surveys — bulk response export (CSV/Excel across all respondents) | MISSING | Add GET /questionnaires/{id}/responses/export?format=csv endpoint streaming all submitted response answers. |
| Documents — general document library (upload, categorize, link to records) | PARTIAL | Add document category, description, and record-link fields to file nodes, enabling CRM-style document library (category/subcategory, link to contact/account). |
| Documents — document revision tracking (version history, download prior versions) | PARTIAL | Add document revision history to general filemanager: on overwrite, store previous version with revision number and allow download of prior revisions. |
| Documents — document expiration date and expiry alerts | PARTIAL | Add optional expires_at field and expiry notification to general filemanager file nodes, mirroring license_agreements.py pattern. |
| Outbound SMS — send individual SMS to a Contact from their record | PARTIAL | Expose SMS compose-and-send action on contact record UI, wiring to sms_delivery.send_sms — platform SMS infrastructure is complete. |
| Outbound SMS — bulk SMS campaign to a contact list or segment | MISSING | Add SMS channel to mass_message_campaigns or marketing campaigns, lifting the 5-number cap and wiring contact-list recipient resolution. |
| Global Activity audit log (cross-module admin view of all user/system actions) | PARTIAL | Add paginated admin GET /ui/admin/audit-log endpoint (real-time query, no export job needed) with user/date/event-type filters for live audit browsing. |

---

## Already PLANNED (no new ticket — covered by existing work)

- **Accounts, Contacts & Relationships**: Account billing and shipping address, Account-Contact relationship (linking contacts to accounts), Contact roles on accounts (e.g. Decision Maker, User, Influencer), Unified contact mechanisms (email, phone, postal address per contact/account), Party roles (customer, supplier, employee, etc.), Party relationships (bidirectional, typed), Legacy contacts migration to party graph, B2B organization (account) creation and member management …(+4)
- **Leads, Targets / Prospects & Target Lists**: Static Target List (named list of Leads/Contacts/Prospects for campaign sends), Dynamic / rule-based Target List (segment membership auto-computed from criteria), Suppression / Exclusion List (do-not-contact list that filters campaign sends), Campaign-to-Target-List linkage (associating lists with campaigns for send targeting)
- **Email client, Inbound email & Email Templates**: Campaign email send using marketing list / segment audience, Campaign email tracking (opens, clicks, unsubscribes)
- **Campaigns & Email Marketing**: Target lists / contact lists (static recipient lists), Email marketing wizard (step-by-step campaign builder UI), Contact/lead import into target list, Rule-based dynamic audience segments (party segments), Marketing tracker code service (campaign visit + order attribution)
- **Cases, Customer Support & Customer Portal**: Helpdesk agent transfer / replacement on disconnect
- **Quotes, Products, Contracts & PDF Templates (AOS)**: Product Catalog — multi-level category trees (parent/child category hierarchy), Product Catalog — product variants (virtual/variant product with feature combinations), Product Catalog — product bundles/kits (composite products with component items), Product Catalog — product price components / price lists (LIST_PRICE, PROMO_PRICE, dated effective windows), Product Catalog — volume/tiered pricing rules (quantity breakpoints, bulk discounts)
- **Invoices, Line Items & Multi-currency (AOS)**: Exchange rate table with live rates per currency, Invoice shipping charge line
