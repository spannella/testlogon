# OpenCATS → testlogon — Gap Analysis (ATS / Recruiting)

Generated 2026-06-11 via a 4-area multi-agent gap analysis (grounded in the live
codebase + all 38 ticket files + 381 existing specs: docs/ofbiz/specs, docs/suitecrm/specs,
docs/ticket-bounty/specs). Sources: [OpenCATS repo](https://github.com/opencats/OpenCATS),
[OpenCATS docs](https://documentation.opencats.org),
[intro/overview](https://opencats-documentation.readthedocs.io/en/latest/introduction.html).

## Headline

OpenCATS is a recruiting **ATS** built around four entities — **Companies, Contacts,
Job Orders, Candidates** — joined by a **candidate↔job-order pipeline** with ranked
statuses, plus a **public career portal** (apply→candidate→pipeline), résumé upload +
**skill tagging** (OpenCATS dropped résumé *parsing* upstream and replaced it with skill
tags), activities/calendar, email templates, saved lists/searches, tags, custom fields,
CSV import, and recruiter reports.

**testlogon already owns the horizontal plumbing** an ATS needs and routes most OpenCATS
"support" capabilities to existing/planned work:
- **HAVE:** merge-field email templates (`notification_templates.py`), email delivery +
  archiving (`email_delivery.py`, EML-007), global multi-module search (`search.py`),
  questionnaires with public published slugs, file manager + S3, users/roles
  (`app/auth/roles.py`), full calendar (`app/routers/calendar.py`).
- **PLANNED (SuiteCRM/OFBiz):** companies/contacts (PTY party/org/B2B + CCT-001/002/003),
  activities/reminders/RSVP/timeline (ACT-002/003/004/009), per-module custom fields
  (STU-011), per-module ACL + record-level security (STU-002/003/004), saved searches
  (RPT-008), static lists (MKT-007), mass-email (MKT-009), report builder (RPT-002/003/005/007),
  web-to-lead public capture (CMP-006/LED-005), public portal pattern (KB-011), admin email
  config (EML-002), lead dedupe/merge + CSV import + round-robin + source attribution
  (LED-004/008/009/010).

**The genuine gap is the vertical recruiting data model — it does not exist anywhere in
code or tickets:** no Job Order / requisition, no Candidate entity, no pipeline, no public
job board, no apply→candidate→pipeline flow, no résumé parsing, no skill-tag registry.
(HRM "Positions" are *internal* employee roles; OPP "Opportunities" are *sales* deals —
neither models a client recruiting requisition.)

---

## Gap matrix (condensed)

### A. Candidates + Résumé / Skills
| Capability | Status | Evidence / note |
|---|---|---|
| Candidate entity (ATS fields: address, current/desired pay, key-skills, date-available, can-relocate, LinkedIn, status, owner) | **PARTIAL/PLANNED** | LED Lead covers name/email/phone/company/title/source/owner/status (`LED-002/003`); **missing** the ATS-specific fields → extend Lead or new Candidate |
| Résumé/CV upload + multiple attachments + "primary resume" | **PARTIAL** | file manager + KB-003 S3-attach pattern exist; no candidate linkage/primary flag |
| Résumé parsing / text extraction → full-text résumé search | **MISSING** | no parsing anywhere; file search is filename-only (`filemanager.py:1734`) |
| Skill tagging + skill-based search | **MISSING** | no cross-module tag/skill store |
| Duplicate detection + merge | **PLANNED** | LED-009 (reusable if Candidate=Lead) |
| Owner/recruiter assignment; source attribution | **PLANNED** | LED-010 / LED-004 |
| Candidate hot-list / quick-add-from-résumé | **MISSING** | no shortlist concept |

### B. Companies & Contacts + Job Orders
| Capability | Status | Evidence / note |
|---|---|---|
| Company entity + address/phone/web/hierarchy/departments | **PLANNED** | PTY-008 (B2B org) + CCT-001 (industry/web/phone) + CCT-002 (hierarchy) |
| Company key-technologies / FEIN / billing-contact pointer | **MISSING** | small additive gaps not in PTY/CCT |
| Contact (name/email/phone/reports-to) | **PLANNED** | PTY-007 mechs + CCT-003 reports-to |
| Contact job-title / is-hot flag | **MISSING** | no title/hot field on PERSON party |
| **Job Order / requisition** (title, client, contact, recruiters, openings, type H/C/C2H/Referral, 7-state status, hot, public, pay/bill rate, location, description, lists) | **MISSING** | **net-new** — HRM Position is internal, OPP is sales |
| Job-order lists/filters (open/hot/mine), openings-vs-placed | **MISSING** | net-new |

### C. Pipeline & Submissions + Activities & Calendar
| Capability | Status | Evidence / note |
|---|---|---|
| Pipeline = candidate↔joborder M:N join | **MISSING** | analogue: OPP-004 junction pattern |
| Ranked, configurable status workflow (100 No-Contact → 900 Placed) + Kanban | **MISSING (strong analogue PLANNED)** | OPP-003 stage-config + Kanban is a near-exact template |
| Status-change logging | **PLANNED-ish** | wire to ACT-009 timeline + audit_event |
| Candidate rating (1–5) within pipeline | **MISSING** | |
| "Submit to client" action (email+resume, advance status, log) | **MISSING** | reuse SES + S3 attach (ACT-003 pattern) |
| Bulk pipeline add/remove | **MISSING** | |
| Placement record (start date, fee) on Placed | **MISSING** | |
| Typed activity logging on entity (Call/Email/Other/Submitted) | **PLANNED** | ACT-009 (per-entity timeline; `activity_feed.py` is social, not CRM) |
| Combined "log activity + schedule next event" | **MISSING** | |
| Calendar: upcoming events / CRUD / recurrence / ICS / sync | **HAVE** | `app/routers/calendar.py` |
| Event reminders/alarms; RSVP; event-type taxonomy; **event↔entity link** | **PLANNED / PARTIAL / MISSING** | ACT-004 / ACT-002 / event-type partial / entity-link **missing** |

### D. Career Portal + Email + Search/Lists/Tags/Custom-fields/Import + Reports + Admin
| Capability | Status | Evidence / note |
|---|---|---|
| **Public job board** (public-flagged jobs, branding, per-posting URL, RSS) | **MISSING** | net-new; reuse KB-011 public-portal + questionnaire-slug patterns |
| **Self-apply → Candidate + pipeline** (name/email/résumé) | **MISSING** | adapt CMP-006/LED-005 web-to-lead plumbing |
| Résumé upload from portal; per-posting screening questionnaire | **PARTIAL** | file manager + questionnaires exist; not wired |
| Send email to candidate/contact (logged); merge-field templates | **HAVE** | `email_delivery.py` + `notification_templates.py` + EML-007/009 |
| Mass email to a list; saved lists; saved searches | **PLANNED** | MKT-009 / MKT-007 / RPT-008 |
| Global/per-module search | **HAVE** | `search.py` (add candidate/job branches) |
| Cross-module tags / skill tags | **MISSING** | no generic tag store |
| Custom fields per module | **PLANNED** | STU-011 (add candidate/job_order entity types) |
| CSV import (candidates/companies/contacts) | **PARTIAL/PLANNED** | export HAVE; lead import LED-008; **candidate import missing** |
| Reports (submissions/placements/recruiter/pipeline/source) | **PARTIAL (framework)** | RPT-002/003/005/007 builder; needs recruiting data source |
| Multiple recruiters/users; access levels; sites | **HAVE / PLANNED** | roles HAVE; STU-002/003/004 fine-grained ACL + groups |
| Career-portal config; email config | **MISSING / PLANNED** | portal config net-new; email config EML-002 |

---

## Recommended new tickets (the net-new ATS vertical)

Proposed prefix **`ATS`**. Decomposed into clusters (each cluster = several tickets: model/table/flag → service → router → FE → tests):

**Tier 1 — Core ATS entities (~15 tickets)**
- **Job Order / requisition**: entity + DDB table + flag; type/status state-machine; hot/public flags; pay-bill-rate/location/description; lists & filters (open/hot/mine + openings-vs-placed); router; FE; tests.
- **Candidate**: entity (extend Lead/PTY PERSON with ATS fields: pay, date-available, can-relocate, LinkedIn, candidate-status); résumé attachment linkage + "primary"; router; FE; tests. (Reuse LED-009 dedupe/merge, LED-010 owner, LED-004 source.)
- **Pipeline**: candidate↔job-order junction; ranked configurable status workflow + Kanban (model on OPP-003/004); status-change → ACT-009 timeline; ratings; tests.

**Tier 2 — Recruiting workflow (~10 tickets)**
- **Career portal / public job board**: public listing of public-flagged jobs, branding/config, per-posting slug URL, RSS feed (reuse KB-011 + questionnaire-slug).
- **Self-apply flow**: public apply endpoint → Candidate + pipeline "New", résumé upload, optional per-posting screening questionnaire (adapt CMP-006/LED-005 + questionnaires).
- **Submit-to-client** action (SES email + résumé attach + advance status + log); **placement record** (start date, fee) on Placed; **bulk pipeline** add/remove.
- **Skill tags**: cross-module tag/skill registry + assignment store + skill search (candidate skills, job required-skills).

**Tier 3 — Depth / peripheral (~10 tickets)**
- **Résumé text extraction** (PDF/DOCX → text) + full-text résumé keyword-search index.
- **Candidate/company CSV import** (model on LED-008/009 dedupe).
- Small company/contact field gaps: `key_technologies`, `fein`, `billing_contact_party_id` (extend CCT/PTY), contact `title` + `is_hot`.
- **Candidate hot-lists / shortlists** + quick-add-from-résumé.
- Reports wiring: submissions / placements / recruiter-activity / pipeline-breakdown / candidates-by-source as RPT-002 report definitions; calendar **event↔entity link** + combined log+schedule.

**Already covered → NO new ticket:** companies/contacts (PTY/CCT), email/templates (HAVE + EML), calendar (HAVE), activities/reminders/RSVP (ACT-*), custom fields (STU-011), ACL/sites (STU-002/003/004), saved searches (RPT-008), static lists (MKT-007), mass email (MKT-009), report builder (RPT-*), email config (EML-002), users/roles (HAVE).

## Scope tiers (for the build decision)
- **Tier 1 — Core ATS entities** (Job Order + Candidate + Pipeline): ~15 tickets
- **Tier 2 — Recruiting workflow** (career portal/apply, submit/placement, skill tags): ~10 tickets
- **Tier 3 — Depth** (résumé parsing/search, CSV import, field gaps, hot-lists, reports wiring): ~10 tickets
- **Everything (T1–T3):** ~35 tickets

All additive + flag-gated default-off, reusing existing primitives (LED dedupe/owner/source, OPP pipeline/Kanban, ACT timeline, questionnaires, file manager/S3, email/SES, KB public portal, RPT reports) — never forking.
