# QST-001: Questionnaire Gaps — Branching, File Upload, One-Response, Targeting

**Ticket**: QST-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Estimated effort**: 10-14 days (can be split into sub-tickets per gap)
**Dependencies**: existing questionnaire system (`app/models_questionnaire.py`, `app/routers/questionnaires.py`, `app/services/questionnaires_repository.py`, `app/services/questionnaire_validation.py`)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The questionnaire builder + handler is a solid MVP (9 question types, immutable
versioned publish, 3-tier validation, partial autosave, PDF export, analytics,
anonymous + authenticated respondents, ~50 pytest + 15 E2E tests all passing).
However there are several meaningful **feature gaps** that block real-world
form/survey use cases:

1. **No branching / conditional (skip) logic** — questions/sections cannot be
   shown/hidden based on prior answers. Designed for in
   `questionnaire_implementation_plan.md` (Phase 2) but not implemented. This is
   the single biggest gap for non-trivial forms.
2. **No file-upload question type** — the type system
   (`app/models_questionnaire.py`) and validators have no file/attachment type;
   forms can't collect documents.
3. **No one-response-per-user enforcement** — the system enforces one *submission
   per session* but a user can start multiple sessions and submit multiple times.
   No "single response per respondent" option for the owner.
4. **No assignment / targeting** — there is no way to *require* specific users (or
   roles/segments) to complete a questionnaire, or to track who has/hasn't
   responded. Visibility is public/private/unlisted only.
5. **Missing config UI for date/time/timezone** — backend validators exist, but
   `QuestionTypeConfigEditor.tsx` has no builder panel for these, so owners can't
   set min/max/format constraints from the UI.
6. **CSV response export not wired** — a `csv_export.py` module exists but is not
   exposed via the questionnaire endpoints (only PDF per-response export is).
7. **E2E coverage gaps** — `frontend/e2e/questionnaires.spec.ts` only exercises
   text/select/slider; date/time/timezone/address/multiselect are unit-tested
   only, and the PDF *download* path isn't E2E'd.

### 1.2 How It Works (proposed)

Address the gaps in priority order; each is independently shippable.

- **Branching (P1)**: add a `visibility_rules` construct to questions/sections —
  show/hide when a referenced earlier answer matches a condition (equals/in/
  range/answered). The validation engine already has conditional/trigger
  primitives at the group level (`questionnaire_validation.py`); extend them to
  drive question/section *visibility*, and skip validation for hidden questions.
  Builder UI: a rule editor on each question ("show this when <question> <op>
  <value>"). Respondent UI: hidden questions are not rendered and not required.
- **File upload (P2)**: add a `file` question type with config (allowed
  extensions, max size, max count). Store uploads via the existing S3/file
  pipeline; persist file refs (not bytes) in the response. Validator checks
  count/size/extension. Builder + respondent UI for upload/preview/remove.
- **One-response-per-user (P2)**: add an owner toggle
  `one_response_per_respondent`; on session start for an authenticated user with
  an existing submitted response, return the existing response / block a new
  submission (configurable: block vs. edit-existing). Anonymous forms keep
  current behaviour.
- **Assignment / targeting (P3)**: add an assignment model (assign a published
  questionnaire to users/roles/segments), a "required for you" surface for
  respondents, and a completion-tracking view for owners (who responded / who
  hasn't / reminders). Reuses notifications for reminders.
- **Config UI for date/time/timezone (P3)**: add the missing panels to
  `QuestionTypeConfigEditor.tsx` (min/max date, time bounds, allowed timezones).
- **CSV export (P3)**: wire `csv_export.py` into a
  `GET /ui/questionnaires/{id}/responses/export.csv` endpoint (owner-only),
  flattening answers by version schema.

### 1.3 Design Principles

- **Versioning-safe**: branching rules, file config, and the one-response flag are
  part of the published immutable schema snapshot, so in-flight responses keep
  their original logic.
- **Backward compatible**: all new features are opt-in; existing questionnaires
  and the 9 current types behave exactly as today.
- **Hidden ≠ required**: branching must exclude hidden questions from validation
  and analytics drop-off attribution.

---

## 2. Implementation

### 2.1 Backend
- `app/models_questionnaire.py`: add `file` question type + config; add
  `visibility_rules` to question/section; add `one_response_per_respondent` to
  questionnaire settings; add assignment models.
- `app/services/questionnaire_validation.py`: evaluate visibility rules; skip
  hidden questions; validate file constraints.
- `app/routers/questionnaires.py`: file-upload sub-endpoint; CSV export endpoint;
  one-response enforcement on session start/submit; assignment CRUD +
  completion-tracking + "assigned to me" endpoints.
- `app/services/questionnaires_repository.py`: persist rules/config/assignments;
  index assignments by respondent for the "required for you" query.

### 2.2 Frontend (`frontend/src/pages/questionnaires/`)
- Builder: branching rule editor per question; file-type config; date/time/tz
  config panels; one-response toggle; assignment UI; CSV export button.
- Respondent: conditional render/skip; file upload widget; "required for you"
  list; blocked/edit-existing behaviour for one-response forms.

### 2.3 Settings
- `QUESTIONNAIRE_FILE_MAX_MB`, `QUESTIONNAIRE_FILE_ALLOWED_EXT`,
  `QUESTIONNAIRE_ASSIGNMENTS_ENABLED` (feature-flag the bigger pieces).

---

## 3. Testing

- **pytest**: visibility-rule evaluation (hidden questions excluded from
  validation); file-type validators (size/ext/count); one-response enforcement;
  assignment + completion tracking; CSV export shape.
- **E2E** (extend `questionnaires.spec.ts` + new specs): branching show/hide flow;
  file upload submit/preview/remove; one-response block/edit; assignment
  "required for you" → complete → owner sees completion; **close the existing E2E
  gaps** by exercising date/time/timezone/address/multiselect and the PDF
  download path.

## 4. Out of Scope / Sub-ticket Split

This can ship as sub-tickets: QST-001a Branching (P1), QST-001b File upload (P2),
QST-001c One-response (P2), QST-001d Assignment/targeting (P3), QST-001e
Config-UI + CSV export + E2E coverage (P3). Rich-text labels and load/stress
testing are out of scope.
