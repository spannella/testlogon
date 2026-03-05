# Questionnaire Creator & Viewer — Implementation Plan

## 1) Goals and scope
- Let authenticated users create and publish questionnaires.
- Let other users discover and submit responses.
- Support rich question types:
  - Short/long text
  - Select (single)
  - Multi-select
  - Radio group
  - Slider/range
  - Date
  - Time
  - Timezone
  - Address
- Support validation at three levels:
  - Per-question
  - Question-group/page-level
  - Whole-form-level
- Provide:
  - Custom hints/help text per question
  - Progress monitoring
  - Previous/next navigation
  - End-of-flow answer summary
  - PDF export of completed response

## 2) User journeys

### A. Creator journey
1. Create new questionnaire (title, description, visibility).
2. Add sections/pages.
3. Add questions to each section and choose question type.
4. Configure options (for select/radio/multi-select), slider bounds/steps, address/timezone settings.
5. Configure validation:
   - Question constraints (required, min/max length, regex, numeric bounds, date/time constraints, choice limits).
   - Group constraints (e.g., at least one of these 3 fields required).
   - Form constraints (cross-section rules).
6. Add custom hint/help text and placeholder text.
7. Preview flow as respondent.
8. Publish questionnaire (versioned snapshot).
9. Monitor response progress and completion analytics.

### B. Respondent journey
1. Open published questionnaire link.
2. Start response session.
3. Answer questions page by page with visible progress bar.
4. Navigate next/back while preserving state.
5. See real-time validation feedback.
6. On final submit, see summary of answers.
7. Download completed response as PDF.

## 3) Domain model and data schema

### Core entities
- `User`
- `Questionnaire`
  - `id`, `owner_id`, `title`, `description`, `status` (`draft|published|archived`), `published_version_id`
- `QuestionnaireVersion`
  - immutable snapshot used for responses
  - `questionnaire_id`, `version_number`, `schema_json`, `published_at`
- `Section`
  - `version_id`, `title`, `description`, `position`
- `Question`
  - `section_id`, `type`, `label`, `hint`, `required`, `config_json`, `position`
- `ValidationRule`
  - `scope` (`question|group|form`), `scope_ref`, `rule_type`, `rule_config_json`, `error_message`
- `ResponseSession`
  - `version_id`, `respondent_id?`, `status` (`in_progress|submitted`), `started_at`, `submitted_at`, `current_section_index`
- `Answer`
  - `response_session_id`, `question_id`, `value_json`, `is_valid`, `validation_errors_json`
- `ProgressEvent` (optional for analytics)
  - saves navigation/progress checkpoints

### Notes
- Store questionnaire structure in normalized tables + optional JSON snapshot for rendering speed.
- Keep published versions immutable so old responses always map to exact schema.
- Use `value_json` for typed answers with consistent serialization.

## 4) Validation engine design

### Rule layering
1. **Question-level** (field-local)
   - required, type checks, min/max, regex, options membership
2. **Group-level** (within section or named group)
   - "at least N answered", "if A then B required", mutually exclusive conditions
3. **Form-level** (cross-section)
   - global dependencies and conditional constraints

### Execution strategy
- Shared validation contract between backend and frontend:
  - Frontend for instant UX feedback.
  - Backend as source of truth at save/submit.
- Validation pipeline:
  1. Normalize answer values.
  2. Run question rules.
  3. Run group rules.
  4. Run form rules.
  5. Return structured error map keyed by question/group/form.

## 5) Question type configuration spec
- `text`: `minLength`, `maxLength`, `regex`, `multiline`
- `select`: `options[]`, `allowOther`
- `multiselect`: `options[]`, `minSelections`, `maxSelections`
- `radio`: `options[]`
- `slider`: `min`, `max`, `step`, `unitLabel`
- `date`: `minDate`, `maxDate`, `disableWeekends?`
- `time`: `minTime`, `maxTime`, `interval`
- `timezone`: `allowedZones[] | all`, default zone
- `address`: structured fields (line1, line2, city, region, postalCode, country), country-specific validation mode

## 6) API design (high level)

### Creator APIs
- `POST /questionnaires` create draft
- `GET /questionnaires/:id` fetch draft
- `PUT /questionnaires/:id` update metadata
- `POST /questionnaires/:id/sections`
- `POST /sections/:id/questions`
- `PUT /questions/:id`
- `PUT /questionnaires/:id/validation-rules`
- `POST /questionnaires/:id/publish`
- `GET /questionnaires/:id/analytics`

### Respondent APIs
- `GET /published/:slug` fetch published schema
- `POST /published/:slug/sessions` start response
- `PUT /sessions/:id/answers` save partial answers
- `POST /sessions/:id/validate` run full validation
- `POST /sessions/:id/submit` submit response
- `GET /sessions/:id/summary` answer summary
- `GET /sessions/:id/pdf` generate/download PDF

## 7) Frontend architecture

### Creator UI
- Questionnaire builder canvas with drag/reorder sections/questions.
- Right-side configuration panel for question settings + hints + validation.
- Rule builder UI for group/form logic (condition blocks).
- Preview mode matching respondent experience.

### Respondent UI
- Stepper/page-based flow by section.
- Progress indicator:
  - simple percentage (`answered required / total required`) or page completion.
- Back/next navigation with autosave.
- Inline validation and section-level errors.
- Final summary page with edit links back to sections.
- Download PDF action after submission.

## 8) PDF export approach
- Server-rendered HTML template of completed response.
- Convert HTML to PDF (Chromium print-to-PDF or wkhtmltopdf equivalent).
- Include:
  - Questionnaire title/version
  - Respondent metadata (if allowed)
  - Submission timestamp
  - Sectioned Q&A with labels and values
- Save generated PDF path/URL for repeated downloads.

## 9) Security, privacy, and compliance
- Authorization:
  - only owner/admin can edit/publish.
  - respondents can only access their own sessions (unless anonymous public links).
- Input sanitization on all text fields/hints.
- Rate limiting for public submission endpoints.
- Optional captcha for anonymous flows.
- PII handling for address/timezone/date/time answers (encryption at rest if required).
- Audit trail for publish events and schema changes.

## 10) Observability and analytics
- Metrics:
  - starts, completions, drop-off by section/question
  - average completion time
  - validation failure hotspots
- Logs:
  - submission failures, PDF generation failures
- Dashboards for creator progress monitoring.

## 11) Delivery phases

### Phase 1 — MVP foundation
- Questionnaire draft builder (core question types)
- Publish immutable version
- Respondent flow with next/back + autosave
- Question-level validation
- Submit + summary screen

### Phase 2 — Advanced validation and analytics
- Group/form rule engine
- Conditional visibility logic (optional enhancement)
- Progress analytics dashboard

### Phase 3 — PDF and hardening
- PDF download pipeline
- Performance optimization and caching
- Security hardening and load testing

## 12) Testing strategy
- Unit tests:
  - validation rule engine
  - question type serializers/parsers
  - progress calculation
- Integration tests:
  - creator publish flow
  - respondent save/submit flow
  - summary correctness
- E2E tests:
  - build questionnaire → publish → respond → submit → download PDF
- Non-functional:
  - concurrency tests for high submission volume
  - accessibility checks (keyboard navigation, labels, ARIA)

## 13) Risks and mitigations
- **Complex rule builder UX** → start with constrained rule templates.
- **Version/schema drift** → immutable versions and strict schema IDs in answers.
- **PDF rendering inconsistencies** → single HTML template and visual regression checks.
- **Address/timezone validation complexity** → modular adapters with country/zone data providers.

## 14) Suggested implementation backlog (example)
1. Define schema contracts and migrations.
2. Build draft questionnaire CRUD.
3. Build publish/versioning flow.
4. Build respondent session/answer APIs.
5. Implement frontend respondent navigation/progress.
6. Implement question-level validation.
7. Implement group/form validation.
8. Build summary page.
9. Add PDF generation and download endpoint.
10. Add analytics instrumentation and dashboard.
11. Add tests and hardening.
