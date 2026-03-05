# Questionnaire Creator & Viewer — Implementation Tickets

This ticket set converts `questionnaire_implementation_plan.md` into delivery-ready engineering work. Tickets are grouped by epic and include scope, deliverables, and acceptance criteria.

## Epic 1: Foundations, Data Model, and Versioning

### QNR-001 — Define questionnaire domain schema and migrations
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None

**Scope**
- Create persistent models for `Questionnaire`, `QuestionnaireVersion`, `Section`, `Question`, `ValidationRule`, `ResponseSession`, and `Answer`.
- Add migration scripts and indexes (owner, questionnaire status, published lookup, response status).
- Capture immutable version linkage so responses always bind to a version.

**Deliverables**
- DB migrations.
- ORM models + repository interfaces.
- ERD update in architecture docs.

**Acceptance Criteria**
- Migrations apply cleanly on new and existing environments.
- A submitted response references a published `QuestionnaireVersion` and cannot be reassigned.
- Query latency for fetch-by-published-id and fetch-response-session is within target SLO.

---

### QNR-002 — Implement questionnaire draft CRUD APIs
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-001

**Scope**
- Add API endpoints for creating, reading, and updating questionnaire metadata in draft state.
- Enforce owner authorization and audit metadata.
- Add soft-delete/archive draft behavior.

**Deliverables**
- Draft CRUD endpoints.
- Service-layer ownership checks.
- API contract tests.

**Acceptance Criteria**
- Owners can create and modify drafts.
- Non-owners receive 403 for draft modifications.
- Archived drafts are excluded from default list views.

---

### QNR-003 — Add section and question composition APIs with ordering
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-002

**Scope**
- Implement create/update/delete/reorder for sections and questions.
- Persist deterministic `position` ordering.
- Validate payload shape per question type.

**Deliverables**
- Section/question management endpoints.
- Reorder operations (bulk move).
- Serialization tests for schema output.

**Acceptance Criteria**
- Reordering survives refresh and publish.
- Deleted questions are not included in published snapshots.
- Invalid type-specific config returns a clear 4xx validation error.

---

### QNR-004 — Publish workflow and immutable version snapshots
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-003

**Scope**
- Implement `publish` operation that snapshots full questionnaire schema.
- Increment version numbers and record publish metadata.
- Prevent edits to published versions.

**Deliverables**
- Publish endpoint + service logic.
- Version snapshot generation utility.
- Tests for immutability and version increments.

**Acceptance Criteria**
- Publishing a draft creates a new immutable version record.
- Existing responses remain mapped to the exact prior version.
- Any attempt to mutate published version returns explicit error.

---

## Epic 2: Validation Engine and Rule Contracts

### QNR-005 — Implement question-level validation engine
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-001

**Scope**
- Build validators for required checks and type-specific constraints.
- Support text, select, multiselect, radio, slider, date, time, timezone, and address validations.
- Return structured error payload keyed by question ID.

**Deliverables**
- Validation library for question-level rules.
- Error code catalog for field-level failures.
- Unit tests for each question type.

**Acceptance Criteria**
- Invalid values produce deterministic error codes and messages.
- Valid answers pass regardless of page order.
- Unit coverage includes edge boundaries for min/max and format checks.

---

### QNR-006 — Implement group-level validation rules
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-005

**Scope**
- Add group/page-level rules (e.g., at least N answered, dependency requirements, exclusivity constraints).
- Allow creators to target explicit group IDs.
- Merge group errors into the unified error map.

**Deliverables**
- Group rule evaluator.
- Group rule schema definitions.
- Integration tests for group scenarios.

**Acceptance Criteria**
- Group constraints evaluate correctly with partially completed sections.
- Group-level errors can be rendered independently from question-level errors.
- Rule definitions reject unknown references.

---

### QNR-007 — Implement form-level validation rules
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-006

**Scope**
- Add cross-section rule execution for global constraints.
- Support conditional rules (`if A then B`) spanning different sections.
- Run form-level evaluation during final submit and optional pre-submit checks.

**Deliverables**
- Form rule evaluator.
- API support for full-form validate endpoint.
- Regression tests for cross-section dependencies.

**Acceptance Criteria**
- Form-level rules execute after question/group rules.
- Submission is blocked when blocking form-level violations exist.
- Error payload clearly differentiates form-level from field/group violations.

---

### QNR-008 — Shared validation contract for frontend/backend
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-005, QNR-006, QNR-007

**Scope**
- Define a shared schema/contract for validation requests and responses.
- Ensure frontend and backend consume the same error code taxonomy.
- Add compatibility/versioning for rule evolution.

**Deliverables**
- Typed validation contract artifact.
- Contract tests across API and frontend client.
- Contract versioning documentation.

**Acceptance Criteria**
- Frontend can render all validation scopes without custom per-endpoint adapters.
- Contract tests fail on incompatible schema changes.
- Backward-compatible changes are documented and versioned.

---

## Epic 3: Creator Experience (Builder UI)

### QNR-009 — Build questionnaire metadata and section management UI
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-002, QNR-003

**Scope**
- Implement creator UI for title/description/visibility and section CRUD.
- Add drag/reorder for sections with autosave.
- Include empty-state and unsaved-change indicators.

**Deliverables**
- Builder shell page.
- Section list/editor components.
- UI tests for section operations.

**Acceptance Criteria**
- Creators can add/remove/reorder sections in draft mode.
- Autosave persists section edits without page refresh loss.
- UI prevents accidental navigation with unsaved edits.

---

### QNR-010 — Build question editor for all required input types
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-009

**Scope**
- Add question cards/forms for text, select, multiselect, radio, slider, date, time, timezone, and address.
- Support type-specific config fields (options, min/max, step, constraints).
- Add in-editor validation for malformed configs.

**Deliverables**
- Question editor components per type.
- Shared question config schema bindings.
- Component tests for each type editor.

**Acceptance Criteria**
- Creator can configure each required question type end-to-end.
- Invalid config cannot be saved.
- Persisted question config rehydrates correctly in editor.

---

### QNR-011 — Add custom hint/help text and placeholder controls
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-010

**Scope**
- Add fields for hint/help text and placeholder text at question level.
- Ensure rendering on respondent screens with accessibility semantics.
- Sanitize stored rich/plain text to prevent injection.

**Deliverables**
- Builder hint/placeholder controls.
- Safe rendering pipeline and sanitization tests.
- Accessibility checks for hint associations.

**Acceptance Criteria**
- Hint text appears under corresponding question in preview/respondent flows.
- Sanitization removes disallowed markup/scripts.
- Screen readers correctly announce hint text via ARIA linkage.

---

### QNR-012 — Add validation rule builder UI (question/group/form)
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-006, QNR-007, QNR-010

**Scope**
- Build UI to define validation rules at all three scopes.
- Provide templates for common conditions (required-if, at-least-one, min/max).
- Display evaluation preview against sample answers.

**Deliverables**
- Rule builder component set.
- Rule template library.
- UI integration tests for save/load/edit flows.

**Acceptance Criteria**
- Creators can create/edit/delete rules across all scopes.
- Saved rules are reloaded in equivalent editable form.
- Invalid rule graph references are blocked with actionable feedback.

---

### QNR-013 — Implement creator preview mode and publish controls
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-004, QNR-010, QNR-012

**Scope**
- Add in-product preview mode that mirrors respondent journey.
- Surface readiness checks before publishing.
- Implement publish confirmation with version summary.

**Deliverables**
- Preview mode route/state.
- Publish modal/checklist UI.
- End-to-end test for draft→preview→publish.

**Acceptance Criteria**
- Preview renders using the same schema used by respondents.
- Publish is blocked when required metadata or blocking validations are unresolved.
- Successful publish shows version identifier and timestamp.

---

## Epic 4: Respondent Experience (Viewer/Answer Flow)

### QNR-014 — Published questionnaire retrieval and session start
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-004

**Scope**
- Add public/auth retrieval for published questionnaire schema via slug/id.
- Start `ResponseSession` with status `in_progress`.
- Support authenticated and optional anonymous respondent modes.

**Deliverables**
- Published fetch endpoint.
- Session-start endpoint.
- Security tests around access modes.

**Acceptance Criteria**
- Respondent can open a published questionnaire and start a session.
- Session initialization records start timestamp and questionnaire version.
- Access policy is enforced for private vs public forms.

---

### QNR-015 — Build page-based respondent flow with autosave
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-014

**Scope**
- Implement page-by-page rendering by section.
- Add autosave and debounced partial answer persistence.
- Restore progress for existing in-progress sessions.

**Deliverables**
- Respondent flow container.
- Autosave client + API integration.
- Resume-session tests.

**Acceptance Criteria**
- Leaving/reloading the page preserves saved answers.
- Partial saves do not submit the questionnaire.
- Resume lands on the last known section/question context.

---

### QNR-016 — Add back/next navigation and progress monitoring
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-015

**Scope**
- Add explicit previous/next controls.
- Display progress bar and completion counters.
- Track completion metrics for answered required questions and page progress.

**Deliverables**
- Navigation controls with disabled-state logic.
- Progress indicator components.
- Telemetry hooks for navigation checkpoints.

**Acceptance Criteria**
- Respondents can navigate backward without data loss.
- Progress updates as answers are saved.
- Progress display remains consistent after session restore.

---

### QNR-017 — Integrate real-time validation feedback in respondent UI
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-008, QNR-015

**Scope**
- Show inline validation errors while editing/advancing.
- Provide section-level and form-level summaries where applicable.
- Prevent submit while blocking violations exist.

**Deliverables**
- Validation-aware form controls.
- Error summary component.
- UX tests for correction flows.

**Acceptance Criteria**
- Field errors appear near the corresponding questions.
- Group/form errors are visible and actionable.
- Submit action remains disabled or blocked with clear reasons.

---

### QNR-018 — Build final answer summary view with edit links
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-016, QNR-017

**Scope**
- Add pre-submit and/or post-submit summary page grouped by section.
- Provide “edit” actions that deep-link back to section/question.
- Ensure summary reflects normalized stored answers.

**Deliverables**
- Summary screen components.
- Summary API endpoint (if server-rendered).
- Test coverage for summary fidelity.

**Acceptance Criteria**
- Summary lists all questions with final answer values.
- Edit links return users to correct location and preserve state.
- Changes made after edit are reflected when returning to summary.

---

## Epic 5: Submission, PDF Export, and Analytics

### QNR-019 — Implement final submission workflow
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-017, QNR-018

**Scope**
- Add submit endpoint that revalidates full response and marks session submitted.
- Lock session from further edits after successful submission (unless configured otherwise).
- Record submitted timestamp and audit event.

**Deliverables**
- Submit endpoint/service.
- Submission state transition tests.
- Audit event instrumentation.

**Acceptance Criteria**
- Submit performs backend authoritative validation.
- Invalid submission returns structured violations with no state transition.
- Valid submission sets status to `submitted` and persists timestamp.

---

### QNR-020 — Generate downloadable PDF for submitted responses
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-019

**Scope**
- Implement server-side response-to-HTML rendering template.
- Convert rendered HTML to PDF and store/retrieve artifact.
- Expose secure download endpoint.

**Deliverables**
- PDF generation service.
- PDF template with sectioned Q&A formatting.
- Integration test for PDF generation and access control.

**Acceptance Criteria**
- Submitted sessions can produce and download a PDF.
- PDF includes questionnaire metadata, submission timestamp, and all answers.
- Unauthorized users cannot access another respondent’s PDF.

---

### QNR-021 — Add creator analytics for progress and completion
**Type:** Feature  
**Priority:** P1  
**Dependencies:** QNR-016, QNR-019

**Scope**
- Capture starts, completions, drop-off points, average completion times.
- Build creator-facing analytics endpoints and dashboard widgets.
- Include validation-failure hotspot reporting.

**Deliverables**
- Analytics aggregation jobs/queries.
- Creator analytics API + UI.
- Dashboard-level tests for metric rendering.

**Acceptance Criteria**
- Creator can view completion funnel for each published version.
- Drop-off metrics identify top abandonment sections/questions.
- Metrics update within agreed freshness window.

---

## Epic 6: Security, Quality, and Release Readiness

### QNR-022 — Authorization, privacy, and abuse protections
**Type:** Feature  
**Priority:** P0  
**Dependencies:** QNR-002, QNR-014, QNR-019

**Scope**
- Enforce ownership and access controls across creator/respondent endpoints.
- Add rate limiting/captcha hooks for anonymous public submissions.
- Ensure PII-safe handling for address/time/date responses (encryption-at-rest as required).

**Deliverables**
- Auth policy checks and middleware updates.
- Rate-limit policy configuration.
- Security tests for unauthorized access attempts.

**Acceptance Criteria**
- Unauthorized access paths return correct denial codes.
- Public submission endpoints are rate-limited.
- Sensitive fields are stored and handled per security requirements.

---

### QNR-023 — Accessibility and UX conformance pass
**Type:** Quality  
**Priority:** P1  
**Dependencies:** QNR-013, QNR-018

**Scope**
- Validate keyboard-only navigation across creator and respondent flows.
- Ensure semantic labels, ARIA bindings, focus management, and error announcements.
- Run contrast and screen-reader checks.

**Deliverables**
- Accessibility audit report.
- Remediation fixes.
- Automated a11y checks in CI where practical.

**Acceptance Criteria**
- Core journeys pass agreed accessibility standards (e.g., WCAG 2.1 AA targets).
- Validation and navigation states are announced to assistive tech.
- No critical accessibility issues remain open for launch.

---

### QNR-024 — End-to-end workflow tests and release checklist
**Type:** Quality  
**Priority:** P0  
**Dependencies:** QNR-013, QNR-020, QNR-022

**Scope**
- Build E2E tests for draft creation → publish → respond → validate → submit → PDF download.
- Add regression tests for version immutability and backward compatibility.
- Produce launch checklist and rollback plan.

**Deliverables**
- Automated E2E suite.
- Release checklist/runbook.
- Sign-off criteria document.

**Acceptance Criteria**
- E2E suite passes in CI for core supported browsers.
- Versioning regression tests prevent schema drift breakages.
- Launch checklist is approved by engineering + product stakeholders.

---

## Recommended Sequencing
1. **MVP track (P0):** QNR-001, QNR-002, QNR-003, QNR-004, QNR-005, QNR-009, QNR-010, QNR-014, QNR-015, QNR-016, QNR-019, QNR-022, QNR-024.  
2. **Post-MVP enhancements (P1):** QNR-006, QNR-007, QNR-008, QNR-011, QNR-012, QNR-013, QNR-017, QNR-018, QNR-020, QNR-021, QNR-023.

## Suggested Milestones
- **Milestone A (Core Builder + Responses):** complete all MVP track items except QNR-024.
- **Milestone B (Advanced Validation + Creator UX):** QNR-006/QNR-007/QNR-008/QNR-012/QNR-013/QNR-017.
- **Milestone C (Exports + Analytics + Hardening):** QNR-020/QNR-021/QNR-023/QNR-024.
