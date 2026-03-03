# Questionnaire Release Checklist & Rollback Runbook (QNR-024)

## Purpose
Operational launch checklist, sign-off criteria, and rollback plan for the Questionnaire core workflow:
**draft creation → publish → respond → validate → submit → PDF download**.

## Pre-Release Gates (Engineering)
- [ ] Backend migration `scripts/migrations/20260302_questionnaire_schema.py` validated in staging.
- [ ] DynamoDB indexes healthy for owner/status/published/response-status lookups.
- [ ] Sensitive-answer settings reviewed (`QUESTIONNAIRE_ENCRYPT_SENSITIVE_ANSWERS`, captcha/rate-limit toggles).
- [ ] Contract compatibility check passes for `2026-03-validation-v1`.
- [ ] E2E regression tests pass (including PDF download and version immutability behavior).

## QA / Product Sign-off
- [ ] Creator flow smoke verified (draft metadata, section/question changes, publish).
- [ ] Respondent flow smoke verified (start/save/validate/submit/resume).
- [ ] Submitted-session PDF generated/downloaded and content sanity checked.
- [ ] Accessibility/UX conformance doc reviewed (`docs/questionnaire-accessibility-audit.md`).
- [ ] Product owner sign-off recorded.

## CI Sign-off Criteria
- [ ] `tests/test_questionnaire_e2e_workflow.py` passes in CI.
- [ ] Existing route/repository regression suites pass.
- [ ] Frontend questionnaire component tests pass.
- [ ] No P0/P1 open defects tagged `questionnaire-launch`.

## Production Readiness Checks
- [ ] Dashboards/alerts configured for 4xx/5xx spikes on `/questionnaires/*` endpoints.
- [ ] Response submit success rate monitored.
- [ ] PDF generation failure rate monitored.
- [ ] On-call handoff completed.

## Rollback Plan
1. **Soft rollback (preferred)**
   - Disable questionnaire routes via deployment flag/routing toggle.
   - Keep table data intact.
   - Notify stakeholders and pause traffic.
2. **Service rollback**
   - Redeploy previous known-good release artifact.
   - Confirm health checks and questionnaire endpoints restored to prior behavior.
3. **Data safety**
   - Do not delete questionnaire table data during incident rollback.
   - If schema migration side-effects observed, use replay-safe scripts and audit logs for corrective updates.
4. **Post-rollback validation**
   - Run focused smoke tests for auth/session core and unrelated critical app flows.
   - File incident timeline and corrective actions.

## Stakeholder Approval
- Engineering lead: ____________________  Date: __________
- Product owner: ______________________  Date: __________
- QA lead: _____________________________  Date: __________
