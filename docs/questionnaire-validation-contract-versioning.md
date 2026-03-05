# Questionnaire Validation Contract Versioning

## Current version
- `contract_version`: `2026-03-validation-v1`
- Canonical schema: `docs/questionnaire-validation-contract-v1.json`
- Backend typed models: `app/contracts/questionnaire_validation_contract.py`
- Frontend typed interfaces: `frontend/src/api/types.ts`

## Compatibility policy

### Backward-compatible changes (same contract version)
- Adding new error codes to the existing taxonomy.
- Adding optional fields to `QuestionnaireValidationIssue`.
- Adding optional request fields with safe defaults.

### Breaking changes (new contract version required)
- Renaming/removing response fields.
- Changing field types.
- Changing scope key strategy (`question_id`, `group:<id>`, `form:<rule_id>`).
- Reinterpreting `can_submit` / `has_blocking_form_error` semantics.

## Change process
1. Introduce new version constant in backend + frontend.
2. Add a new schema artifact (`...-v2.json`) instead of mutating v1.
3. Keep old contract accepted for migration window when feasible.
4. Extend contract drift tests to assert both schema and typed interfaces.
