package com.testlogon.android.core.model.questionnaire

/**
 * AND-346 - respondent SESSION + validation DTOs for the published-questionnaire surface (epic E45).
 * These are the CORRECTED contract shapes (mirroring the backend OpenAPI + frontend
 * src/api/endpoints/questionnaires.ts + types.ts), NOT the spec's pre-correction draft.
 *
 * RECONCILIATION NOTE (core-model has no Moshi): NO `@Json` / `@JsonClass` annotations (AND-319 KYC
 * precedent). Property names ARE the snake_case wire keys, decoded via the reflective
 * KotlinJsonAdapterFactory on the shared Moshi. The `AnswerValue` map values decode via the custom
 * core-network AnswerValueAdapter.
 *
 * SECURITY (FR / §8): answer-bearing DTOs (SessionSaveReq, QuestionnaireValidationRequest, and the
 * envelopes carrying answers_by_question_id) override toString() to REDACT answer values (PII). They
 * must never be logged with their answers.
 *
 * Required structural keys (FR-6, absence -> JsonDataException): response_session_id, questionnaire_id,
 * version_id, status on the session state; is_valid, can_submit, has_blocking_form_error, errors on the
 * validation response; the envelope wrappers (session, answers_by_question_id, result, artifact) are
 * required at their top level. Optional fields are nullable with null defaults.
 */

// ---- Start session ----

/**
 * Request body for POST .../sessions. `questionnaire_id` is optional (the web client posts `{}`). There
 * is NO `resume_token` and the start response does NOT inline the questionnaire.
 */
data class ResponseSessionStartReq(
    val questionnaire_id: String? = null,
)

/**
 * Response envelope for POST .../sessions. The start response carries only the opaque session object
 * (no inlined questionnaire). `session` is required at the top level (FR-6).
 */
data class ResponseSessionEnvelope(
    val session: Map<String, @JvmSuppressWildcards Any?>,
)

// ---- Session state ----

/**
 * Typed view of the session object. Required keys: response_session_id, questionnaire_id, version_id,
 * status (absence -> JsonDataException). Tolerates unknown keys.
 */
data class SessionState(
    val response_session_id: String,
    val questionnaire_id: String,
    val version_id: String,
    val status: String,
    val started_at: String? = null,
    val current_section_index: Int? = null,
    val current_question_id: String? = null,
    val respondent_id: String? = null,
)

/**
 * Response for GET .../sessions/{response_session_id} and the PUT save. Envelope of the session state +
 * the answers map. Both wrappers (`session`, `answers_by_question_id`) are required at the top level.
 * toString() redacts the answers (PII).
 */
data class SessionStateEnvelope(
    val session: SessionState,
    val answers_by_question_id: Map<String, AnswerValue>,
) {
    override fun toString(): String =
        "SessionStateEnvelope(session=$session, answers_by_question_id=<" +
            "${answers_by_question_id.size} redacted>)"
}

/**
 * Request body for the PUT save (NOT PATCH; NOT a flat {answers}). Carries the full answers map plus
 * optional cursor fields. toString() redacts the answers (PII).
 */
data class SessionSaveReq(
    val answers_by_question_id: Map<String, AnswerValue>,
    val current_section_index: Int? = null,
    val current_question_id: String? = null,
) {
    override fun toString(): String =
        "SessionSaveReq(answers_by_question_id=<${answers_by_question_id.size} redacted>, " +
            "current_section_index=$current_section_index, current_question_id=$current_question_id)"
}

// ---- Validation (validate + submit share the request shape) ----

/**
 * Request body for both validate and submit (submit typically sets final_submit=true). Defaults mirror
 * the shared FE/BE contract: contract_version "2026-03-validation-v1", final_submit false, empty rule
 * lists. toString() redacts the answers (PII).
 */
data class QuestionnaireValidationRequest(
    val answers_by_question_id: Map<String, AnswerValue>,
    val contract_version: String = "2026-03-validation-v1",
    val final_submit: Boolean = false,
    val form_rules: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
    val group_rules: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
) {
    override fun toString(): String =
        "QuestionnaireValidationRequest(answers_by_question_id=<" +
            "${answers_by_question_id.size} redacted>, contract_version=$contract_version, " +
            "final_submit=$final_submit, form_rules=$form_rules, group_rules=$group_rules)"
}

/**
 * A single validation issue. The owning question id is the MAP KEY in
 * [QuestionnaireValidationResponse.errors] - there is NO `field_id` on the issue. `blocking` and
 * `rule_id` are optional.
 */
data class ValidationIssue(
    val code: String,
    val message: String,
    val blocking: Boolean? = null,
    val rule_id: String? = null,
)

/**
 * Response for validate (and the `result` inside the submit envelope). `errors` is keyed by question id
 * (scope key) -> list of issues. Required keys: is_valid, can_submit, has_blocking_form_error, errors.
 */
data class QuestionnaireValidationResponse(
    val is_valid: Boolean,
    val can_submit: Boolean,
    val has_blocking_form_error: Boolean,
    val errors: Map<String, List<ValidationIssue>>,
    val contract_version: String? = null,
)

// ---- Submit + PDF envelopes ----

/**
 * Response for POST .../submit. Envelope of the (opaque) session object + the validation `result`. NO
 * `pdf_url` / `submitted_at`. Both wrappers required at the top level.
 */
data class SessionSubmitEnvelope(
    val session: Map<String, @JvmSuppressWildcards Any?>,
    val result: QuestionnaireValidationResponse,
)

/**
 * Response body for POST .../pdf (PDF generation owned by AND-349; the body is modeled here). `artifact`
 * is required at the top level and is an opaque map.
 */
data class SessionPdfEnvelope(
    val artifact: Map<String, @JvmSuppressWildcards Any?>,
)
