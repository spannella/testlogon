package com.testlogon.android.core.model.questionnaire

/**
 * AND-348 - the respondent SESSION domain model for the public questionnaire-response flow (epic E45).
 *
 * This is the feature-domain projection of AND-346's wire DTOs ([SessionState] /
 * [SessionStateEnvelope] / answers_by_question_id). It is the single in-memory representation the
 * repository, ViewModel and (later) renderer share. SUBMIT + PDF are OUT OF SCOPE (AND-349).
 *
 * Field notes:
 * - [sessionId] is the wire response_session_id (the opaque server handle for save/validate/get).
 * - [slug] is the NAV ARG (the published slug); it is NOT carried in the server session object, so it
 *   is threaded in from navigation and used as the local-draft primary key (FR-7 single active session
 *   per slug per device).
 * - [versionId] is the STRING schema identity (the server has NO integer schema_version). It is the
 *   value compared for schema-version safety (FR-6): a changed versionId surfaces SchemaChanged rather
 *   than silently discarding answers.
 * - [answers] is the typed answer map keyed by question id.
 * - [currentSectionIndex] / [currentQuestionId] are the optional resume cursor.
 *
 * RECONCILIATION NOTE (core-model has no Moshi): this is a plain immutable domain type; mapping
 * happens in the feature repository, not via Moshi annotations.
 */
data class RespondentSession(
    val sessionId: String,
    val slug: String,
    val questionnaireId: String,
    val versionId: String,
    val answers: Map<String, AnswerValue>,
    val status: SessionStatus,
    val currentSectionIndex: Int? = null,
    val currentQuestionId: String? = null,
)

/**
 * AND-348 - the respondent session lifecycle status.
 *
 * The wire only ever carries "in_progress" | "submitted"; [EXPIRED] is a CLIENT-ONLY state (e.g. the
 * server rejected a stale session) and is never decoded from the wire. An unknown / absent wire token
 * maps to [IN_PROGRESS] (never throws) per the error-handling contract.
 */
enum class SessionStatus {
    IN_PROGRESS,
    SUBMITTED,
    EXPIRED,
    ;

    companion object {
        /** Maps the wire status token to a [SessionStatus]; unknown/null -> [IN_PROGRESS] (never throws). */
        fun fromWire(token: String?): SessionStatus = when (token?.trim()?.lowercase()) {
            "submitted" -> SUBMITTED
            "in_progress" -> IN_PROGRESS
            else -> IN_PROGRESS
        }
    }
}
