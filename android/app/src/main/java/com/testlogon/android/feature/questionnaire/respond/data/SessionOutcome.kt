package com.testlogon.android.feature.questionnaire.respond.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.RespondentSession

/**
 * AND-348 - the start/resume outcome. Most paths return a plain [ApiResult]<[RespondentSession]>, but
 * schema-version safety (FR-6) needs a THIRD success-shaped branch that is neither a normal success nor
 * a transport/HTTP error: the cached draft's schema identity no longer matches the server session, so
 * the answers must NOT be silently discarded - the UI must prompt. [SchemaChanged] carries enough to
 * re-derive the choice (the slug, the cached vs server versionId, and the server-fresh session).
 */
sealed interface SessionStartOutcome {

    /** A usable session (started, resumed, or reconciled) on a matching schema. */
    data class Ready(val session: RespondentSession) : SessionStartOutcome

    /**
     * The server session's [serverVersionId] differs from the locally cached [cachedVersionId]
     * (FR-6). The cached answers are PRESERVED (not discarded); the ViewModel surfaces a prompt and
     * the user explicitly chooses to reload the new schema (which clears the draft). [serverSession]
     * is the fresh server snapshot to adopt on reload.
     */
    data class SchemaChanged(
        val slug: String,
        val cachedVersionId: String,
        val serverVersionId: String,
        val serverSession: RespondentSession,
    ) : SessionStartOutcome

    /** A transport (offline) or HTTP/parse failure. Wraps the underlying [ApiResult] failure variant. */
    data class Failed(val error: ApiResult<Nothing>) : SessionStartOutcome
}

/**
 * AND-348 - the validate outcome handed to the renderer (AND-347) and the submit gate (AND-349).
 * [fieldErrors] is the per-question FIRST blocking-or-any message (questionId -> message), already
 * flattened from the wire's questionId -> List<ValidationIssue>. [canSubmit] is the server's
 * can_submit verdict (the AND-349 hand-off). [isValid] / [hasBlockingFormError] are surfaced for
 * completeness.
 */
data class SessionValidation(
    val isValid: Boolean,
    val canSubmit: Boolean,
    val hasBlockingFormError: Boolean,
    val fieldErrors: Map<String, String>,
)
