package com.testlogon.android.feature.questionnaire.respond.data

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationResponse
import com.testlogon.android.core.model.questionnaire.SessionPdfEnvelope
import com.testlogon.android.core.model.questionnaire.SessionStatus

/**
 * AND-349 - the outcome of a FINAL submit of a respondent session (epic E45).
 *
 * The submit endpoint REUSES AND-346's SessionSubmitEnvelope (session + result). A 200 is NOT
 * automatically a successful submit: the server returns the same validation envelope and a
 * result.can_submit == false on a 200 is a VALIDATION FAILURE that must be mapped back to per-field
 * errors (NOT a confirmation). There is NO submission_id on the wire, so a successful submit surfaces the
 * response_session_id + the session status instead.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
sealed interface SubmitOutcome {

    /**
     * The submit succeeded (result.can_submit && result.is_valid). [sessionId] is the wire
     * response_session_id (there is no submission_id); [sessionStatus] is the terminal session status
     * (typically SUBMITTED). The form is no longer editable.
     */
    data class Submitted(
        val sessionId: String,
        val sessionStatus: SessionStatus,
    ) : SubmitOutcome

    /**
     * A 200 with result.can_submit == false: the server rejected the submit on validation. [validation]
     * carries canSubmit=false, the per-field error map (questionId -> first blocking-or-any message), and
     * [SessionValidation.firstErrorQuestionId] (the first errored field IN FIELD ORDER, for scroll-to).
     * The draft is intact; the user fixes the fields and re-submits.
     */
    data class ValidationFailed(val validation: SessionValidation) : SubmitOutcome

    /** A transport / HTTP / parse failure. The draft is intact and the submit is retryable (no auto-retry). */
    data class Failed(val error: ApiError) : SubmitOutcome
}

/**
 * AND-349 - a generated PDF artifact descriptor mapped (tolerantly) from [SessionPdfEnvelope.artifact],
 * which is an opaque map on the wire. [filename] / [mimeType] are best-effort; both fall back to sane
 * defaults so an opaque artifact never blocks the download (the bytes come from the streamed GET, not
 * this descriptor).
 */
data class PdfArtifact(
    val filename: String,
    val mimeType: String,
) {
    companion object {
        const val DEFAULT_MIME = "application/pdf"
        const val DEFAULT_FILENAME = "questionnaire-response.pdf"

        /** Maps an opaque PDF envelope's artifact map to a [PdfArtifact], tolerating missing keys. */
        fun from(envelope: SessionPdfEnvelope): PdfArtifact {
            val artifact = envelope.artifact
            val name = firstString(artifact, "filename", "file_name", "name")
                ?.takeIf { it.isNotBlank() }
                ?: DEFAULT_FILENAME
            val mime = firstString(artifact, "mime_type", "mimetype", "content_type")
                ?.takeIf { it.isNotBlank() }
                ?: DEFAULT_MIME
            return PdfArtifact(filename = name, mimeType = mime)
        }

        private fun firstString(map: Map<String, Any?>, vararg keys: String): String? =
            keys.firstNotNullOfOrNull { map[it] as? String }
    }
}

/**
 * AND-349 - maps a [QuestionnaireValidationResponse] (the submit `result`) to a [SubmitOutcome] given
 * the question order ([fieldOrder]) used to compute the first-errored field for scroll-to-first.
 *
 * Decision: result.can_submit && result.is_valid -> [SubmitOutcome.Submitted]; otherwise
 * [SubmitOutcome.ValidationFailed] with the flattened field-error map (prefer a blocking issue's message)
 * and [SessionValidation.firstErrorQuestionId] computed in [fieldOrder].
 */
fun SessionSubmitMapping.toSubmitOutcome(): SubmitOutcome {
    val result = result
    return if (result.can_submit && result.is_valid) {
        SubmitOutcome.Submitted(sessionId = sessionId, sessionStatus = status)
    } else {
        val fieldErrors = result.errors.mapNotNull { (questionId, issues) ->
            val chosen = issues.firstOrNull { it.blocking == true } ?: issues.firstOrNull()
            chosen?.let { questionId to it.message }
        }.toMap()
        val firstErrorQuestionId = firstErroredInOrder(fieldErrors.keys, fieldOrder)
        SubmitOutcome.ValidationFailed(
            SessionValidation(
                isValid = result.is_valid,
                canSubmit = result.can_submit,
                hasBlockingFormError = result.has_blocking_form_error,
                fieldErrors = fieldErrors,
                firstErrorQuestionId = firstErrorQuestionId,
                // AND-350: carry the raw wire errors (incl. group:/form: keys) for the VM's reconciler.
                serverErrors = result.errors,
            ),
        )
    }
}

/**
 * AND-349 - the inputs the submit mapper needs from the wire envelope (kept off the raw DTO so the DTO
 * stays a pure transport type). [sessionId] / [status] come from the opaque session object; [result] is
 * the validation result; [fieldOrder] is the schema question order (may be empty - the map then falls
 * back to first error encountered).
 */
data class SessionSubmitMapping(
    val sessionId: String,
    val status: SessionStatus,
    val result: QuestionnaireValidationResponse,
    val fieldOrder: List<String> = emptyList(),
)

/**
 * Returns the first questionId from [order] that has an error, or - if [order] is empty / contains none
 * of them - the first key in [errored] (iteration order). Null when there are no errors.
 */
private fun firstErroredInOrder(errored: Set<String>, order: List<String>): String? {
    if (errored.isEmpty()) return null
    val inOrder = order.firstOrNull { it in errored }
    return inOrder ?: errored.firstOrNull()
}
