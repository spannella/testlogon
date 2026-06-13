package com.testlogon.android.feature.questionnaire.respond

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus

/**
 * AND-348 / AND-349 - the single UI state for the respondent session lifecycle. AND-349 adds the terminal
 * [Submitted] variant (submit + PDF); [Active.canSubmit] is the submit gate.
 */
sealed interface RespondentSessionUiState {

    /** Initial load (start / resume in flight). */
    data object Loading : RespondentSessionUiState

    /**
     * An editable session. [answers] is the in-memory working copy (may be ahead of the server while
     * [syncState] is SYNC_PENDING / SAVING). [fieldErrors] is the per-question validation message map
     * from the last validate / a rejected submit. [canSubmit] is the server's verdict. [submitting]
     * (AND-349) disables the form + blocks double-tap while a submit is in flight. [firstErrorQuestionId]
     * (AND-349) is the first errored field IN SCHEMA ORDER for scroll-to-first after a rejected submit.
     */
    data class Active(
        val session: RespondentSession,
        val answers: Map<String, AnswerValue>,
        val fieldErrors: Map<String, String> = emptyMap(),
        val syncState: SyncState = SyncState.SYNCED,
        val canSubmit: Boolean = false,
        val submitting: Boolean = false,
        val firstErrorQuestionId: String? = null,
    ) : RespondentSessionUiState

    /**
     * AND-349 - TERMINAL: the session was submitted (or was already submitted on load, FR-7). The form is
     * no longer editable. There is NO submission_id on the wire, so the confirmation shows the
     * [sessionId] (response_session_id) + [sessionStatus]. [pdfState] tracks the on-demand PDF download.
     */
    data class Submitted(
        val sessionId: String,
        val sessionStatus: SessionStatus,
        val pdfState: PdfState = PdfState.Idle,
    ) : RespondentSessionUiState

    /**
     * FR-6 schema-version safety: the server schema changed under the cached draft. The user must
     * explicitly reload (which adopts the new schema and clears the local answers); answers are NOT
     * silently discarded.
     */
    data class SchemaChanged(val slug: String) : RespondentSessionUiState

    /** A terminal load failure (offline with no cached draft, or an HTTP/parse error). */
    data class Error(val error: ApiError) : RespondentSessionUiState
}

/**
 * AND-349 - the on-demand PDF download state inside the terminal [RespondentSessionUiState.Submitted]
 * confirmation. The bytes are streamed to cache then handed to the system chooser via OpenWithLauncher;
 * a failure is retryable.
 */
sealed interface PdfState {
    /** No download attempted yet. */
    data object Idle : PdfState

    /** A generate + download is in flight (the button shows a spinner + is disabled). */
    data object Downloading : PdfState

    /** The last download failed; [message] is shown and the action is retryable. */
    data class Error(val message: String) : PdfState
}

/**
 * AND-348 - the autosave sync indicator. SYNCED: server has the latest. SYNC_PENDING: a local edit is
 * buffered (debounce not yet fired, or offline). SAVING: a PUT is in flight. SYNC_ERROR: the last sync
 * failed (the draft stays dirty for a later retry).
 */
enum class SyncState {
    SYNCED,
    SYNC_PENDING,
    SAVING,
    SYNC_ERROR,
}
