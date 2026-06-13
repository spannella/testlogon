package com.testlogon.android.feature.questionnaire.respond

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.RespondentSession

/**
 * AND-348 - the single UI state for the respondent session lifecycle. SUBMIT + PDF are OUT OF SCOPE
 * (AND-349); [RespondentSessionUiState.Active.canSubmit] is the hand-off the submit screen consumes.
 */
sealed interface RespondentSessionUiState {

    /** Initial load (start / resume in flight). */
    data object Loading : RespondentSessionUiState

    /**
     * An editable session. [answers] is the in-memory working copy (may be ahead of the server while
     * [syncState] is SYNC_PENDING / SAVING). [fieldErrors] is the per-question validation message map
     * from the last validate. [canSubmit] is the server's verdict (AND-349 hand-off).
     */
    data class Active(
        val session: RespondentSession,
        val answers: Map<String, AnswerValue>,
        val fieldErrors: Map<String, String> = emptyMap(),
        val syncState: SyncState = SyncState.SYNCED,
        val canSubmit: Boolean = false,
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
