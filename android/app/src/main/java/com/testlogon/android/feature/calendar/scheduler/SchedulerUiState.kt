package com.testlogon.android.feature.calendar.scheduler

import com.testlogon.android.data.scheduler.ScheduledAction

/**
 * AND-275 — UI state for the scheduler create/edit sheet.
 *
 * Loading appears only in Edit mode while the existing action is fetched. Editing carries the live form,
 * per-field errors (local validation + mapped 422 loc paths), submit/offline flags, and a transient
 * server error. Saved is terminal (the sheet dismisses).
 */
sealed interface SchedulerUiState {
    data object Loading : SchedulerUiState

    data class Editing(
        val mode: SchedulerMode,
        val form: SchedulerForm,
        val fieldErrors: Map<SchedulerField, String> = emptyMap(),
        val isSubmitting: Boolean = false,
        val isOffline: Boolean = false,
        val transientError: String? = null,
    ) : SchedulerUiState

    data class Saved(val action: ScheduledAction) : SchedulerUiState

    data class LoadError(val message: String, val isOffline: Boolean) : SchedulerUiState
}
