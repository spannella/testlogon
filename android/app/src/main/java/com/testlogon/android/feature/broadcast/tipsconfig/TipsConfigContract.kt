package com.testlogon.android.feature.broadcast.tipsconfig

/**
 * AND-315 — UI state contract for the SMALL host tip-config editor.
 *
 * Render states: Loading | Editing | Saving | Error | Offline. [Editing] is the editable form (dollars text
 * + the enabled switch) with the `dirty` flag, per-field validation errors, and a one-shot `saveError`.
 */
sealed interface TipsConfigUiState {

    /** Initial load before the current config arrives. */
    data object Loading : TipsConfigUiState

    /** The editable form. Amounts are edited in DOLLARS; cents conversion happens in the ViewModel. */
    data class Editing(
        val enabled: Boolean,
        val minDollars: String,
        val maxDollars: String,
        val dirty: Boolean,
        val fieldErrors: Map<TipField, TipFieldError>,
        val saveError: String?,
    ) : TipsConfigUiState {
        /** Save is permitted only when dirty and there are no blocking field errors. */
        val canSave: Boolean get() = dirty && fieldErrors.isEmpty()
    }

    /** A PATCH is in flight. */
    data object Saving : TipsConfigUiState

    /** A load failure (a save failure stays in [Editing] via `saveError`). [retryable] gates Retry. */
    data class Error(val message: String, val retryable: Boolean) : TipsConfigUiState

    /** A load transport failure (offline). */
    data object Offline : TipsConfigUiState
}

/** The two editable bound fields (used to key validation errors). */
enum class TipField { MIN, MAX }

/** Client validation error kinds for a tip bound. */
enum class TipFieldError { REQUIRED, OUT_OF_RANGE, MIN_GREATER_THAN_MAX }
