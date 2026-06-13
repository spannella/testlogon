package com.testlogon.android.feature.sponsorship.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.sponsorship.DealAction
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.ViewerRole

/**
 * AND-366 - the exhaustive UI state for the sponsorship DEAL DETAIL screen.
 *
 * [Loading] is the first-load spinner; [Error] carries the [ApiError] for the retry surface (the deal GET is
 * idempotent so a retry is safe). [Content] carries the loaded [deal] + best-effort [history] (a history-load
 * failure folds to an empty list, NOT an Error), the CLIENT-SIDE-derived [viewerRole] and the
 * [availableActions] set (non-empty only in proposed / negotiating for a party), [actionInFlight] (the single
 * in-flight management action - while non-null ALL actions are disabled, NO double-submit), and the optional
 * [counterForm] sub-state (non-null only while the negotiate counter dialog is open).
 */
sealed interface SponsorshipDealUiState {

    data object Loading : SponsorshipDealUiState

    data class Content(
        val deal: SponsorshipDealDetail,
        val history: List<SponsorshipDealEvent> = emptyList(),
        val viewerRole: ViewerRole,
        val availableActions: Set<DealAction> = emptySet(),
        val actionInFlight: DealAction? = null,
        val counterForm: CounterForm? = null,
    ) : SponsorshipDealUiState

    data class Error(val error: ApiError) : SponsorshipDealUiState
}

/**
 * AND-366 - the editable state of the NEGOTIATE counter-offer form (shown in a dialog). [compensationText] is
 * the USD-cents entry pre-filled from the deal's current compensation; [note] is the optional message;
 * [compensationError] / [noteError] are per-field inline errors mapped from a server 422 (by loc tail
 * compensation_cents / note); [submitting] disables the form while the counter POST is in flight.
 */
data class CounterForm(
    val compensationText: String = "",
    val note: String = "",
    val compensationError: CounterFieldError? = null,
    val noteError: CounterFieldError? = null,
    val submitting: Boolean = false,
)

/**
 * AND-366 - the per-field error kinds the counter form can surface. CLIENT_* are local validation failures
 * (compensation below the 1000-cent minimum / note over 2000 chars / unparseable amount); SERVER is a 422
 * rejection routed back by loc tail (the generic server message - the field is highlighted but the copy is a
 * fixed string resource, never the raw server text).
 */
enum class CounterFieldError {
    CLIENT_COMPENSATION_TOO_LOW,
    CLIENT_COMPENSATION_INVALID,
    CLIENT_NOTE_TOO_LONG,
    SERVER,
}

/**
 * AND-366 - one-shot effects from the deal screen (snackbar-style messages that should NOT be re-emitted on
 * recomposition / rotation). [ActionFailed] is a retryable failure of a management action (NON-idempotent ->
 * the user re-triggers manually, NEVER auto-retried). [ActionSucceeded] confirms a completed action.
 */
sealed interface SponsorshipDealEffect {
    data class ActionFailed(val action: DealAction, val message: String) : SponsorshipDealEffect
    data class ActionSucceeded(val action: DealAction) : SponsorshipDealEffect
}
