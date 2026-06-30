package com.testlogon.android.feature.settings.callrate

/** Stable testTags for the call-rate settings screen. */
object CallRateTestTags {
    const val SCREEN = "call_rate_screen"
    const val ERROR_RETRY = "call_rate_error_retry"
    const val RATE_INPUT = "call_rate_rate_input"
    const val MIN_BALANCE_INPUT = "call_rate_min_balance_input"
    const val MAX_DURATION_INPUT = "call_rate_max_duration_input"
    const val ENABLED_SWITCH = "call_rate_enabled_switch"
    const val SAVE_BUTTON = "call_rate_save_button"
    const val DELETE_BUTTON = "call_rate_delete_button"
}

/**
 * Exhaustive UI state for the call-rate (paid-calls) settings screen, mirroring the web CallRateSettings page.
 *
 * [Loading] is the first-load spinner; [Content] holds the editable form ([hasRate] true when a rate already
 * exists -> "Save Changes" + Disable button; false -> "Enable Paid Calls"); [Error] is the retry surface.
 * The form stores the rate as a DOLLARS string for editing; the VM converts to/from cents.
 */
sealed interface CallRateUiState {

    data object Loading : CallRateUiState

    data class Content(
        val hasRate: Boolean,
        val rateDollars: String,
        val minBalanceMinutes: String,
        val maxDurationMinutes: String,
        val enabled: Boolean,
        val currency: String = "USD",
        val saving: Boolean = false,
        val deleting: Boolean = false,
        val formError: String? = null,
        val savedMessage: String? = null,
    ) : CallRateUiState

    data class Error(val message: String) : CallRateUiState
}
