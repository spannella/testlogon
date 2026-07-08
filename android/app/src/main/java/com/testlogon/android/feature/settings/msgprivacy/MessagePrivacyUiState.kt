package com.testlogon.android.feature.settings.msgprivacy

/** TIP-B4 (TIP-404) — stable testTags for the message-privacy settings screen. */
object MessagePrivacyTestTags {
    const val SCREEN = "msg_privacy_screen"
    const val ERROR_RETRY = "msg_privacy_error_retry"
    const val REQUIRE_SWITCH = "msg_privacy_require_switch"
    const val MIN_TIP_INPUT = "msg_privacy_min_tip_input"
    const val SAVE_BUTTON = "msg_privacy_save_button"
    const val ALLOWLIST_INPUT = "msg_privacy_allowlist_input"
    const val ALLOWLIST_ADD = "msg_privacy_allowlist_add"
    const val ALLOWLIST_ROW = "msg_privacy_allowlist_row"
    const val ALLOWLIST_REMOVE = "msg_privacy_allowlist_remove"
}

/**
 * TIP-B4 (TIP-404) — exhaustive UI state for the message-privacy (pay-to-message) settings screen.
 *
 * [Loading] is the first-load spinner; [Content] holds the editable form; [Error] is the retry
 * surface. The min-tip amount is edited as a DOLLARS string; the VM converts to/from cents.
 */
sealed interface MessagePrivacyUiState {

    data object Loading : MessagePrivacyUiState

    data class Content(
        val requireTip: Boolean,
        val minTipDollars: String,
        /** Current tip-free allowlist (user_subs). */
        val allowlist: List<String>,
        /** Draft text of the "add user" field. */
        val allowlistInput: String = "",
        val saving: Boolean = false,
        /** user_sub currently being added/removed (drives the per-row spinner), or null. */
        val mutatingAllowlist: String? = null,
        val formError: String? = null,
        val savedMessage: String? = null,
    ) : MessagePrivacyUiState

    data class Error(val message: String) : MessagePrivacyUiState
}
