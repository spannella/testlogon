package com.testlogon.android.feature.guest

/**
 * AND-312 - UI state for the guest ACCEPT screen (the invited guest's join flow).
 *
 * [displayName] is the REQUIRED (1..100) name the guest types; [accepted] holds the [GuestAcceptResult] once
 * the accept POST succeeds (surfacing input_id / ingest_url for the FLAGGED AND-308 media handoff). [error]
 * is a one-shot human-readable banner.
 */
data class GuestAcceptUiState(
    val displayName: String = "",
    val isSubmitting: Boolean = false,
    val accepted: GuestAcceptResult? = null,
    val error: String? = null,
) {
    /** The Accept button is enabled only for a non-blank, in-range name when not already submitting/accepted. */
    val canSubmit: Boolean
        get() = !isSubmitting && accepted == null &&
            displayName.trim().length in MIN_NAME_LENGTH..MAX_NAME_LENGTH

    companion object {
        const val MIN_NAME_LENGTH = 1
        const val MAX_NAME_LENGTH = 100
    }
}
