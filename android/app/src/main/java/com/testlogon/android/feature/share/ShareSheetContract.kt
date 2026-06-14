package com.testlogon.android.feature.share

import com.testlogon.android.feature.share.model.ShareLink

/**
 * AND-335 - UI contract for the owner ShareSheet (state + one-shot events).
 *
 * The create form offers fixed expiry presets (1h / 24h / 7d / 30d -> expiry_hours 1 / 24 / 168 / 720),
 * an optional password, and a max-downloads stepper (1..100). Existing links are shown in a list with a
 * copy + revoke affordance per row. Revoke is OPTIMISTIC (the row disappears immediately and is rolled
 * back on failure).
 */

/** Fixed expiry presets the sheet exposes (label key + the wire expiry_hours value). */
enum class ExpiryPreset(val hours: Int) {
    ONE_HOUR(1),
    ONE_DAY(24),
    SEVEN_DAYS(168),
    THIRTY_DAYS(720),
}

/** The owner ShareSheet UI state. */
data class ShareSheetUiState(
    val fileId: String = "",
    val links: List<ShareLink> = emptyList(),
    val isLoading: Boolean = true,
    val isStale: Boolean = false,
    // Create form
    val expiry: ExpiryPreset = ExpiryPreset.ONE_DAY,
    val passwordEnabled: Boolean = false,
    val password: String = "",
    val maxDownloads: Int = DEFAULT_MAX_DOWNLOADS,
    val isCreating: Boolean = false,
    // Row keys (linkId) currently mid-revoke (optimistically hidden).
    val revoking: Set<String> = emptySet(),
    val error: String? = null,
) {
    /** The create button is enabled when not already creating and the password (if on) is valid. */
    val canCreate: Boolean
        get() = !isCreating && (!passwordEnabled || password.length in PASSWORD_MIN..PASSWORD_MAX)

    /** Links rendered to the user (optimistically-revoked rows are hidden). */
    val visibleLinks: List<ShareLink>
        get() = links.filterNot { it.linkId in revoking }

    companion object {
        const val DEFAULT_MAX_DOWNLOADS = 1
        const val MAX_DOWNLOADS_LIMIT = 100
        const val MIN_DOWNLOADS = 1
        const val PASSWORD_MIN = 4
        const val PASSWORD_MAX = 128
    }
}

/** One-shot effects from the owner ShareSheet (consumed by the UI). */
sealed interface ShareSheetEvent {
    /** Copy [url] to the clipboard. */
    data class CopyToClipboard(val url: String) : ShareSheetEvent

    /** Show a transient confirmation message ([messageRes] is a string resource id). */
    data class ShowMessage(val messageRes: Int) : ShareSheetEvent
}
