package com.testlogon.android.feature.share

import com.testlogon.android.feature.share.model.PublicShare
import com.testlogon.android.feature.share.model.PublicShareState

/**
 * AND-335 - UI contract for the session-free PublicShareScreen.
 *
 * The screen resolves the link on entry. The [PublicShareUiState] models the four phases: Loading while
 * resolving, Info once the metadata is known (with a password gate + download progress), Terminal for the
 * non-downloadable states (expired / revoked / exhausted / unavailable), and Error for a transient
 * failure (offline / parse) that the user can retry.
 */
sealed interface PublicShareUiState {

    /** Resolving the link metadata. */
    data object Loading : PublicShareUiState

    /**
     * The link resolved and is (potentially) downloadable. [needsPassword] is true when the link is
     * password-protected and a valid password has not yet unlocked it; [downloading] / [progress] drive
     * the download button + progress bar ([progress] is null when the total size is unknown).
     */
    data class Info(
        val share: PublicShare,
        val needsPassword: Boolean,
        val password: String = "",
        val passwordError: String? = null,
        val verifyingPassword: Boolean = false,
        val downloading: Boolean = false,
        val progress: Float? = null,
        val savedFileName: String? = null,
    ) : PublicShareUiState

    /** A non-downloadable terminal state (the panel explains why). */
    data class Terminal(val state: PublicShareState) : PublicShareUiState

    /** A transient error the user can retry. */
    data class Error(val message: String, val retryable: Boolean = true) : PublicShareUiState
}
