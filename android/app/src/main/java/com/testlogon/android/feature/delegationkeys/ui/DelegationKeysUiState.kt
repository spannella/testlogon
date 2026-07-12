package com.testlogon.android.feature.delegationkeys.ui

import com.testlogon.android.feature.delegationkeys.data.DelegationApiKey
import com.testlogon.android.feature.delegationkeys.data.ManagedCreator

/**
 * UI state for the delegation-API keys screen (web parity: /delegation-api). The screen has two tabs
 * (My Keys / Keys For My Account), a create dialog, and a one-time-secret banner.
 *
 * The canonical delegation permissions the web exposes (frontend ALL_PERMISSIONS). The create dialog
 * intersects these with the selected creator's allowed subset.
 */
object DelegationPermissions {
    val ALL: List<String> = listOf(
        "chat_read",
        "chat_respond",
        "feed_read",
        "feed_post",
        "feed_moderate",
        "broadcast_moderate",
        "broadcast_control",
    )
}

/** Which tab is selected. */
enum class DelegationKeysTab { MINE, CREATOR }

/** Exhaustive UI state for the delegation-keys screen. */
sealed interface DelegationKeysUiState {

    data object Loading : DelegationKeysUiState

    data class Content(
        val tab: DelegationKeysTab = DelegationKeysTab.MINE,
        val myKeys: List<DelegationApiKey> = emptyList(),
        val creatorKeys: List<DelegationApiKey> = emptyList(),
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
        val revokingId: String? = null,
        val newSecret: String? = null,
        val actionError: String? = null,
    ) : DelegationKeysUiState

    data class Error(val message: String) : DelegationKeysUiState
}

/**
 * The create-dialog form sub-state. [canSubmit] requires a non-blank label, a selected creator, and at
 * least one permission. [creators] are the caller's managed creators; [allowedForSelected] is the selected
 * creator's allowed permission subset (a permission outside it is disabled in the UI).
 */
data class CreateDelegationKeyForm(
    val visible: Boolean = false,
    val label: String = "",
    val creatorId: String = "",
    val permissions: Set<String> = emptySet(),
    val creators: List<ManagedCreator> = emptyList(),
    val submitting: Boolean = false,
    val submitError: String? = null,
) {
    val allowedForSelected: Set<String>
        get() = creators.firstOrNull { it.creatorId == creatorId }?.permissions?.toSet() ?: emptySet()

    val canSubmit: Boolean
        get() = label.isNotBlank() && creatorId.isNotBlank() && permissions.isNotEmpty() && !submitting
}
