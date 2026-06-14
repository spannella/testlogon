package com.testlogon.android.feature.delegates.ui

import com.testlogon.android.core.network.delegates.DelegatedConversationOut
import com.testlogon.android.core.network.delegates.DelegatedPostOut

/**
 * AND-360 - UI state for the focused delegate-console demonstration. Proves "a delegate can act in
 * delegated surfaces": it lists the managed creator's delegate feed posts + conversations and gates the
 * create-post / send-message affordances on feed_post / chat_respond.
 *
 * [active] is false when not in delegate mode (the console shows the enter prompt). The capability flags
 * mirror the repository gates so the UI can hide / disable affordances WITHOUT attempting a blocked call.
 */
data class DelegateConsoleUiState(
    val active: Boolean = false,
    val creatorName: String? = null,
    val loading: Boolean = false,
    val canReadFeed: Boolean = false,
    val canPostFeed: Boolean = false,
    val canReadChat: Boolean = false,
    val canRespond: Boolean = false,
    val posts: List<DelegatedPostOut> = emptyList(),
    val conversations: List<DelegatedConversationOut> = emptyList(),
    val notice: String? = null,
    val loadFailed: Boolean = false,
)
