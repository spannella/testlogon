package com.testlogon.android.feature.delegates.ui

import com.testlogon.android.core.model.delegates.ManagedCreator
import com.testlogon.android.core.network.delegates.DelegatedConversationOut
import com.testlogon.android.core.network.delegates.DelegatedPostOut

/**
 * AND-360 - UI state for the focused delegate-console demonstration. Proves "a delegate can act in
 * delegated surfaces": it lists the managed creator's delegate feed posts + conversations and gates the
 * create-post / send-message affordances on feed_post / chat_respond.
 *
 * [active] is false when not in delegate mode. T4 — in that state the console is NOT a dead-end: it shows
 * the [managedCreators] the caller may act for, each with an "Enter" action that puts the app into delegate
 * context (DelegationContextProvider.enter). [managedLoading] / [managedError] / [entering] drive that
 * picker. Once entered, [active] is true and the capability flags + delegate feed / messaging render.
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
    // ---- T4: managed-creators picker (shown when NOT active) ----
    /** Creators the current principal may act for (source of the Enter picker). */
    val managedCreators: List<ManagedCreator> = emptyList(),
    /** The managed-creators GET is in flight. */
    val managedLoading: Boolean = false,
    /** The managed-creators GET failed (transport / server). */
    val managedError: Boolean = false,
    /** An Enter action is in flight for this creatorId (the row shows progress + is disabled). */
    val entering: String? = null,
)
