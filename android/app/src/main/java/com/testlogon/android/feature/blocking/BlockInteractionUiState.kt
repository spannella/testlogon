package com.testlogon.android.feature.blocking

import androidx.annotation.StringRes
import com.testlogon.android.core.model.blocking.BlockRelationship

/**
 * AND-382 - render-ready state for the embedded block / unblock interaction.
 *
 * This single state object is hosted by BOTH the profile screen (overflow Block / unblock placeholder)
 * and the message-thread screen (overflow Block + composer gating). It is intentionally screen-agnostic
 * so the affordance is identical across surfaces (spec sec.4.4 / 4.5).
 */
data class BlockInteractionUiState(
    /** The viewed counterpart's user id. Empty until hydrated. */
    val targetUserId: String = "",
    /** The counterpart's handle for confirm-dialog / menu copy. */
    val targetHandle: String = "",
    val relationship: BlockRelationship = BlockRelationship.Normal,
    /** True while the confirm dialog is shown (before the user confirms a block). */
    val confirmVisible: Boolean = false,
    /** True while a block/unblock mutation is in flight (disables the action; double-submit guard). */
    val inFlight: Boolean = false,
) {
    /** The signed-in user blocked this counterpart -> show the unblock placeholder. */
    val blockedByMe: Boolean get() = relationship == BlockRelationship.BlockedByMe

    /** Either direction -> hide content + disable contact. */
    val contactBlocked: Boolean get() = relationship.contactBlocked

    /** Composer is enabled only when contact is allowed and no mutation is mid-flight. */
    val composerEnabled: Boolean get() = !contactBlocked

    /** The Block action is offered only when not already blocked-by-me and not mid-flight. */
    val canBlock: Boolean get() = !blockedByMe && !inFlight && targetUserId.isNotEmpty()
}

/** One-shot effects (AND-382); Channel-backed so they are not replayed on rotation. */
sealed interface BlockInteractionEffect {
    /** A transient, non-blocking message (e.g. "Couldn't update - tap to retry"). */
    data class ShowMessage(@StringRes val resId: Int) : BlockInteractionEffect
}
