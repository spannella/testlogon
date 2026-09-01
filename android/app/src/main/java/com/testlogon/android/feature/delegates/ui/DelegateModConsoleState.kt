package com.testlogon.android.feature.delegates.ui

import com.testlogon.android.core.network.delegates.DelegatedBroadcastBanOut
import com.testlogon.android.core.network.delegates.DelegatedBroadcastModLogEntry
import com.testlogon.android.core.network.delegates.DelegatedBroadcastModeratorOut

/**
 * AND-360 - UI sub-state for the delegate BROADCAST MODERATION console section rendered inside the delegate
 * console. It is only meaningful when the active context has broadcast_moderate (or broadcast_control for
 * the start/stop affordances) and a session id has been entered.
 *
 * The reads ([moderators] / [bans] / [log]) degrade to honest-empty on a 404 in the repository, so an
 * empty list here means "nothing to show" rather than an error; [readFailed] is only set for a genuine
 * non-404 read failure. [busy] guards a mutation in flight so double-taps are ignored.
 */
data class DelegateModConsoleState(
    /** True when the active context may moderate the broadcast (drives showing the whole section). */
    val canModerate: Boolean = false,
    /** True when the active context may start / stop / schedule (drives the control affordances). */
    val canControl: Boolean = false,
    /** The broadcast session id the moderator is acting on (entered by the user; blank = none yet). */
    val sessionId: String = "",
    /** True while a moderation read (moderators / bans / log) is in flight. */
    val loading: Boolean = false,
    /** A genuine (non-404) read failure occurred - the UI shows a retry. */
    val readFailed: Boolean = false,
    /** A mutation (ban / mute / pin / etc) is in flight - affordances are disabled to prevent double-taps. */
    val busy: Boolean = false,
    val moderators: List<DelegatedBroadcastModeratorOut> = emptyList(),
    val bans: List<DelegatedBroadcastBanOut> = emptyList(),
    val log: List<DelegatedBroadcastModLogEntry> = emptyList(),
    /** True once the caller has registered as an active moderator for [sessionId] this session. */
    val registered: Boolean = false,
)
