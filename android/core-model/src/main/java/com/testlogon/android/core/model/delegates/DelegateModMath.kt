package com.testlogon.android.core.model.delegates

/**
 * AND-360 - PURE permission / role gating math for the delegate broadcast MODERATION surface.
 *
 * core-model stays Moshi-free and has NO core-network dependency: this is plain domain logic with no
 * Android / IO. It centralizes the "may this delegate perform this broadcast action?" decision so the
 * repository, the ViewModel affordance-visibility and the tests all agree on one rule set, and it derives
 * a couple of read-side summaries (moderation-type labels, whether a viewer is currently banned).
 *
 * THE RULE (mirrors the backend router gating): broadcast CONTROL actions (start / stop / schedule) need
 * [DelegatePermission.BROADCAST_CONTROL]; every MODERATION action (mute / ban / unban / pin / unpin /
 * delete-chat / announce / moderator-register) AND the moderation READS (moderators / bans / log) need
 * [DelegatePermission.BROADCAST_MODERATE]. A null context = acting as oneself = no delegate grant = denied.
 */

/**
 * The distinct delegate broadcast actions the UI can attempt. [requiredPermission] is the single typed
 * permission that gates the action - the whole gating rule lives on the enum so there is exactly one
 * source of truth.
 */
enum class BroadcastModAction(val requiredPermission: DelegatePermission) {
    // ---- control ----
    START(DelegatePermission.BROADCAST_CONTROL),
    STOP(DelegatePermission.BROADCAST_CONTROL),
    SCHEDULE(DelegatePermission.BROADCAST_CONTROL),

    // ---- moderation (mutations) ----
    MUTE(DelegatePermission.BROADCAST_MODERATE),
    BAN(DelegatePermission.BROADCAST_MODERATE),
    UNBAN(DelegatePermission.BROADCAST_MODERATE),
    PIN(DelegatePermission.BROADCAST_MODERATE),
    UNPIN(DelegatePermission.BROADCAST_MODERATE),
    DELETE_CHAT(DelegatePermission.BROADCAST_MODERATE),
    ANNOUNCE(DelegatePermission.BROADCAST_MODERATE),
    REGISTER_MODERATOR(DelegatePermission.BROADCAST_MODERATE),

    // ---- moderation (reads) ----
    LIST_MODERATORS(DelegatePermission.BROADCAST_MODERATE),
    LIST_BANS(DelegatePermission.BROADCAST_MODERATE),
    VIEW_LOG(DelegatePermission.BROADCAST_MODERATE),
    ;

    /** True when this action gates on [DelegatePermission.BROADCAST_CONTROL] (start / stop / schedule). */
    val isControl: Boolean get() = requiredPermission == DelegatePermission.BROADCAST_CONTROL

    /** True when this action gates on [DelegatePermission.BROADCAST_MODERATE] (everything else). */
    val isModeration: Boolean get() = requiredPermission == DelegatePermission.BROADCAST_MODERATE
}

/** AND-360 - the single, pure gating helpers for delegate broadcast moderation. */
object DelegateModMath {

    /**
     * The core decision: may the delegate holding [context] perform [action]? A null context (acting as
     * oneself) is always denied; otherwise the action's [BroadcastModAction.requiredPermission] must be in
     * the granted set. [DelegatePermission.UNKNOWN] tokens in the set are inert (never gate anything on).
     */
    fun canPerform(context: DelegationContext?, action: BroadcastModAction): Boolean =
        context != null && action.requiredPermission in context.permissions

    /**
     * The subset of [BroadcastModAction] the delegate holding [context] may currently perform. Empty when
     * the context is null (acting as oneself). Used to drive affordance visibility without re-deriving the
     * rule per widget.
     */
    fun allowedActions(context: DelegationContext?): Set<BroadcastModAction> =
        if (context == null) emptySet()
        else BroadcastModAction.entries.filter { it.requiredPermission in context.permissions }.toSet()

    /**
     * True when the context can perform ANY moderation action (drives showing the moderation console at
     * all). Distinct from [canControl] so a moderate-only delegate still sees the console, and a
     * control-only delegate does not see moderation affordances.
     */
    fun canModerate(context: DelegationContext?): Boolean =
        context != null && DelegatePermission.BROADCAST_MODERATE in context.permissions

    /** True when the context can perform broadcast control (start / stop / schedule). */
    fun canControl(context: DelegationContext?): Boolean =
        context != null && DelegatePermission.BROADCAST_CONTROL in context.permissions

    /**
     * True when [userId] appears in [bannedUserIds] (case-sensitive exact match). Lets the UI flip a
     * ban row's affordance between Ban and Unban without duplicating the membership test. A blank
     * [userId] is never considered banned.
     */
    fun isBanned(userId: String, bannedUserIds: Collection<String>): Boolean =
        userId.isNotBlank() && userId in bannedUserIds

    /**
     * Maps a raw wire moderation_type token to a stable, human-facing label. Unknown / blank tokens fall
     * through to a title-cased echo of the token (or "Action" when blank) so a new server type never
     * renders as an empty cell. The mapping is intentionally exhaustive over the known delegate actions.
     */
    fun moderationLabel(moderationType: String?): String = when (moderationType?.trim()?.lowercase()) {
        null, "" -> "Action"
        "mute" -> "Muted a viewer"
        "ban" -> "Banned a viewer"
        "unban" -> "Unbanned a viewer"
        "pin" -> "Pinned a message"
        "unpin" -> "Unpinned a message"
        "delete", "delete_chat", "delete_message" -> "Deleted a message"
        "announce", "announcement" -> "Posted an announcement"
        "start" -> "Started the broadcast"
        "stop" -> "Stopped the broadcast"
        "register", "moderator_register" -> "Joined as moderator"
        else -> moderationType.trim().replaceFirstChar { it.uppercaseChar() }
    }

    /**
     * Counts moderation-log entries by their normalized [moderationLabel]. Deterministic input order is
     * preserved by using a LinkedHashMap. Empty input yields an empty map. Used for a compact "activity"
     * summary at the top of the log without pulling a charting dep.
     */
    fun countByType(types: List<String?>): Map<String, Int> {
        val counts = LinkedHashMap<String, Int>()
        for (t in types) {
            val label = moderationLabel(t)
            counts[label] = (counts[label] ?: 0) + 1
        }
        return counts
    }
}
