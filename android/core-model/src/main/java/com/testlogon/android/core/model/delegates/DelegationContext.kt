package com.testlogon.android.core.model.delegates

/**
 * AND-360 - the manage-as-creator OVERLAY domain model layered on top of the AND-359 delegation context.
 *
 * AND-359 published the raw, observable selection ([ManagingCreator] with a List of permission Strings).
 * AND-360 READS that and projects it into a typed [DelegationContext] whose [permissions] is a Set of the
 * strongly-typed [DelegatePermission]. The delegate-path repositories gate every action on these typed
 * permissions, and the banner / focused demonstration render off this context. This is overlay-only: it
 * does NOT redefine the AND-359 enter / exit flow or the [ManagingCreator] model.
 *
 * core-model stays Moshi-free and has NO core-network dependency: these are plain domain types. The wire
 * permission strings are sourced from ManagedCreatorOut.permissions (rows with status == "active") and
 * bridged into the typed enum by [DelegatePermission.from]. Unknown / future wire tokens map to
 * [DelegatePermission.UNKNOWN] for forward-compat - the parser never crashes on an unrecognized token.
 */

/**
 * AND-360 - the real wire permission tokens that gate delegate actions across feed / broadcast /
 * messaging. [wire] is the exact server string (sourced from ManagedCreatorOut.permissions). [UNKNOWN] is
 * the forward-compat sink for any token this build does not recognize - it carries an empty [wire] and is
 * ignored for gating (an action is permitted ONLY when its specific permission is present).
 */
enum class DelegatePermission(val wire: String) {
    CHAT_READ("chat_read"),
    CHAT_RESPOND("chat_respond"),
    FEED_READ("feed_read"),
    FEED_POST("feed_post"),
    FEED_MODERATE("feed_moderate"),
    BROADCAST_MODERATE("broadcast_moderate"),
    BROADCAST_CONTROL("broadcast_control"),
    UNKNOWN("");

    companion object {
        /**
         * Resolves a raw wire token to its [DelegatePermission], or [UNKNOWN] when unrecognized (forward
         * compat - never throws). The match is exact against [wire]; [UNKNOWN] itself is never returned by
         * a positive match (its [wire] is empty), so a blank token also resolves to [UNKNOWN].
         */
        fun from(token: String): DelegatePermission =
            entries.firstOrNull { it != UNKNOWN && it.wire == token } ?: UNKNOWN
    }
}

/**
 * AND-360 - the typed, active manage-as-creator context the overlay gates on. [creatorId] is the @Path
 * segment used to scope delegate traffic; [creatorName] is the human label (may be null); [permissions]
 * is the typed grant set. Non-null means the principal is acting as a delegate of [creatorId]; the overlay
 * exposes this as a StateFlow and the can* helpers below drive affordance visibility / API gating.
 */
data class DelegationContext(
    val creatorId: String,
    val creatorName: String?,
    val permissions: Set<DelegatePermission>,
)

/**
 * AND-360 - projects the AND-359 [ManagingCreator] selection into the typed [DelegationContext]. The
 * permission Strings are mapped through [DelegatePermission.from]; unrecognized tokens become [UNKNOWN]
 * and are retained in the set but are inert for gating (the can* helpers only check the specific typed
 * permissions). This is the single bridge from the AND-359 published context to the AND-360 overlay.
 */
fun ManagingCreator.toDelegationContext(): DelegationContext = DelegationContext(
    creatorId = creatorId,
    creatorName = label,
    permissions = permissions.map { DelegatePermission.from(it) }.toSet(),
)

// ---- AND-360 capability helpers (null-safe: a null context = acting as oneself = no delegate grant) ----

/** True when the delegate may CREATE / DELETE feed posts on the creator's behalf (feed_post). */
fun DelegationContext?.canPostFeed(): Boolean =
    this != null && DelegatePermission.FEED_POST in permissions

/** True when the delegate may MODERATE the creator's feed (feed_moderate). */
fun DelegationContext?.canModerateFeed(): Boolean =
    this != null && DelegatePermission.FEED_MODERATE in permissions

/** True when the delegate may READ the creator's feed posts (feed_read). */
fun DelegationContext?.canReadFeed(): Boolean =
    this != null && DelegatePermission.FEED_READ in permissions

/** True when the delegate may LIST / READ the creator's conversations + messages (chat_read). */
fun DelegationContext?.canReadChat(): Boolean =
    this != null && DelegatePermission.CHAT_READ in permissions

/** True when the delegate may SEND messages on the creator's behalf (chat_respond). */
fun DelegationContext?.canRespondMessages(): Boolean =
    this != null && DelegatePermission.CHAT_RESPOND in permissions

/** True when the delegate may START / STOP / SCHEDULE the creator's broadcasts (broadcast_control). */
fun DelegationContext?.canControlBroadcast(): Boolean =
    this != null && DelegatePermission.BROADCAST_CONTROL in permissions

/** True when the delegate may MODERATE the creator's broadcast (mute / ban / pin / etc; broadcast_moderate). */
fun DelegationContext?.canModerateBroadcast(): Boolean =
    this != null && DelegatePermission.BROADCAST_MODERATE in permissions
