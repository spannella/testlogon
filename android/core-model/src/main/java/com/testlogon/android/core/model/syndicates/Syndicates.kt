package com.testlogon.android.core.model.syndicates

/**
 * AND-356 - domain model + split-mode enum for the READ-ONLY syndicate overview (Feed / Treasury /
 * Revenue-split).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTOs (core-network
 * SyndicateDtos) carry `mode` as a raw String; [SplitMode.from] parses that token into the typed enum with
 * a [SplitMode.UNKNOWN] fallback so an unrecognized mode NEVER crashes the UI (mirrors GroupRole / OrgRole).
 *
 * MONEY: every monetary value is *_cents (Int). Format with [formatCents] (cents + ISO currency code ->
 * locale string). The role badge is DERIVED (admin_user_id == the current user); there is NO viewer_role
 * field, so [SyndicateOverview.isAdmin] is computed at the mapper boundary.
 *
 * ROOM: the spec mentions a Room cache, but persistence across process death is DEFERRED - the feed +
 * ledger are network Paging-3 sources and the non-paged snapshots are kept in-memory in the ViewModel.
 */

/** The revenue-split mode (tiered is NOT a mode; an unrecognized token -> [UNKNOWN], never throws). */
enum class SplitMode {
    EQUAL,
    WEIGHTED,
    PERFORMANCE,
    UNKNOWN,
    ;

    companion object {
        /** Parses a wire token into a [SplitMode]; null / unknown -> [UNKNOWN] (never throws). */
        fun from(wire: String?): SplitMode = when (wire?.trim()?.lowercase()) {
            "equal" -> EQUAL
            "weighted" -> WEIGHTED
            "performance" -> PERFORMANCE
            else -> UNKNOWN
        }
    }
}

/**
 * The syndicate overview / profile header. [isAdmin] is the DERIVED role-badge signal (admin_user_id == the
 * current user); [isMember] gates the NotMember empty-state. [currency] is an UPPER-cased ISO code.
 */
data class SyndicateOverview(
    val id: String,
    val name: String,
    val memberCount: Int? = null,
    val isAdmin: Boolean = false,
    val isMember: Boolean = true,
    val currency: String,
)

/** One plain feed post (reverse-chronological). [createdAt] is kept as a Long epoch (relative-time at UI). */
data class SyndicateFeedItem(
    val postId: String,
    val authorName: String? = null,
    val authorAvatarUrl: String? = null,
    val createdAt: Long,
    val text: String? = null,
    val imageUrl: String? = null,
    val reactionCount: Int? = null,
    val commentCount: Int? = null,
    val tipCount: Int? = null,
    val poll: com.testlogon.android.core.model.poll.ArbitraryPoll? = null,
    /**
     * ADV syndicate-feed ads — non-null when this row is a server-injected SPONSORED (paid) unit. When set,
     * the UI renders the distinct (non-tippable) Sponsored card instead of a normal feed post.
     */
    val sponsored: com.testlogon.android.core.model.ads.SponsoredAd? = null,
)

/** The treasury summary. All amounts are *_cents (Int); [currency] is an UPPER-cased ISO code. */
data class TreasurySummary(
    val balanceCents: Int,
    val depositedCents: Int,
    val disbursedCents: Int,
    val currency: String,
)

/**
 * One ledger entry. [direction] is the raw "credit" / "debit" token; [amountCents] is the magnitude; [ts]
 * is a Long epoch (relative-time at UI). [isCredit] is a small convenience for the +/- sign.
 */
data class TreasuryEntry(
    val entryId: String? = null,
    val direction: String,
    val amountCents: Int,
    val reason: String? = null,
    val ts: Long,
    val counterpartyUserId: String? = null,
) {
    /** True when this entry is an inflow (credit); the UI renders debits with a minus sign. */
    val isCredit: Boolean get() = direction.equals(DIRECTION_CREDIT, ignoreCase = true)

    companion object {
        const val DIRECTION_CREDIT = "credit"
        const val DIRECTION_DEBIT = "debit"
    }
}

/**
 * The revenue-split policy. [weightsBps] is a userId -> basis-points map (10000 = 100%). [weightSumOk] is
 * computed ONLY for [SplitMode.WEIGHTED]: it is true when the weights sum is within 1bp of 10000; for
 * equal / performance (and an empty weights map) there is NO check and it is always true.
 */
data class RevenueSplitPolicy(
    val mode: SplitMode,
    val platformFeeBps: Int? = null,
    val performanceMetric: String? = null,
    val performanceWindowDays: Int? = null,
    val updatedAt: Long? = null,
    val updatedBy: String? = null,
    val weightsBps: Map<String, Int> = emptyMap(),
) {
    /** The sum of all member weights in basis points (0 when there are no weights). */
    val weightSumBps: Int get() = weightsBps.values.sum()

    /**
     * True unless this is a WEIGHTED split whose weights deviate by more than 1bp from 10000. Equal /
     * performance modes (and an empty weights map under weighted) are NOT checked and return true.
     */
    val weightSumOk: Boolean
        get() = if (mode == SplitMode.WEIGHTED && weightsBps.isNotEmpty()) {
            kotlin.math.abs(weightSumBps - FULL_SHARE_BPS) <= WEIGHT_TOLERANCE_BPS
        } else {
            true
        }

    companion object {
        /** Basis points representing a full 100% share. */
        const val FULL_SHARE_BPS = 10_000

        /** The allowed +/- deviation (in bps) from a full share before flagging a weighted mismatch. */
        const val WEIGHT_TOLERANCE_BPS = 1
    }
}

/** OPTIONAL viewer-earnings projection (not required by the overview screen). */
data class MemberEarnings(
    val userId: String? = null,
    val earnedCents: Int? = null,
    val currency: String? = null,
    val windowDays: Int? = null,
)

// ---- AND-357: open-licensing sub-surface (extends AND-356, same core-model file) ----

/**
 * AND-357 - the fixed open-licensing content type. The wire ships one of 6 values
 * video|music|image|post|broadcast|clip; [from] parses that token into the typed enum with an [UNKNOWN]
 * fallback so an unrecognized value NEVER crashes the UI (mirrors [SplitMode] / GroupRole). [WIRE_VALUES] is
 * the ordered list of the 6 valid wire tokens for the register-form picker (UNKNOWN is NOT offerable).
 */
enum class LicensingContentType(val wire: String) {
    VIDEO("video"),
    MUSIC("music"),
    IMAGE("image"),
    POST("post"),
    BROADCAST("broadcast"),
    CLIP("clip"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** The 6 selectable wire tokens for the register picker (UNKNOWN excluded). */
        val WIRE_VALUES: List<LicensingContentType> =
            listOf(VIDEO, MUSIC, IMAGE, POST, BROADCAST, CLIP)

        /** Parses a wire token into a [LicensingContentType]; null / unknown -> [UNKNOWN] (never throws). */
        fun from(wire: String?): LicensingContentType = when (wire?.trim()?.lowercase()) {
            "video" -> VIDEO
            "music" -> MUSIC
            "image" -> IMAGE
            "post" -> POST
            "broadcast" -> BROADCAST
            "clip" -> CLIP
            else -> UNKNOWN
        }
    }
}

/**
 * Batch-7 - one row of the caller's syndicate list (GET ui/syndicates -> a bare array). [role] is the
 * caller's role token (e.g. admin|member), kept raw for a small badge; [joinedAt] is a Long epoch.
 */
data class SyndicateListItem(
    val id: String,
    val name: String,
    val role: String? = null,
    val joinedAt: Long? = null,
)

/**
 * PAR-35(a) - one discoverable syndicate (GET ui/syndicates/discover). [memberCount] / [description] are
 * informational for the discover card; there is NO caller role here (the caller is not a member yet).
 */
data class SyndicateDiscoverItem(
    val id: String,
    val name: String,
    val description: String? = null,
    val memberCount: Int? = null,
    val createdAt: Long? = null,
)

/**
 * AND-357 - one open-licensing content row. [contentType] is the typed enum (UNKNOWN fallback); [exempt]
 * gates the "Exempt" vs "Auto-licensed" label; [registeredAt] is kept a Long epoch-SECONDS value
 * (relative-time at the UI), null when absent.
 */
data class OpenLicensingContent(
    val contentId: String,
    val contentType: LicensingContentType,
    val creatorId: String? = null,
    val exempt: Boolean = false,
    val registeredAt: Long? = null,
)

/**
 * AND-357 - the result of a register-content mutation (a RECEIPT, NOT a list row). [licensesCreated] is the
 * count of licenses minted (surfaced as success feedback); [contentId] echoes the registered content id.
 */
data class RegistrationResult(
    val contentId: String? = null,
    val licensesCreated: Int = 0,
)

/** Batch-9 (#12) - one syndicate member row. [joinedAt] is a Long epoch (relative-time at UI). */
data class SyndicateMember(
    val userId: String,
    val displayName: String,
    val role: String,
    val joinedAt: Long = 0,
)
