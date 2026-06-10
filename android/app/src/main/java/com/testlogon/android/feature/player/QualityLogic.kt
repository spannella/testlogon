package com.testlogon.android.feature.player

/**
 * AND-169 — PURE, JVM-unit-testable adaptive-quality / data-saver policy.
 *
 * Everything in this file is framework-free (no android.net, no Media3, no ExoPlayer): the quality
 * enum, the metered/data-saver network status, the cap-resolution rule, and the EffectiveQuality
 * projection are plain data + functions over Int/Boolean so the cap-mapping logic is covered by the
 * JVM unit suite. The actual TrackSelectionParameters application lives in the runtime controller
 * ([ExoVideoPlayerController.applyQuality]) and consumes [QualityTrackParams] decided here.
 */

/**
 * AND-169 FR-1 — user-selectable target ceiling. [maxHeightPx] is the ceiling this option imposes:
 *  - AUTO -> null (no user-imposed ceiling; ABR free, subject only to the metered cap)
 *  - P1080..P360 -> the discrete height ceiling
 *  - DATA_SAVER -> 0 sentinel ("force lowest available rendition"); the strongest constraint
 */
enum class VideoQuality(val maxHeightPx: Int?) {
    AUTO(null),
    P1080(1080),
    P720(720),
    P480(480),
    P360(360),
    DATA_SAVER(0),
    ;

    companion object {
        val DEFAULT = AUTO

        /** Forward-compatible parse of a persisted enum name; unknown/null -> [DEFAULT]. */
        fun fromName(value: String?): VideoQuality =
            entries.firstOrNull { it.name == value } ?: DEFAULT
    }
}

/**
 * AND-169 §4.1 — the persisted quality policy: the user's [userSelection], whether to cap on metered
 * networks, and the configurable metered ceiling (default 480p; not surfaced in UI v1).
 */
data class QualityPolicy(
    val userSelection: VideoQuality = VideoQuality.DEFAULT,
    val capOnMetered: Boolean = true,
    val meteredMaxHeightPx: Int = DEFAULT_METERED_MAX_HEIGHT_PX,
) {
    companion object {
        const val DEFAULT_METERED_MAX_HEIGHT_PX = 480
    }
}

/**
 * AND-169 §4.2 — current network status as it affects quality. [isMetered] from absence of
 * NET_CAPABILITY_NOT_METERED; [dataSaverActive] from the OS Data Saver background restriction. Both
 * fail open (false) when connectivity cannot be observed (§7).
 */
data class NetworkStatus(
    val isMetered: Boolean = false,
    val dataSaverActive: Boolean = false,
) {
    /** True when either signal should trigger the metered cap. */
    val isConstrained: Boolean get() = isMetered || dataSaverActive
}

/**
 * AND-169 §4.5 — the pure Media3 video-size constraint decided for the player, free of Media3 types.
 *  - [forceLowest] -> setMaxVideoSize(1, 1) (lowest rendition)
 *  - [maxHeightPx] != null -> setMaxVideoSize(MAX, maxHeightPx) (height ceiling)
 *  - both unset (AUTO, unconstrained) -> clearVideoSizeConstraints()
 * Exactly one of (forceLowest, maxHeightPx) is meaningful at a time; forceLowest wins.
 */
data class QualityTrackParams(
    val forceLowest: Boolean,
    val maxHeightPx: Int?,
)

/**
 * AND-169 §4.4 — the resolved, observable effective quality combining prefs + connectivity.
 * [selection] echoes the user's choice for the UI check-state; [maxHeightPx] is the resolved ceiling
 * (null = unbounded); [capped] reflects whether the network is currently constraining; [forceLowest]
 * is the data-saver sentinel.
 */
data class EffectiveQuality(
    val selection: VideoQuality = VideoQuality.DEFAULT,
    val maxHeightPx: Int? = null,
    val capped: Boolean = false,
    val forceLowest: Boolean = false,
) {
    /** The pure Media3 constraint to hand the controller. */
    fun toTrackParams(): QualityTrackParams =
        QualityTrackParams(forceLowest = forceLowest, maxHeightPx = if (forceLowest) null else maxHeightPx)
}

/**
 * AND-169 — pure data-saver side-effects beyond the quality ceiling. Kept here so the autoplay
 * decision is JVM-tested alongside the cap mapping.
 */
object PlaybackPolicy {
    /**
     * Data-saver (the "cap quality on metered networks" toggle) disables autoplay by default; the
     * user's explicit autoplay choice is honored only when data-saver is OFF. With data-saver ON,
     * autoplay is forced off regardless of [userAutoplay] (AND-169 §1: "data-saver ... disables
     * autoplay").
     */
    fun autoplayEnabled(userAutoplay: Boolean, capOnMetered: Boolean): Boolean =
        userAutoplay && !capOnMetered
}

/**
 * AND-169 §4.3 — the cap-resolution rule. The MOST RESTRICTIVE of (user selection, metered cap) wins:
 * AUTO contributes no ceiling; DATA_SAVER (height 0) forces lowest and always wins; an explicit user
 * choice below the metered cap is honored over the cap.
 *
 * Pure object so the entire matrix {quality} x {metered/unmetered/dataSaver} x {capOn/capOff} is
 * JVM-tested with no Android on the classpath.
 */
object QualityPolicyResolver {

    /**
     * Returns the effective max video height in px, or null for "unbounded (Auto)". The DATA_SAVER
     * sentinel (0) is returned as 0 and means "force lowest" (see [resolve]).
     */
    fun resolveMaxHeightPx(policy: QualityPolicy, net: NetworkStatus): Int? {
        val cap: Int? = if (net.isConstrained && policy.capOnMetered) policy.meteredMaxHeightPx else null
        val user: Int? = policy.userSelection.maxHeightPx // null=AUTO, 0=DATA_SAVER, else height
        // 0 (data-saver) is the most restrictive; otherwise the smaller positive ceiling wins.
        return listOfNotNull(cap, user).minByOrNull { if (it == 0) Int.MIN_VALUE else it }
    }

    /** Resolves the full [EffectiveQuality] projection for prefs + connectivity. */
    fun resolve(policy: QualityPolicy, net: NetworkStatus): EffectiveQuality {
        val resolved = resolveMaxHeightPx(policy, net)
        val forceLowest = resolved == 0
        return EffectiveQuality(
            selection = policy.userSelection,
            maxHeightPx = if (forceLowest) null else resolved,
            capped = net.isConstrained && policy.capOnMetered,
            forceLowest = forceLowest,
        )
    }
}
