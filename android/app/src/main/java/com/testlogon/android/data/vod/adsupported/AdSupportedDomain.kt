package com.testlogon.android.data.vod.adsupported

import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.data.ads.toCtaActions

/**
 * AND-194 — pure, JVM-unit-testable ad-supported domain model + scheduler.
 *
 * Framework-free (no Android, no Media3): cue points arrive from the backend as integer SECONDS and are
 * converted to millis at this boundary (`* 1000L`) for ExoPlayer convenience. The [AdBreakScheduler] is
 * an OPTIMISTIC mirror of the gating; the authoritative unlock is the server's
 * playback_unlocked / next_required_break_id (applied by the repository/ViewModel).
 */

/** A single ad break (one creative). [positionMs] is the content cue point in millis. */
data class AdBreak(
    val breakId: String,
    val slotType: String,        // "pre_roll" | "mid_roll" | "overlay"
    val positionMs: Long,
    val durationMs: Long,
    val creativeId: String,
    val creativeUrl: String,
    val creativeType: String,    // "video" | "image"
    val skipAfterMs: Long,
    val slotIndex: Int,
    /** ADV2-207 (F2) — the per-serve ad_click_id minted by serve_ad (now surfaced on the VOD break);
     *  stashed for CPA attribution + sent on the CTA-click CPC charge. */
    val adClickId: String = "",
    /** ADV2-207 (F2) — structured click-through CTA targets served with this break (AdCtaBar). */
    val ctas: List<CtaAction> = emptyList(),
    val completed: Boolean,
) {
    val isPreRoll: Boolean get() = slotType == VodAdSupportedApi.SLOT_PRE_ROLL
    val isMidRoll: Boolean get() = slotType == VodAdSupportedApi.SLOT_MID_ROLL
    val isOverlay: Boolean get() = slotType == VodAdSupportedApi.SLOT_OVERLAY

    /**
     * A break is "non-skippable" when its skip offset is >= its duration (no skippable window). The
     * skip affordance enables only after [skipAfterMs] of ad playback when skippable.
     */
    val isSkippable: Boolean get() = skipAfterMs < durationMs
}

/** A started ad-supported session + its playback grant. */
data class AdSupportedSession(
    val sessionId: String,
    val videoId: String,
    val status: String,
    val playbackUrl: String,
    val adSchedule: List<AdBreak>,
    val breaksTotal: Int,
    val breaksCompleted: Int,
    val nextRequiredBreakId: String?,
    val playbackUnlocked: Boolean,
    val adsFree: Boolean,
    val tokenExpiresAt: Long,
)

/** Result of reporting a break (updated server-authoritative gating state). */
data class AdBreakReport(
    val ok: Boolean,
    val breakId: String,
    val completed: Boolean,
    val breaksCompleted: Int,
    val breaksTotal: Int,
    val nextRequiredBreakId: String?,
    val playbackUnlocked: Boolean,
)

/**
 * AND-194 §4.4 — pure ad-break scheduling & forward-seek gating. Holds no Android dependencies.
 *
 * The watched-set is driven by the server `completed` flags + reports, so it stays consistent across
 * re-entry. Only mid-roll breaks gate the content timeline; overlays never block, and pre-roll is
 * handled at start. Forward seek to `targetMs` is allowed iff there is no unwatched mid-roll cue in
 * `(currentMs, targetMs]`.
 */
class AdBreakScheduler(initialBreaks: List<AdBreak>) {

    private val breaks: List<AdBreak> = initialBreaks.sortedBy { it.positionMs }
    private val watched: MutableSet<String> = initialBreaks.filter { it.completed }.map { it.breakId }.toMutableSet()

    fun markWatched(breakId: String) {
        watched += breakId
    }

    fun isWatched(breakId: String): Boolean = breakId in watched

    fun preRoll(): AdBreak? = breaks.firstOrNull { it.isPreRoll }

    /** Earliest unwatched mandatory mid-roll cue crossed by linear playback past [positionMs], or null. */
    fun breakCrossedBy(positionMs: Long): AdBreak? =
        breaks.firstOrNull { it.isMidRoll && !isWatched(it.breakId) && it.positionMs <= positionMs }

    /** True iff a forward seek from [currentMs] to [targetMs] crosses no unwatched mandatory mid-roll. */
    fun isForwardSeekAllowed(currentMs: Long, targetMs: Long): Boolean {
        if (targetMs <= currentMs) return true // backward / no-op seeks are unrestricted
        return breaks.none {
            it.isMidRoll && !isWatched(it.breakId) && it.positionMs > currentMs && it.positionMs <= targetMs
        }
    }

    /**
     * The break that must play before content reaches/resumes at [targetMs] (the earliest unwatched
     * mandatory mid-roll in `(currentMs, targetMs]`), or null. Backward seeks never return a break.
     */
    fun breakDueForSeek(currentMs: Long, targetMs: Long): AdBreak? {
        if (targetMs <= currentMs) return null
        return breaks.firstOrNull {
            it.isMidRoll && !isWatched(it.breakId) && it.positionMs > currentMs && it.positionMs <= targetMs
        }
    }
}

// ---- Mappers (seconds -> millis at this boundary) ----

fun VodAdBreakDto.toDomain(): AdBreak = AdBreak(
    breakId = breakId,
    slotType = slotType,
    positionMs = positionSeconds * 1000L,
    durationMs = durationSeconds * 1000L,
    creativeId = creativeId,
    creativeUrl = creativeUrl,
    creativeType = creativeType,
    skipAfterMs = skipAfterSeconds * 1000L,
    slotIndex = slotIndex,
    adClickId = adClickId,
    ctas = ctas.toCtaActions(),
    completed = completed,
)

fun VodAdSupportedStartOutDto.toDomain(): AdSupportedSession = AdSupportedSession(
    sessionId = sessionId,
    videoId = videoId,
    status = status,
    playbackUrl = playbackUrl,
    adSchedule = adSchedule.map { it.toDomain() },
    breaksTotal = breaksTotal,
    breaksCompleted = breaksCompleted,
    nextRequiredBreakId = nextRequiredBreakId,
    playbackUnlocked = playbackUnlocked,
    adsFree = adsFree,
    tokenExpiresAt = tokenExpiresAt,
)

fun VodAdSupportedSessionOutDto.toDomain(): AdSupportedSession = AdSupportedSession(
    sessionId = sessionId,
    videoId = videoId,
    status = status,
    playbackUrl = "", // session read has no playback grant
    adSchedule = adSchedule.map { it.toDomain() },
    breaksTotal = breaksTotal,
    breaksCompleted = breaksCompleted,
    nextRequiredBreakId = nextRequiredBreakId,
    playbackUnlocked = playbackUnlocked,
    adsFree = adsFree,
    tokenExpiresAt = 0L,
)

fun VodAdBreakReportOutDto.toDomain(): AdBreakReport = AdBreakReport(
    ok = ok,
    breakId = breakId,
    completed = completed,
    breaksCompleted = breaksCompleted,
    breaksTotal = breaksTotal,
    nextRequiredBreakId = nextRequiredBreakId,
    playbackUnlocked = playbackUnlocked,
)
