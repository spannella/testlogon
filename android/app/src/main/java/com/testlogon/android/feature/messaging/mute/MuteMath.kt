package com.testlogon.android.feature.messaging.mute

/**
 * FE-140 - pure, integer-only math for per-conversation mute. No android.*, no clock reads: the
 * caller passes nowSec (epoch SECONDS) in, keeping every function JVM-unit-testable and
 * deterministic.
 *
 * Wire contract (matches the web muteConversation + AND-159 Android group mute):
 *  - muted_until is an epoch-SECONDS Long; 0 (or any value <= now) means NOT muted.
 *  - "Until I turn it back on" is represented by [FOREVER_SENTINEL], a far-future epoch so the
 *    same isMuted(mutedUntil, now) comparison works without a special case.
 */
object MuteMath {

    /** Far-future sentinel (seconds) for "mute until turned off". ~ year 5138; safely > any real now. */
    const val FOREVER_SENTINEL: Long = 100_000_000_000L

    const val OPT_1_HOUR = "1h"
    const val OPT_8_HOURS = "8h"
    const val OPT_1_WEEK = "1w"
    const val OPT_UNTIL_OFF = "until_off"

    private const val HOUR_SECONDS = 60L * 60L
    private const val DAY_SECONDS = 24L * HOUR_SECONDS
    private const val WEEK_SECONDS = 7L * DAY_SECONDS

    /** The selectable mute durations, in display order. */
    fun muteOptions(): List<String> = listOf(OPT_1_HOUR, OPT_8_HOURS, OPT_1_WEEK, OPT_UNTIL_OFF)

    /**
     * Resolve a chosen [optionId] to the absolute muted_until epoch seconds given [nowSec].
     * "until off" maps to [FOREVER_SENTINEL]; an unknown id falls back to 1 hour (fail-short, never
     * an accidental forever).
     */
    fun computeMutedUntil(optionId: String, nowSec: Long): Long = when (optionId) {
        OPT_1_HOUR -> nowSec + HOUR_SECONDS
        OPT_8_HOURS -> nowSec + 8L * HOUR_SECONDS
        OPT_1_WEEK -> nowSec + WEEK_SECONDS
        OPT_UNTIL_OFF -> FOREVER_SENTINEL
        else -> nowSec + HOUR_SECONDS
    }

    /** True when [mutedUntil] is strictly in the future relative to [nowSec]. 0/past => not muted. */
    fun isMuted(mutedUntil: Long, nowSec: Long): Boolean = mutedUntil > nowSec

    /** True when this mute has no practical end (the "until off" sentinel or beyond). */
    fun isForever(mutedUntil: Long): Boolean = mutedUntil >= FOREVER_SENTINEL

    /**
     * A short human label for the current mute state. Empty when not muted. "Muted" for the forever
     * sentinel; otherwise "Muted for <n> <unit>" rounded UP to the coarsest whole unit remaining.
     */
    fun mutedLabel(mutedUntil: Long, nowSec: Long): String {
        if (!isMuted(mutedUntil, nowSec)) return ""
        if (isForever(mutedUntil)) return "Muted"
        val remaining = mutedUntil - nowSec
        return when {
            remaining >= DAY_SECONDS -> {
                val days = ceilDiv(remaining, DAY_SECONDS)
                "Muted for " + days + (if (days == 1L) " day" else " days")
            }
            remaining >= HOUR_SECONDS -> {
                val hours = ceilDiv(remaining, HOUR_SECONDS)
                "Muted for " + hours + (if (hours == 1L) " hour" else " hours")
            }
            else -> {
                val mins = ceilDiv(remaining, 60L).coerceAtLeast(1L)
                "Muted for " + mins + (if (mins == 1L) " minute" else " minutes")
            }
        }
    }

    /** Human label for a duration [optionId] as shown in the picker. */
    fun formatMuteOption(optionId: String): String = when (optionId) {
        OPT_1_HOUR -> "1 hour"
        OPT_8_HOURS -> "8 hours"
        OPT_1_WEEK -> "1 week"
        OPT_UNTIL_OFF -> "Until I turn it back on"
        else -> optionId
    }

    private fun ceilDiv(a: Long, b: Long): Long = (a + b - 1L) / b
}
