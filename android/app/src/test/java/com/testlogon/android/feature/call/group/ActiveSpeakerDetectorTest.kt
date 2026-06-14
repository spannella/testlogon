package com.testlogon.android.feature.call.group

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-300 — pure unit tests for [ActiveSpeakerDetector]. Inputs are FINITE [flowOf]/[flow] level maps so the
 * flow completes deterministically; the hold window is driven by a controllable virtual clock (the [now]
 * override), NOT real time. No android, no SDK.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ActiveSpeakerDetectorTest {

    @Test
    fun emitsArgmaxAboveThreshold() = runTest {
        val detector = ActiveSpeakerDetector(thresholdLevel = 0.15f, holdMs = 500, now = { 0L })
        val levels = flowOf(
            mapOf("a" to 0.2f, "b" to 0.6f, "c" to 0.1f),
        )
        val out = detector.detect(levels).toList()
        assertEquals(listOf("b"), out)
    }

    @Test
    fun emitsNull_whenAllBelowThreshold() = runTest {
        val detector = ActiveSpeakerDetector(thresholdLevel = 0.15f, holdMs = 500, now = { 0L })
        val levels = flowOf(
            mapOf("a" to 0.05f, "b" to 0.1f),
        )
        val out = detector.detect(levels).toList()
        assertEquals(listOf<String?>(null), out)
    }

    @Test
    fun emptyLevels_yieldsNull() = runTest {
        val detector = ActiveSpeakerDetector(thresholdLevel = 0.15f, holdMs = 500, now = { 0L })
        val out = detector.detect(flowOf(emptyMap())).toList()
        assertEquals(listOf<String?>(null), out)
    }

    @Test
    fun holdsCurrentSpeaker_doesNotSwitchBeforeHoldMs() = runTest {
        // Virtual clock advanced by the source between emissions; stays within the 500ms hold window.
        var clock = 0L
        val detector = ActiveSpeakerDetector(thresholdLevel = 0.15f, holdMs = 500, now = { clock })
        val levels = flow {
            clock = 0L
            emit(mapOf("a" to 0.6f, "b" to 0.2f)) // a is loudest -> becomes speaker
            clock = 100L
            emit(mapOf("a" to 0.2f, "b" to 0.6f)) // b louder, but only 100ms in -> HELD on a
            clock = 200L
            emit(mapOf("a" to 0.2f, "b" to 0.6f)) // still < 500ms -> HELD on a
        }
        val out = detector.detect(levels).toList()
        // distinctUntilChanged collapses the held repeats -> a single "a".
        assertEquals(listOf("a"), out)
    }

    @Test
    fun switchesSpeaker_afterHoldMsElapsed() = runTest {
        var clock = 0L
        val detector = ActiveSpeakerDetector(thresholdLevel = 0.15f, holdMs = 500, now = { clock })
        val levels = flow {
            clock = 0L
            emit(mapOf("a" to 0.6f, "b" to 0.2f)) // a speaker
            clock = 600L
            emit(mapOf("a" to 0.2f, "b" to 0.6f)) // 600ms >= holdMs -> switch to b
        }
        val out = detector.detect(levels).toList()
        assertEquals(listOf("a", "b"), out)
    }

    @Test
    fun clearsToNull_whenEveryoneGoesQuiet() = runTest {
        var clock = 0L
        val detector = ActiveSpeakerDetector(thresholdLevel = 0.15f, holdMs = 500, now = { clock })
        val levels = flow {
            clock = 0L
            emit(mapOf("a" to 0.6f))
            clock = 100L
            emit(mapOf("a" to 0.05f)) // below threshold -> clears immediately, ignoring hold
        }
        val out = detector.detect(levels).toList()
        assertEquals(listOf("a", null), out)
    }
}
