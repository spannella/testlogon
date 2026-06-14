package com.testlogon.android.feature.messaging.typing

import com.testlogon.android.data.messaging.typing.TypingRepository
import com.testlogon.android.data.messaging.typing.TypingUserDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TypingSignalControllerTest {

    private class FakeRepo : TypingRepository {
        val starts = mutableListOf<String>()
        val stops = mutableListOf<String>()
        var throwOnSend = false
        override suspend fun start(conversationId: String) {
            if (throwOnSend) throw RuntimeException("boom")
            starts += conversationId
        }
        override suspend fun stop(conversationId: String) {
            if (throwOnSend) throw RuntimeException("boom")
            stops += conversationId
        }
        override suspend fun poll(conversationId: String): List<TypingUserDto> = emptyList()
    }

    @Test
    fun rapidKeystrokesWithinThrottle_sendOneStart() = runTest {
        val repo = FakeRepo()
        var now = 0L
        val c = TypingSignalController("c1", repo, clock = { now }, throttleMs = 3_000, idleMs = 5_000)
        val job = launch { c.run() }
        repeat(10) { c.onInput(TypingInput.Keystroke) }
        runCurrent()
        assertEquals(1, repo.starts.size)
        assertEquals(0, repo.stops.size)
        job.cancelAndJoin()
    }

    @Test
    fun sustainedTypingPastThrottle_resendsStart() = runTest {
        val repo = FakeRepo()
        var now = 0L
        val c = TypingSignalController("c1", repo, clock = { now }, throttleMs = 3_000, idleMs = 30_000)
        val job = launch { c.run() }
        c.onInput(TypingInput.Keystroke); runCurrent()
        now = 3_500; c.onInput(TypingInput.Keystroke); runCurrent()
        now = 7_000; c.onInput(TypingInput.Keystroke); runCurrent()
        assertEquals(3, repo.starts.size)
        job.cancelAndJoin()
    }

    @Test
    fun clearedSendsOneStop() = runTest {
        val repo = FakeRepo()
        val c = TypingSignalController("c1", repo, clock = { 0L }, throttleMs = 3_000, idleMs = 5_000)
        val job = launch { c.run() }
        c.onInput(TypingInput.Keystroke); runCurrent()
        c.onInput(TypingInput.Cleared); runCurrent()
        assertEquals(1, repo.stops.size)
        job.cancelAndJoin()
    }

    @Test
    fun sentSendsOneStop() = runTest {
        val repo = FakeRepo()
        val c = TypingSignalController("c1", repo, clock = { 0L })
        val job = launch { c.run() }
        c.onInput(TypingInput.Keystroke); runCurrent()
        c.onInput(TypingInput.Sent); runCurrent()
        assertEquals(1, repo.stops.size)
        job.cancelAndJoin()
    }

    @Test
    fun idleTimeoutSynthesizesStop() = runTest {
        val repo = FakeRepo()
        val c = TypingSignalController("c1", repo, clock = { 0L }, throttleMs = 3_000, idleMs = 5_000)
        val job = launch { c.run() }
        c.onInput(TypingInput.Keystroke); runCurrent()
        assertEquals(0, repo.stops.size)
        advanceTimeBy(5_100)
        runCurrent()
        assertEquals(1, repo.stops.size)
        job.cancelAndJoin()
    }

    @Test
    fun scopeCancellationSendsFinalStop() = runTest {
        val repo = FakeRepo()
        val c = TypingSignalController("c1", repo, clock = { 0L }, idleMs = 60_000)
        val job = launch { c.run() }
        c.onInput(TypingInput.Keystroke); runCurrent()
        job.cancelAndJoin()
        // The NonCancellable finally block fires a final stop.
        assertEquals(1, repo.stops.size)
    }

    @Test
    fun sendFailureDoesNotCrash() = runTest {
        val repo = FakeRepo().apply { throwOnSend = true }
        val c = TypingSignalController("c1", repo, clock = { 0L })
        val job = launch { c.run() }
        c.onInput(TypingInput.Keystroke)
        runCurrent()
        // No exception propagated; controller still alive.
        job.cancelAndJoin()
    }
}
