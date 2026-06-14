package com.testlogon.android.feature.messaging.typing

import com.testlogon.android.data.messaging.typing.TypingRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * AND-146 (send side) — converts composer activity into debounced typing start/stop network calls.
 *
 * Pure of Android types so it is JVM-unit-testable: time comes from an injected [clock] (epoch ms for
 * throttle bookkeeping) and idle detection uses a cancellable [delay] job (virtual-time friendly under
 * runTest). Drive it by emitting [TypingInput]s; collect [run] inside the ViewModel scope.
 *
 * Behaviour (FR-1..FR-3):
 *  - first Keystroke (or one past the throttle window) sends start; intermediate keystrokes coalesce
 *    so at most one start fires per [throttleMs] while typing continues,
 *  - a refresh start re-fires every [throttleMs] of continuous typing (keeps the receiver expiry alive),
 *  - Cleared / Sent / Left, or [idleMs] of silence after the last keystroke, send a single stop,
 *  - send failures are swallowed (FR-8); a final stop is sent on scope cancel.
 */
class TypingSignalController(
    private val conversationId: String,
    private val repo: TypingRepository,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val throttleMs: Long = TypingConfig.THROTTLE_MS,
    private val idleMs: Long = TypingConfig.IDLE_MS,
) {
    private val input = Channel<TypingInput>(capacity = Channel.BUFFERED)

    /** Non-suspending emit from UI callbacks. */
    fun onInput(i: TypingInput) {
        input.trySend(i)
    }

    /**
     * Collects inputs until the surrounding scope is cancelled. Each Keystroke (re)arms a single idle
     * job that fires a synthetic stop after [idleMs] of silence. The terminal `finally` guarantees a
     * stop on teardown.
     */
    suspend fun run() = coroutineScope {
        var typing = false
        var lastStartAt = 0L
        var idleJob: Job? = null

        fun stopIfTyping() {
            if (typing) {
                typing = false
                idleJob?.cancel()
                idleJob = null
                launch { runCatching { repo.stop(conversationId) } } // FR-8 best-effort
            }
        }

        try {
            input.consumeAsFlow().collect { event ->
                when (event) {
                    TypingInput.Keystroke -> {
                        val now = clock()
                        if (!typing || now - lastStartAt >= throttleMs) {
                            lastStartAt = now
                            typing = true
                            launch { runCatching { repo.start(conversationId) } } // FR-8 best-effort
                        }
                        // (Re)arm the idle watchdog on every keystroke.
                        idleJob?.cancel()
                        idleJob = launch {
                            delay(idleMs)
                            stopIfTyping()
                        }
                    }
                    TypingInput.Cleared,
                    TypingInput.Sent,
                    TypingInput.Left,
                    -> stopIfTyping()
                }
            }
        } finally {
            idleJob?.cancel()
            if (typing) {
                withContext(NonCancellable) { runCatching { repo.stop(conversationId) } }
            }
        }
    }
}

/** Composer activity signals fed into [TypingSignalController]. */
sealed interface TypingInput {
    /** A keystroke that left the field non-empty. */
    data object Keystroke : TypingInput

    /** The field was cleared to empty. */
    data object Cleared : TypingInput

    /** The message was sent. */
    data object Sent : TypingInput

    /** The user left the screen / it stopped. */
    data object Left : TypingInput
}

/** AND-146 — typing timing constants (conservative for the flaky dev host). */
object TypingConfig {
    /** Min interval between start sends while typing continues (FR-1/FR-2). */
    const val THROTTLE_MS = 3_000L

    /** Composer silence after the last keystroke that triggers a stop (FR-3a). */
    const val IDLE_MS = 5_000L

    /** Remote typing-entry self-expiry; > sender throttle so a live typer never flickers (FR-5). */
    const val TTL_MS = 6_000L
}
