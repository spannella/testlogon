package com.testlogon.android.feature.call.group

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map

/**
 * AND-300 — PURE (android-free, Compose-free), JVM-testable active-speaker detector.
 *
 * Consumes a cold [Flow] of per-participant audio levels (userId -> level in 0f..1f) and emits the userId of
 * the current active speaker, or null when nobody is above [thresholdLevel]. It is a debounce/hold over the
 * argmax-above-threshold: once a speaker is chosen it is HELD for at least [holdMs] before switching to a new
 * loudest speaker, so the highlight does not flicker between participants on every frame.
 *
 * Real audio levels come from AND-299's full-mesh ([com.testlogon.android.data.webrtc.MeshConnectionManager]),
 * which runs per-peer audio-level sampling. Native WebRTC is FLAGGED (the mesh stub never emits and exposes
 * no levels), so in production today the level flow is empty -> this detector simply yields null. The wiring
 * is real so the SDK-backed mesh slots in without view-model changes.
 *
 * The result is a COLD [Flow]; [distinctUntilChanged] is applied to it (safe on a cold flow — never on a
 * StateFlow). Hold timing is driven by the input emissions' wall-clock timestamps captured via [now], which
 * a test can override with a virtual clock; the operator does not start its own timers, so a finite input
 * flow completes deterministically.
 */
class ActiveSpeakerDetector(
    private val thresholdLevel: Float = 0.15f,
    private val holdMs: Long = 500,
    private val now: () -> Long = System::currentTimeMillis,
) {

    /**
     * Map [levels] to the current active speaker userId (or null). For each level map we pick the loudest
     * participant whose level is strictly above [thresholdLevel] (ties broken by userId for determinism). A
     * new candidate only replaces the held speaker once [holdMs] has elapsed since the held speaker was last
     * (re)affirmed; if the held speaker is still audible it is kept regardless of [holdMs]. When no one is
     * above threshold the speaker clears to null immediately.
     */
    fun detect(levels: Flow<Map<String, Float>>): Flow<String?> =
        levels
            .map { frame -> loudestAboveThreshold(frame) }
            .hold()
            .distinctUntilChanged()

    /** The userId with the highest level above [thresholdLevel], or null if none qualify. Deterministic. */
    private fun loudestAboveThreshold(frame: Map<String, Float>): String? =
        frame.entries
            .filter { it.value > thresholdLevel }
            .maxWithOrNull(compareBy({ it.value }, { it.key }))
            ?.key

    /**
     * Hold/debounce: keep the current speaker for at least [holdMs] before switching to a different one.
     * - null candidate (everyone quiet) clears the held speaker immediately.
     * - the same speaker re-affirms the hold window (refreshes the timestamp).
     * - a different speaker only takes over once [holdMs] has elapsed since the held speaker started; until
     *   then the held speaker is re-emitted.
     */
    private fun Flow<String?>.hold(): Flow<String?> = flow {
        var held: String? = null
        var heldSinceMs = 0L
        collect { candidate ->
            val tNow = now()
            val next = when {
                candidate == null -> null
                candidate == held -> {
                    heldSinceMs = tNow
                    held
                }
                held == null -> candidate
                tNow - heldSinceMs >= holdMs -> candidate
                else -> held
            }
            if (next != held) {
                heldSinceMs = tNow
            }
            held = next
            emit(next)
        }
    }
}
