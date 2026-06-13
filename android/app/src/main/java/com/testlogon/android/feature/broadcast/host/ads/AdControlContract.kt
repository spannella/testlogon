package com.testlogon.android.feature.broadcast.host.ads

/**
 * AND-316 — UI state contract for the host AD-BREAK / AD-CONFIG surface.
 *
 * A single flat [AdControlUiState] (a plain MutableStateFlow drives it synchronously) carries the editable
 * [config] form, the live ad-break state (active / startedAt / derived remaining), the running mutation
 * guard, and load-level error / offline flags. The viewer-side ad RENDERING is OUT OF SCOPE — this is the
 * host control plane only.
 */
data class AdControlUiState(
    val loading: Boolean = true,
    val hasConfig: Boolean = false,
    val config: AdConfigForm = AdConfigForm(),
    val adBreakActive: Boolean = false,
    val adBreakStartedAt: Long? = null,
    val adBreakDurationSeconds: Int = 0,
    val skipAfterSeconds: Int = 0,
    val remainingSeconds: Int = 0,
    val totalAdBreaks: Int = 0,
    val mutationInFlight: Boolean = false,
    val error: String? = null,
    val offline: Boolean = false,
)

/**
 * AND-316 — the editable ad-config form. [midRollDurationSeconds] / [skipAfterSeconds] are the in-progress
 * numeric values; [durationValid] (15..60) and [skipValid] (5..30) are derived validation flags; [dirty]
 * marks unsaved edits relative to the persisted config.
 */
data class AdConfigForm(
    val preRollEnabled: Boolean = false,
    val midRollDurationSeconds: Int = DEFAULT_DURATION_SECONDS,
    val skipAfterSeconds: Int = DEFAULT_SKIP_SECONDS,
    val durationValid: Boolean = true,
    val skipValid: Boolean = true,
    val dirty: Boolean = false,
) {
    /** Save is permitted only when there are unsaved edits AND both bounds are valid. */
    val canSave: Boolean get() = dirty && durationValid && skipValid

    companion object {
        const val DEFAULT_DURATION_SECONDS = 30
        const val DEFAULT_SKIP_SECONDS = 5
    }
}

/** AND-316 — verified server bounds for the ad-config numeric fields. */
object AdConfigBounds {
    const val DURATION_MIN = 15
    const val DURATION_MAX = 60
    const val SKIP_MIN = 5
    const val SKIP_MAX = 30

    fun durationValid(seconds: Int): Boolean = seconds in DURATION_MIN..DURATION_MAX
    fun skipValid(seconds: Int): Boolean = seconds in SKIP_MIN..SKIP_MAX
}
