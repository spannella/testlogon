package com.testlogon.android.feature.call.incall

import com.testlogon.android.feature.call.billing.BillingCondition
import com.testlogon.android.feature.call.domain.CallEndReason

/**
 * AND-298 — pure (android-free) UI contract for the in-call (1:1) screen.
 *
 * [InCallUiState] is the single immutable snapshot the screen renders; it merges the app-scoped
 * [com.testlogon.android.feature.call.domain.CallSessionState] (control plane) with the LOCAL,
 * optimistic media-control state owned by the view model (mic/camera/route/pip/controls) — native media
 * is FLAGGED (the peer seam returns NotConfigured) so the toggles are real UI state but do not touch a
 * real track. Kept pure/JVM-friendly (NO Compose imports) so the mapping logic is unit-testable; the
 * Compose-only [PipCorner] -> Alignment mapping lives as an extension in InCallScreen.kt.
 */
data class InCallUiState(
    val callId: String,
    val peerName: String?,
    val peerAvatarUrl: String? = null,
    val lifecycle: InCallLifecycle = InCallLifecycle.Connecting,
    val isVideoCall: Boolean = false,
    val hasLocalVideo: Boolean = false,
    val hasRemoteVideo: Boolean = false,
    val micEnabled: Boolean = true,
    val cameraEnabled: Boolean = true,
    val flipInFlight: Boolean = false,
    val hasMultipleCameras: Boolean = true,
    val audioRoute: AudioRoute = AudioRoute.EARPIECE,
    val availableRoutes: Set<AudioRoute> = setOf(AudioRoute.EARPIECE, AudioRoute.SPEAKER),
    val quality: ConnectionQuality = ConnectionQuality.UNKNOWN,
    val showWeakBanner: Boolean = false,
    val mediaUnavailable: Boolean = false,
    val durationLabel: String = "",
    val controlsVisible: Boolean = true,
    val localTileCorner: PipCorner = PipCorner.TOP_END,
    val endedReason: CallEndReason? = null,
    /**
     * AND-301 — paid-call billing for the running-cost overlay + final-cost summary. [paid] gates the
     * overlay; [runningCostCents] is authoritative (heartbeat) when [isEstimate] is false; [finalCostCents]
     * is set on Ended ([finalIsEstimate] when it falls back to the local estimate). All default to the
     * free-call zero so non-paid calls render unchanged.
     */
    val paid: Boolean = false,
    val runningCostCents: Int = 0,
    val isEstimate: Boolean = false,
    val billingCondition: BillingCondition = BillingCondition.None,
    val finalCostCents: Int? = null,
    val finalIsEstimate: Boolean = false,
)

/** Coarse, UI-rendered lifecycle derived from the domain [com.testlogon.android.feature.call.domain.CallPhase]. */
enum class InCallLifecycle { Connecting, Connected, Reconnecting, Ending, Ended }

/** Audio output route the user can pick (local UI state; native audio routing is FLAGGED). */
enum class AudioRoute { EARPIECE, SPEAKER, BLUETOOTH, WIRED }

/** Derived connection quality from the (FLAGGED) stats sampler; UNKNOWN when no real stats exist. */
enum class ConnectionQuality { EXCELLENT, GOOD, POOR, LOST, UNKNOWN }

/** Which corner the local picture-in-picture tile is docked in. */
enum class PipCorner { TOP_START, TOP_END, BOTTOM_START, BOTTOM_END }

/** User intents the screen forwards to the view model. */
sealed interface InCallAction {
    data object ToggleMic : InCallAction
    data object ToggleCamera : InCallAction
    data object FlipCamera : InCallAction
    data class SetRoute(val route: AudioRoute) : InCallAction
    data object CycleRoute : InCallAction
    data object EndCall : InCallAction
    data class MoveLocalTile(val corner: PipCorner) : InCallAction
    data object ToggleControls : InCallAction
}
