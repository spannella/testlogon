package com.testlogon.android.feature.signing

import com.testlogon.android.feature.signing.model.PacketAction
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.primaryAction

// AND-340 - UI state + one-shot events for the e-signature packet DETAIL screen.

/** The sealed UI state for the packet detail (no list; this is the single-packet detail surface). */
sealed interface PacketDetailUiState {

    /** Initial single read of the packet + its events. */
    data object Loading : PacketDetailUiState

    /**
     * The loaded [packet] (status / signers / fields manifest / capabilities) + its audit [events].
     * [isStale] is true when a refresh failed and this is a retained last-known snapshot; [refreshing]
     * drives pull-to-refresh; [actionInFlight] disables the primary action while send() is running.
     */
    data class Content(
        val packet: SignaturePacket,
        val events: List<PacketEvent>,
        val isStale: Boolean = false,
        val refreshing: Boolean = false,
        val actionInFlight: Boolean = false,
    ) : PacketDetailUiState {

        /** The status + role driven primary action affordance (derived; never stored). */
        val action: PacketAction get() = primaryAction(packet)
    }

    /** A terminal load error with no prior content to fall back to. [retryable] gates the Retry action. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : PacketDetailUiState
}

/** One-shot navigation/feedback events emitted by [PacketDetailViewModel]. */
sealed interface PacketDetailEvent {

    /** An assigned signer tapped Sign; the deep capture flow is AND-342/343. Carries the packet id. */
    data class NavigateToSign(val packetId: String) : PacketDetailEvent

    /** The draft was sent successfully (the screen refreshes + may show a confirmation). */
    data object PacketSent : PacketDetailEvent

    /** The send action failed; carries a user-facing message. */
    data class ActionFailed(val message: String) : PacketDetailEvent
}
