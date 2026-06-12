package com.testlogon.android.feature.call.fsm

/**
 * AND-305 — a small, serializable snapshot of a NON-TERMINAL call so an in-progress call rehydrates on a
 * cold start (process death mid-call). Pure (android-free): the (de)serialization is plain string codec so
 * it is JVM-unit-testable without DataStore. [CallSnapshotStore] persists/clears it.
 *
 * Only fields needed to reconstruct a [CallState] are kept. [stateName] is the [CallState] subclass name
 * ("Dialing"/"IncomingRinging"/"Connecting"/"Active"/"Reconnecting"); terminal states are never persisted.
 */
data class CallSnapshot(
    val callId: String,
    val stateName: String,
    val peerUserId: String,
    val peerConversationId: String,
    val peerDisplayName: String?,
    val isVideo: Boolean,
    val startedAtMs: Long,
) {
    companion object {
        /** Builds a snapshot from a live [CallState], or null for Idle/Ending/Ended (not persistable). */
        fun from(state: CallState): CallSnapshot? = when (state) {
            is CallState.Dialing -> build(state.callId, "Dialing", state.peer, state.isVideo, 0L)
            is CallState.IncomingRinging ->
                build(state.callId, "IncomingRinging", state.peer, state.isVideo, 0L)
            is CallState.Connecting -> build(state.callId, "Connecting", state.peer, state.isVideo, 0L)
            is CallState.Active ->
                build(state.callId, "Active", state.peer, state.isVideo, state.startedAtMs)
            is CallState.Reconnecting ->
                build(state.callId, "Reconnecting", state.peer, state.isVideo, state.startedAtMs)
            is CallState.Idle, is CallState.Ending, is CallState.Ended -> null
        }

        private fun build(
            callId: String,
            stateName: String,
            peer: PeerRef,
            isVideo: Boolean,
            startedAtMs: Long,
        ) = CallSnapshot(
            callId = callId,
            stateName = stateName,
            peerUserId = peer.userId,
            peerConversationId = peer.conversationId,
            peerDisplayName = peer.displayName,
            isVideo = isVideo,
            startedAtMs = startedAtMs,
        )
    }

    /** The [PeerRef] this snapshot describes. */
    fun peer(): PeerRef = PeerRef(peerUserId, peerConversationId, peerDisplayName)

    /**
     * Reconstructs the [CallState]. A Reconnecting snapshot rehydrates as [CallState.Active] (we resume
     * optimistically and let the live ICE layer re-drive a disconnect if needed). An unknown name -> Idle.
     */
    fun toState(): CallState = when (stateName) {
        "Dialing" -> CallState.Dialing(callId, peer(), isVideo)
        "IncomingRinging" -> CallState.IncomingRinging(callId, peer(), isVideo)
        "Connecting" -> CallState.Connecting(callId, peer(), isVideo)
        "Active" -> CallState.Active(callId, peer(), isVideo, startedAtMs)
        "Reconnecting" -> CallState.Active(callId, peer(), isVideo, startedAtMs)
        else -> CallState.Idle
    }
}

/**
 * AND-305 — pure, android-free codec for [CallSnapshot] (a tiny pipe-delimited record, base64-free; the
 * display name is the only free-text field and is length-prefixed so embedded delimiters are safe). Used by
 * the DataStore-backed store and directly unit-testable.
 */
object CallSnapshotCodec {

    private const val VERSION = "v1"
    private const val SEP = '|'

    fun encode(s: CallSnapshot): String {
        val name = s.peerDisplayName ?: ""
        // Length-prefix the free-text display name so it can contain the separator safely.
        return buildString {
            append(VERSION).append(SEP)
            append(s.callId).append(SEP)
            append(s.stateName).append(SEP)
            append(s.peerUserId).append(SEP)
            append(s.peerConversationId).append(SEP)
            append(s.isVideo).append(SEP)
            append(s.startedAtMs).append(SEP)
            append(name.length).append(SEP)
            append(name)
        }
    }

    fun decode(raw: String?): CallSnapshot? {
        if (raw.isNullOrEmpty()) return null
        // Split only the leading fixed fields (8 separators) then take the remainder as the name body.
        val parts = raw.split(SEP, limit = 9)
        if (parts.size < 9 || parts[0] != VERSION) return null
        return try {
            val nameLen = parts[7].toInt()
            val name = parts[8].take(nameLen)
            CallSnapshot(
                callId = parts[1],
                stateName = parts[2],
                peerUserId = parts[3],
                peerConversationId = parts[4],
                peerDisplayName = name.ifEmpty { null }.takeIf { nameLen > 0 },
                isVideo = parts[5].toBooleanStrictOrNull() ?: return null,
                startedAtMs = parts[6].toLongOrNull() ?: return null,
            )
        } catch (e: NumberFormatException) {
            null
        }
    }
}
