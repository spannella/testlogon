package com.testlogon.android.feature.call.fsm

import com.testlogon.android.data.call.CallId

/**
 * AND-305 — user intents from the FSM screens, mapped to [CallEvent] via [toEvent]. Pure (android-free).
 *
 * Kept separate from [CallEvent] so the UI surface is a small, stable vocabulary while the FSM event set
 * (which also carries remote/timer events) can evolve independently. [StartOutgoing] mints the client call
 * id here (the only impure-ish call, isolated to intent->event mapping; the reducer still receives a ready
 * id and stays pure).
 */
sealed interface CallIntent {

    data class StartOutgoing(val peer: PeerRef, val isVideo: Boolean) : CallIntent
    data object Accept : CallIntent
    data object Decline : CallIntent
    data object HangUp : CallIntent
    data object ToggleMute : CallIntent
    data object ToggleCamera : CallIntent
    data object ToggleSpeaker : CallIntent
    data object FlipCamera : CallIntent

    fun toEvent(): CallEvent = when (this) {
        is StartOutgoing -> CallEvent.StartOutgoing(CallId.new(), peer, isVideo)
        Accept -> CallEvent.Accept
        Decline -> CallEvent.Decline
        HangUp -> CallEvent.HangUp
        ToggleMute -> CallEvent.ToggleMute
        ToggleCamera -> CallEvent.ToggleCamera
        ToggleSpeaker -> CallEvent.ToggleSpeaker
        FlipCamera -> CallEvent.FlipCamera
    }
}
