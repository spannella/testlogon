package com.testlogon.android.core.call.audio

import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.Build
import android.telecom.CallAudioState
import androidx.annotation.RequiresApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-304 — @Singleton audio router for the self-managed Telecom connection.
 *
 * Owns two concerns, both defensively guarded so an OEM audio quirk can never crash the call:
 *   1. Transient-exclusive audio FOCUS — [resume] requests it (so the call ducks/silences other audio),
 *      [pause] abandons it (on hold). API 26+ uses [AudioFocusRequest]; older paths use the deprecated
 *      int API. Failures are swallowed.
 *   2. The observable [audioState] StateFlow the in-call UI can render. The (android) Telecom connection
 *      forwards every onCallAudioStateChanged here via [onSystemAudioState], which delegates the actual
 *      bit -> route translation to the PURE [CallAudioMapping] so the mapping stays unit-testable.
 *
 * STOP-AND-FLAG: call MEDIA is FLAGGED (no real WebRTC audio track — see
 * [com.testlogon.android.data.webrtc.PeerConnectionController]). This router manages OS audio FOCUS and
 * mirrors the SYSTEM-reported route, but there is no live stream to route; it is the focus/route control
 * plane that the real engine will plug into when the native WebRTC SDK is wired.
 */
@Singleton
class CallAudioRouter @Inject constructor(
    private val audioManager: AudioManager?,
) {

    private val _audioState = MutableStateFlow(CallAudioStateUi())
    val audioState: StateFlow<CallAudioStateUi> = _audioState.asStateFlow()

    private var focusRequest: AudioFocusRequest? = null

    /**
     * Updates [audioState] from a real platform [CallAudioState]. Reads only the primitive route ints +
     * mute flag and hands them to [CallAudioMapping] (android-free). API 26+ — CallAudioState is only
     * delivered by a self-managed Connection, which is itself gated on API 26.
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun onSystemAudioState(state: CallAudioState) {
        runCatching {
            _audioState.value = CallAudioMapping.map(
                activeRouteBit = state.route,
                supportedRouteMask = state.supportedRouteMask,
                isMuted = state.isMuted,
            )
        }
    }

    /** Requests transient-exclusive audio focus for the active call. No-op + safe if AudioManager is null. */
    fun resume() {
        val am = audioManager ?: return
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val attributes = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build()
                val request = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE)
                    .setAudioAttributes(attributes)
                    .build()
                focusRequest = request
                am.requestAudioFocus(request)
            } else {
                @Suppress("DEPRECATION")
                am.requestAudioFocus(
                    null,
                    AudioManager.STREAM_VOICE_CALL,
                    AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE,
                )
            }
        }
    }

    /** Abandons audio focus (call held/ended). Idempotent + safe if AudioManager is null. */
    fun pause() {
        val am = audioManager ?: return
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                focusRequest?.let { am.abandonAudioFocusRequest(it) }
                focusRequest = null
            } else {
                @Suppress("DEPRECATION")
                am.abandonAudioFocus(null)
            }
        }
    }
}
