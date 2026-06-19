package com.testlogon.android.data.webrtc

import kotlinx.coroutines.flow.MutableStateFlow
import org.webrtc.VideoTrack
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Process-singleton holder for the live call's local + remote [VideoTrack]s, written by
 * [RealPeerConnectionController] and read by the real video renderer (the Compose
 * `SurfaceViewRenderer`s in the in-call screen attach these tracks as sinks). Kept separate from the
 * pure [PeerConnectionController] interface so org.webrtc types never leak into the SDK-free seam.
 */
@Singleton
class CallMediaHolder @Inject constructor() {
    val localVideo = MutableStateFlow<VideoTrack?>(null)
    val remoteVideo = MutableStateFlow<VideoTrack?>(null)

    fun clear() {
        localVideo.value = null
        remoteVideo.value = null
    }
}
