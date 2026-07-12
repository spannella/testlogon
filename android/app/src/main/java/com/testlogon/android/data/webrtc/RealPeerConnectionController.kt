package com.testlogon.android.data.webrtc

import android.content.Context
import android.util.Log
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.suspendCancellableCoroutine
import livekit.org.webrtc.AudioSource
import livekit.org.webrtc.AudioTrack
import livekit.org.webrtc.Camera2Enumerator
import livekit.org.webrtc.CameraVideoCapturer
import livekit.org.webrtc.EglBase
import livekit.org.webrtc.IceCandidate as RtcIceCandidate
import livekit.org.webrtc.MediaConstraints
import livekit.org.webrtc.MediaStream
import livekit.org.webrtc.PeerConnection
import livekit.org.webrtc.PeerConnectionFactory
import livekit.org.webrtc.RtpReceiver
import livekit.org.webrtc.SdpObserver
import livekit.org.webrtc.SessionDescription
import livekit.org.webrtc.SurfaceTextureHelper
import livekit.org.webrtc.VideoSource
import livekit.org.webrtc.VideoTrack
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume

/**
 * Real native-WebRTC [PeerConnectionController] (1:1 calls). Wraps one `org.webrtc.PeerConnection`:
 * builds the ICE config from [PeerConfig], captures local mic (always) + front camera (when video is
 * enabled) and adds the tracks, drives offer/answer + remote-description + trickle-ICE, surfaces the
 * remote video track to [CallMediaHolder], and maps the native connection state to [PeerLifecycle].
 *
 * Same-LAN peers connect via host/STUN candidates (TURN not required). Threading: native callbacks land
 * on the WebRTC signaling thread; [MutableStateFlow]/[MutableSharedFlow] are concurrency-safe and the
 * suspend SDP wrappers resume from those callbacks.
 */
@Singleton
class RealPeerConnectionController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val factory: PeerConnectionFactory,
    private val eglBase: EglBase,
    private val mediaHolder: CallMediaHolder,
) : PeerConnectionController {

    private val _lifecycle = MutableStateFlow<PeerLifecycle>(PeerLifecycle.Idle)
    override val lifecycle: StateFlow<PeerLifecycle> = _lifecycle.asStateFlow()

    private val _localIce = MutableSharedFlow<IceCandidate>(
        replay = 0,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    override val localIceCandidates: SharedFlow<IceCandidate> = _localIce.asSharedFlow()

    private var peer: PeerConnection? = null
    private var audioSource: AudioSource? = null
    private var audioTrack: AudioTrack? = null
    private var videoSource: VideoSource? = null
    private var videoTrack: VideoTrack? = null
    private var capturer: CameraVideoCapturer? = null
    private var surfaceHelper: SurfaceTextureHelper? = null

    private val streamId = "tl_stream"

    override suspend fun init(config: PeerConfig): PeerResult<Unit> {
        return try {
            val iceServers = config.iceServers.map { s ->
                val b = PeerConnection.IceServer.builder(s.urls)
                s.username?.let { b.setUsername(it) }
                s.credential?.let { b.setPassword(it) }
                b.createIceServer()
            }
            val rtcConfig = PeerConnection.RTCConfiguration(iceServers).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
                bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
                rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
                if (config.relayOnly) {
                    iceTransportsType = PeerConnection.IceTransportsType.RELAY
                }
            }
            val pc = factory.createPeerConnection(rtcConfig, PcObserver())
                ?: return PeerResult.Failed("createPeerConnection returned null")
            peer = pc
            _lifecycle.value = PeerLifecycle.Connecting

            if (config.enableAudio) {
                val src = factory.createAudioSource(MediaConstraints())
                val track = factory.createAudioTrack("tl_audio", src)
                track.setEnabled(true)
                pc.addTrack(track, listOf(streamId))
                audioSource = src
                audioTrack = track
            }
            if (config.enableVideo) {
                startCamera()?.let { track ->
                    pc.addTrack(track, listOf(streamId))
                    videoTrack = track
                    track.setEnabled(true)
                    mediaHolder.localVideo.value = track
                }
            }
            PeerResult.Ok(Unit)
        } catch (t: Throwable) {
            PeerResult.Failed(t.javaClass.simpleName)
        }
    }

    private fun startCamera(): VideoTrack? {
        val enumerator = Camera2Enumerator(context)
        val names = enumerator.deviceNames
        val deviceName = names.firstOrNull { enumerator.isFrontFacing(it) } ?: names.firstOrNull() ?: return null
        val cap = enumerator.createCapturer(deviceName, null) ?: return null
        val helper = SurfaceTextureHelper.create("TlCaptureThread", eglBase.eglBaseContext)
        val source = factory.createVideoSource(cap.isScreencast)
        cap.initialize(helper, context, source.capturerObserver)
        cap.startCapture(1280, 720, 30)
        capturer = cap
        surfaceHelper = helper
        videoSource = source
        return factory.createVideoTrack("tl_video", source)
    }

    override suspend fun createOffer(): PeerResult<SdpDescription> {
        val pc = peer ?: return PeerResult.NotConfigured
        val offer = awaitCreate { pc.createOffer(it, MediaConstraints()) }
            ?: return PeerResult.Failed("createOffer")
        if (!awaitSet { pc.setLocalDescription(it, offer) }) return PeerResult.Failed("setLocal(offer)")
        return PeerResult.Ok(offer.toDomain())
    }

    override suspend fun createAnswer(): PeerResult<SdpDescription> {
        val pc = peer ?: return PeerResult.NotConfigured
        val answer = awaitCreate { pc.createAnswer(it, MediaConstraints()) }
            ?: return PeerResult.Failed("createAnswer")
        if (!awaitSet { pc.setLocalDescription(it, answer) }) return PeerResult.Failed("setLocal(answer)")
        return PeerResult.Ok(answer.toDomain())
    }

    override suspend fun setRemoteDescription(sdp: SdpDescription): PeerResult<Unit> {
        val pc = peer ?: return PeerResult.NotConfigured
        val ok = awaitSet { pc.setRemoteDescription(it, sdp.toRtc()) }
        return if (ok) PeerResult.Ok(Unit) else PeerResult.Failed("setRemoteDescription")
    }

    override suspend fun addIceCandidate(candidate: IceCandidate): PeerResult<Unit> {
        val pc = peer ?: return PeerResult.NotConfigured
        return try {
            pc.addIceCandidate(RtcIceCandidate(candidate.sdpMid, candidate.sdpMLineIndex, candidate.candidate))
            PeerResult.Ok(Unit)
        } catch (t: Throwable) {
            PeerResult.Failed(t.javaClass.simpleName)
        }
    }

    override fun close() {
        runCatching { capturer?.stopCapture() }
        runCatching { capturer?.dispose() }
        runCatching { surfaceHelper?.dispose() }
        runCatching { videoSource?.dispose() }
        runCatching { audioSource?.dispose() }
        runCatching { peer?.close() }
        runCatching { peer?.dispose() }
        capturer = null; surfaceHelper = null; videoSource = null; audioSource = null
        videoTrack = null; audioTrack = null; peer = null
        mediaHolder.clear()
        _lifecycle.value = PeerLifecycle.Closed
    }

    // ── Camera / mic controls ────────────────────────────────────────────────────────────────────
    fun setMicEnabled(enabled: Boolean) { audioTrack?.setEnabled(enabled) }
    fun setCameraEnabled(enabled: Boolean) {
        videoTrack?.setEnabled(enabled)
        runCatching { if (enabled) capturer?.startCapture(1280, 720, 30) else capturer?.stopCapture() }
    }
    fun switchCamera() { capturer?.switchCamera(null) }

    // ── Observer ─────────────────────────────────────────────────────────────────────────────────
    private inner class PcObserver : PeerConnection.Observer {
        override fun onIceCandidate(candidate: RtcIceCandidate) {
            _localIce.tryEmit(IceCandidate(candidate.sdpMid, candidate.sdpMLineIndex, candidate.sdp))
        }

        override fun onConnectionChange(newState: PeerConnection.PeerConnectionState) {
            Log.d("TLHUB", "peer connectionState=$newState")
            _lifecycle.value = when (newState) {
                PeerConnection.PeerConnectionState.CONNECTED -> PeerLifecycle.Connected
                PeerConnection.PeerConnectionState.CONNECTING,
                PeerConnection.PeerConnectionState.NEW,
                PeerConnection.PeerConnectionState.DISCONNECTED -> PeerLifecycle.Connecting
                PeerConnection.PeerConnectionState.FAILED -> PeerLifecycle.Failed("ice_failed")
                PeerConnection.PeerConnectionState.CLOSED -> PeerLifecycle.Closed
            }
        }

        override fun onAddTrack(receiver: RtpReceiver, mediaStreams: Array<out MediaStream>) {
            when (val track = receiver.track()) {
                is VideoTrack -> { Log.d("TLHUB", "remote VideoTrack received"); track.setEnabled(true); mediaHolder.remoteVideo.value = track }
                is AudioTrack -> track.setEnabled(true)
            }
        }

        override fun onIceConnectionChange(s: PeerConnection.IceConnectionState) { Log.d("TLHUB", "peer iceState=$s") }
        override fun onIceCandidatesRemoved(candidates: Array<out RtcIceCandidate>) {}
        override fun onSignalingChange(s: PeerConnection.SignalingState) {}
        override fun onIceGatheringChange(s: PeerConnection.IceGatheringState) {}
        override fun onIceConnectionReceivingChange(receiving: Boolean) {}
        override fun onAddStream(stream: MediaStream) {}
        override fun onRemoveStream(stream: MediaStream) {}
        override fun onDataChannel(channel: livekit.org.webrtc.DataChannel) {}
        override fun onRenegotiationNeeded() {}
    }

    // ── suspend SDP wrappers ─────────────────────────────────────────────────────────────────────
    private suspend fun awaitCreate(block: (SdpObserver) -> Unit): SessionDescription? =
        suspendCancellableCoroutine { cont ->
            block(object : SdpObserver {
                override fun onCreateSuccess(sdp: SessionDescription) { if (cont.isActive) cont.resume(sdp) }
                override fun onSetSuccess() {}
                override fun onCreateFailure(error: String?) { if (cont.isActive) cont.resume(null) }
                override fun onSetFailure(error: String?) {}
            })
        }

    private suspend fun awaitSet(block: (SdpObserver) -> Unit): Boolean =
        suspendCancellableCoroutine { cont ->
            block(object : SdpObserver {
                override fun onCreateSuccess(sdp: SessionDescription) {}
                override fun onSetSuccess() { if (cont.isActive) cont.resume(true) }
                override fun onCreateFailure(error: String?) {}
                override fun onSetFailure(error: String?) { if (cont.isActive) cont.resume(false) }
            })
        }
}

private fun SessionDescription.toDomain(): SdpDescription =
    SdpDescription(
        type = when (type) {
            SessionDescription.Type.OFFER -> SdpType.OFFER
            SessionDescription.Type.ANSWER -> SdpType.ANSWER
            SessionDescription.Type.PRANSWER -> SdpType.PRANSWER
            else -> SdpType.OFFER
        },
        sdp = description,
    )

private fun SdpDescription.toRtc(): SessionDescription =
    SessionDescription(
        when (type) {
            SdpType.OFFER -> SessionDescription.Type.OFFER
            SdpType.ANSWER -> SessionDescription.Type.ANSWER
            SdpType.PRANSWER -> SessionDescription.Type.PRANSWER
        },
        sdp,
    )
