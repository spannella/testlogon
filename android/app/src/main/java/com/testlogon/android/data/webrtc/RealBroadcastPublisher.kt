package com.testlogon.android.data.webrtc

import android.content.Context
import android.net.Uri
import android.util.Log
import com.testlogon.android.core.network.SettingsStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.webrtc.AudioSource
import org.webrtc.Camera2Enumerator
import org.webrtc.CameraVideoCapturer
import org.webrtc.DataChannel
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.SurfaceTextureHelper
import org.webrtc.VideoSource
import org.webrtc.VideoTrack
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume

/**
 * Real host "go-live" publisher (AND-288). Captures the front camera + mic, builds a send-only
 * PeerConnection, and publishes it to the media server over WHIP (WebRTC-HTTP Ingest Protocol): POST the
 * fully-gathered SDP offer to `<host>:8889/<sessionId>/whip` and apply the returned answer. The media
 * server (MediaMTX) packages the stream to HLS, which viewers play via the session playback URL.
 */
@Singleton
class RealBroadcastPublisher @Inject constructor(
    @ApplicationContext private val context: Context,
    private val factory: PeerConnectionFactory,
    private val eglBase: EglBase,
    private val settingsStore: SettingsStore,
    private val mediaHolder: CallMediaHolder,
) : BroadcastPublisher {

    // A bare client: the WHIP POST goes to the media server, not the API, so it must NOT carry the
    // app auth/CSRF/base-url interceptors (which were rewriting the request -> 404).
    private val whipClient = OkHttpClient()

    private val _state = MutableStateFlow<PublishState>(PublishState.Idle)
    override val state: StateFlow<PublishState> = _state.asStateFlow()

    private var peer: PeerConnection? = null
    private var capturer: CameraVideoCapturer? = null
    private var surfaceHelper: SurfaceTextureHelper? = null
    private var videoSource: VideoSource? = null
    private var audioSource: AudioSource? = null

    override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult {
        return try {
            _state.value = PublishState.Starting
            val gathered = CompletableDeferred<Unit>()
            val rtcConfig = PeerConnection.RTCConfiguration(emptyList()).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_ONCE
            }
            val pc = factory.createPeerConnection(rtcConfig, object : PeerConnection.Observer {
                override fun onIceCandidate(c: IceCandidate?) {}
                override fun onIceCandidatesRemoved(c: Array<out IceCandidate>?) {}
                override fun onSignalingChange(s: PeerConnection.SignalingState?) {}
                override fun onIceConnectionChange(s: PeerConnection.IceConnectionState?) { Log.d("TLBCAST", "ice=$s") }
                override fun onIceConnectionReceivingChange(b: Boolean) {}
                override fun onConnectionChange(s: PeerConnection.PeerConnectionState?) {
                    Log.d("TLBCAST", "conn=$s")
                    when (s) {
                        PeerConnection.PeerConnectionState.CONNECTED -> _state.value = PublishState.Live
                        PeerConnection.PeerConnectionState.FAILED -> _state.value = PublishState.Failed("ice_failed")
                        else -> {}
                    }
                }
                override fun onIceGatheringChange(s: PeerConnection.IceGatheringState?) {
                    Log.d("TLBCAST", "gather=$s")
                    if (s == PeerConnection.IceGatheringState.COMPLETE) gathered.complete(Unit)
                }
                override fun onAddStream(s: MediaStream?) {}
                override fun onRemoveStream(s: MediaStream?) {}
                override fun onDataChannel(d: DataChannel?) {}
                override fun onRenegotiationNeeded() {}
                override fun onAddTrack(r: RtpReceiver?, s: Array<out MediaStream>?) {}
            }) ?: return fail("createPeerConnection null")
            peer = pc

            val aSrc = factory.createAudioSource(MediaConstraints())
            val aTrack = factory.createAudioTrack("bcast_audio", aSrc)
            aTrack.setEnabled(true)
            pc.addTrack(aTrack, listOf("bcast"))
            audioSource = aSrc

            val vTrack = startCamera() ?: return fail("camera")
            vTrack.setEnabled(true)
            mediaHolder.localVideo.value = vTrack
            pc.addTrack(vTrack, listOf("bcast"))

            val offer = awaitCreate { pc.createOffer(it, MediaConstraints()) } ?: return fail("createOffer")
            val h264Offer = SessionDescription(offer.type, preferH264(offer.description))
            if (!awaitSet { pc.setLocalDescription(it, h264Offer) }) return fail("setLocal")
            // Non-trickle WHIP: publish the offer only after ICE gathering completes (bounded).
            withTimeoutOrNull(8000) { gathered.await() }
            val full = pc.localDescription ?: return fail("no local desc")

            val answer = postWhip(whipUrl(sessionId), full.description) ?: return fail("whip")
            if (!awaitSet { pc.setRemoteDescription(it, SessionDescription(SessionDescription.Type.ANSWER, answer)) }) {
                return fail("setRemote")
            }
            _state.value = PublishState.Live
            Log.d("TLBCAST", "published session=$sessionId")
            GoLiveResult.Started
        } catch (t: Throwable) {
            Log.d("TLBCAST", "goLive error ${t.javaClass.simpleName}: ${t.message}")
            stop()
            _state.value = PublishState.Failed(t.javaClass.simpleName)
            GoLiveResult.Failed(t.javaClass.simpleName)
        }
    }

    private fun fail(reason: String): GoLiveResult {
        Log.d("TLBCAST", "fail: $reason")
        _state.value = PublishState.Failed(reason)
        return GoLiveResult.Failed(reason)
    }

    private fun whipUrl(sessionId: String): String {
        val host = Uri.parse(settingsStore.baseUrl).host ?: "127.0.0.1"
        return "http://$host:8889/$sessionId/whip"
    }

    private suspend fun postWhip(url: String, offerSdp: String): String? = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url(url)
            .post(offerSdp.toRequestBody("application/sdp".toMediaType()))
            .build()
        try {
            whipClient.newCall(req).execute().use { resp ->
                Log.d("TLBCAST", "whip POST $url -> ${resp.code}")
                if (resp.isSuccessful) resp.body?.string() else null
            }
        } catch (t: Throwable) {
            Log.d("TLBCAST", "whip error ${t.javaClass.simpleName}")
            null
        }
    }

    private fun startCamera(): VideoTrack? {
        val enumerator = Camera2Enumerator(context)
        val names = enumerator.deviceNames
        val deviceName = names.firstOrNull { enumerator.isFrontFacing(it) } ?: names.firstOrNull() ?: return null
        val cap = enumerator.createCapturer(deviceName, null) ?: return null
        val helper = SurfaceTextureHelper.create("TlBcastCapture", eglBase.eglBaseContext)
        val source = factory.createVideoSource(cap.isScreencast)
        cap.initialize(helper, context, source.capturerObserver)
        cap.startCapture(1280, 720, 30)
        capturer = cap
        surfaceHelper = helper
        videoSource = source
        return factory.createVideoTrack("bcast_video", source)
    }

    /**
     * HLS cannot carry VP8/VP9, so restrict the m=video media line to H264 payload types only. MediaMTX
     * then negotiates H264, which it can repackage to HLS without transcoding.
     */
    private fun preferH264(sdp: String): String {
        val nl = if (sdp.contains("\r\n")) "\r\n" else "\n"
        val lines = sdp.split(nl).toMutableList()
        val mIdx = lines.indexOfFirst { it.startsWith("m=video") }
        if (mIdx < 0) return sdp
        val h264Pts = lines
            .filter { it.startsWith("a=rtpmap:") && it.contains("H264", ignoreCase = true) }
            .mapNotNull { it.removePrefix("a=rtpmap:").substringBefore(" ").takeIf { pt -> pt.isNotEmpty() } }
        if (h264Pts.isEmpty()) return sdp
        val parts = lines[mIdx].split(" ")
        if (parts.size < 4) return sdp
        // Reorder (H264 payload types first) rather than removing others, so the SDP stays valid;
        // MediaMTX negotiates the first offered video codec.
        val others = parts.drop(3).filterNot { it in h264Pts }
        lines[mIdx] = (parts.take(3) + h264Pts + others).joinToString(" ")
        return lines.joinToString(nl)
    }

    override fun stop() {
        runCatching { capturer?.stopCapture() }
        runCatching { capturer?.dispose() }
        runCatching { surfaceHelper?.dispose() }
        runCatching { videoSource?.dispose() }
        runCatching { audioSource?.dispose() }
        runCatching { peer?.close() }
        runCatching { peer?.dispose() }
        capturer = null; surfaceHelper = null; videoSource = null; audioSource = null; peer = null
        mediaHolder.localVideo.value = null
    }

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
