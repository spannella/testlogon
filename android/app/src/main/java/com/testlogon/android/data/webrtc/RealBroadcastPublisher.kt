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
    private val iceServersProvider: IceServersProvider,
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
    private var videoTrack: VideoTrack? = null

    /**
     * #7a — open the front camera and publish the local video track to [CallMediaHolder] WITHOUT
     * building a peer, so the host sees a real self-preview before tapping Go Live. Idempotent: if a
     * track is already running (preview or live) it is reused. Runs on the IO/default thread; capture
     * start is cheap and the WebRTC camera APIs are thread-safe for this usage.
     */
    override suspend fun startPreview() {
        if (videoTrack != null) {
            // Already previewing/publishing: make sure the holder points at the running track.
            mediaHolder.localVideo.value = videoTrack
            return
        }
        runCatching {
            val vTrack = startCamera()
            if (vTrack != null) {
                vTrack.setEnabled(true)
                mediaHolder.localVideo.value = vTrack
                // NB: leave _state at Idle — a preview is NOT a publish. Moving it to Starting would make
                // the Ingest VM fold to Negotiating and disable the "Go Live" button (#7a regression).
            }
        }.onFailure { Log.d("TLBCAST", "startPreview error ${it.javaClass.simpleName}") }
    }

    override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult {
        return try {
            _state.value = PublishState.Starting
            val gathered = CompletableDeferred<Unit>()
            // Phone -> public media server (MediaMTX on EC2) crosses NAT, so the offerer MUST gather a
            // server-reflexive (srflx) candidate or ICE can never connect over the internet. With an empty
            // ICE list the peer only gathers host (LAN) candidates -> publish silently fails off-LAN.
            // IceServersProvider never throws and falls back to Google STUN (TurnFetchConfig.stunOnlyFallback)
            // when the call-scoped TURN endpoint is unavailable for a broadcast session.
            val iceServers = iceServersProvider.current(sessionId).map { s ->
                PeerConnection.IceServer.builder(s.urls).apply {
                    s.username?.let { setUsername(it) }
                    s.credential?.let { setPassword(it) }
                }.createIceServer()
            }
            Log.d("TLBCAST", "ice servers=${iceServers.size}")
            val rtcConfig = PeerConnection.RTCConfiguration(iceServers).apply {
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

            // Reuse a preview that is already running (#7a) so we don't re-open the camera; otherwise
            // open it now. Either way the local track is published to the media holder for the preview.
            val vTrack = videoTrack ?: startCamera() ?: return fail("camera")
            vTrack.setEnabled(true)
            mediaHolder.localVideo.value = vTrack
            pc.addTrack(vTrack, listOf("bcast"))

            val offer = awaitCreate { pc.createOffer(it, MediaConstraints()) } ?: return fail("createOffer")
            val h264Offer = SessionDescription(offer.type, preferH264(offer.description))
            if (!awaitSet { pc.setLocalDescription(it, h264Offer) }) return fail("setLocal")
            // Non-trickle WHIP: publish the offer only after ICE gathering completes (bounded).
            withTimeoutOrNull(8000) { gathered.await() }
            val full = pc.localDescription ?: return fail("no local desc")

            when (val whip = postWhip(whipUrl(sessionId), full.description)) {
                is WhipResult.Answer -> {
                    if (!awaitSet {
                            pc.setRemoteDescription(it, SessionDescription(SessionDescription.Type.ANSWER, whip.sdp))
                        }
                    ) {
                        return fail(REASON_SET_REMOTE)
                    }
                }
                // Honest partial: the live-streaming media server (MediaMTX WHIP ingest, :8889) is not
                // deployed/reachable. The local camera + mic capture IS running (preview shows), but no
                // stream reaches viewers. We DELIBERATELY do NOT stop() here so the host keeps a real
                // local preview; the UI surfaces a clear "server not reachable" message.
                WhipResult.Unreachable -> return fail(REASON_SERVER_UNREACHABLE)
                is WhipResult.Rejected -> return fail(REASON_WHIP_REJECTED)
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

    /** Outcome of the WHIP ingest POST, distinguishing "no server" from "server said no". */
    private sealed interface WhipResult {
        /** The media server returned an SDP answer; publishing can proceed. */
        data class Answer(val sdp: String) : WhipResult
        /** The WHIP endpoint could not be reached at all (connect/IO failure -> server not deployed). */
        data object Unreachable : WhipResult
        /** The server was reached but rejected the offer (non-2xx / empty body). */
        data class Rejected(val code: Int) : WhipResult
    }

    private suspend fun postWhip(url: String, offerSdp: String): WhipResult = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url(url)
            .post(offerSdp.toRequestBody("application/sdp".toMediaType()))
            .build()
        try {
            whipClient.newCall(req).execute().use { resp ->
                Log.d("TLBCAST", "whip POST $url -> ${resp.code}")
                val body = resp.body?.string()
                if (resp.isSuccessful && !body.isNullOrBlank()) {
                    WhipResult.Answer(body)
                } else {
                    WhipResult.Rejected(resp.code)
                }
            }
        } catch (t: Throwable) {
            // Connect/IO failure: the WHIP ingest server (MediaMTX :8889) is not deployed/reachable.
            Log.d("TLBCAST", "whip unreachable ${t.javaClass.simpleName}")
            WhipResult.Unreachable
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
        val track = factory.createVideoTrack("bcast_video", source)
        videoTrack = track
        return track
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
        runCatching { videoTrack?.dispose() }
        capturer = null; surfaceHelper = null; videoSource = null; audioSource = null; peer = null; videoTrack = null
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

    companion object {
        /**
         * The WHIP ingest media server (MediaMTX, :8889) could not be reached. The host's local camera
         * preview keeps running, but the broadcast does not reach any viewer — the live-streaming
         * infrastructure is not deployed. The UI maps this to a clear, honest message.
         */
        const val REASON_SERVER_UNREACHABLE = "server_unreachable"
        const val REASON_WHIP_REJECTED = "whip_rejected"
        const val REASON_SET_REMOTE = "set_remote"
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
