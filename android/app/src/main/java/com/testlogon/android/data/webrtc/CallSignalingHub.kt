package com.testlogon.android.data.webrtc

import android.util.Log
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.feature.call.domain.ActiveCall
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallPhase
import com.testlogon.android.feature.call.incoming.CallPushHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Real WebRTC call signaling + media orchestrator.
 *
 * Inbound call/webrtc events are delivered two ways and de-duplicated by event id: (1) a reliable POLL
 * of `GET messaging/events/poll` over the normal authenticated client (the long-lived SSE stream auth is
 * unreliable on this backend), and (2) the SSE stream as a fast-path bonus. Each fresh event is routed:
 *  - `call.*` -> [CallPushHandler] (rings the callee + feeds accept/terminal to [CallManager]) — how a
 *    call is delivered WITHOUT FCM.
 *  - `webrtc.offer|answer|ice_candidate` -> the per-call media negotiation.
 *
 * Media is driven by observing [CallManager.state]: at [CallPhase.Connecting] it negotiates for
 * [ActiveCall.role] (OFFERER creates+sends the offer; ANSWERER answers the inbound offer), trickles ICE,
 * and calls [CallManager.onConnected] when the peer connects. Outbound signals POST via [SignalingApi].
 */
@Singleton
class CallSignalingHub @Inject constructor(
    private val eventStream: MessagingEventStream,
    private val callPushHandler: CallPushHandler,
    private val callManager: CallManager,
    private val peer: PeerConnectionController,
    private val iceServers: IceServersProvider,
    private val signalingApi: SignalingApi,
    private val scope: CoroutineScope,
) {

    private val inbound = MutableSharedFlow<MessagingEvent.CallSignal>(
        replay = 0,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    private val seen = java.util.Collections.synchronizedSet(LinkedHashSet<String>())
    private var started = false
    private var negotiationJob: Job? = null
    private var negotiatingCallId: String? = null

    @Synchronized
    fun start() {
        if (started) return
        started = true
        Log.d("TLHUB", "start: poll + SSE for call signaling")
        scope.launch { pollLoop() }
        scope.launch { collectSse() }
        scope.launch { observeCallState() }
    }

    /** Reliable inbound delivery: short authenticated GETs (the SSE stream auth is unreliable here). */
    private suspend fun pollLoop() {
        var primed = false
        while (true) {
            try {
                val resp = signalingApi.pollEvents(limit = 100)
                val fresh = resp.events.filter { it.eventId != null && seen.add(it.eventId!!) }
                if (!primed) {
                    primed = true // first successful poll: ignore the pre-existing backlog (stale calls)
                    Log.d("TLHUB", "poll primed, ignored backlog=${fresh.size}")
                } else {
                    fresh.forEach { ev ->
                        val type = ev.type ?: return@forEach
                        if (type.startsWith("call.") || type.startsWith("webrtc.")) {
                            Log.d("TLHUB", "poll inbound type=$type call=${ev.callId}")
                            processSignal(type, ev.callId ?: return@forEach, ev.conversationId ?: "", ev.senderId, ev.payload?.toMap() ?: emptyMap())
                        }
                    }
                }
            } catch (t: Throwable) {
                Log.d("TLHUB", "poll error: ${t.javaClass.simpleName}")
            }
            delay(1200)
        }
    }

    private suspend fun collectSse() {
        while (true) {
            try {
                eventStream.events().collect { streamEvent ->
                    val event = (streamEvent as? MessagingStreamEvent.Event)?.event ?: return@collect
                    if (event !is MessagingEvent.CallSignal) return@collect
                    if (event.eventIdOrType().let { !seen.add(it) }) return@collect
                    Log.d("TLHUB", "sse inbound type=${event.type} call=${event.callId}")
                    processSignal(event.type, event.callId, event.conversationId, event.senderId, event.payload)
                }
            } catch (_: Throwable) {
            }
            delay(2000)
        }
    }

    private fun processSignal(
        type: String,
        callId: String,
        conversationId: String,
        senderId: String?,
        payload: Map<String, Any?>,
    ) {
        when {
            type.startsWith("call.") -> {
                val map = buildMap {
                    put("type", type)
                    put("call_id", callId)
                    put("conversation_id", conversationId)
                    senderId?.let { put("caller_user_id", it) }
                    (payload["caller_name"] as? String)?.takeIf { it.isNotBlank() }?.let { put("caller_name", it) }
                    ((payload["initial_mode"] ?: payload["mode"] ?: payload["accepted_mode"]) as? String)?.let { put("initial_mode", it) }
                }
                val handled = callPushHandler.tryHandle(map)
                Log.d("TLHUB", "call event $type handled=$handled map=$map")
            }
            type.startsWith("webrtc.") ->
                inbound.tryEmit(MessagingEvent.CallSignal(type, callId, conversationId, senderId, payload))
        }
    }

    private suspend fun observeCallState() {
        callManager.state.collect { st ->
            val call = st.call
            if (st.phase is CallPhase.Connecting && call != null && negotiatingCallId != call.callId) {
                negotiatingCallId = call.callId
                negotiationJob?.cancel()
                Log.d("TLHUB", "start negotiation role=${call.role} call=${call.callId}")
                negotiationJob = scope.launch { negotiate(call) }
            } else if (st.phase.isTerminal || st.phase == CallPhase.Idle) {
                negotiationJob?.cancel()
                negotiationJob = null
                negotiatingCallId = null
            }
        }
    }

    private suspend fun negotiate(call: ActiveCall) = coroutineScope {
        val servers = iceServers.current(call.callId)
        val init = peer.init(
            PeerConfig(
                iceServers = servers,
                role = call.role,
                enableAudio = true,
                enableVideo = call.mode == com.testlogon.android.data.call.CallMode.VIDEO,
                relayOnly = com.testlogon.android.BuildConfig.WEBRTC_FORCE_RELAY,
            ),
        )
        if (init !is PeerResult.Ok) return@coroutineScope

        launch {
            peer.localIceCandidates.collect { ice ->
                send(
                    call, "webrtc.ice_candidate",
                    mapOf("candidate" to ice.candidate, "sdp_mid" to ice.sdpMid, "sdp_mline_index" to ice.sdpMLineIndex),
                )
            }
        }
        launch {
            peer.lifecycle.collect { lc ->
                Log.d("TLHUB", "negotiate lifecycle=$lc call=${call.callId}")
                if (lc is PeerLifecycle.Connected) callManager.onConnected()
            }
        }
        launch {
            inbound.filter { it.callId == call.callId }.collect { sig ->
                when (sig.type) {
                    "webrtc.offer" -> {
                        val sdp = sig.payload["sdp"] as? String ?: return@collect
                        peer.setRemoteDescription(SdpDescription(SdpType.OFFER, sdp))
                        when (val ans = peer.createAnswer()) {
                            is PeerResult.Ok -> send(call, "webrtc.answer", mapOf("sdp" to ans.value.sdp, "sdp_type" to "answer"))
                            else -> Unit
                        }
                    }
                    "webrtc.answer" -> {
                        val sdp = sig.payload["sdp"] as? String ?: return@collect
                        peer.setRemoteDescription(SdpDescription(SdpType.ANSWER, sdp))
                    }
                    "webrtc.ice_candidate" -> {
                        val cand = sig.payload["candidate"] as? String ?: return@collect
                        peer.addIceCandidate(
                            IceCandidate(
                                sdpMid = sig.payload["sdp_mid"] as? String,
                                sdpMLineIndex = (sig.payload["sdp_mline_index"] as? Number)?.toInt() ?: 0,
                                candidate = cand,
                            ),
                        )
                    }
                }
            }
        }
        if (call.role == PeerRole.OFFERER) {
            when (val offer = peer.createOffer()) {
                is PeerResult.Ok -> send(call, "webrtc.offer", mapOf("sdp" to offer.value.sdp, "sdp_type" to "offer"))
                else -> Unit
            }
        }
    }

    private suspend fun send(call: ActiveCall, type: String, payload: Map<String, Any?>) {
        Log.d("TLHUB", "send $type call=${call.callId} -> ${call.peerUserId}")
        runCatching {
            signalingApi.sendCallSignal(
                callId = call.callId,
                body = CallSignalingInDto(
                    type = type,
                    eventId = UUID.randomUUID().toString(),
                    conversationId = call.conversationId,
                    recipientUserId = call.peerUserId,
                    nonce = UUID.randomUUID().toString(),
                    sentAt = System.currentTimeMillis() / 1_000L,
                    payload = payload,
                ),
            )
        }.onFailure { Log.d("TLHUB", "send $type failed: ${it.javaClass.simpleName}") }
    }
}

private fun MessagingEvent.CallSignal.eventIdOrType(): String = "$type:$callId:${payload.hashCode()}"

private fun SignalPayloadDto.toMap(): Map<String, Any?> = buildMap {
    sdp?.let { put("sdp", it) }
    sdpType?.let { put("sdp_type", it) }
    candidate?.let { put("candidate", it) }
    sdpMid?.let { put("sdp_mid", it) }
    sdpMlineIndex?.let { put("sdp_mline_index", it) }
    mode?.let { put("mode", it) }
    acceptedMode?.let { put("accepted_mode", it) }
    initialMode?.let { put("initial_mode", it) }
    callerName?.let { put("caller_name", it) }
}
