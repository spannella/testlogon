package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.PublishState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-317 — presentation SEAM over the FLAGGED [BroadcastPublisher] (AND-288/308) so AND-318 can fake the
 * ingest with a settable status flow. It REUSES the publisher (no real WebRTC here) and maps its
 * [PublishState] to a client [IngestStatus]:
 *  - NotConfigured / Unavailable -> [IngestStatus.Unavailable]
 *  - Live -> [IngestStatus.Connected]
 *  - Starting -> [IngestStatus.Connecting]
 *  - Failed -> [IngestStatus.Failed]
 *  - Idle -> [IngestStatus.Idle]
 *
 * The publisher exposes only [PublishState] (there is no Connected/NotConfigured state on the enum); Live is
 * the publisher's "media up" state, mapped to Connected. Because the stub stays Unavailable, [open] resolves
 * to Unavailable in practice — the FSM/VM logic over this seam is the deliverable, not real media.
 */
interface WebRtcIngestController {

    /** Hot, mapped ingest status (the VM collects this and dispatches IngestStatusChanged). */
    val status: StateFlow<IngestStatus>

    /** Begin publishing for [sessionId]. Maps to [BroadcastPublisher.goLive]. */
    suspend fun open(sessionId: String)

    /** Stop publishing / release. Idempotent. Maps to [BroadcastPublisher.stop]. */
    fun close()
}

@Singleton
class DefaultWebRtcIngestController @Inject constructor(
    private val publisher: BroadcastPublisher,
    @AppScope scope: CoroutineScope,
) : WebRtcIngestController {

    override val status: StateFlow<IngestStatus> = publisher.state
        .map { it.toIngestStatus() }
        .stateIn(
            scope = scope,
            started = SharingStarted.Eagerly,
            initialValue = publisher.state.value.toIngestStatus(),
        )

    override suspend fun open(sessionId: String) {
        // AND-308 ingest input allocation is the host control plane's concern; the FLAGGED publisher's
        // go-live takes the session + (would-be) input id. We pass the sessionId for both — the stub never
        // opens a camera/mic and always resolves NotConfigured (-> Unavailable via the state flow).
        publisher.goLive(sessionId = sessionId, inputId = sessionId)
    }

    override fun close() {
        publisher.stop()
    }
}

/** Maps the FLAGGED publisher [PublishState] to the client [IngestStatus]. */
internal fun PublishState.toIngestStatus(): IngestStatus = when (this) {
    PublishState.Idle -> IngestStatus.Idle
    PublishState.Starting -> IngestStatus.Connecting
    PublishState.Live -> IngestStatus.Connected
    is PublishState.Failed -> IngestStatus.Failed
    PublishState.Unavailable -> IngestStatus.Unavailable
}
