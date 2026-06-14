package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.HostControlRepository
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-317 — thin presentation-layer SEAM over the EXISTING host data repositories so AND-318 can fake the
 * control plane without touching [HostControlRepository] / [BroadcastRepository] (and their existing fakes).
 *
 * It defines NO new endpoints: every [control] action delegates to a real call —
 *  - Start / Stop / Resume / Reschedule -> [HostControlRepository] (AND-309)
 *  - Schedule / CancelSchedule -> [BroadcastRepository] (AND-307)
 *  - [loadSession] -> [HostControlRepository.session] (re-sync after a failed action)
 *  - [create] -> [BroadcastRepository.create]
 *
 * Reschedule converts the [Instant] to epoch SECONDS (the wire contract used by both repos).
 */
interface BroadcastHostRepository {

    suspend fun loadSession(id: String): ApiResult<BroadcastSession>

    suspend fun control(
        action: ControlAction,
        sessionId: String,
        draft: SessionDraft? = null,
        startsAt: Instant? = null,
    ): ApiResult<BroadcastSession>

    suspend fun create(profileId: String): ApiResult<BroadcastSession>
}

@Singleton
class DefaultBroadcastHostRepository @Inject constructor(
    private val hostControl: HostControlRepository,
    private val broadcast: BroadcastRepository,
) : BroadcastHostRepository {

    override suspend fun loadSession(id: String): ApiResult<BroadcastSession> =
        hostControl.session(id)

    override suspend fun control(
        action: ControlAction,
        sessionId: String,
        draft: SessionDraft?,
        startsAt: Instant?,
    ): ApiResult<BroadcastSession> = when (action) {
        ControlAction.Start -> hostControl.start(sessionId)
        ControlAction.Stop -> hostControl.stop(sessionId)
        ControlAction.Resume -> hostControl.resume(sessionId)
        ControlAction.Reschedule -> hostControl.reschedule(
            sessionId = sessionId,
            scheduledAtEpochSeconds = epochSecondsOf(startsAt ?: draft?.scheduledAt),
        )
        ControlAction.Schedule -> broadcast.schedule(
            sessionId = sessionId,
            scheduledAtEpochSeconds = epochSecondsOf(startsAt ?: draft?.scheduledAt),
            name = draft?.name,
            description = null,
        )
        ControlAction.CancelSchedule -> broadcast.cancelSchedule(sessionId)
    }

    override suspend fun create(profileId: String): ApiResult<BroadcastSession> =
        broadcast.create(profileId)

    private fun epochSecondsOf(instant: Instant?): Long = (instant ?: Instant.EPOCH).epochSecond
}
