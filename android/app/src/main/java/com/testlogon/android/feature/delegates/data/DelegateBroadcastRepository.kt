package com.testlogon.android.feature.delegates.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.DelegatePermission
import com.testlogon.android.core.model.delegates.canControlBroadcast
import com.testlogon.android.core.model.delegates.canModerateBroadcast
import com.testlogon.android.core.network.delegates.DelegateBroadcastApi
import com.testlogon.android.core.network.delegates.DelegatedModerationIn
import com.testlogon.android.core.network.delegates.DelegatedScheduleSessionIn
import com.testlogon.android.core.network.error.ApiErrorParser
import retrofit2.HttpException
import retrofit2.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-360 - the delegate-PATH BROADCAST overlay repository (manage-as-creator broadcast).
 *
 * Every action: requires an active delegate context (else "not in delegate mode"); GATES on the typed
 * permission (PermissionDenied WITHOUT calling the API when absent); calls [DelegateBroadcastApi] with the
 * active creatorId (attribution = @Path); and AUTO-EXITS on a 403. start / stop / schedule are gated by
 * broadcast_control; mute / ban by broadcast_moderate (there is NO broadcast_operate / broadcast_publish).
 * The full broadcast console is owned by the broadcast epic; this is the overlay control + a representative
 * moderation pair.
 */
@Singleton
class DelegateBroadcastRepository @Inject constructor(
    private val api: DelegateBroadcastApi,
    private val contextProvider: DelegationContextProvider,
    delegationRepository: DelegationRepository,
    errorParser: ApiErrorParser,
) {

    private val guard = DelegateGuard(
        context = contextProvider::current,
        errorParser = errorParser,
        autoExit = DelegateAutoExit(contextProvider, delegationRepository),
    )

    /** True when the current context may START / STOP / SCHEDULE the creator's broadcasts (broadcast_control). */
    fun canControl(): Boolean = contextProvider.current().canControlBroadcast()

    /** True when the current context may MODERATE the creator's broadcast (broadcast_moderate). */
    fun canModerate(): Boolean = contextProvider.current().canModerateBroadcast()

    /** START a broadcast session. Gated by broadcast_control. */
    suspend fun startSession(sessionId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_CONTROL) { creatorId ->
            api.startSession(creatorId, sessionId).requireSuccess()
        }

    /** STOP a broadcast session. Gated by broadcast_control. */
    suspend fun stopSession(sessionId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_CONTROL) { creatorId ->
            api.stopSession(creatorId, sessionId).requireSuccess()
        }

    /** SCHEDULE a broadcast session. Gated by broadcast_control. */
    suspend fun scheduleSession(title: String?, scheduledAt: String?): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_CONTROL) { creatorId ->
            api.scheduleSession(
                creatorId,
                DelegatedScheduleSessionIn(title = title, scheduledAt = scheduledAt),
            ).requireSuccess()
        }

    /** MUTE a viewer. Gated by broadcast_moderate. */
    suspend fun muteViewer(sessionId: String, userId: String, reason: String? = null): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.muteViewer(creatorId, sessionId, DelegatedModerationIn(userId, reason)).requireSuccess()
        }

    /** BAN a viewer. Gated by broadcast_moderate. */
    suspend fun banViewer(sessionId: String, userId: String, reason: String? = null): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.banViewer(creatorId, sessionId, DelegatedModerationIn(userId, reason)).requireSuccess()
        }

    /** Maps a 2xx empty body to Unit; a non-2xx is folded into a Failure by the guard via HttpException. */
    private fun Response<Unit>.requireSuccess() {
        if (!isSuccessful) throw HttpException(this)
    }
}
