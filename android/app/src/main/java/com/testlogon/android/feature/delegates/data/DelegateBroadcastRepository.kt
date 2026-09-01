package com.testlogon.android.feature.delegates.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.DelegatePermission
import com.testlogon.android.core.model.delegates.canControlBroadcast
import com.testlogon.android.core.model.delegates.canModerateBroadcast
import com.testlogon.android.core.network.delegates.DelegateBroadcastApi
import com.testlogon.android.core.network.delegates.DelegatedAnnouncementIn
import com.testlogon.android.core.network.delegates.DelegatedBroadcastBanOut
import com.testlogon.android.core.network.delegates.DelegatedBroadcastModLogEntry
import com.testlogon.android.core.network.delegates.DelegatedBroadcastModeratorOut
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
 * broadcast_control; every moderation action (mute / ban / unban / pin / unpin / delete-chat / announce /
 * moderator-register) AND the moderation READS (moderators / bans / log) by broadcast_moderate (there is
 * NO broadcast_operate / broadcast_publish). Mirrors the web delegateBroadcast.ts surface 1:1.
 *
 * DEGRADE-ON-404: the READS ([moderators] / [bans] / [moderationLog]) fold a 404 (session gone / not yet
 * live on this edge) into an honest EMPTY list rather than an error - a read must never wall the console.
 * MUTATIONS never soften 404; a failed action surfaces as a Failure so the UI can notify.
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

    // ---- Broadcast control (broadcast_control) ----

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

    // ---- Chat moderation mutations (broadcast_moderate) ----

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

    /** UNBAN a viewer. Gated by broadcast_moderate. */
    suspend fun unbanViewer(sessionId: String, userId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.unbanViewer(creatorId, sessionId, userId).requireSuccess()
        }

    /** POST an announcement into broadcast chat. Gated by broadcast_moderate. */
    suspend fun postAnnouncement(sessionId: String, text: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.postAnnouncement(creatorId, sessionId, DelegatedAnnouncementIn(text)).requireSuccess()
        }

    /** PIN a chat message. Gated by broadcast_moderate. */
    suspend fun pinMessage(sessionId: String, messageId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.pinMessage(creatorId, sessionId, messageId).requireSuccess()
        }

    /** UNPIN a chat message. Gated by broadcast_moderate. */
    suspend fun unpinMessage(sessionId: String, messageId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.unpinMessage(creatorId, sessionId, messageId).requireSuccess()
        }

    /** DELETE a chat message. Gated by broadcast_moderate. */
    suspend fun deleteChatMessage(sessionId: String, messageId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.deleteChatMessage(creatorId, sessionId, messageId).requireSuccess()
        }

    // ---- Moderator management (broadcast_moderate) ----

    /** REGISTER the caller as an active moderator for this session. Gated by broadcast_moderate. */
    suspend fun registerModerator(sessionId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.registerModerator(creatorId, sessionId).requireSuccess()
        }

    // ---- Moderation reads (broadcast_moderate; DEGRADE-ON-404 to honest empty) ----

    /** LIST active moderators (BARE ARRAY). Gated by broadcast_moderate. 404 -> honest empty. */
    suspend fun moderators(sessionId: String): ApiResult<List<DelegatedBroadcastModeratorOut>> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.listModerators(creatorId, sessionId)
        }.emptyOn404()

    /** LIST banned viewers (BARE ARRAY). Gated by broadcast_moderate. 404 -> honest empty. */
    suspend fun bans(sessionId: String): ApiResult<List<DelegatedBroadcastBanOut>> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.listBans(creatorId, sessionId)
        }.emptyOn404()

    /** GET the moderation log (BARE ARRAY). Gated by broadcast_moderate. 404 -> honest empty. */
    suspend fun moderationLog(
        sessionId: String,
        limit: Int = 100,
    ): ApiResult<List<DelegatedBroadcastModLogEntry>> =
        guard.gated(DelegatePermission.BROADCAST_MODERATE) { creatorId ->
            api.getModerationLog(creatorId, sessionId, limit)
        }.emptyOn404()

    /** Maps a 2xx empty body to Unit; a non-2xx is folded into a Failure by the guard via HttpException. */
    private fun Response<Unit>.requireSuccess() {
        if (!isSuccessful) throw HttpException(this)
    }

    /**
     * DEGRADE-ON-404: a read whose Failure is a 404 (session gone / feed not live on this edge) becomes an
     * honest EMPTY list rather than an error, so a read never walls the console. Any other Failure /
     * NetworkError passes through unchanged (a permission-denied 403 still surfaces + auto-exits).
     */
    private fun <T> ApiResult<List<T>>.emptyOn404(): ApiResult<List<T>> =
        if (this is ApiResult.Failure && error.status == 404) ApiResult.Success(emptyList()) else this
}
