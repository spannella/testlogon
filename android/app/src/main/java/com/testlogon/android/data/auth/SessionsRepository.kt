package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-043 — active-sessions data layer over [AuthApi].
 *
 * `GET /ui/sessions` -> sorted list (current pinned, then last_seen_at desc);
 * `POST /ui/sessions/revoke {session_id}` and `POST /ui/sessions/revoke_others` for revocation.
 * The current session is resolved primarily by the row's `is_current`, with a defensive fallback
 * matching against [AuthStateStore.userSub]-correlated [getMe] session id.
 */
interface SessionsRepository {
    suspend fun listSessions(): ApiResult<List<SessionInfo>>
    suspend fun revoke(sessionId: String): ApiResult<Unit>
    suspend fun revokeOthers(): ApiResult<Unit>

    /** Current session id from the in-memory principal (getMe), or null if unknown. */
    fun currentSessionId(): String?

    /** AND-045 — last-known-good sessions snapshot for offline/stale rendering, or null. */
    fun cachedSessions(): List<SessionInfo>?
}

@Singleton
class SessionsRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authRepository: AuthRepository,
    private val errorParser: ApiErrorParser,
    private val cache: AuthAreaCache,
) : SessionsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listSessions(): ApiResult<List<SessionInfo>> =
        apiCall { api.listSessions().sessions }.let { result ->
            when (result) {
                is ApiResult.Success -> {
                    val sorted = sortRows(result.data)
                    cache.putSessions(sorted)
                    ApiResult.Success(sorted)
                }
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override fun cachedSessions(): List<SessionInfo>? = cache.sessions

    override suspend fun revoke(sessionId: String): ApiResult<Unit> =
        apiCall { api.revokeSession(RevokeSessionReq(sessionId)) }.toUnit()

    override suspend fun revokeOthers(): ApiResult<Unit> =
        apiCall { api.revokeOtherSessions() }.toUnit()

    override fun currentSessionId(): String? = authRepository.cachedUser.value?.sessionId

    /** Current row pinned to top; the rest by last_seen_at desc. */
    private fun sortRows(rows: List<SessionInfo>): List<SessionInfo> {
        val currentId = currentSessionId()
        return rows.sortedWith(
            compareByDescending<SessionInfo> { it.isCurrent || it.sessionId == currentId }
                .thenByDescending { it.lastSeenAt },
        )
    }

    private fun ApiResult<StatusResp>.toUnit(): ApiResult<Unit> = when (this) {
        is ApiResult.Success -> ApiResult.Success(Unit)
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is java.net.SocketTimeoutException)
        }
    }
}
