package com.testlogon.android.data.messaging.helpdesk

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Qualifier
import javax.inject.Singleton

/** AND-161 — qualifier for the configured helpdesk group id (BuildConfig.HELPDESK_GROUP_ID). */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class HelpdeskGroupId

/**
 * AND-161 / AND-162 — data layer for the helpdesk queue + claim.
 *
 * `loadQueue` is a single bounded fetch (no paging). A 200 means the caller is an agent for the group;
 * a 403 is the not-an-agent signal, surfaced as [ApiResult.Failure] with status 403 (HTTP_FORBIDDEN),
 * which the ViewModel maps to a NotAuthorized state with no error toast. `claim` is a non-idempotent
 * POST (never auto-retried). CancellationException is always re-thrown. No helpdesk PII is logged.
 */
interface HelpdeskRepository {

    /** Fetch the queue (single bounded array). 403 -> Failure(status=403) = not-an-agent. */
    suspend fun loadQueue(state: String? = null, limit: Int = HelpdeskApi.DEFAULT_LIMIT): ApiResult<List<HelpdeskQueueItem>>

    /** Claim a queued conversation for the current agent. */
    suspend fun claim(conversationId: String): ApiResult<HelpdeskClaimResult>

    /** Re-fetch the queue and locate this conversation's current assignment (no single-conversation GET). */
    suspend fun refreshAssignment(conversationId: String): ApiResult<HelpdeskQueueItem?>
}

@Singleton
class HelpdeskRepositoryImpl @Inject constructor(
    private val api: HelpdeskApi,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
    @HelpdeskGroupId private val helpdeskGroupId: String,
) : HelpdeskRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadQueue(state: String?, limit: Int): ApiResult<List<HelpdeskQueueItem>> =
        withContext(io) {
            val me = authStateStore.userSub.value
            when (val r = apiCall { api.getQueue(groupId = helpdeskGroupId, state = state, limit = limit) }) {
                is ApiResult.Success ->
                    ApiResult.Success(r.data.map { it.toHelpdeskQueueItem(me) }.sortedForQueue())
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun claim(conversationId: String): ApiResult<HelpdeskClaimResult> = withContext(io) {
        val me = authStateStore.userSub.value
        when (val r = apiCall { api.claim(conversationId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.toResult(me))
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun refreshAssignment(conversationId: String): ApiResult<HelpdeskQueueItem?> =
        withContext(io) {
            when (val r = loadQueue()) {
                is ApiResult.Success ->
                    ApiResult.Success(r.data.firstOrNull { it.conversationId == conversationId })
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    companion object {
        const val HTTP_FORBIDDEN = 403
    }
}

/**
 * AND-161 — provides the configured helpdesk group id from BuildConfig (web: VITE_HELPDESK_GROUP_ID).
 * Swap to remote/per-user config when the production group-id scheme is finalized (OQ-5).
 */
@Module
@InstallIn(SingletonComponent::class)
object HelpdeskConfigModule {
    @Provides
    @HelpdeskGroupId
    @Singleton
    fun provideHelpdeskGroupId(): String = com.testlogon.android.BuildConfig.HELPDESK_GROUP_ID
}
