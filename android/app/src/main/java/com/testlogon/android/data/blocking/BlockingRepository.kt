package com.testlogon.android.data.blocking

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockRelationship
import com.testlogon.android.core.model.blocking.BlockedUser
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-382 - block / unblock data layer over [BlockApi].
 *
 * Holds the session's blocked-by-me user-id set in an in-memory [StateFlow] so feature ViewModels can
 * combine it with their content flows and suppress blocked-authored items client-side WITHOUT
 * re-fetching or invalidating Room/Paging caches (spec sec.6). The set is seeded by [refreshBlockList]
 * and updated OPTIMISTICALLY on block/unblock with rollback on failure (spec sec.4.3).
 *
 * Mutations (block/unblock) are non-idempotent POSTs and are NEVER auto-retried; only the GET reads
 * are retry-eligible (handled by callers). Any 200 from block/unblock maps to Success regardless of
 * the status string (FR-6 idempotency; citation audit sec.16 #16). 401 refresh-and-retry is handled
 * transparently by the AND-027 SessionAuthenticator on the shared OkHttp client.
 */
interface BlockingRepository {

    /** Reactive set of user ids the current user has blocked (best-effort session cache). */
    val blockedUserIds: StateFlow<Set<String>>

    /** Optimistically block [userId]; reconciles on success, reverts on failure. */
    suspend fun block(userId: String): ApiResult<Unit>

    /** Optimistically unblock [userId]; reconciles on success, reverts on failure. */
    suspend fun unblock(userId: String): ApiResult<Unit>

    /** Idempotent GET of the full blocked list; hydrates [blockedUserIds] on success. */
    suspend fun refreshBlockList(): ApiResult<List<BlockedUser>>

    /** Idempotent GET of the per-user relationship (both directions). */
    suspend fun blockStatus(userId: String): ApiResult<BlockRelationship>

    /** True if [userId] is in the local blocked-by-me set (synchronous, cache-only). */
    fun isBlocked(userId: String): Boolean

    /** Logout cleanup: empties the in-memory blocked set. */
    fun clear()
}

@Singleton
class BlockingRepositoryImpl @Inject constructor(
    private val api: BlockApi,
    private val errorParser: ApiErrorParser,
) : BlockingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val _blockedUserIds = MutableStateFlow<Set<String>>(emptySet())
    override val blockedUserIds: StateFlow<Set<String>> = _blockedUserIds.asStateFlow()

    override fun isBlocked(userId: String): Boolean = userId in _blockedUserIds.value

    override suspend fun block(userId: String): ApiResult<Unit> = withContext(io) {
        val alreadyBlocked = userId in _blockedUserIds.value
        // Optimistic add (no-op if already present, so idempotent re-block doesn't disturb the set).
        _blockedUserIds.update { it + userId }
        val result = call { unitFrom(api.block(BlockRequestDto(targetUserId = userId))) }
        if (result !is ApiResult.Success && !alreadyBlocked) {
            // Roll back only the change we introduced.
            _blockedUserIds.update { it - userId }
        }
        result
    }

    override suspend fun unblock(userId: String): ApiResult<Unit> = withContext(io) {
        val wasBlocked = userId in _blockedUserIds.value
        // Optimistic remove.
        _blockedUserIds.update { it - userId }
        val result = call { unitFrom(api.unblock(UnblockRequestDto(targetUserId = userId))) }
        if (result !is ApiResult.Success && wasBlocked) {
            // Restore on failure.
            _blockedUserIds.update { it + userId }
        }
        result
    }

    override suspend fun refreshBlockList(): ApiResult<List<BlockedUser>> = withContext(io) {
        call {
            val dto = bodyFrom(api.listBlocks())
            val domain = dto.blockedUsers.map { it.toDomain() }
            _blockedUserIds.value = domain.map { it.userId }.toSet()
            domain
        }
    }

    override suspend fun blockStatus(userId: String): ApiResult<BlockRelationship> = withContext(io) {
        call {
            val relationship = bodyFrom(api.blockStatus(userId)).toRelationship()
            // Keep the local set coherent with the freshly-read blocked-by-me direction.
            if (relationship == BlockRelationship.BlockedByMe) {
                _blockedUserIds.update { it + userId }
            } else {
                _blockedUserIds.update { it - userId }
            }
            relationship
        }
    }

    override fun clear() {
        _blockedUserIds.value = emptySet()
    }

    // ---- helpers ----

    /** Any 2xx -> Unit (idempotency: do not branch on the BlockActionResponse status). */
    private fun unitFrom(response: Response<*>) {
        if (!response.isSuccessful) throw HttpException(response)
    }

    /** Unwrap a 2xx body or throw HttpException so the call{} wrapper maps it to Failure. */
    private fun <T> bodyFrom(response: Response<T>): T {
        if (!response.isSuccessful) throw HttpException(response)
        return requireNotNull(response.body()) { "Empty body on a 2xx response" }
    }

    /**
     * Shared call wrapper: CancellationException re-thrown; HttpException + JsonDataException ->
     * Failure (parsed via the shared FastAPI detail mapper); transport IOException -> NetworkError.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    } catch (e: IllegalArgumentException) {
        // Empty-body-on-2xx guard -> treat as a parse failure rather than crashing.
        ApiResult.Failure(ApiError(status = ApiError.STATUS_PARSE, message = "Malformed response", raw = e.message))
    }
}
