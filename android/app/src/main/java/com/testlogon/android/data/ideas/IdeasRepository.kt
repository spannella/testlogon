package com.testlogon.android.data.ideas

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Product-ideas data layer over [IdeasApi].
 *
 * loadIdeas() issues the idempotent GET ui/agents/ideas (first page) and maps to [IdeasPage];
 * submitIdea() POSTs the mutation (not auto-retried). Every call is wrapped in [ApiResult]
 * (CancellationException re-thrown, HTTP -> Failure, transport -> NetworkError). A last-known-good page
 * is held in memory so a failed refresh can fall back to a stale snapshot; [clear] empties it (logout
 * cleanup).
 */
interface IdeasRepository {

    suspend fun loadIdeas(): ApiResult<IdeasPage>

    suspend fun submitIdea(title: String, description: String): ApiResult<Unit>

    fun cached(): IdeasPage?

    fun clear()
}

@Singleton
class IdeasRepositoryImpl @Inject constructor(
    private val api: IdeasApi,
    private val errorParser: ApiErrorParser,
) : IdeasRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: IdeasPage? = null

    override suspend fun loadIdeas(): ApiResult<IdeasPage> = withContext(io) {
        call { api.listIdeas(limit = PAGE_SIZE).toDomain() }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun submitIdea(
        title: String,
        description: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.submitIdea(
                IdeaCreateReqDto(
                    title = title.trim(),
                    description = description.trim(),
                ),
            )
            Unit
        }
    }

    override fun cached(): IdeasPage? = snapshot

    override fun clear() {
        snapshot = null
    }

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
    }

    private companion object {
        private const val PAGE_SIZE = 50
    }
}
