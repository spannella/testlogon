package com.testlogon.android.data.appeals

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
 * Appeals data layer over [AppealsApi].
 *
 * loadAppeals() issues the idempotent GET v1/appeals (first page) and maps to [AppealsPage];
 * submitAppeal()/withdrawAppeal() POST the mutations (not auto-retried). Every call is wrapped in
 * [ApiResult] (CancellationException re-thrown, HTTP -> Failure, transport -> NetworkError). A
 * last-known-good page is held in memory so a failed refresh can fall back to a stale snapshot;
 * [clear] empties it (logout cleanup).
 */
interface AppealsRepository {

    suspend fun loadAppeals(): ApiResult<AppealsPage>

    suspend fun loadEnforcementOptions(): ApiResult<List<EnforcementOption>>

    suspend fun submitAppeal(enforcementId: String, appealText: String): ApiResult<Unit>

    suspend fun withdrawAppeal(appealId: String): ApiResult<Unit>

    fun cached(): AppealsPage?

    fun clear()
}

@Singleton
class AppealsRepositoryImpl @Inject constructor(
    private val api: AppealsApi,
    private val errorParser: ApiErrorParser,
) : AppealsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: AppealsPage? = null

    override suspend fun loadAppeals(): ApiResult<AppealsPage> = withContext(io) {
        call { api.listMyAppeals(limit = PAGE_SIZE).toDomain() }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun loadEnforcementOptions(): ApiResult<List<EnforcementOption>> = withContext(io) {
        call { api.getEnforcementOptions().toDomain() }
    }

    override suspend fun submitAppeal(
        enforcementId: String,
        appealText: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.submitAppeal(
                AppealCreateReqDto(
                    enforcementId = enforcementId.trim(),
                    appealText = appealText.trim(),
                ),
            )
            Unit
        }
    }

    override suspend fun withdrawAppeal(appealId: String): ApiResult<Unit> = withContext(io) {
        call { api.withdrawAppeal(appealId); Unit }
    }

    override fun cached(): AppealsPage? = snapshot

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
