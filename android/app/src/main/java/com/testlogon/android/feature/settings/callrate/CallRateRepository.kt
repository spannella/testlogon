package com.testlogon.android.feature.settings.callrate

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.callrate.CallRateApi
import com.testlogon.android.core.network.callrate.CallRateDto
import com.testlogon.android.core.network.callrate.CallRateInDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.feed.CurrentUserRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the creator paid-calls rate settings over [CallRateApi]. Mirrors the web CallRateSettings page:
 * read the caller's own rate (404 -> not configured), and set/update/delete it.
 *
 * The GET is keyed by creator_id; for the "own rate" view the web passes the signed-in user's id, so the repo
 * resolves the caller's user_sub via the shared [CurrentUserRepository] (GET /ui/me, cached) before reading.
 */
interface CallRateRepository {

    /** GET the caller's own rate. Returns Success(null) when no rate is configured yet (backend 404). */
    suspend fun getOwnRate(): ApiResult<CallRate?>

    /** POST (create) or PUT (update) the caller's own rate. [update]=true uses PUT. */
    suspend fun saveRate(rate: CallRate, update: Boolean): ApiResult<CallRate>

    /** DELETE the caller's rate (disable paid calls). */
    suspend fun deleteRate(): ApiResult<Unit>
}

@Singleton
class DefaultCallRateRepository @Inject constructor(
    private val api: CallRateApi,
    private val currentUser: CurrentUserRepository,
    private val errorParser: ApiErrorParser,
) : CallRateRepository {

    override suspend fun getOwnRate(): ApiResult<CallRate?> =
        withContext(Dispatchers.IO) {
            when (val idResult = currentUser.currentUserSub()) {
                is ApiResult.Success -> call {
                    try {
                        api.getRate(idResult.data).toDomain()
                    } catch (e: HttpException) {
                        if (e.code() == HTTP_NOT_FOUND) null else throw e
                    }
                }
                is ApiResult.Failure -> idResult
                is ApiResult.NetworkError -> idResult
            }
        }

    override suspend fun saveRate(rate: CallRate, update: Boolean): ApiResult<CallRate> =
        withContext(Dispatchers.IO) {
            call {
                val body = CallRateInDto(
                    rateCentsPerMinute = rate.rateCentsPerMinute,
                    enabled = rate.enabled,
                    minBalanceMinutes = rate.minBalanceMinutes,
                    maxDurationMinutes = rate.maxDurationMinutes,
                )
                val dto = if (update) api.updateRate(body) else api.setRate(body)
                dto.toDomain()
            }
        }

    override suspend fun deleteRate(): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.deleteRate() } }

    private fun CallRateDto.toDomain(): CallRate = CallRate(
        rateCentsPerMinute = rateCentsPerMinute,
        enabled = enabled,
        currency = currency,
        minBalanceMinutes = minBalanceMinutes,
        maxDurationMinutes = maxDurationMinutes,
    )

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_NOT_FOUND = 404
    }
}
