package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.AccountStatus
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
 * AND-082 — account status data layer over [AccountStatusApi]. Read-only; this screen makes only
 * an authenticated GET and routes lifecycle mutations elsewhere (handoff).
 */
interface AccountStatusRepository {
    suspend fun getStatus(): ApiResult<AccountStatus>
}

@Singleton
class AccountStatusRepositoryImpl @Inject constructor(
    private val api: AccountStatusApi,
    private val errorParser: ApiErrorParser,
) : AccountStatusRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getStatus(): ApiResult<AccountStatus> = withContext(io) {
        try {
            ApiResult.Success(api.getStatus().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}
