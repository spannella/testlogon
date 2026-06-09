package com.testlogon.android.data.alerts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
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
 * AND-086 — email alert-target data layer over [EmailAlertApi].
 *
 * list returns the flat verified-address list; begin/confirm/remove drive the double opt-in and
 * each return the updated address list mapped from AlertPreferences.emails. All calls fold into
 * [ApiResult] and never throw (CancellationException re-thrown). Only the GET is conceptually
 * retry-eligible; the three POSTs are single-shot.
 */
interface EmailAlertRepository {
    suspend fun listEmails(): ApiResult<List<String>>
    suspend fun begin(email: String): ApiResult<AlertBeginResult>
    suspend fun confirm(challengeId: String, code: String): ApiResult<List<String>>
    suspend fun remove(email: String): ApiResult<List<String>>
}

@Singleton
class EmailAlertRepositoryImpl @Inject constructor(
    private val api: EmailAlertApi,
    private val errorParser: ApiErrorParser,
) : EmailAlertRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listEmails(): ApiResult<List<String>> = withContext(io) {
        apiCall { api.getEmailPrefs() }.map { it.emails }
    }

    override suspend fun begin(email: String): ApiResult<AlertBeginResult> = withContext(io) {
        apiCall { api.begin(EmailBeginRequest(email.trim())) }
            .map { AlertBeginResult(it.challengeId, it.sentTo) }
    }

    override suspend fun confirm(challengeId: String, code: String): ApiResult<List<String>> =
        withContext(io) {
            apiCall { api.confirm(EmailConfirmRequest(challengeId, code.trim())) }.map { it.emails }
        }

    override suspend fun remove(email: String): ApiResult<List<String>> = withContext(io) {
        apiCall { api.remove(EmailRemoveRequest(email)) }.map { it.emails }
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
}
