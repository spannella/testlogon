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
 * AND-087 — SMS alert-target data layer over [SmsAlertApi].
 *
 * Mirrors the email repository: list returns AlertPreferences.sms_numbers; begin/confirm/remove
 * drive the begin->confirm double opt-in keyed by challenge_id (confirm) and phone (remove). Phone
 * input is normalized to a leading "+" plus digits before submission ([normalizePhone]); resend is
 * literally a second begin (no /resend endpoint exists). All calls fold into [ApiResult].
 */
interface SmsAlertRepository {
    suspend fun listNumbers(): ApiResult<List<String>>
    suspend fun begin(rawPhone: String): ApiResult<AlertBeginResult>
    suspend fun confirm(challengeId: String, code: String): ApiResult<List<String>>
    suspend fun resend(rawPhone: String): ApiResult<AlertBeginResult> = begin(rawPhone)
    suspend fun remove(phone: String): ApiResult<List<String>>
}

/** Strips whitespace/dashes/parens; keeps a single leading "+" and digits. Region-agnostic. */
fun normalizePhone(raw: String): String {
    val trimmed = raw.trim()
    val hasPlus = trimmed.startsWith("+")
    val digits = trimmed.filter { it.isDigit() }
    return if (hasPlus) "+$digits" else digits
}

@Singleton
class SmsAlertRepositoryImpl @Inject constructor(
    private val api: SmsAlertApi,
    private val errorParser: ApiErrorParser,
) : SmsAlertRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listNumbers(): ApiResult<List<String>> = withContext(io) {
        apiCall { api.getSmsPrefs() }.map { it.smsNumbers }
    }

    override suspend fun begin(rawPhone: String): ApiResult<AlertBeginResult> = withContext(io) {
        apiCall { api.begin(SmsBeginRequest(normalizePhone(rawPhone))) }
            .map { AlertBeginResult(it.challengeId, it.sentTo) }
    }

    override suspend fun confirm(challengeId: String, code: String): ApiResult<List<String>> =
        withContext(io) {
            apiCall { api.confirm(SmsConfirmRequest(challengeId, code.trim())) }.map { it.smsNumbers }
        }

    override suspend fun remove(phone: String): ApiResult<List<String>> = withContext(io) {
        apiCall { api.remove(SmsRemoveRequest(phone)) }.map { it.smsNumbers }
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
