package com.testlogon.android.feature.agents.llmkeys.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.CreateLlmKeyRequest
import com.testlogon.android.core.network.agents.LlmKeysApi
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AGENTS-BASICS (web-parity) - data layer for the LLM provider KEYS surface over [LlmKeysApi].
 *
 * [list] folds the {keys:[...]} envelope. [create]/[delete] are NON-idempotent mutations (no auto-retry).
 * [test] triggers a server-side provider probe. Same [call] fold as the B-APIKEY repository.
 */
interface LlmKeysRepository {
    suspend fun list(): ApiResult<List<LlmKey>>
    suspend fun providers(): ApiResult<List<LlmProvider>>
    suspend fun create(request: CreateLlmKeyRequest): ApiResult<LlmKey>
    suspend fun delete(keyId: String): ApiResult<Unit>
    suspend fun test(keyId: String): ApiResult<LlmKeyTestResult>
}

@Singleton
class DefaultLlmKeysRepository @Inject constructor(
    private val api: LlmKeysApi,
    private val errorParser: ApiErrorParser,
) : LlmKeysRepository {

    override suspend fun list(): ApiResult<List<LlmKey>> =
        withContext(Dispatchers.IO) { call { api.list().keys.map { it.toDomain() } } }

    override suspend fun providers(): ApiResult<List<LlmProvider>> =
        withContext(Dispatchers.IO) { call { api.providers().providers.map { it.toDomain() } } }

    override suspend fun create(request: CreateLlmKeyRequest): ApiResult<LlmKey> =
        withContext(Dispatchers.IO) { call { api.create(request).toDomain() } }

    override suspend fun delete(keyId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.delete(keyId) } }

    override suspend fun test(keyId: String): ApiResult<LlmKeyTestResult> =
        withContext(Dispatchers.IO) { call { api.test(keyId).toDomain() } }

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
}
