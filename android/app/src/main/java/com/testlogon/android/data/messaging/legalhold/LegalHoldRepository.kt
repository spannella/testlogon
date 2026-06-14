package com.testlogon.android.data.messaging.legalhold

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-164 — READ-ONLY data layer for legal holds.
 *
 * Fetches the active holds for a conversation and resolves the conversation-level hold plus a per-message
 * lookup. No write path, no optimistic updates, no local mutation of hold state. A 404 (or empty list)
 * is the expected "no holds" case and degrades to not-held — the UI is byte-for-byte unchanged. Hold
 * metadata is NEVER logged.
 *
 * Failures fold into [ApiResult.Failure] / [ApiResult.NetworkError]; CancellationException is re-thrown.
 */
interface LegalHoldRepository {

    /** Fetch all active holds for [conversationId] (raw list, for per-message resolution + the banner). */
    suspend fun loadActiveHolds(conversationId: String): ApiResult<List<LegalHold>>

    /**
     * Resolve the conversation-level hold (the first active hold with `message_id == null`), or null.
     * A failed fetch is propagated so callers can apply the fail-safe (keep last-known held state).
     */
    suspend fun conversationHold(conversationId: String): ApiResult<LegalHold?>
}

@Singleton
class LegalHoldRepositoryImpl @Inject constructor(
    private val api: LegalHoldApi,
    private val errorParser: ApiErrorParser,
) : LegalHoldRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadActiveHolds(conversationId: String): ApiResult<List<LegalHold>> =
        withContext(io) {
            when (val r = apiCall { api.listLegalHolds(conversationId) }) {
                is ApiResult.Success ->
                    ApiResult.Success(
                        r.data.filter { HoldStatus.fromWire(it.status) == HoldStatus.ACTIVE }
                            .map { it.toDomain() },
                    )
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun conversationHold(conversationId: String): ApiResult<LegalHold?> =
        withContext(io) {
            when (val r = apiCall { api.listLegalHolds(conversationId) }) {
                is ApiResult.Success ->
                    ApiResult.Success(resolveHold(r.data, conversationId, messageId = null))
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
}

/** AND-164 — provides [LegalHoldApi] on the shared Retrofit and binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object LegalHoldApiModule {
    @Provides
    @Singleton
    fun provideLegalHoldApi(retrofit: Retrofit): LegalHoldApi =
        retrofit.create(LegalHoldApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class LegalHoldDataModule {
    @Binds
    @Singleton
    abstract fun bindLegalHoldRepository(impl: LegalHoldRepositoryImpl): LegalHoldRepository
}
