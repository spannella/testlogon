package com.testlogon.android.feature.signing.packetlist

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.signing.SigningApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SUX-008 — data layer for the signing INBOX browse buckets.
 *
 * Deliberately SEPARATE from [com.testlogon.android.feature.signing.data.SignatureRepository] (the
 * DETAIL repo): adding list members to that interface would force an override into all five existing
 * fakes across the signing test tree. This inbox repo REUSES the same [SigningApi] (AND-339 + the
 * SUX-008 inbox additions) and the shared [ApiErrorParser], and maps each row to the feature domain
 * before the typed [ApiResult] — the identical wrap discipline as SignatureRepositoryImpl.
 *
 * DEGRADE-ON-404: each bucket call returns its own [ApiResult]; a 404 surfaces as an [ApiResult.Failure]
 * with status 404 which the ViewModel treats as "this bucket unavailable" (see SigningInboxMath).
 */
interface SigningInboxRepository {

    /** Packets awaiting the caller's signature. */
    suspend fun awaiting(limit: Int = 100): ApiResult<List<SigningInboxItem>>

    /** Packets the caller sent (as owner). */
    suspend fun sent(limit: Int = 100): ApiResult<List<SigningInboxItem>>

    /** Completed packets the caller signed. */
    suspend fun completedForMe(limit: Int = 100): ApiResult<List<SigningInboxItem>>

    /** The caller's draft packets. */
    suspend fun drafts(limit: Int = 100): ApiResult<List<SigningInboxItem>>
}

@Singleton
class SigningInboxRepositoryImpl @Inject constructor(
    private val signingApi: SigningApi,
    private val errorParser: ApiErrorParser,
) : SigningInboxRepository {

    override suspend fun awaiting(limit: Int): ApiResult<List<SigningInboxItem>> =
        withContext(Dispatchers.IO) { call { signingApi.listAwaiting(limit).items.map { it.toDomain() } } }

    override suspend fun sent(limit: Int): ApiResult<List<SigningInboxItem>> =
        withContext(Dispatchers.IO) { call { signingApi.listSent(limit).items.map { it.toDomain() } } }

    override suspend fun completedForMe(limit: Int): ApiResult<List<SigningInboxItem>> =
        withContext(Dispatchers.IO) { call { signingApi.listCompletedForMe(limit).items.map { it.toDomain() } } }

    override suspend fun drafts(limit: Int): ApiResult<List<SigningInboxItem>> =
        withContext(Dispatchers.IO) { call { signingApi.listDrafts(limit).items.map { it.toDomain() } } }

    /** Folds a block into [ApiResult]; mirrors SignatureRepositoryImpl.call. */
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
