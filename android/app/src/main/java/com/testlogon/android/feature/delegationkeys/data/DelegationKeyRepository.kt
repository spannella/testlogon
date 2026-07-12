package com.testlogon.android.feature.delegationkeys.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.delegationkeys.DelegationApiKeyCreateRequest
import com.testlogon.android.core.network.delegationkeys.DelegationKeyApi
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
 * Data layer for the delegation-API keys surface (web parity: /delegation-api), over [DelegationKeyApi].
 * Two key groups: the caller's MY keys (issued as a delegate) and CREATOR keys (issued by other delegates,
 * scoped to the caller's account). create / revoke are NON-idempotent mutations (never auto-retried). Each
 * call folds into [ApiResult] via [call]; mirrors DefaultApiKeysRepository / SyndicateRepositoryImpl.
 */
interface DelegationKeyRepository {

    /** GET the caller's own (as-delegate) delegation API keys. */
    suspend fun listMyKeys(): ApiResult<List<DelegationApiKey>>

    /** GET the delegation API keys scoped to the caller's account (issued by other delegates). */
    suspend fun listCreatorKeys(): ApiResult<List<DelegationApiKey>>

    /** GET the creators the caller delegates for (populates the create dialog). */
    suspend fun listManagedCreators(): ApiResult<List<ManagedCreator>>

    /** POST a new delegation API key. On success returns the created key with the one-time secret. */
    suspend fun createKey(
        label: String,
        creatorId: String,
        permissions: List<String>,
        expiresInDays: Int?,
    ): ApiResult<CreatedDelegationApiKey>

    /** DELETE (revoke) one of the caller's own (as-delegate) keys. */
    suspend fun revokeMyKey(keyId: String): ApiResult<Unit>

    /** DELETE (revoke) a key scoped to the caller's account. */
    suspend fun revokeCreatorKey(keyId: String): ApiResult<Unit>
}

@Singleton
class DefaultDelegationKeyRepository @Inject constructor(
    private val api: DelegationKeyApi,
    private val errorParser: ApiErrorParser,
) : DelegationKeyRepository {

    override suspend fun listMyKeys(): ApiResult<List<DelegationApiKey>> =
        withContext(Dispatchers.IO) { call { api.listMyKeys().map { it.toDomain() } } }

    override suspend fun listCreatorKeys(): ApiResult<List<DelegationApiKey>> =
        withContext(Dispatchers.IO) { call { api.listCreatorKeys().map { it.toDomain() } } }

    override suspend fun listManagedCreators(): ApiResult<List<ManagedCreator>> =
        withContext(Dispatchers.IO) { call { api.listManagedCreators().map { it.toDomain() } } }

    override suspend fun createKey(
        label: String,
        creatorId: String,
        permissions: List<String>,
        expiresInDays: Int?,
    ): ApiResult<CreatedDelegationApiKey> = withContext(Dispatchers.IO) {
        call {
            api.createKey(
                DelegationApiKeyCreateRequest(
                    label = label,
                    creatorId = creatorId,
                    permissions = permissions,
                    expiresInDays = expiresInDays,
                ),
            ).toCreated()
        }
    }

    override suspend fun revokeMyKey(keyId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.revokeMyKey(keyId) } }

    override suspend fun revokeCreatorKey(keyId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.revokeCreatorKey(keyId) } }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (preserving status); malformed JSON -> Failure;
     * transport failures -> NetworkError. Cancellation is re-thrown.
     */
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
