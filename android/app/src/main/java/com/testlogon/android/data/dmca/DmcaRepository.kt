package com.testlogon.android.data.dmca

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
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
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-384 - data layer for DMCA submission + the best-effort draft cache.
 *
 * [submit] issues exactly ONE POST v1/dmca/claims and performs ZERO retries (the POST is non-idempotent and a
 * duplicate DMCA notice is a real harm - FR-4 / AC-4). A non-2xx becomes [ApiResult.Failure] via
 * [ApiErrorParser] (which preserves the 422 body in [com.testlogon.android.core.model.ApiError.raw] for the
 * per-field loc-tail mapping). A transport failure becomes [ApiResult.NetworkError]; [CancellationException]
 * is always re-thrown. The claimant PII / signature in the request are NEVER logged here.
 *
 * The 401-refresh-once-then-fail behavior is delegated to the core-network auth interceptor (AND-027); this
 * repository sees only the post-refresh outcome.
 */
interface DmcaRepository {

    /** Submits a single, non-idempotent DMCA claim. No auto-retry. */
    suspend fun submit(request: DmcaClaimRequest): ApiResult<DmcaClaimCreateResponse>

    suspend fun loadDraft(targetKey: String): DmcaDraft?
    suspend fun saveDraft(targetKey: String, draft: DmcaDraft)
    suspend fun clearDraft(targetKey: String)

    /** Clears ALL cached drafts (sign-out PII hygiene - AC-6). */
    suspend fun clearAllDrafts()
}

@Singleton
class DefaultDmcaRepository @Inject constructor(
    private val api: DmcaApi,
    private val draftStore: DmcaDraftStore,
    private val errorParser: ApiErrorParser,
) : DmcaRepository {

    // No @IoDispatcher qualifier exists in this project; settable so tests can inject a test dispatcher.
    var io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun submit(request: DmcaClaimRequest): ApiResult<DmcaClaimCreateResponse> =
        withContext(io) {
            apiCallResponse { api.submitClaim(request) }
                .map { it } // identity: the DTO is the domain value (DTO->domain mapping happens in the VM)
        }

    override suspend fun loadDraft(targetKey: String): DmcaDraft? =
        withContext(io) { draftStore.load(targetKey) }

    override suspend fun saveDraft(targetKey: String, draft: DmcaDraft) =
        withContext(io) { draftStore.save(targetKey, draft) }

    override suspend fun clearDraft(targetKey: String) =
        withContext(io) { draftStore.clear(targetKey) }

    override suspend fun clearAllDrafts() =
        withContext(io) { draftStore.clearAll() }

    /**
     * Unwraps a Retrofit [Response]: a non-2xx (or a null 2xx body) becomes [ApiResult.Failure] via
     * [ApiErrorParser]; an [IOException] becomes [ApiResult.NetworkError]. ZERO retries.
     */
    private suspend fun <T> apiCallResponse(block: suspend () -> Response<T>): ApiResult<T> = try {
        val response = block()
        val body = response.body()
        if (response.isSuccessful && body != null) {
            ApiResult.Success(body)
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** AND-384 - provides [DmcaApi] on the shared authenticated Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object DmcaApiModule {
    @Provides
    @Singleton
    fun provideDmcaApi(retrofit: Retrofit): DmcaApi = retrofit.create(DmcaApi::class.java)
}

/** AND-384 - binds the DMCA repository + the DataStore-backed draft store. */
@Module
@InstallIn(SingletonComponent::class)
abstract class DmcaDataModule {
    @Binds
    @Singleton
    abstract fun bindDmcaRepository(impl: DefaultDmcaRepository): DmcaRepository

    @Binds
    @Singleton
    abstract fun bindDmcaDraftStore(impl: DataStoreDmcaDraftStore): DmcaDraftStore
}
