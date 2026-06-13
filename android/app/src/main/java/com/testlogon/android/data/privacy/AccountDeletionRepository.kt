package com.testlogon.android.data.privacy

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-386 - data layer for the account-deletion request/cancel surface (spec §4).
 *
 * The server is the single source of truth. [getStatus] reads the deletion requests LIST and derives the
 * active vs pending state (there is no singleton status GET); [requestDeletion] issues exactly ONE
 * non-idempotent POST carrying `{password, confirm_text, reason?}`; [cancelDeletion] issues exactly ONE
 * non-idempotent cancel POST then re-fetches the authoritative state. A non-2xx becomes [ApiResult.Failure]
 * via [ApiErrorParser] (preserving the 422 body in ApiError.raw); a transport failure becomes
 * [ApiResult.NetworkError]; [CancellationException] is always re-thrown. The 401-refresh-once behavior is
 * delegated to the core-network auth interceptor (AND-027). No password / request_id / timestamps are logged
 * here (spec §8 / AC-8). The last successful status is best-effort mirrored to DataStore for the offline
 * stale view (FR-6).
 */
interface AccountDeletionRepository {

    /** GET the requests list and derive the authoritative [DeletionStatus] (Active | Pending). */
    suspend fun getStatus(): ApiResult<DeletionStatus>

    /** Single non-idempotent create. Returns the resulting pending state. */
    suspend fun requestDeletion(
        password: String,
        confirmText: String,
        reason: String? = null,
    ): ApiResult<DeletionStatus.Pending>

    /** Single non-idempotent cancel, then a re-fetch of the authoritative state. */
    suspend fun cancelDeletion(requestId: String): ApiResult<DeletionStatus>

    /** Reads the best-effort last-known status (for the offline stale view), or null. */
    suspend fun lastKnownStatus(): DeletionStatus?

    /** Wipes the local last-known mirror on sign-out (PII hygiene). */
    suspend fun clearCache()
}

@Singleton
class DefaultAccountDeletionRepository @Inject constructor(
    private val api: PrivacyApi,
    private val statusStore: AccountDeletionStatusStore,
    private val errorParser: ApiErrorParser,
) : AccountDeletionRepository {

    // No @IoDispatcher qualifier exists in this project; settable so tests can inject a test dispatcher.
    var io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getStatus(): ApiResult<DeletionStatus> = withContext(io) {
        when (val r = apiCall { api.listDeletions() }) {
            is ApiResult.Success -> {
                val status = r.data.toDeletionStatus()
                statusStore.save(status)
                ApiResult.Success(status)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun requestDeletion(
        password: String,
        confirmText: String,
        reason: String?,
    ): ApiResult<DeletionStatus.Pending> = withContext(io) {
        val body = AccountDeletionRequestDto(
            password = password,
            confirmText = confirmText,
            reason = reason?.takeIf { it.isNotBlank() },
        )
        when (val r = apiCall { api.requestDeletion(body) }) {
            is ApiResult.Success -> {
                val pending = r.data.toPending()
                statusStore.save(pending)
                ApiResult.Success(pending)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun cancelDeletion(requestId: String): ApiResult<DeletionStatus> = withContext(io) {
        when (val r = apiCall { api.cancelDeletion(requestId) }) {
            is ApiResult.Success -> {
                // After a successful cancel, re-fetch the authoritative state (the cancel body alone is
                // not the full status). If the re-fetch fails transiently, fall back to Active (the cancel
                // succeeded) and mirror that.
                when (val status = apiCall { api.listDeletions() }) {
                    is ApiResult.Success -> {
                        val derived = status.data.toDeletionStatus()
                        statusStore.save(derived)
                        ApiResult.Success(derived)
                    }
                    is ApiResult.Failure -> {
                        statusStore.save(DeletionStatus.Active)
                        ApiResult.Success(DeletionStatus.Active)
                    }
                    is ApiResult.NetworkError -> {
                        statusStore.save(DeletionStatus.Active)
                        ApiResult.Success(DeletionStatus.Active)
                    }
                }
            }
            is ApiResult.Failure ->
                // 409 (nothing to cancel) / 404 (request gone) are recoverable: re-fetch the truth so the
                // UI never sticks on a stale Cancel button (spec §7 / AC-7). Other failures pass through.
                if (r.error.status == 404 || r.error.status == 409) {
                    when (val status = apiCall { api.listDeletions() }) {
                        is ApiResult.Success -> {
                            val derived = status.data.toDeletionStatus()
                            statusStore.save(derived)
                            ApiResult.Success(derived)
                        }
                        is ApiResult.Failure -> r
                        is ApiResult.NetworkError -> r
                    }
                } else {
                    r
                }
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun lastKnownStatus(): DeletionStatus? = withContext(io) { statusStore.load() }

    override suspend fun clearCache() = withContext(io) { statusStore.clear() }

    /**
     * Unwraps a Retrofit [Response]: a non-2xx (or a null 2xx body) becomes [ApiResult.Failure] via
     * [ApiErrorParser]; an [IOException] becomes [ApiResult.NetworkError]. ZERO retries here (mutations are
     * never auto-retried; the idempotent GET's bounded backoff is delegated to the network layer).
     */
    private suspend fun <T> apiCall(block: suspend () -> Response<T>): ApiResult<T> = try {
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

/** AND-386 - binds the account-deletion repository. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AccountDeletionDataModule {
    @Binds
    @Singleton
    abstract fun bindAccountDeletionRepository(
        impl: DefaultAccountDeletionRepository,
    ): AccountDeletionRepository
}
