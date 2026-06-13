package com.testlogon.android.data.account

import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthRepository
import com.testlogon.android.data.preferences.AccountStatusRepository
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
 * AND-387 - data layer for the four account-lifecycle MUTATIONS (closure start/finalize, suspend,
 * reactivate), plus a [status] read that delegates to AND-082's [AccountStatusRepository] (the idempotent
 * `GET ui/account/status`, which carries the AND-016 backoff at the network layer). The server is the single
 * source of truth; no lifecycle status is cached to Room/DataStore (it is short-lived + security-sensitive,
 * held only in the ViewModel StateFlow - spec §6).
 *
 * Resilience / safety (spec §5/§7/§8):
 *  - Each mutation issues EXACTLY ONE non-idempotent POST (NEVER auto-retried).
 *  - A non-2xx becomes [ApiResult.Failure] via [ApiErrorParser] (preserving the 422 body in ApiError.raw);
 *    a transport failure becomes [ApiResult.NetworkError]; [CancellationException] is always re-thrown.
 *  - On a SUCCESSFUL closure-finalize or suspend, the local session is torn down (cookie jar + DataStore
 *    auth state) via [AuthRepository.logout] - the AND-032 teardown seam - BEFORE returning. Teardown is
 *    never run on a failure (the user is not silently signed out).
 *  - On a SUCCESSFUL reactivate, [AuthRepository.getMe] is re-fetched so the cached principal/auth state
 *    reflects `active` again (spec FR-5).
 *  - 401 is handled by the core-network authenticator (one refresh + single retry); a still-401 bubbles as
 *    Failure.
 *  - No password / cookie / CSRF token / reason text / full challenge_id is logged here (spec §8).
 */
interface AccountLifecycleRepository {

    /** GET status (idempotent; delegates to AND-082's read with AND-016 backoff). Drives action gating. */
    suspend fun status(): ApiResult<AccountStatus>

    /** Single non-idempotent POST closure/start (no body). Returns the re-auth challenge. */
    suspend fun startClosure(): ApiResult<ClosureStartResult>

    /** Single non-idempotent POST closure/finalize with [challengeId]; on success runs teardown. */
    suspend fun finalizeClosure(challengeId: String): ApiResult<AccountStatus>

    /** Single non-idempotent POST suspend with optional [reason]; on success runs teardown. */
    suspend fun suspend(reason: String?): ApiResult<AccountStatus>

    /** Single non-idempotent POST reactivate (optional [reason]); on success re-fetches getMe. */
    suspend fun reactivate(reason: String? = null): ApiResult<AccountStatus>
}

@Singleton
class DefaultAccountLifecycleRepository @Inject constructor(
    private val api: AccountLifecycleApi,
    private val statusRepository: AccountStatusRepository,
    private val authRepository: AuthRepository,
    private val errorParser: ApiErrorParser,
) : AccountLifecycleRepository {

    // No @IoDispatcher qualifier exists in this project; settable so tests can inject a test dispatcher.
    var io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun status(): ApiResult<AccountStatus> = statusRepository.getStatus()

    override suspend fun startClosure(): ApiResult<ClosureStartResult> = withContext(io) {
        when (val r = apiCall { api.startClosure() }) {
            is ApiResult.Success -> ApiResult.Success(r.data.toDomain())
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun finalizeClosure(challengeId: String): ApiResult<AccountStatus> = withContext(io) {
        when (val r = apiCall { api.finalizeClosure(ClosureFinalizeDto(challengeId)) }) {
            is ApiResult.Success -> {
                // Full local teardown (AND-032): cookie jar + DataStore auth state. Best-effort server
                // logout is folded into AuthRepository.logout(); we never block/fail closure on it.
                authRepository.logout()
                ApiResult.Success(r.data.toAccountStatus())
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun suspend(reason: String?): ApiResult<AccountStatus> = withContext(io) {
        val body = AccountStatusReqDto(reason = reason?.takeIf { it.isNotBlank() })
        when (val r = apiCall { api.suspendAccount(body) }) {
            is ApiResult.Success -> {
                authRepository.logout() // AND-032 teardown - Android signs the user out on suspend (Q4).
                ApiResult.Success(r.data.toAccountStatus())
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun reactivate(reason: String?): ApiResult<AccountStatus> = withContext(io) {
        val body = AccountStatusReqDto(reason = reason?.takeIf { it.isNotBlank() })
        when (val r = apiCall { api.reactivateAccount(body) }) {
            is ApiResult.Success -> {
                // Refresh the principal so auth state reflects `active` again (spec FR-5). Best-effort:
                // a transient getMe failure does not undo the successful reactivate.
                authRepository.getMe()
                ApiResult.Success(r.data.toAccountStatus())
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    /**
     * Unwraps a Retrofit [Response]: a non-2xx (or a null 2xx body) becomes [ApiResult.Failure] via
     * [ApiErrorParser]; an [IOException] becomes [ApiResult.NetworkError]. ZERO retries (mutations are never
     * auto-retried - spec FR-7).
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

/** AND-387 - provides [AccountLifecycleApi] on the shared authenticated Retrofit + binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object AccountLifecycleApiModule {
    @Provides
    @Singleton
    fun provideAccountLifecycleApi(retrofit: Retrofit): AccountLifecycleApi =
        retrofit.create(AccountLifecycleApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AccountLifecycleDataModule {
    @Binds
    @Singleton
    abstract fun bindAccountLifecycleRepository(
        impl: DefaultAccountLifecycleRepository,
    ): AccountLifecycleRepository
}
