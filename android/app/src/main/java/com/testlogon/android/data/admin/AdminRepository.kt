package com.testlogon.android.data.admin

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.AdminDashboard
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-403 - READ-ONLY data layer over [AdminApi] for the admin alerts/dashboards surface.
 *
 * [loadDashboard] fetches the two general-admin health reads CONCURRENTLY (coroutineScope { async ; async })
 * and AGGREGATES them client-side into a single [AdminDashboard] (alerts derived + sorted, metric tiles built -
 * see AdminMappers). The aggregation is ATOMIC (AND-403 §7 / AC-6): if EITHER sub-call fails the whole result
 * fails, so a misleadingly-partial admin view is never shown; a failing async cancels its sibling (structured
 * concurrency). A backend `403` on either read surfaces as Failure(status=403) which the ViewModel maps to the
 * Forbidden state (defense in depth - AND-403 §4 / FR-8).
 *
 * This is STRICTLY READ-ONLY (AND-403 §8 / AC-3): no mutation method exists; [AdminApi] exposes only GETs. The
 * repo wraps the raw DTO returns in [ApiResult] via the established call{} pattern (HTTP errors -> Failure via
 * [ApiErrorParser] preserving the status; transport -> NetworkError; CancellationException re-thrown). It does
 * NOT cache: admin alerts/metrics are operational, time-sensitive and auth-scoped, so they are held only in the
 * ViewModel StateFlow (AND-403 §6 - no Room, no disk cache, no migration, no Pixel smoke).
 *
 * [isAdmin] is a convenience over the [AdminRoleProvider] seam for the ViewModel's client-side pre-check
 * (AND-403 §4 ViewModel-layer gate); the backend `403` remains the final authority.
 */
interface AdminRepository {

    /** Concurrently loads + aggregates the admin dashboard. Atomic (either sub-call failing fails the result). */
    suspend fun loadDashboard(): ApiResult<AdminDashboard>

    /** Client-side role pre-check (UNKNOWN default -> true on the cookie client; backend 403 is authoritative). */
    fun isAdmin(): Boolean
}

@Singleton
class DefaultAdminRepository @Inject constructor(
    private val api: AdminApi,
    private val errorParser: ApiErrorParser,
    private val roleProvider: AdminRoleProvider,
) : AdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadDashboard(): ApiResult<AdminDashboard> = withContext(io) {
        call {
            coroutineScope {
                val jobsDeferred = async { api.getJobHealth() }
                val webhookDeferred = async { api.getWebhookHealth() }
                toAdminDashboard(jobsDeferred.await(), webhookDeferred.await())
            }
        }
    }

    override fun isAdmin(): Boolean = roleProvider.mayAttemptAdminReads()

    /**
     * Folds a block into [ApiResult]: HTTP errors -> Failure (via [ApiErrorParser], preserving the status so a
     * 401/403 surfaces with its code for the VM's handoff/Forbidden mapping); transport failures ->
     * NetworkError (timeout flag set for SocketTimeoutException); CancellationException is re-thrown (never
     * swallowed - structured concurrency). Mirrors AdminBillingConfigRepositoryImpl / WebhooksRepository.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** AND-403 - provides the [AdminApi] on the shared (authenticated) Retrofit (reuses the AND-027 stack). */
@Module
@InstallIn(SingletonComponent::class)
object AdminApiModule {

    @Provides
    @Singleton
    fun provideAdminApi(retrofit: Retrofit): AdminApi = retrofit.create(AdminApi::class.java)
}

/** AND-403 - binds the read-only admin dashboard repository. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdminDataModule {

    @Binds
    @Singleton
    abstract fun bindAdminRepository(impl: DefaultAdminRepository): AdminRepository
}
