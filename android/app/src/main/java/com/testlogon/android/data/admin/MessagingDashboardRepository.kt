package com.testlogon.android.data.admin

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.model.admin.MessagingDashboard
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
 * AND-404 - READ-ONLY data layer over [MessagingDashboardApi] for the admin email/SMS delivery dashboards.
 *
 * [dashboard] fans out the per-channel stats + deliveries reads CONCURRENTLY (coroutineScope { async ; async })
 * and merges them into a single [MessagingDashboard]. Unlike the AND-403 atomic aggregation, AND-404 §7 / TC-09
 * requires PARTIAL fan-out: STATS is the critical path (its failure fails the whole result so the auth/error
 * mapping in the ViewModel still applies), but a DELIVERIES (activity) failure is NON-FATAL - the metrics are
 * returned with `activityFailed = true` and an empty activity list, so the screen shows the metrics plus a
 * non-blocking inline notice rather than blanking. A stats `403`/`401` surfaces as Failure(status) which the
 * ViewModel maps to Forbidden / auth handoff (defense in depth - AND-404 FR6 / §7).
 *
 * STRICTLY READ-ONLY (AND-404 §8 / AC2): [MessagingDashboardApi] exposes only GETs; there is no mutation method.
 * The repo wraps raw DTO returns in [ApiResult] via the established call{} pattern (HTTP errors -> Failure via
 * [ApiErrorParser] preserving the status; transport -> NetworkError; CancellationException re-thrown). It does
 * NOT cache to disk (admin delivery health is operational, time-sensitive and auth-scoped, held only in the
 * ViewModel StateFlow - mirrors AND-403; no Room, no migration, no Pixel smoke).
 */
interface MessagingDashboardRepository {

    /** Concurrently loads + merges one channel's dashboard. Stats-critical; a deliveries failure is non-fatal. */
    suspend fun dashboard(channel: DashboardChannel): ApiResult<MessagingDashboard>

    /** Client-side role pre-check (UNKNOWN default -> true on the cookie client; backend 403 is authoritative). */
    fun isAdmin(): Boolean
}

@Singleton
class DefaultMessagingDashboardRepository @Inject constructor(
    private val api: MessagingDashboardApi,
    private val errorParser: ApiErrorParser,
    private val roleProvider: AdminRoleProvider,
) : MessagingDashboardRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun dashboard(channel: DashboardChannel): ApiResult<MessagingDashboard> = withContext(io) {
        when (channel) {
            DashboardChannel.EMAIL -> loadEmail()
            DashboardChannel.SMS -> loadSms()
        }
    }

    private suspend fun loadEmail(): ApiResult<MessagingDashboard> = call {
        coroutineScope {
            // Deliveries (activity) is non-critical: a failure degrades to activityFailed, never fails the load.
            val statsDeferred = async { api.getEmailStats() }
            val deliveriesDeferred = async { runCatchingDeliveries { api.getEmailDeliveries() } }
            val stats = statsDeferred.await()
            val deliveries = deliveriesDeferred.await()
            toEmailDashboard(stats, deliveries ?: DeliveryListDto())
                .copy(activityFailed = deliveries == null)
        }
    }

    private suspend fun loadSms(): ApiResult<MessagingDashboard> = call {
        coroutineScope {
            val statsDeferred = async { api.getSmsStats() }
            val deliveriesDeferred = async { runCatchingDeliveries { api.getSmsDeliveries() } }
            val stats = statsDeferred.await()
            val deliveries = deliveriesDeferred.await()
            toSmsDashboard(stats, deliveries ?: DeliveryListDto())
                .copy(activityFailed = deliveries == null)
        }
    }

    override fun isAdmin(): Boolean = roleProvider.mayAttemptAdminReads()

    /**
     * Runs the deliveries read, returning null on a transport / HTTP error so the activity part degrades
     * gracefully (AND-404 §7 - non-fatal). [CancellationException] is re-thrown to preserve structured
     * concurrency; the critical stats sibling drives whole-load failure.
     */
    private suspend fun runCatchingDeliveries(block: suspend () -> DeliveryListDto): DeliveryListDto? = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        null
    } catch (e: IOException) {
        null
    }

    /**
     * Folds a block into [ApiResult]: HTTP errors -> Failure (via [ApiErrorParser], preserving the status so a
     * 401/403 surfaces for the VM's auth/Forbidden mapping); transport -> NetworkError (timeout flag set for
     * SocketTimeoutException); CancellationException re-thrown. Mirrors AND-403 DefaultAdminRepository.
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

/** AND-404 - provides the [MessagingDashboardApi] on the shared (authenticated) Retrofit (reuses AND-027). */
@Module
@InstallIn(SingletonComponent::class)
object MessagingDashboardApiModule {

    @Provides
    @Singleton
    fun provideMessagingDashboardApi(retrofit: Retrofit): MessagingDashboardApi =
        retrofit.create(MessagingDashboardApi::class.java)
}

/** AND-404 - binds the read-only email/SMS dashboard repository. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MessagingDashboardDataModule {

    @Binds
    @Singleton
    abstract fun bindMessagingDashboardRepository(
        impl: DefaultMessagingDashboardRepository,
    ): MessagingDashboardRepository
}
