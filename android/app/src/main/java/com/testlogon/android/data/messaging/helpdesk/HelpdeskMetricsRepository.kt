package com.testlogon.android.data.messaging.helpdesk

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.helpdesk.HelpdeskMetrics
import com.testlogon.android.data.auth.AuthStateStore
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-377 — data layer for the helpdesk agent dashboard metrics.
 *
 * CRITICAL CONTRACT NOTE (spec §5 / §16 #5): there is NO `GET /messaging/helpdesk/metrics` endpoint
 * server-side, and the web client has no metrics call. The realistic primary path is the Q1
 * client-side derivation: the four count metrics are computed from the existing helpdesk queue
 * ([HelpdeskRepository.loadQueue], owned by AND-161). Time-based metrics (avg first-response, avg
 * resolution) and throughput (resolved-by-me-today) have NO client source, so they stay null and
 * render as a dash. If/when a real metrics endpoint lands, swap [refreshMetrics] to call it.
 *
 * Role gating reuses the queue-403 probe: a 403 from [HelpdeskRepository.loadQueue] is the canonical
 * not-an-agent signal (spec §1 / FR-1), surfaced as [ApiResult.Failure] with status 403.
 *
 * Staleness/offline (FR-6): a tiny in-memory cache of the last successfully-derived metrics is kept
 * so a failed refresh can fall back to stale Content + banner without a Room migration (gotcha:
 * prefer in-memory stale over a schema change). The cache is cleared on logout / agent change so a
 * different agent never sees another's per-agent counts (§8 / TC-12) — it keys on the current
 * `user_sub` and drops the cache when it changes.
 */
interface HelpdeskMetricsRepository {

    /** Last successfully-derived snapshot (in-memory, for stale fallback), or null. */
    fun cachedMetrics(): StateFlow<CachedMetrics?>

    /**
     * Refresh the dashboard. Reuses the queue probe ONCE: 403 -> Failure(403) (not-an-agent /
     * AccessDenied); 200 -> derive counts + keep the top-N preview, then cache; transport failure ->
     * NetworkError (the caller falls back to cache). Returns the derived metrics AND the queue preview
     * so the dashboard renders both from a single request.
     */
    suspend fun refreshMetrics(): ApiResult<HelpdeskDashboardData>
}

/** Metrics + the top-N helpdesk queue preview, both produced from a single queue fetch. */
data class HelpdeskDashboardData(
    val metrics: HelpdeskMetrics,
    val queuePreview: List<HelpdeskQueueItem>,
)

/** A cached dashboard snapshot tagged with when it was cached (epoch seconds) for the stale banner. */
data class CachedMetrics(
    val data: HelpdeskDashboardData,
    val cachedAtEpochSeconds: Long,
)

@Singleton
class HelpdeskMetricsRepositoryImpl @Inject constructor(
    private val queueRepository: HelpdeskRepository,
    private val authStateStore: AuthStateStore,
) : HelpdeskMetricsRepository {

    /**
     * Epoch-SECONDS clock seam. Settable property (NOT a ctor param) because Hilt cannot inject a bare
     * lambda / honor a Kotlin ctor default; tests overwrite it for deterministic timestamps.
     */
    var nowSeconds: () -> Long = { System.currentTimeMillis() / 1000L }

    private val _cache = MutableStateFlow<CachedMetrics?>(null)

    // The agent the cache belongs to; clears the cache when the principal changes (logout / switch).
    @Volatile
    private var cachedForUserSub: String? = null

    override fun cachedMetrics(): StateFlow<CachedMetrics?> = _cache.asStateFlow()

    override suspend fun refreshMetrics(): ApiResult<HelpdeskDashboardData> {
        val me = authStateStore.userSub.value
        if (me != cachedForUserSub) {
            // Principal changed (logout or different agent): drop any stale per-agent cache.
            _cache.value = null
            cachedForUserSub = me
        }
        return when (val r = queueRepository.loadQueue()) {
            is ApiResult.Success -> {
                val ts = nowSeconds()
                val metrics = deriveMetrics(r.data, currentUserId = me, generatedAtEpochSeconds = ts)
                val data = HelpdeskDashboardData(
                    metrics = metrics,
                    queuePreview = r.data.take(QUEUE_PREVIEW_LIMIT),
                )
                _cache.value = CachedMetrics(data = data, cachedAtEpochSeconds = ts)
                cachedForUserSub = me
                ApiResult.Success(data)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    companion object {
        /** Top-N helpdesk queue rows shown inline on the dashboard (FR-3 default 25). */
        const val QUEUE_PREVIEW_LIMIT = 25

        /**
         * AND-377 — Q1 client-side derivation: compute the four count metrics from helpdesk queue
         * items. Open = not closed; unassigned = no active agent; assigned-to-me = active agent is the
         * current user; SLA-at-risk = awaiting-agent AND unassigned (the queue exposes no SLA timer,
         * so this is the only sound client signal). Time/throughput metrics have no client source.
         */
        fun deriveMetrics(
            items: List<HelpdeskQueueItem>,
            currentUserId: String?,
            generatedAtEpochSeconds: Long,
        ): HelpdeskMetrics {
            val open = items.count { it.routingState != HelpdeskRoutingState.CLOSED }
            val unassigned = items.count {
                it.routingState != HelpdeskRoutingState.CLOSED && it.claimState == ClaimState.UNASSIGNED
            }
            val assignedToMe = items.count {
                it.routingState != HelpdeskRoutingState.CLOSED &&
                    it.claimState == ClaimState.CLAIMED_BY_ME &&
                    !currentUserId.isNullOrBlank()
            }
            val slaAtRisk = items.count {
                it.routingState == HelpdeskRoutingState.AWAITING_AGENT &&
                    it.claimState == ClaimState.UNASSIGNED
            }
            return HelpdeskMetrics(
                openCount = open,
                unassignedCount = unassigned,
                assignedToMeCount = assignedToMe,
                slaAtRiskCount = slaAtRisk,
                avgFirstResponseSeconds = null,
                avgResolutionSeconds = null,
                resolvedByMeToday = null,
                deltas = emptyMap(),
                generatedAtEpochSeconds = generatedAtEpochSeconds,
            )
        }
    }
}

/** AND-377 — binds the metrics repository implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class HelpdeskMetricsRepositoryModule {
    @Binds
    @Singleton
    abstract fun bindHelpdeskMetricsRepository(
        impl: HelpdeskMetricsRepositoryImpl,
    ): HelpdeskMetricsRepository
}
