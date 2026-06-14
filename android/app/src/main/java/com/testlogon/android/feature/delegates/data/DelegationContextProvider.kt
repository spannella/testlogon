package com.testlogon.android.feature.delegates.data

import com.testlogon.android.core.data.delegates.DelegationStateStore
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.DelegationContext
import com.testlogon.android.core.model.delegates.ManagedCreator
import com.testlogon.android.core.model.delegates.toDelegationContext
import com.testlogon.android.data.auth.AppScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-360 - the OVERLAY context provider. Bridges the AND-359 published manage-as selection into the
 * typed [DelegationContext] that the delegate-path repositories gate on and the banner / focused
 * demonstration render off.
 *
 * REUSE: this READS the AND-359 [DelegationStateStore.managingCreator] flow and orchestrates over the
 * AND-359 [DelegationRepository] (managedCreators / enter / exit). It does NOT redefine the enter / exit
 * flow or the ManagingCreator model - it only projects + adds the permission-resolving [enterAsCreator]
 * convenience. The active path-scoping seam stays [DelegationRepository.activeCreatorId].
 *
 * The [delegationContext] is a hot, derived StateFlow shared on the application-lifetime [AppScope]
 * scope (mirrors AuthStateStore), so every overlay consumer observes one consistent context.
 */
@Singleton
class DelegationContextProvider @Inject constructor(
    private val delegationRepository: DelegationRepository,
    delegationStateStore: DelegationStateStore,
    @AppScope scope: CoroutineScope,
) {

    /**
     * The active typed [DelegationContext], or null when the principal acts as themselves. Derived from
     * the AND-359 managingCreator flag via [toDelegationContext] (wire permission Strings -> typed set).
     */
    val delegationContext: StateFlow<DelegationContext?> =
        delegationStateStore.managingCreator
            .map { it?.toDelegationContext() }
            .stateIn(
                scope,
                SharingStarted.Eagerly,
                delegationStateStore.managingCreator.value?.toDelegationContext(),
            )

    /** Snapshot of the current typed context (for synchronous gating in the delegate repositories). */
    fun current(): DelegationContext? = delegationContext.value

    /**
     * AND-360 convenience over the AND-359 enter flow: fetch the caller's managed creators, find
     * [creatorId], resolve its granted permissions (only when status == "active"), and ENTER manage-as
     * mode with them via [DelegationRepository.enter]. Returns the resulting typed [DelegationContext].
     *
     * The network failure / not-found cases pass through as the matching ApiResult variant; the actual
     * enter itself is a pure-local AND-359 mutation (no extra round-trip).
     */
    suspend fun enterAsCreator(creatorId: String): ApiResult<DelegationContext> =
        when (val managed = delegationRepository.managedCreators()) {
            is ApiResult.Success -> {
                val match = managed.data.firstOrNull { it.creatorId == creatorId }
                    ?: return ApiResult.Failure(NotManagedError)
                val permissions = match.activePermissions()
                when (val entered = delegationRepository.enter(creatorId, match.label, permissions)) {
                    is ApiResult.Success -> ApiResult.Success(entered.data.toDelegationContext())
                    is ApiResult.Failure -> entered
                    is ApiResult.NetworkError -> entered
                }
            }
            is ApiResult.Failure -> managed
            is ApiResult.NetworkError -> managed
        }

    /** EXIT delegate mode (delegates to the AND-359 pure-local exit). */
    suspend fun exit(): ApiResult<Unit> = delegationRepository.exit()

    private companion object {
        /** A managed creator that is not in the caller's managed list (the enter target was not found). */
        val NotManagedError = com.testlogon.android.core.model.ApiError(
            status = com.testlogon.android.core.model.ApiError.STATUS_PARSE,
            message = "That creator is not available to manage.",
            code = "not_managed",
        )
    }
}

/**
 * AND-360 - the permission tokens this managed creator actually grants: only when its [ManagedCreator.status]
 * is "active" (an inactive / revoked / pending row grants nothing). Forward-compat: the raw Strings are
 * carried as-is; the typed projection (and gating) drops unrecognized tokens to UNKNOWN downstream.
 */
internal fun ManagedCreator.activePermissions(): List<String> =
    if (status == "active") permissions else emptyList()
