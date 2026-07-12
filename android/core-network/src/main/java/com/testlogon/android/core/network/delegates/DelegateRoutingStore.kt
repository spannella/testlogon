package com.testlogon.android.core.network.delegates

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Delegate full-parity messaging: process-global holder for the ACTIVE manage-as-creator id used by
 * [DelegateRoutingInterceptor] to re-target the SHARED messaging endpoints onto their delegate
 * (creator-attributed) equivalents.
 *
 * WHY a core-network holder (not the core-data DelegationStateStore): the OkHttp client + interceptor
 * chain live in :core-network, which depends only on :core-model (NOT :core-data / :app). So the app
 * layer bridges its typed delegation context into this tiny volatile holder (see
 * DelegationContextProvider), and the interceptor reads it with zero cross-module coupling.
 *
 * [activeCreatorId] is non-null EXACTLY while the principal is acting as a delegate of that creator; the
 * interceptor rewrites the supported messaging requests to the `messaging/delegate/{creatorId}/...`
 * routes so every send/read is attributed to the CREATOR. Null = acting as oneself = no rewrite.
 */
@Singleton
class DelegateRoutingStore @Inject constructor() {

    @Volatile
    var activeCreatorId: String? = null
}
