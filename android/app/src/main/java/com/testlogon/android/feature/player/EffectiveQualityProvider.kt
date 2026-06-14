package com.testlogon.android.feature.player

import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.data.preferences.PlaybackQualityPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-169 §4.4 — the single source of truth for resolved playback quality.
 *
 * Combines the persisted [QualityPolicy] ([PlaybackQualityPreferences]) with the live
 * [NetworkStatus] ([MeteredNetworkObserver]) through the pure [QualityPolicyResolver] into a hot
 * [StateFlow]. Scoped @Singleton on the application scope so a single connectivity callback is
 * shared; `WhileSubscribed(5_000)` avoids leaking the callback when no player is active (§6). All the
 * cap math is the pure resolver — this is only the flow plumbing.
 */
@Singleton
class EffectiveQualityProvider @Inject constructor(
    prefs: PlaybackQualityPreferences,
    connectivity: MeteredNetworkObserver,
    @AppScope scope: CoroutineScope,
) {
    val effective: StateFlow<EffectiveQuality> =
        combine(prefs.qualityPolicy(), connectivity.observe()) { policy, net ->
            QualityPolicyResolver.resolve(policy, net)
        }
            .distinctUntilChanged()
            .stateIn(
                scope = scope,
                started = SharingStarted.WhileSubscribed(5_000),
                initialValue = QualityPolicyResolver.resolve(prefs.currentPolicy(), connectivity.current()),
            )
}
