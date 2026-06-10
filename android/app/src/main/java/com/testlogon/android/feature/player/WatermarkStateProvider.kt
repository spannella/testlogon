package com.testlogon.android.feature.player

import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-170 §4.2 — builds the [WatermarkUiState] flow from the current playable item + signed-in
 * identity.
 *
 * REAL-CONTRACT NOTE: identity comes from the verified `/ui/me` token only — [AuthStateStore.userSub]
 * (the persisted `user_sub`). Email/username are NOT available from `/ui/me` (`MeResp` is
 * `{user_sub, session_id, ip}`, AND-170 §5/OA-1), so the overlay is guaranteed only `user_sub` +
 * timestamp; richer identity stays nullable for when a profile source surfaces it. `requiresWatermark`
 * has no backend authority (AND-170 §5/OA-2) — it is a product/Android-local policy carried on
 * [PlayableItem], safe-defaulting to false.
 *
 * The policy DECISION is the pure [WatermarkPolicy.evaluate]; this only wires the flows + the clock.
 */
@Singleton
class WatermarkStateProvider @Inject constructor(
    private val authStateStore: AuthStateStore,
) {
    /**
     * Combines the host-supplied [item] flow with identity into [WatermarkUiState]. [nowMs] /
     * [zoneOffsetMinutes] / [zoneAbbrev] are injectable so previews/tests force a deterministic clock.
     */
    fun watermarkState(
        item: Flow<PlayableItem?>,
        nowMs: () -> Long = { System.currentTimeMillis() },
        zoneOffsetMinutes: Int = 0,
        zoneAbbrev: String = "UTC",
    ): Flow<WatermarkUiState> =
        combine(item, identity()) { playable, identity ->
            WatermarkPolicy.evaluate(playable, identity, nowMs(), zoneOffsetMinutes, zoneAbbrev)
        }

    private fun identity(): Flow<UserIdentity?> =
        authStateStore.userSub.map { sub -> sub?.let { UserIdentity(userSub = it) } }
}
