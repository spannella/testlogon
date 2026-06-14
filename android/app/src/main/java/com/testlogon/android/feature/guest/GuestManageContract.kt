package com.testlogon.android.feature.guest

/**
 * AND-312 - UI state contract for the host-side guest MANAGE surface.
 *
 * Single flat state (no sealed split) because the screen always renders the invite card + guest list with an
 * inline error banner, mirroring the AND-310/311 inputs/layout transient-overlay style. [isStale] flags a
 * failed refresh over a warm in-memory cache; [inFlight] holds the row keys with an optimistic mutation in
 * progress (rendered non-interactive); [error] is a one-shot human-readable banner.
 */
data class GuestManageUiState(
    val guests: List<Guest> = emptyList(),
    val invite: GuestInvite? = null,
    val isLoading: Boolean = true,
    val isStale: Boolean = false,
    val inFlight: Set<String> = emptySet(),
    val error: String? = null,
)
