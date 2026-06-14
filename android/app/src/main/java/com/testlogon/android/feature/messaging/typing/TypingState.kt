package com.testlogon.android.feature.messaging.typing

import com.testlogon.android.data.messaging.realtime.MessagingEvent

/** AND-146 — one remote typer in the open conversation, with a wall-clock expiry for self-clearing. */
data class TypingUiUser(
    val userId: String,
    val displayName: String,
    val expiresAtMillis: Long,
)

/**
 * AND-146 — pure reducers for the "who is typing" map. Kept free of Android types / coroutines so the
 * apply/sweep/label logic is fully JVM-testable.
 */
object TypingReducer {

    /**
     * Applies an inbound [MessagingEvent.Typing] to [current]. `is_typing:false` removes the user
     * immediately; `is_typing:true` (re)adds them with a fresh expiry of now + [ttlMs]. The display
     * name is resolved via [resolveName] (falls back to [fallbackName] when unknown).
     */
    fun apply(
        current: Map<String, TypingUiUser>,
        event: MessagingEvent.Typing,
        nowMillis: Long,
        ttlMs: Long,
        fallbackName: String,
        resolveName: (userId: String) -> String?,
    ): Map<String, TypingUiUser> =
        if (!event.isTyping) {
            current - event.userId
        } else {
            current + (event.userId to TypingUiUser(
                userId = event.userId,
                displayName = resolveName(event.userId) ?: fallbackName,
                expiresAtMillis = nowMillis + ttlMs,
            ))
        }

    /** Removes entries whose expiry is at/after [nowMillis] (self-clearing on a dropped stop, FR-5). */
    fun sweepExpired(current: Map<String, TypingUiUser>, nowMillis: Long): Map<String, TypingUiUser> =
        current.filterValues { it.expiresAtMillis > nowMillis }

    /** Stable display ordering for the indicator label. */
    fun ordered(current: Map<String, TypingUiUser>): List<TypingUiUser> =
        current.values.sortedBy { it.displayName }
}

/**
 * AND-146 — what the typing indicator should render, independent of string resources (so the
 * branching is JVM-testable). The UI maps each case to the localized plural string.
 */
sealed interface TypingLabel {
    data object Hidden : TypingLabel
    data class One(val name: String) : TypingLabel
    data class Two(val first: String, val second: String) : TypingLabel
    data object Several : TypingLabel

    companion object {
        fun of(users: List<TypingUiUser>): TypingLabel = when (users.size) {
            0 -> Hidden
            1 -> One(users[0].displayName)
            2 -> Two(users[0].displayName, users[1].displayName)
            else -> Several
        }
    }
}
