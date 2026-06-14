package com.testlogon.android.core.model

/**
 * Why the session ended — surfaced on the login screen as an expiry banner (AND-044).
 *
 * Lives in `core-model` so the network layer (which raises the signal) and the feature/nav layers
 * (which render + route) can share it without a dependency cycle.
 */
enum class LogoutReason {
    /** Refresh failed after a 401 — the primary unrecoverable-expiry path. */
    SESSION_EXPIRED,

    /** Server explicitly invalidated the session (forward-compat; collapses to expired today). */
    SESSION_REVOKED,

    /** Explicit user logout. */
    USER_INITIATED,

    UNKNOWN,
    ;

    companion object {
        fun fromName(raw: String?): LogoutReason =
            entries.firstOrNull { it.name == raw } ?: UNKNOWN
    }
}
