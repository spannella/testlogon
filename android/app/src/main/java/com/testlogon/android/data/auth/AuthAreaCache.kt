package com.testlogon.android.data.auth

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-045 — minimal in-memory last-known-good cache for the two auth-area reads (`/ui/me`,
 * `/ui/sessions`). Kept deliberately small (process-lifetime, no disk) per the "keep minimal"
 * scope; it lets screens render the previous snapshot behind a stale indicator instead of a blank
 * error when the flaky dev host is unreachable. Cleared on logout to prevent cross-identity leakage.
 */
@Singleton
class AuthAreaCache @Inject constructor() {

    @Volatile
    var me: User? = null
        private set

    @Volatile
    var sessions: List<SessionInfo>? = null
        private set

    fun putMe(user: User) { me = user }

    fun putSessions(rows: List<SessionInfo>) { sessions = rows }

    fun clear() {
        me = null
        sessions = null
    }
}
