package com.testlogon.android.data.subscriptions

import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** AND-234 — a minimal [AuthStateStore] test double seeded with a fixed user id (X-User-Id source). */
class FakeAuthStateStore(userSub: String? = "usr_me") : AuthStateStore {
    private val _userSub = MutableStateFlow(userSub)
    override val userSub: StateFlow<String?> = _userSub
    override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(userSub != null)

    fun setUser(userSub: String?) {
        _userSub.value = userSub
    }

    override suspend fun setAuthenticated(userSub: String) {
        _userSub.value = userSub
    }

    override suspend fun clear(reason: LogoutReason) {
        _userSub.value = null
    }

    override suspend fun lastLogoutReason(): LogoutReason? = null

    override suspend fun clearLogoutReason() = Unit
}
