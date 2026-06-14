package com.testlogon.android.data.feed

import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Minimal test [AuthStateStore]; only userSub is exercised by the comments repository. */
class FakeAuthStateStore(userSub: String? = null) : AuthStateStore {
    private val _userSub = MutableStateFlow(userSub)
    override val userSub: StateFlow<String?> = _userSub
    private val _authed = MutableStateFlow(userSub != null)
    override val isAuthenticated: StateFlow<Boolean> = _authed

    override suspend fun setAuthenticated(userSub: String) {
        _userSub.value = userSub
        _authed.value = true
    }

    override suspend fun clear(reason: LogoutReason) {
        _userSub.value = null
        _authed.value = false
    }

    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}
