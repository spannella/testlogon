package com.testlogon.android.data.auth

import com.testlogon.android.core.model.LogoutReason
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** In-memory [AuthStateStore] for JVM tests. */
class FakeAuthStateStore : AuthStateStore {
    private val _authed = MutableStateFlow(false)
    private val _sub = MutableStateFlow<String?>(null)

    var setAuthenticatedCalls = 0
    var clearCalls = 0
    var lastClearReason: LogoutReason? = null
    private var storedReason: LogoutReason? = null

    override val isAuthenticated: StateFlow<Boolean> = _authed
    override val userSub: StateFlow<String?> = _sub

    override suspend fun setAuthenticated(userSub: String) {
        setAuthenticatedCalls++
        _sub.value = userSub
        _authed.value = true
    }

    override suspend fun clear(reason: LogoutReason) {
        clearCalls++
        lastClearReason = reason
        storedReason = reason
        _sub.value = null
        _authed.value = false
    }

    override suspend fun lastLogoutReason(): LogoutReason? = storedReason

    override suspend fun clearLogoutReason() {
        storedReason = null
    }
}
