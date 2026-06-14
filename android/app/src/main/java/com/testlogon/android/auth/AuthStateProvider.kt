package com.testlogon.android.auth

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Minimal auth-state abstraction observed by the auth-gated router (AND-025).
 *
 * This is the seam between the navigation layer and the real session source. Wave 4 (AND-029)
 * replaces the default implementation with a DataStore + `getMe()`-backed one that reflects the
 * cookie session.
 */
interface AuthStateProvider {
    /** `true` when a session exists; `false` otherwise. Hot, replays the latest value. */
    val isAuthenticated: StateFlow<Boolean>
}

/**
 * TEMPORARY default implementation — always reports "not authenticated".
 *
 * WAVE 4 / AND-029: replace this with the real session-backed `AuthStateStore`-driven provider
 * (the Hilt binding in [com.testlogon.android.auth.AuthModule] should point at the real impl).
 * Kept here so the navigation layer compiles and the app boots into the unauthenticated graph.
 */
@Singleton
class DefaultAuthStateProvider @Inject constructor() : AuthStateProvider {
    private val _isAuthenticated = MutableStateFlow(false)
    override val isAuthenticated: StateFlow<Boolean> = _isAuthenticated.asStateFlow()
}
