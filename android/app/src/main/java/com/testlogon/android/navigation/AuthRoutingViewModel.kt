package com.testlogon.android.navigation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.auth.AuthStateProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * Bridges the observed [AuthStateProvider] into a lifecycle-aware flow the host can collect.
 *
 * WAVE 4 / AND-025+: this is where logout(), session-expiry handling, and pending-return-route
 * capture will be added once the real session source (AND-029) lands.
 */
@HiltViewModel
class AuthRoutingViewModel @Inject constructor(
    authStateProvider: AuthStateProvider,
) : ViewModel() {

    val isAuthenticated: StateFlow<Boolean> =
        authStateProvider.isAuthenticated.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = authStateProvider.isAuthenticated.value,
        )
}
