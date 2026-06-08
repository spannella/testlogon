package com.testlogon.android.feature.profile

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.auth.AuthRepository
import com.testlogon.android.data.auth.AuthStateStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ProfileUiState(
    val userSub: String? = null,
    val loggingOut: Boolean = false,
)

/**
 * Backs the authenticated Profile tab: shows the current principal and drives logout (AND-032).
 * Logout always resolves to the unauthenticated state; the nav gate (AppNavHost) then swaps graphs
 * once [AuthStateStore.isAuthenticated] flips to false.
 */
@HiltViewModel
class ProfileViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    authStateStore: AuthStateStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ProfileUiState(userSub = authStateStore.userSub.value))
    val uiState: StateFlow<ProfileUiState> = _uiState.asStateFlow()

    fun onLogout() {
        if (_uiState.value.loggingOut) return
        _uiState.update { it.copy(loggingOut = true) }
        viewModelScope.launch {
            authRepository.logout()
            // Navigation is driven by the auth-state flow; reset the flag for safety.
            _uiState.update { it.copy(loggingOut = false) }
        }
    }
}
