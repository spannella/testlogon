package com.testlogon.android.feature.auth.passkey

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PasskeyRepository
import com.testlogon.android.data.auth.RegisteredPasskey
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-062 — passkey-registration UI state (Account/Security). */
sealed interface PasskeyRegisterUiState {
    data class Idle(val supported: Boolean) : PasskeyRegisterUiState
    data object InProgress : PasskeyRegisterUiState
    data class Success(val passkey: RegisteredPasskey) : PasskeyRegisterUiState
    data class Error(val message: String) : PasskeyRegisterUiState
}

/**
 * AND-062 — drives platform-passkey registration. Detects capability on init (Channel-free state),
 * and runs begin → Credential Manager → finish via [PasskeyRepository]. The trigger is disabled while
 * a ceremony is in flight; cancellation surfaces a non-blocking error and never persists state.
 */
@HiltViewModel
class PasskeyRegisterViewModel @Inject constructor(
    private val repository: PasskeyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<PasskeyRegisterUiState>(PasskeyRegisterUiState.Idle(supported = false))
    val uiState: StateFlow<PasskeyRegisterUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            _uiState.update { PasskeyRegisterUiState.Idle(supported = repository.isSupported()) }
        }
    }

    fun register(activity: Context, label: String?) {
        if (_uiState.value is PasskeyRegisterUiState.InProgress) return
        _uiState.update { PasskeyRegisterUiState.InProgress }
        viewModelScope.launch {
            when (val r = repository.registerPasskey(activity, label?.takeIf { it.isNotBlank() })) {
                is ApiResult.Success -> _uiState.update { PasskeyRegisterUiState.Success(r.data) }
                is ApiResult.Failure -> _uiState.update { PasskeyRegisterUiState.Error(r.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        PasskeyRegisterUiState.Error("Couldn't reach the server. Check your connection and try again.")
                    }
            }
        }
    }

    fun reset() {
        viewModelScope.launch {
            _uiState.update { PasskeyRegisterUiState.Idle(supported = repository.isSupported()) }
        }
    }
}
