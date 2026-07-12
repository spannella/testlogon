package com.testlogon.android.feature.admessaging.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.admessaging.data.AdMessagingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-511/601 (F5+F6) — the per-user "Allow promotional (ad) messages" opt-out toggle, hosted as a self-
 * contained section on the Message-Privacy settings screen.
 *
 * [allow] = true means the user RECEIVES ad DMs (from accounts they follow/subscribe to); turning it OFF
 * opts the user out — a relationship no longer results in ad DMs. Backed by GET/PUT
 * /ui/ads/messages/ad-preferences. Optimistic toggle with a revert-on-failure; a save in flight gates
 * further toggles. Kept OFF the giant MessagePrivacyViewModel so the existing pay-to-message form is
 * untouched.
 */
@HiltViewModel
class AdMessagePrefsViewModel @Inject constructor(
    private val repository: AdMessagingRepository,
) : ViewModel() {

    sealed interface State {
        data object Loading : State
        data class Loaded(val allow: Boolean, val saving: Boolean = false, val error: String? = null) : State
        data class Error(val message: String) : State
    }

    private val _state = MutableStateFlow<State>(State.Loading)
    val state: StateFlow<State> = _state.asStateFlow()

    init { load() }

    fun load() {
        _state.value = State.Loading
        viewModelScope.launch {
            _state.value = when (val result = repository.getAdPreferences()) {
                is ApiResult.Success -> State.Loaded(allow = result.data)
                is ApiResult.Failure -> State.Error(result.error.message)
                is ApiResult.NetworkError -> State.Error(OFFLINE)
            }
        }
    }

    fun onToggle(allow: Boolean) {
        val current = _state.value as? State.Loaded ?: return
        if (current.saving) return
        _state.value = current.copy(allow = allow, saving = true, error = null)
        viewModelScope.launch {
            when (val result = repository.setAdPreferences(allow)) {
                is ApiResult.Success -> _state.value = State.Loaded(allow = result.data)
                is ApiResult.Failure ->
                    _state.value = current.copy(allow = !allow, saving = false, error = result.error.message)
                is ApiResult.NetworkError ->
                    _state.value = current.copy(allow = !allow, saving = false, error = OFFLINE)
            }
        }
    }

    private companion object {
        const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
