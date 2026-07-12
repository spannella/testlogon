package com.testlogon.android.feature.wishlist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.wishlist.WishlistItem
import com.testlogon.android.data.wishlist.WishlistRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** ECOM — the Wishlist screen's load state; the item list itself streams from the shared repository. */
sealed interface WishlistUiState {
    data object Loading : WishlistUiState
    data class Content(val items: List<WishlistItem>) : WishlistUiState
    data class Error(val message: String) : WishlistUiState
}

/** ECOM — one-shot Wishlist effects. */
sealed interface WishlistEvent {
    data class RemoveFailed(val message: String) : WishlistEvent
}

/**
 * ECOM — presentation logic for the Wishlist screen (SHOP hub). Reads the shared [WishlistRepository]
 * list (so a heart toggle anywhere reflects here) and force-refreshes on init. Remove is optimistic in
 * the repository; a failure reverts and surfaces a snackbar.
 */
@HiltViewModel
class WishlistViewModel @Inject constructor(
    private val repository: WishlistRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<WishlistUiState>(WishlistUiState.Loading)
    val uiState: StateFlow<WishlistUiState> = _uiState.asStateFlow()

    private val _events = Channel<WishlistEvent>(Channel.BUFFERED)
    val events: Flow<WishlistEvent> = _events.receiveAsFlow()

    init {
        // Reflect the shared list immediately + on every subsequent change.
        repository.items
            .onEach { items ->
                _uiState.update { current ->
                    if (current is WishlistUiState.Error) current else WishlistUiState.Content(items)
                }
            }
            .launchIn(viewModelScope)
        refresh()
    }

    fun refresh() {
        if (_uiState.value !is WishlistUiState.Content) _uiState.update { WishlistUiState.Loading }
        viewModelScope.launch {
            when (val r = repository.refresh()) {
                is ApiResult.Success -> _uiState.update { WishlistUiState.Content(r.data) }
                is ApiResult.Failure ->
                    if (_uiState.value !is WishlistUiState.Content) {
                        _uiState.update { WishlistUiState.Error(r.error.message) }
                    }
                is ApiResult.NetworkError ->
                    if (_uiState.value !is WishlistUiState.Content) {
                        _uiState.update { WishlistUiState.Error(OFFLINE_MESSAGE) }
                    }
            }
        }
    }

    fun remove(item: WishlistItem) {
        viewModelScope.launch {
            when (val r = repository.remove(item.categoryId, item.itemId)) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> _events.send(WishlistEvent.RemoveFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(WishlistEvent.RemoveFailed(OFFLINE_MESSAGE))
            }
        }
    }

    companion object {
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
