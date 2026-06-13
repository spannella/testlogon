package com.testlogon.android.feature.tickets.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.feature.tickets.data.TicketsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-372 - drives the READ-ONLY ticket LIST within one space (screen 2 of the 3-screen flow).
 *
 * spaceId arrives as a nav arg via [SavedStateHandle] (survives process death). [tickets] is a network Paging-3
 * stream (cursor-keyed) cached in [viewModelScope] so a rotation does not re-fetch; the empty / error / loading
 * states come from Paging's LoadState at the UI and pull-to-refresh is LazyPagingItems.refresh(). Separately,
 * [spaceTitle] holds the space name for the top bar (a best-effort getSpace read - a failure leaves it null and
 * the screen falls back to a generic title). A TERMINAL 401 on the title read -> one-shot
 * [TicketsEffect.NavigateToLogin]. There is NO poll loop and NO mutation (composing is AND-373).
 */
@HiltViewModel
class TicketListViewModel @Inject constructor(
    private val repository: TicketsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val spaceId: String =
        checkNotNull(savedState[ARG_SPACE_ID]) { "missing $ARG_SPACE_ID nav arg" }

    /** The viewer's tickets in this space (network Paging-3); cached so a rotation does not re-fetch. */
    val tickets: Flow<PagingData<Ticket>> =
        repository.ticketsPager(spaceId).cachedIn(viewModelScope)

    private val _spaceTitle = MutableStateFlow<String?>(null)
    val spaceTitle: StateFlow<String?> = _spaceTitle.asStateFlow()

    private val _effects = Channel<TicketsEffect>(Channel.BUFFERED)
    val effects: Flow<TicketsEffect> = _effects.receiveAsFlow()

    init {
        loadTitle()
    }

    /** Best-effort space-name read for the top bar; a 401 routes to login, any other failure is tolerated. */
    private fun loadTitle() {
        viewModelScope.launch {
            when (val result = repository.getSpace(spaceId)) {
                is ApiResult.Success -> _spaceTitle.value = result.data.name
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(TicketsEffect.NavigateToLogin)
                    }
                is ApiResult.NetworkError -> Unit
            }
        }
    }

    companion object {
        const val ARG_SPACE_ID = "spaceId"

        private const val HTTP_UNAUTHORIZED = 401
    }
}
