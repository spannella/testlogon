package com.testlogon.android.feature.stories

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.stories.StoriesRepository
import com.testlogon.android.data.stories.StoryBarItem
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-199 — drives the horizontal stories tray rendered above the feed.
 *
 * Exposes the cached-then-restyled [StoriesRepository.trayFlow] as a [StateFlow] and refreshes the bar
 * on init and on viewer dismiss (web parity: invalidate on close). Ring styling is server `has_unseen`
 * OR-merged with the local viewed set inside the repository, so a ring restyles immediately on return.
 */
@HiltViewModel
class StoriesTrayViewModel @Inject constructor(
    private val repo: StoriesRepository,
) : ViewModel() {

    val tray: StateFlow<ApiResult<List<StoryBarItem>>> =
        repo.trayFlow().stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = ApiResult.Success(emptyList()),
        )

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch { repo.refreshTray() }
    }
}
