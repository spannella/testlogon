package com.testlogon.android.feature.collaborations.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.collaborations.data.CollaborationsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

/**
 * AND-358 - drives the READ-ONLY collaborations LIST (network Paging-3).
 *
 * Exposes [items] as a cached [PagingData] flow so a rotation does not re-fetch; pull-to-refresh is driven by
 * LazyPagingItems.refresh() at the UI (the empty / error / loading states come from Paging's LoadState).
 * [viewerId] is the viewer's own user id (from [AuthStateStore]) so each row can render the viewer's own
 * percent share (split[viewerId]). There is NO poll loop and NO mutation (READ-ONLY).
 */
@HiltViewModel
class CollaborationsListViewModel @Inject constructor(
    repository: CollaborationsRepository,
    authStateStore: AuthStateStore,
) : ViewModel() {

    /** The viewer's own user id (may be null when unresolved); used to render each row's own share. */
    val viewerId: String? = authStateStore.userSub.value?.takeIf { it.isNotBlank() }

    /** The viewer's collaborations (network Paging-3); cached so a rotation does not re-fetch. */
    val items: Flow<PagingData<Collaboration>> =
        repository.listPager().cachedIn(viewModelScope)
}
