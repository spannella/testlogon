package com.testlogon.android.feature.projects.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.feature.projects.data.ProjectsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

/**
 * AND-374 - drives the PROJECTS LIST (screen 1).
 *
 * [items] is a network Paging-3 stream (cursor-keyed) cached in [viewModelScope] so a rotation does not
 * re-fetch; the loading / empty / error / offline states come from Paging's LoadState at the UI and
 * pull-to-refresh is LazyPagingItems.refresh(). There is NO poll loop and NO mutation. A terminal 401 on a
 * page load surfaces as a Paging LoadState.Error at the UI (the list screen routes it to re-auth), mirroring
 * the AND-372 TicketListViewModel idiom.
 */
@HiltViewModel
class ProjectsListViewModel @Inject constructor(
    repository: ProjectsRepository,
) : ViewModel() {

    val items: Flow<PagingData<Project>> =
        repository.projectsPager().cachedIn(viewModelScope)
}
