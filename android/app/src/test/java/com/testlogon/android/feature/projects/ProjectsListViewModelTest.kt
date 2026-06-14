package com.testlogon.android.feature.projects

import androidx.paging.testing.asSnapshot
import com.squareup.moshi.Moshi
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.projects.ProjectListEnvelope
import com.testlogon.android.feature.projects.data.ProjectsRepositoryImpl
import com.testlogon.android.feature.projects.testing.FakeProjectsApi
import com.testlogon.android.feature.projects.testing.FakeProjectsApi.Companion.sampleProjectOut
import com.testlogon.android.feature.projects.ui.ProjectsListViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-376 - paging tests for [ProjectsListViewModel] (AC-6 / TC-12). The existing AND-374 suite covered the
 * detail ViewModel and the PagingSource in isolation, but NOT the LIST ViewModel's cursor-keyed Paging stream
 * end-to-end. Here the VM is driven by a REAL [ProjectsRepositoryImpl] whose Pager runs the real
 * ProjectsPagingSource over a [FakeProjectsApi], so [ProjectsListViewModel.items] is asserted via asSnapshot:
 * the second page is requested with the returned `cursor` and both pages are appended in order. A first-page
 * error surfaces (the list screen routes Paging LoadState.Error to re-auth / retry), asserted by the snapshot
 * throwing rather than crashing the VM.
 *
 * Cursor pagination: the first page returns a non-null `cursor`, the second returns `cursor:null` to terminate.
 * No nested runTest; the MainDispatcherRule supplies the dispatcher the cachedIn(viewModelScope) collects on.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ProjectsListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun repo(api: FakeProjectsApi) = ProjectsRepositoryImpl(
        api = api,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun items_pagingStream_appendsSecondPage_keyedOnReturnedCursor() = runTest {
        // Two cursor-keyed pages: page 1 -> cursor "cur2"; page 2 (fetched WITH cur2) -> cursor null (end).
        // FakeProjectsApi records (cursor, limit) BEFORE invoking the projects() lambda, so reading
        // api.listProjectsArgs.last() inside the lambda yields THIS request's cursor (null on the first page,
        // "cur2" on the append). The lambda captures `api` directly (it is not the lambda's receiver).
        val api = FakeProjectsApi()
        api.projects = {
            if (api.listProjectsArgs.last().first == null) {
                ProjectListEnvelope(
                    items = listOf(sampleProjectOut("p1"), sampleProjectOut("p2")),
                    cursor = "cur2",
                )
            } else {
                ProjectListEnvelope(
                    items = listOf(sampleProjectOut("p3"), sampleProjectOut("p4")),
                    cursor = null,
                )
            }
        }
        val vm = ProjectsListViewModel(repo(api))

        val snapshot = vm.items.asSnapshot { scrollTo(3) }

        assertEquals(listOf("p1", "p2", "p3", "p4"), snapshot.map { it.id })
        // the second (append) request carried the cursor returned by page 1
        assertTrue(api.listProjectsArgs.size >= 2)
        assertEquals(null, api.listProjectsArgs.first().first)
        assertTrue(api.listProjectsArgs.any { it.first == "cur2" })
    }

    @Test
    fun items_firstPageError_surfacesViaSnapshot_doesNotCrashViewModel() = runTest {
        val api = FakeProjectsApi(projects = { throw FakeProjectsApi.httpProjectError(500) })
        val vm = ProjectsListViewModel(repo(api))

        val error = runCatching { vm.items.asSnapshot { } }.exceptionOrNull()

        // The PagingSource folds the HTTP error to LoadResult.Error; asSnapshot rethrows it (the screen renders
        // a retry affordance from LoadState.Error). The VM construction itself never threw.
        assertTrue(error != null)
        assertEquals(1, api.listProjectsArgs.size)
    }
}
