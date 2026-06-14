package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.groups.testing.FakeGroupsRepo
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-355 - tests for [GroupsListViewModel]: load -> Content/Empty/Error over the {groups} ENVELOPE;
 * refresh keeps the cached list and surfaces a staleError banner on a refresh failure (instead of dropping
 * to a terminal Error). Uses runCurrent (NOT advanceUntilIdle) over a StandardTestDispatcher.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class GroupsListViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private fun group(id: String) = Group(id = id, name = "G-$id", myRole = GroupRole.MEMBER)

    private fun vm(repo: FakeGroupsRepo) = GroupsListViewModel(repository = repo)

    @Test
    fun load_success_populatesContent() = runTest {
        val repo = FakeGroupsRepo(myGroupsResult = ApiResult.Success(listOf(group("1"), group("2"))))
        val vm = vm(repo)
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is GroupsListUiState.Content)
        assertEquals(2, (state as GroupsListUiState.Content).groups.size)
    }

    @Test
    fun load_emptyList_isEmpty() = runTest {
        val repo = FakeGroupsRepo(myGroupsResult = ApiResult.Success(emptyList()))
        val vm = vm(repo)
        runCurrent()
        assertEquals(GroupsListUiState.Empty, vm.uiState.value)
    }

    @Test
    fun load_failure_isError() = runTest {
        val repo = FakeGroupsRepo(myGroupsResult = FakeGroupsRepo.failure(status = 500))
        val vm = vm(repo)
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is GroupsListUiState.Error)
        assertEquals(500, (state as GroupsListUiState.Error).error.status)
    }

    @Test
    fun refresh_failure_keepsCachedList_withStaleBanner() = runTest {
        val repo = FakeGroupsRepo(myGroupsResult = ApiResult.Success(listOf(group("1"))))
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is GroupsListUiState.Content)

        repo.myGroupsResult = FakeGroupsRepo.failure(status = 503)
        vm.refresh()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is GroupsListUiState.Content)
        val content = state as GroupsListUiState.Content
        // the cached list is retained; the failure surfaces as a stale banner, not a terminal error
        assertEquals(1, content.groups.size)
        assertFalse(content.isRefreshing)
        assertEquals(503, content.staleError?.status)
    }

    @Test
    fun refresh_success_clearsStaleBanner() = runTest {
        val repo = FakeGroupsRepo(myGroupsResult = ApiResult.Success(listOf(group("1"))))
        val vm = vm(repo)
        runCurrent()

        repo.myGroupsResult = ApiResult.Success(listOf(group("1"), group("2")))
        vm.refresh()
        runCurrent()

        val content = vm.uiState.value as GroupsListUiState.Content
        assertEquals(2, content.groups.size)
        assertNull(content.staleError)
        assertFalse(content.isRefreshing)
    }
}
