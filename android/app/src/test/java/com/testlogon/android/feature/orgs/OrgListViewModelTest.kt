package com.testlogon.android.feature.orgs

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.feature.orgs.testing.FakeOrgsRepo
import com.testlogon.android.feature.orgs.testing.FakeSelectedOrgStore
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-361 - unit tests for [OrgListViewModel] (FR-1): load -> Content, empty -> Empty (distinct from
 * Error), failure -> Error, refresh()/retry(), and select() writing the existing SelectedOrgStore.
 *
 * REUSE: uses the existing AND-353 [FakeOrgsRepo] / [FakeSelectedOrgStore] (no new fakes). Uses runCurrent
 * (NOT advanceUntilIdle).
 */
class OrgListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun anOrg(id: String, role: OrgRole = OrgRole.MEMBER) =
        Org(orgId = id, name = "org-$id", callerRole = role)

    private fun vm(repo: FakeOrgsRepo, store: FakeSelectedOrgStore = FakeSelectedOrgStore()) =
        OrgListViewModel(repo, store)

    @Test
    fun load_success_emitsContent() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(
            orgsResult = ApiResult.Success(listOf(anOrg("a"), anOrg("b", OrgRole.OWNER))),
        )
        val sut = vm(repo)
        runCurrent()

        val state = sut.uiState.value
        assertTrue(state is OrgListUiState.Content)
        assertEquals(listOf("a", "b"), (state as OrgListUiState.Content).orgs.map { it.orgId })
        assertEquals(false, state.isRefreshing)
    }

    @Test
    fun load_emptyList_emitsEmpty_notError() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = ApiResult.Success(emptyList()))
        val sut = vm(repo)
        runCurrent()

        assertEquals(OrgListUiState.Empty, sut.uiState.value)
    }

    @Test
    fun load_failure_emitsError() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = FakeOrgsRepo.failure(status = 500))
        val sut = vm(repo)
        runCurrent()

        val state = sut.uiState.value
        assertTrue(state is OrgListUiState.Error)
        assertEquals(500, (state as OrgListUiState.Error).error.status)
    }

    @Test
    fun load_networkError_emitsError() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(
            orgsResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false),
        )
        val sut = vm(repo)
        runCurrent()

        val state = sut.uiState.value
        assertTrue(state is OrgListUiState.Error)
        assertEquals(ApiError.STATUS_NETWORK, (state as OrgListUiState.Error).error.status)
    }

    @Test
    fun refresh_reReadsAndUpdatesContent() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = ApiResult.Success(listOf(anOrg("a"))))
        val sut = vm(repo)
        runCurrent()

        repo.orgsResult = ApiResult.Success(listOf(anOrg("a"), anOrg("c")))
        sut.refresh()
        runCurrent()

        val state = sut.uiState.value
        assertTrue(state is OrgListUiState.Content)
        assertEquals(listOf("a", "c"), (state as OrgListUiState.Content).orgs.map { it.orgId })
        assertEquals(false, state.isRefreshing)
    }

    @Test
    fun refresh_failure_keepsCurrentContent() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = ApiResult.Success(listOf(anOrg("a"))))
        val sut = vm(repo)
        runCurrent()

        repo.orgsResult = FakeOrgsRepo.failure(status = 500)
        sut.refresh()
        runCurrent()

        val state = sut.uiState.value
        assertTrue(state is OrgListUiState.Content)
        assertEquals(listOf("a"), (state as OrgListUiState.Content).orgs.map { it.orgId })
        assertEquals(false, state.isRefreshing)
    }

    @Test
    fun retry_fromError_recoversToContent() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = FakeOrgsRepo.failure(status = 500))
        val sut = vm(repo)
        runCurrent()
        assertTrue(sut.uiState.value is OrgListUiState.Error)

        repo.orgsResult = ApiResult.Success(listOf(anOrg("a")))
        sut.retry()
        runCurrent()

        assertTrue(sut.uiState.value is OrgListUiState.Content)
    }

    @Test
    fun select_writesSelectedOrgStore() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = ApiResult.Success(listOf(anOrg("a"), anOrg("b"))))
        val store = FakeSelectedOrgStore()
        val sut = vm(repo, store)
        runCurrent()

        sut.select("b")
        runCurrent()

        assertEquals("b", store.storedId)
    }

    @Test
    fun select_blankId_isNoOp() = runTest(mainRule.dispatcher) {
        val repo = FakeOrgsRepo(orgsResult = ApiResult.Success(listOf(anOrg("a"))))
        val store = FakeSelectedOrgStore()
        val sut = vm(repo, store)
        runCurrent()

        sut.select("")
        runCurrent()

        assertNull(store.storedId)
    }
}
