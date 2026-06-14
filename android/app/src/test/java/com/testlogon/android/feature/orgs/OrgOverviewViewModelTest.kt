package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.orgs.testing.FakeOrgsRepo
import com.testlogon.android.feature.orgs.testing.FakeSelectedOrgStore
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-354 - tests for [OrgOverviewViewModel]: load DERIVES the overview from listOrgs (the OrgOut row +
 * caller role) + listMembers().size; the stale banner (FR-9) is raised on a refresh failure with cached
 * content; Empty (no orgs) and Error (cache-less failure) surfaces. runCurrent (NOT advanceUntilIdle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OrgOverviewViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private val org = Org(orgId = "org_1", name = "Acme", callerRole = OrgRole.ADMIN)

    private fun ovMember(sub: String, role: OrgRole = OrgRole.MEMBER) =
        OrgMember(userSub = sub, role = role)

    private fun overviewVm(
        repo: FakeOrgsRepo,
        selected: String? = "org_1",
    ) = OrgOverviewViewModel(
        repository = repo,
        selectedOrgStore = FakeSelectedOrgStore(selected),
    )

    private fun loadedRepo(): FakeOrgsRepo = FakeOrgsRepo(
        orgsResult = ApiResult.Success(listOf(org)),
        membersResult = ApiResult.Success(listOf(ovMember("a"), ovMember("b"), ovMember("c"))),
    )

    private fun overviewContent(vm: OrgOverviewViewModel): OrgOverviewUiState.Content =
        vm.uiState.value as OrgOverviewUiState.Content

    @Test
    fun load_derivesContent_orgMemberCountAndCallerRole() = runTest {
        val vm = overviewVm(loadedRepo())
        runCurrent()
        val state = overviewContent(vm)
        assertEquals("org_1", state.org.orgId)
        assertEquals(3, state.memberCount)
        assertEquals(OrgRole.ADMIN, state.callerRole)
        assertTrue(state.canManage)
        assertFalse(state.isStale)
    }

    @Test
    fun load_noOrgs_isEmpty() = runTest {
        val repo = FakeOrgsRepo(orgsResult = ApiResult.Success(emptyList()))
        val vm = overviewVm(repo, selected = null)
        runCurrent()
        assertTrue(vm.uiState.value is OrgOverviewUiState.Empty)
    }

    @Test
    fun load_orgsFailure_noCache_isError() = runTest {
        val repo = FakeOrgsRepo(orgsResult = FakeOrgsRepo.failure(status = 500))
        val vm = overviewVm(repo)
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is OrgOverviewUiState.Error)
        assertEquals(500, (state as OrgOverviewUiState.Error).error.status)
    }

    @Test
    fun reload_failureWithCache_keepsContent_staleBanner() = runTest {
        val repo = loadedRepo()
        val vm = overviewVm(repo)
        runCurrent()
        assertFalse(overviewContent(vm).isStale)

        // a reload whose listOrgs now fails must KEEP the cached content with isStale = true (FR-9)
        repo.orgsResult = FakeOrgsRepo.failure(status = 503)
        vm.onRetry()
        runCurrent()

        val state = overviewContent(vm)
        assertTrue(state.isStale)
        assertEquals(3, state.memberCount)
    }
}
