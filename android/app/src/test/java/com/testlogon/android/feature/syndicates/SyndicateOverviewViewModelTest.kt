package com.testlogon.android.feature.syndicates

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.syndicates.testing.FakeSyndicateRepo
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewUiState
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewViewModel
import com.testlogon.android.feature.syndicates.ui.TabState
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-356 - tests for [SyndicateOverviewViewModel]: load -> Content with the derived role badge + both tab
 * snapshots; a 403 OR is_member==false -> NotMember (FR-7); a refresh failure KEEPS the last-good Content
 * with isStale=true (FR-6, in-memory). Uses runCurrent (NOT advanceUntilIdle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SyndicateOverviewViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private fun vm(repo: FakeSyndicateRepo, syndicateId: String = "syn_1") = SyndicateOverviewViewModel(
        repository = repo,
        imageUploader = com.testlogon.android.feature.feed.FakeCommentImageUploader(),
        arbitraryPollRepository = com.testlogon.android.feature.messaging.fakeArbitraryPollRepository(),
        adTracker = object : com.testlogon.android.data.ads.AdTrackRepository {
            override suspend fun track(
                event: com.testlogon.android.data.ads.AdEvent,
                ad: com.testlogon.android.data.feed.SponsoredInfo,
            ) = com.testlogon.android.core.model.ApiResult.Success(Unit)
            override suspend fun clickCta(
                adClickId: String,
                action: com.testlogon.android.data.ads.CtaAction,
            ) = com.testlogon.android.core.model.ApiResult.Success(Unit)
        },
        adAttribution = com.testlogon.android.data.ads.AdClickAttributionStore(),
        authStateStore = com.testlogon.android.data.auth.FakeAuthStateStore(),
        savedState = SavedStateHandle(mapOf(SyndicateOverviewViewModel.ARG_SYNDICATE_ID to syndicateId)),
    )

    private fun content(vm: SyndicateOverviewViewModel): SyndicateOverviewUiState.Content =
        vm.uiState.value as SyndicateOverviewUiState.Content

    @Test
    fun load_success_isContent_withAdminBadge_andTabs() = runTest {
        val vm = vm(FakeSyndicateRepo())
        runCurrent()

        val state = content(vm)
        assertEquals("Aces", state.overview.name)
        assertTrue(state.overview.isAdmin)
        assertFalse(state.isStale)
        assertTrue(state.treasury is TabState.Content)
        assertTrue(state.split is TabState.Content)
    }

    @Test
    fun load_isMemberFalse_isNotMember() = runTest {
        val repo = FakeSyndicateRepo(
            overviewResult = ApiResult.Success(
                SyndicateOverview(id = "syn_1", name = "Aces", isMember = false, currency = "USD"),
            ),
        )
        val vm = vm(repo)
        runCurrent()
        assertEquals(SyndicateOverviewUiState.NotMember, vm.uiState.value)
    }

    @Test
    fun load_403_isNotMember() = runTest {
        val repo = FakeSyndicateRepo(overviewResult = FakeSyndicateRepo.failure(status = 403))
        val vm = vm(repo)
        runCurrent()
        assertEquals(SyndicateOverviewUiState.NotMember, vm.uiState.value)
    }

    @Test
    fun load_404_isNotMember() = runTest {
        val repo = FakeSyndicateRepo(overviewResult = FakeSyndicateRepo.failure(status = 404))
        val vm = vm(repo)
        runCurrent()
        assertEquals(SyndicateOverviewUiState.NotMember, vm.uiState.value)
    }

    @Test
    fun load_nonForbiddenFailure_isError() = runTest {
        val repo = FakeSyndicateRepo(overviewResult = FakeSyndicateRepo.failure(status = 500))
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is SyndicateOverviewUiState.Error)
    }

    @Test
    fun refreshFailure_keepsLastGoodContent_andSetsStale() = runTest {
        val repo = FakeSyndicateRepo()
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is SyndicateOverviewUiState.Content)

        // a subsequent overview read fails with a non-403 error -> keep stale content
        repo.overviewResult = FakeSyndicateRepo.failure(status = 500)
        vm.refresh()
        runCurrent()

        val state = content(vm)
        assertTrue(state.isStale)
        assertEquals("Aces", state.overview.name)
    }

    @Test
    fun load_treasuryTabFailure_doesNotBlankScreen() = runTest {
        val repo = FakeSyndicateRepo(treasuryResult = FakeSyndicateRepo.failure(status = 500))
        val vm = vm(repo)
        runCurrent()

        val state = content(vm)
        // header + split still render; only the treasury tab is in error
        assertTrue(state.treasury is TabState.Error)
        assertTrue(state.split is TabState.Content)
    }
}
