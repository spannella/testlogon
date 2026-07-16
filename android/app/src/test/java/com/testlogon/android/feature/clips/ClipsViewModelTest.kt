package com.testlogon.android.feature.clips

import androidx.paging.testing.asSnapshot
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.ClipsPage
import com.testlogon.android.feature.feed.FakeFeedBookmarkRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ClipsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeClipsRepository()
    private val bookmarks = FakeFeedBookmarkRepository()

    @Test
    fun clips_emitsPagedItems_acrossTwoPages() = runTest {
        repo.pages[null] = ApiResult.Success(
            ClipsPage(
                listOf(FakeClipsRepository.sampleClip("clp_1"), FakeClipsRepository.sampleClip("clp_2")),
                nextCursor = "cur2",
            ),
        )
        repo.pages["cur2"] = ApiResult.Success(
            ClipsPage(listOf(FakeClipsRepository.sampleClip("clp_3")), nextCursor = null),
        )
        val vm = ClipsViewModel(repo, bookmarks)
        val ids = vm.clips.asSnapshot().map { it.clipId }
        assertEquals(listOf("clp_1", "clp_2", "clp_3"), ids)
    }

    @Test
    fun toggleMute_flipsMuteState() = runTest {
        val vm = ClipsViewModel(repo, bookmarks)
        assertFalse(vm.ui.value.muted)
        vm.toggleMute()
        assertTrue(vm.ui.value.muted)
        vm.toggleMute()
        assertFalse(vm.ui.value.muted)
    }

    @Test
    fun setActivePage_mirrorsSettledPage() = runTest {
        val vm = ClipsViewModel(repo, bookmarks)
        assertEquals(0, vm.ui.value.activePage)
        vm.setActivePage(3)
        assertEquals(3, vm.ui.value.activePage)
    }

    @Test
    fun setMuted_setsExplicitValue() = runTest {
        val vm = ClipsViewModel(repo, bookmarks)
        vm.setMuted(true)
        assertTrue(vm.ui.value.muted)
    }
}
