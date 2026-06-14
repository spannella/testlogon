package com.testlogon.android.feature.videos

import androidx.paging.testing.asSnapshot
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.videos.VideoPage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VideosViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeVideosRepository()

    @Test
    fun videos_emitsPagedItems_acrossTwoPages() = runTest {
        repo.pages[null] = ApiResult.Success(
            VideoPage(listOf(FakeVideosRepository.summary("v1"), FakeVideosRepository.summary("v2")), cursor = "c1"),
        )
        repo.pages["c1"] = ApiResult.Success(VideoPage(listOf(FakeVideosRepository.summary("v3")), cursor = null))

        val vm = VideosViewModel(repo)
        val ids = vm.videos.asSnapshot().map { it.id }
        assertEquals(listOf("v1", "v2", "v3"), ids)
    }
}
