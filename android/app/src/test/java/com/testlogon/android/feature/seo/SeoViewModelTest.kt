package com.testlogon.android.feature.seo

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.seo.data.ResourceType
import com.testlogon.android.feature.seo.data.SeoMetadata
import com.testlogon.android.feature.seo.data.SeoRepository
import com.testlogon.android.feature.seo.ui.SeoUiState
import com.testlogon.android.feature.seo.ui.SeoViewModel
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-400 - JVM tests for [SeoViewModel]: Loading->Content on success, Loading->Empty on an empty
 * payload, retryable Error on transport/5xx vs non-retryable on 422, and re-fetch via load().
 */
class SeoViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun metadata(title: String? = "Title") = SeoMetadata(
        resourceType = "profile",
        resourceId = "abc",
        available = true,
        title = title,
        description = "d",
        canonicalUrl = "https://x",
        siteName = "S",
        locale = "en_US",
        og = mapOf("og:title" to "T"),
        twitter = mapOf("twitter:card" to "summary"),
        image = "https://img",
        jsonLd = "{}",
    )

    private val empty = SeoMetadata(
        resourceType = "post", resourceId = "p", available = false,
        title = null, description = null, canonicalUrl = null, siteName = null,
        locale = null, og = emptyMap(), twitter = emptyMap(), image = null, jsonLd = null,
    )

    private class FakeRepo(var result: ApiResult<SeoMetadata>) : SeoRepository {
        val calls = mutableListOf<Triple<ResourceType, String, String?>>()
        override suspend fun metadata(type: ResourceType, id: String, secondaryId: String?): ApiResult<SeoMetadata> {
            calls += Triple(type, id, secondaryId)
            return result
        }
        override suspend fun metadataForPath(path: String): ApiResult<SeoMetadata> = result
    }

    private fun handle() = SavedStateHandle(
        mapOf(
            SeoViewModel.ARG_RESOURCE_TYPE to "profile",
            SeoViewModel.ARG_ID to "abc123",
        ),
    )

    @Test
    fun success_emitsContent() = runTest {
        val repo = FakeRepo(ApiResult.Success(metadata()))
        val vm = SeoViewModel(repo, handle())
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is SeoUiState.Content)
        assertEquals("Title", (state as SeoUiState.Content).metadata.title)
        assertEquals(Triple(ResourceType.PROFILE, "abc123", null), repo.calls.first())
    }

    @Test
    fun emptyPayload_emitsEmpty() = runTest {
        val vm = SeoViewModel(FakeRepo(ApiResult.Success(empty)), handle())
        advanceUntilIdle()
        assertTrue(vm.state.value is SeoUiState.Empty)
    }

    @Test
    fun serverError_emitsRetryableError() = runTest {
        val vm = SeoViewModel(FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom"))), handle())
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is SeoUiState.Error)
        assertTrue((state as SeoUiState.Error).retryable)
    }

    @Test
    fun validationError_emitsNonRetryableError() = runTest {
        val vm = SeoViewModel(FakeRepo(ApiResult.Failure(ApiError(status = 422, message = "field required"))), handle())
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is SeoUiState.Error)
        assertFalse((state as SeoUiState.Error).retryable)
        assertEquals("field required", state.message)
    }

    @Test
    fun networkError_emitsRetryableError() = runTest {
        val vm = SeoViewModel(FakeRepo(ApiResult.NetworkError(RuntimeException("offline"))), handle())
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is SeoUiState.Error)
        assertTrue((state as SeoUiState.Error).retryable)
    }

    @Test
    fun load_reFetches() = runTest {
        val repo = FakeRepo(ApiResult.Success(metadata()))
        val vm = SeoViewModel(repo, handle())
        advanceUntilIdle()
        vm.load()
        advanceUntilIdle()
        assertEquals(2, repo.calls.size)
        assertTrue(vm.state.value is SeoUiState.Content)
    }
}
