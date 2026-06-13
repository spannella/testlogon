package com.testlogon.android.feature.share

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.share.data.ShareRepository
import com.testlogon.android.feature.share.model.PublicShare
import com.testlogon.android.feature.share.model.ShareLink
import com.testlogon.android.feature.share.model.ShareLinkOptions
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-335 - unit tests for [ShareSheetViewModel]. init lists; create maps + prepends + emits a copy event;
 * revoke is optimistic (row hidden) with rollback on failure; copy emits a clipboard event. MainDispatcher
 * Rule + runCurrent (NO advanceUntilIdle); backgroundScope.launch for event collection; org.junit.Test.
 */
class ShareSheetViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeShareRepo : ShareRepository {
        var listResult: ApiResult<List<ShareLink>> = ApiResult.Success(emptyList())
        var createResult: ApiResult<ShareLink> =
            ApiResult.Success(shareLink("new", "https://host/s/new"))
        var revokeResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var lastCreateOptions: ShareLinkOptions? = null

        override suspend fun listLinks(fileId: String): ApiResult<List<ShareLink>> = listResult
        override suspend fun createLink(
            fileId: String,
            options: ShareLinkOptions,
        ): ApiResult<ShareLink> {
            lastCreateOptions = options
            return createResult
        }
        override suspend fun revokeLink(linkId: String): ApiResult<Unit> = revokeResult
        override suspend fun resolvePublic(linkId: String, password: String?): ApiResult<PublicShare> =
            throw UnsupportedOperationException()
    }

    private fun vm(repo: ShareRepository): ShareSheetViewModel =
        ShareSheetViewModel(repo, SavedStateHandle(mapOf(ShareSheetViewModel.ARG_FILE_ID to "f1")))

    @Test
    fun init_listsLinksForFile() = runTest {
        val repo = FakeShareRepo().apply {
            listResult = ApiResult.Success(listOf(shareLink("a", "ua"), shareLink("b", "ub")))
        }
        val sheet = vm(repo)
        runCurrent()
        assertEquals(listOf("a", "b"), sheet.uiState.value.links.map { it.linkId })
        assertFalse(sheet.uiState.value.isLoading)
    }

    @Test
    fun create_prependsLink_andEmitsCopyEvent() = runTest {
        val repo = FakeShareRepo().apply {
            listResult = ApiResult.Success(listOf(shareLink("old", "uo")))
            createResult = ApiResult.Success(shareLink("new", "https://host/s/new"))
        }
        val sheet = vm(repo)
        runCurrent()

        val copied = mutableListOf<String>()
        backgroundScope.launch {
            sheet.events.collect { event ->
                if (event is ShareSheetEvent.CopyToClipboard) copied += event.url
            }
        }

        sheet.onExpiryChange(ExpiryPreset.SEVEN_DAYS)
        sheet.onMaxDownloadsChange(5)
        sheet.create()
        runCurrent()

        assertEquals(listOf("new", "old"), sheet.uiState.value.links.map { it.linkId })
        assertEquals(168, repo.lastCreateOptions?.expiryHours)
        assertEquals(5, repo.lastCreateOptions?.maxDownloads)
        assertTrue(copied.contains("https://host/s/new"))
    }

    @Test
    fun create_doubleSendGuarded() = runTest {
        val repo = FakeShareRepo()
        val sheet = vm(repo)
        runCurrent()
        sheet.create()
        // isCreating is set synchronously; a second call is a no-op while in flight.
        assertTrue(sheet.uiState.value.isCreating)
        sheet.create()
        runCurrent()
        assertFalse(sheet.uiState.value.isCreating)
    }

    @Test
    fun revoke_optimisticThenSuccess_dropsRow() = runTest {
        val repo = FakeShareRepo().apply {
            listResult = ApiResult.Success(listOf(shareLink("a", "ua"), shareLink("b", "ub")))
        }
        val sheet = vm(repo)
        runCurrent()

        sheet.revoke("a")
        // Optimistically hidden immediately.
        assertEquals(listOf("b"), sheet.uiState.value.visibleLinks.map { it.linkId })
        runCurrent()
        // Confirmed removal.
        assertEquals(listOf("b"), sheet.uiState.value.links.map { it.linkId })
    }

    @Test
    fun revoke_failure_rollsBack() = runTest {
        val repo = FakeShareRepo().apply {
            listResult = ApiResult.Success(listOf(shareLink("a", "ua")))
            revokeResult = ApiResult.Failure(ApiError(500, "boom"))
        }
        val sheet = vm(repo)
        runCurrent()

        sheet.revoke("a")
        runCurrent()
        // Row restored on failure.
        assertEquals(listOf("a"), sheet.uiState.value.visibleLinks.map { it.linkId })
        assertEquals("boom", sheet.uiState.value.error)
    }

    @Test
    fun copy_emitsClipboardEvent() = runTest {
        val repo = FakeShareRepo()
        val sheet = vm(repo)
        runCurrent()

        val copied = mutableListOf<String>()
        backgroundScope.launch {
            sheet.events.collect { event ->
                if (event is ShareSheetEvent.CopyToClipboard) copied += event.url
            }
        }
        sheet.copy(shareLink("z", "https://host/s/z"))
        runCurrent()
        assertTrue(copied.contains("https://host/s/z"))
    }
}

/** AND-335 - distinct fake-helper name (top-level so the nested fake can reference it too). */
private fun shareLink(id: String, url: String) = ShareLink(
    linkId = id,
    fileNodeId = "f1",
    shareUrl = url,
    expiresAt = null,
    maxDownloads = 1,
    downloadCount = 0,
    passwordProtected = false,
    createdAt = null,
    revoked = false,
)
