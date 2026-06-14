package com.testlogon.android.feature.files.download

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.files.download.CachedFile
import com.testlogon.android.data.files.download.DownloadRepository
import com.testlogon.android.data.files.download.DownloadStatus
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File

/**
 * AND-334 - unit tests for [FileActionsViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop - it collects the bounded [DownloadRepository.download]
 * flow, which terminates on its own. Tests drive with bounded runCurrent (the StandardTestDispatcher
 * from [MainDispatcherRule]) and NEVER advanceUntilIdle. The one-shot OpenFile channel is collected via
 * backgroundScope.launch. Distinct fake-helper names; the fake repo serves a configurable
 * Flow<DownloadStatus> (no nested runTest).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class FileActionsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    // ---- distinct fake-helper names ----

    private class FakeDownloadRepo(
        private val statuses: () -> Flow<DownloadStatus>,
    ) : DownloadRepository {
        var downloadCalls = 0
        override fun download(node: FileNode): Flow<DownloadStatus> {
            downloadCalls++
            return statuses()
        }
    }

    private fun fileNode(name: String = "report.bin", path: String = "/docs/report.bin") =
        FileNode(path = path, name = name, type = FileNodeType.FILE)

    private fun cachedFor(node: FileNode) = CachedFile(
        path = node.path,
        file = File("/tmp/${node.name}"),
        mimeType = "application/pdf",
        displayName = node.name,
    )

    private fun vm(repo: DownloadRepository): FileActionsViewModel =
        FileActionsViewModel(repository = repo, savedState = SavedStateHandle())

    @Test
    fun onDownload_progressesToSuccess_andEmitsOpenFileEvent() = runTest {
        val node = fileNode()
        val cached = cachedFor(node)
        val repo = FakeDownloadRepo {
            flow {
                emit(DownloadStatus.InProgress(bytesDownloaded = 0L, totalBytes = 10L))
                emit(DownloadStatus.InProgress(bytesDownloaded = 10L, totalBytes = 10L))
                emit(DownloadStatus.Success(cached))
            }
        }
        val model = vm(repo)

        val opened = mutableListOf<OpenFile>()
        val job = backgroundScope.launch { model.events.collect { opened += it } }

        model.onDownload(node)
        // immediately (before the collector runs) the VM marks InProgress.
        assertTrue(model.uiState.value is FileDownloadUiState.InProgress)

        runCurrent() // drains the bounded flow.
        val success = model.uiState.value as FileDownloadUiState.Success
        assertEquals(cached, success.cached)
        // the one-shot open-with event fired with the same cached file.
        assertEquals(listOf(OpenFile(cached)), opened)
        assertEquals(1, repo.downloadCalls)
        job.cancel()
    }

    @Test
    fun onDownload_intermediateProgress_isProjectedToUiState() = runTest {
        val node = fileNode()
        // a single InProgress that never terminates (a held flow) so we can observe the projection.
        val gate = CompletableDeferred<Unit>()
        val repo = FakeDownloadRepo {
            flow {
                emit(DownloadStatus.InProgress(bytesDownloaded = 5L, totalBytes = 10L))
                gate.await() // park so no terminal status arrives.
            }
        }
        val model = vm(repo)

        model.onDownload(node)
        runCurrent()
        val inProgress = model.uiState.value as FileDownloadUiState.InProgress
        assertEquals(5L, inProgress.bytesDownloaded)
        assertEquals(10L, inProgress.totalBytes)
        assertEquals(0.5f, inProgress.fraction)
        gate.complete(Unit) // release the parked collector so the test scope can finish.
    }

    @Test
    fun onCancel_whileInFlight_marksCancelled_andNoOpenFile() = runTest {
        val node = fileNode()
        val gate = CompletableDeferred<Unit>()
        val repo = FakeDownloadRepo {
            flow {
                emit(DownloadStatus.InProgress(bytesDownloaded = 1L, totalBytes = null))
                gate.await() // hold the download open.
            }
        }
        val model = vm(repo)

        val opened = mutableListOf<OpenFile>()
        val job = backgroundScope.launch { model.events.collect { opened += it } }

        model.onDownload(node)
        runCurrent()
        assertTrue(model.uiState.value is FileDownloadUiState.InProgress)

        model.onCancel()
        runCurrent()
        assertEquals(FileDownloadUiState.Cancelled, model.uiState.value)
        // a cancelled download never opens.
        assertTrue(opened.isEmpty())
        gate.complete(Unit)
        job.cancel()
    }

    @Test
    fun onDownload_failure_setsErrorState_withRetryableFlag() = runTest {
        val repo = FakeDownloadRepo {
            flow {
                emit(DownloadStatus.InProgress(bytesDownloaded = 0L, totalBytes = null))
                emit(DownloadStatus.Failed(ApiError(status = 503, message = "down"), retryable = true))
            }
        }
        val model = vm(repo)

        model.onDownload(fileNode())
        runCurrent()
        val error = model.uiState.value as FileDownloadUiState.Error
        assertEquals("down", error.message)
        assertTrue(error.retryable)
    }

    @Test
    fun onSaveToDownloads_returnsCached_onlyAfterSuccess() = runTest {
        val node = fileNode()
        val cached = cachedFor(node)
        val repo = FakeDownloadRepo {
            flow { emit(DownloadStatus.Success(cached)) }
        }
        val model = vm(repo)

        // before any download there is nothing to save.
        assertNull(model.onSaveToDownloads())

        model.onDownload(node)
        runCurrent()
        assertEquals(cached, model.onSaveToDownloads())
    }
}
