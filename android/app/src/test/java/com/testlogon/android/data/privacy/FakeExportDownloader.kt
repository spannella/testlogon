package com.testlogon.android.data.privacy

import android.net.Uri
import com.testlogon.android.core.model.ApiError

/**
 * AND-385 - a recording [ExportDownloader] fake. Returns a preset outcome and records the requested id BEFORE
 * returning (so a test can assert the call even on failure). Avoids any real MediaStore / Uri parsing.
 */
class FakeExportDownloader(
    private val result: DownloadResult = DownloadResult.Failure(
        ApiError(status = 500, message = "boom"),
        retryable = true,
    ),
) : ExportDownloader {

    val requested = mutableListOf<String>()

    override suspend fun download(requestId: String): DownloadResult {
        requested += requestId
        return result
    }

    companion object {
        /** A success outcome with a stub content Uri (mockable without Robolectric via a no-op Uri). */
        fun success(uri: Uri): FakeExportDownloader =
            FakeExportDownloader(DownloadResult.Success(uri, displayName = "export.zip"))
    }
}
