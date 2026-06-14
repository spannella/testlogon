package com.testlogon.android.feature.privacy

import android.net.Uri
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.privacy.ExportRequest
import com.testlogon.android.data.privacy.ExportStatus
import com.testlogon.android.data.privacy.PrivacyExportRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * AND-385 - a controllable [PrivacyExportRepository] fake for ViewModel tests. The cache flow is a settable
 * [MutableStateFlow]; network calls return preset results and record their invocations. Helper names are
 * distinct so none shadows an interface method.
 */
class FakePrivacyExportRepository(
    initial: List<ExportRequest> = emptyList(),
) : PrivacyExportRepository {

    val cache = MutableStateFlow(initial)

    var refreshResult: ApiResult<List<ExportRequest>> = ApiResult.Success(emptyList())
    var requestResult: ApiResult<ExportRequest> = ApiResult.Success(
        sample("exp_new", ExportStatus.PROCESSING),
    )
    var refreshOneResult: ApiResult<ExportRequest> = ApiResult.Success(
        sample("exp_new", ExportStatus.COMPLETED),
    )
    var downloadResult: ApiResult<Uri> = ApiResult.Failure(
        com.testlogon.android.core.model.ApiError(status = 500, message = "boom"),
    )

    var refreshCount = 0
    var requestCount = 0
    val refreshOneCalls = mutableListOf<String>()
    val downloadCalls = mutableListOf<String>()

    override fun observeRequests(): Flow<List<ExportRequest>> = cache

    override suspend fun refresh(): ApiResult<List<ExportRequest>> {
        refreshCount++
        (refreshResult as? ApiResult.Success)?.let { cache.value = it.data }
        return refreshResult
    }

    override suspend fun requestExport(categories: Map<String, Boolean>): ApiResult<ExportRequest> {
        requestCount++
        (requestResult as? ApiResult.Success)?.let { r ->
            cache.value = (cache.value.filterNot { it.id == r.data.id } + r.data)
        }
        return requestResult
    }

    override suspend fun refreshOne(requestId: String): ApiResult<ExportRequest> {
        refreshOneCalls += requestId
        (refreshOneResult as? ApiResult.Success)?.let { r ->
            cache.value = cache.value.map { if (it.id == requestId) r.data else it }
        }
        return refreshOneResult
    }

    override suspend fun download(requestId: String): ApiResult<Uri> {
        downloadCalls += requestId
        return downloadResult
    }

    override suspend fun clearCache() {
        cache.value = emptyList()
    }

    companion object {
        fun sample(
            id: String,
            status: ExportStatus,
            createdAtEpochMs: Long = 1_000L,
            downloadUrl: String? = if (status == ExportStatus.COMPLETED) "/d/$id" else null,
        ): ExportRequest = ExportRequest(
            id = id,
            status = status,
            createdAtEpochMs = createdAtEpochMs,
            downloadExpiresAtEpochMs = null,
            sizeBytes = if (status == ExportStatus.COMPLETED) 100L else null,
            downloadUrl = downloadUrl,
        )
    }
}
