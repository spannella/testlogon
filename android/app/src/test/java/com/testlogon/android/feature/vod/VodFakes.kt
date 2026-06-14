package com.testlogon.android.feature.vod

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.VodCategory
import com.testlogon.android.data.vod.VodPage
import com.testlogon.android.data.vod.VodRepository
import com.testlogon.android.data.vod.VodSummary

/**
 * AND-191 — shared fake [VodRepository] for paging + ViewModel tests. Catalog pages are keyed by
 * "<category>|<cursor>" so different filters return different pages; categories is one result.
 */
class FakeVodRepository : VodRepository {

    val pages = mutableMapOf<String, ApiResult<VodPage>>()
    val requests = mutableListOf<String>()
    var categoriesResult: ApiResult<List<VodCategory>> = ApiResult.Success(emptyList())

    override suspend fun catalogPage(
        cursor: String?,
        limit: Int,
        category: String?,
        query: String?,
    ): ApiResult<VodPage> {
        val key = "${category.orEmpty()}|${cursor.orEmpty()}"
        requests += key
        return pages[key] ?: ApiResult.Success(VodPage(emptyList(), null))
    }

    override suspend fun categories(): ApiResult<List<VodCategory>> = categoriesResult

    companion object {
        fun summary(id: String) = VodSummary(id = id, title = "T-$id", thumbnailUrl = null, durationSec = 90)
    }
}
