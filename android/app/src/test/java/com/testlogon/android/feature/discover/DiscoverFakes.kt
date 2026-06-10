package com.testlogon.android.feature.discover

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.DiscoverContent
import com.testlogon.android.data.discover.DiscoverRepository
import com.testlogon.android.data.discover.RecentSearch
import com.testlogon.android.data.discover.Recommendations
import com.testlogon.android.data.discover.RecommendationsRepository
import com.testlogon.android.data.discover.SearchFilters
import com.testlogon.android.data.discover.SearchHistoryRepository
import com.testlogon.android.data.discover.SearchRepository
import com.testlogon.android.data.discover.SearchResults
import com.testlogon.android.data.discover.TagPostPage
import com.testlogon.android.data.discover.TagRepository
import com.testlogon.android.data.feed.PostActionsRepository
import com.testlogon.android.core.model.ApiError
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

/** AND-182 — fake discover repository for ViewModel tests. */
class FakeDiscoverRepository : DiscoverRepository {
    var result: ApiResult<DiscoverContent> = ApiResult.Success(DiscoverContent(emptyList(), emptyList(), emptyList()))
    var cachedValue: DiscoverContent? = null
    var calls = 0
    override suspend fun getDiscover(): ApiResult<DiscoverContent> {
        calls++
        return result
    }
    override fun cached(): DiscoverContent? = cachedValue
    override fun clearCache() { cachedValue = null }
}

/** AND-184 — fake recommendations repository for ViewModel tests. */
class FakeRecommendationsRepository : RecommendationsRepository {
    var result: ApiResult<Recommendations> = ApiResult.Success(Recommendations(emptyList(), "for_you"))
    var cachedValue: Recommendations? = null
    var calls = 0
    override suspend fun getRecommendations(): ApiResult<Recommendations> {
        calls++
        return result
    }
    override fun cached(): Recommendations? = cachedValue
    override fun clearCache() { cachedValue = null }
}

/** AND-185 / AND-186 — fake search repository for ViewModel tests. */
class FakeSearchRepository : SearchRepository {
    var result: ApiResult<SearchResults> = ApiResult.Success(SearchResults("", emptyList()))
    var cachedByQuery: MutableMap<String, SearchResults> = mutableMapOf()
    val queries = mutableListOf<String>()
    /** AND-186 — records the `types` filter sent on each call (null = ALL). */
    val filterTypes = mutableListOf<String?>()
    override suspend fun search(query: String, filters: SearchFilters, limit: Int): ApiResult<SearchResults> {
        queries += query
        filterTypes += filters.toTypesParam()
        return result
    }
    override fun cached(query: String, filters: SearchFilters): SearchResults? = cachedByQuery[query]
    override fun clearCache() { cachedByQuery.clear() }
}

/** AND-186 — fake search-history repository (server-backed recent searches). */
class FakeSearchHistoryRepository : SearchHistoryRepository {
    /** Backing list, most-recent-first. */
    var items = mutableListOf<RecentSearch>()
    val recorded = mutableListOf<Pair<String, Int>>()
    val removed = mutableListOf<String>()
    var cleared = 0
    override suspend fun recent(limit: Int): List<RecentSearch> = items.toList()
    override suspend fun record(query: String, resultCount: Int) {
        val trimmed = query.trim()
        if (trimmed.length < SearchHistoryRepository.MIN_RECORD_LEN) return
        recorded += trimmed to resultCount
        items.removeAll { it.query.trim().lowercase() == trimmed.lowercase() }
        items.add(0, RecentSearch(id = "id-${recorded.size}", query = trimmed))
    }
    override suspend fun remove(id: String): ApiResult<Unit> {
        removed += id
        items.removeAll { it.id == id }
        return ApiResult.Success(Unit)
    }
    override suspend fun clear(): ApiResult<Unit> {
        cleared++
        items.clear()
        return ApiResult.Success(Unit)
    }
}

/** AND-183 — fake tag repository for paging-source tests. */
class FakeTagRepository : TagRepository {
    /** Map of cursor (null = first page) -> result. */
    var pages: MutableMap<String?, ApiResult<TagPostPage>> = mutableMapOf()
    val cursors = mutableListOf<String?>()
    override suspend fun getTagPage(tag: String, cursor: String?, limit: Int): ApiResult<TagPostPage> {
        cursors += cursor
        return pages[cursor] ?: ApiResult.Failure(ApiError(status = 404, message = "no page"))
    }
}

/** AND-175 — fake post-actions repository (only [notInterested] is exercised by recs). */
class FakePostActionsRepository : PostActionsRepository {
    val notInterestedIds = mutableListOf<String>()
    override val suppressed: Flow<Set<String>> = MutableStateFlow(emptySet())
    override suspend fun hide(postId: String): ApiResult<Unit> = ApiResult.Success(Unit)
    override suspend fun notInterested(postId: String): ApiResult<Unit> {
        notInterestedIds += postId
        return ApiResult.Success(Unit)
    }
    override suspend fun unhide(postId: String): ApiResult<Unit> = ApiResult.Success(Unit)
}
