package com.testlogon.android.data.bookmarks

import com.testlogon.android.core.data.feed.BookmarkStateDao
import com.testlogon.android.core.data.feed.BookmarkStateEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map

/** In-memory fake [BookmarkStateDao] for JVM unit tests of [FeedBookmarkRepositoryImpl]. */
class FakeBookmarkStateDao : BookmarkStateDao {
    private val rows = MutableStateFlow<List<BookmarkStateEntity>>(emptyList())

    override fun observeIds(): Flow<List<String>> = rows.map { list -> list.map { it.contentId } }

    override fun observeIdsForType(type: String): Flow<List<String>> =
        rows.map { list -> list.filter { it.contentType == type }.map { it.contentId } }

    override fun isBookmarked(type: String, id: String): Flow<Boolean> =
        rows.map { list -> list.any { it.contentType == type && it.contentId == id } }

    override suspend fun find(type: String, id: String): BookmarkStateEntity? =
        rows.value.firstOrNull { it.contentType == type && it.contentId == id }

    override suspend fun upsert(entity: BookmarkStateEntity) {
        rows.value = rows.value.filterNot { it.contentType == entity.contentType && it.contentId == entity.contentId } + entity
    }

    override suspend fun setPending(type: String, id: String, pending: Boolean) {
        rows.value = rows.value.map {
            if (it.contentType == type && it.contentId == id) it.copy(pending = pending) else it
        }
    }

    override suspend fun delete(type: String, id: String) {
        rows.value = rows.value.filterNot { it.contentType == type && it.contentId == id }
    }

    fun snapshot(): List<BookmarkStateEntity> = rows.value
}
