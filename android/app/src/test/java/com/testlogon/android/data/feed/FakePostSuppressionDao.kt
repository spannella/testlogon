package com.testlogon.android.data.feed

import com.testlogon.android.core.data.feed.PostSuppressionDao
import com.testlogon.android.core.data.feed.PostSuppressionEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

/** In-memory fake [PostSuppressionDao] for JVM unit tests of [PostActionsRepositoryImpl]. */
class FakePostSuppressionDao : PostSuppressionDao {
    private val rows = MutableStateFlow<List<PostSuppressionEntity>>(emptyList())

    override fun observeAll(): Flow<List<PostSuppressionEntity>> = rows

    override suspend fun getAll(): List<PostSuppressionEntity> = rows.value

    override suspend fun upsert(entity: PostSuppressionEntity) {
        rows.value = rows.value.filterNot { it.postId == entity.postId } + entity
    }

    override suspend fun setPending(postId: String, pending: Boolean) {
        rows.value = rows.value.map { if (it.postId == postId) it.copy(pending = pending) else it }
    }

    override suspend fun delete(postId: String) {
        rows.value = rows.value.filterNot { it.postId == postId }
    }

    override suspend fun purgeOlderThan(cutoffEpochMs: Long) {
        rows.value = rows.value.filter { it.createdAtEpochMs >= cutoffEpochMs }
    }

    fun snapshot(): List<PostSuppressionEntity> = rows.value
}
