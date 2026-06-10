package com.testlogon.android.data.paywall

import com.testlogon.android.core.data.paywall.EntitlementDao
import com.testlogon.android.core.data.paywall.EntitlementEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map

/** In-memory fake [EntitlementDao] for JVM unit tests of [PaywallRepositoryImpl]. */
class FakeEntitlementDao : EntitlementDao {
    private val rows = MutableStateFlow<List<EntitlementEntity>>(emptyList())

    override fun isEntitled(userSub: String, postId: String): Flow<Boolean> =
        rows.map { list -> list.any { it.userSub == userSub && it.postId == postId } }

    override fun observeEntitledPosts(userSub: String): Flow<List<String>> =
        rows.map { list -> list.filter { it.userSub == userSub }.map { it.postId } }

    override suspend fun exists(userSub: String, postId: String): Boolean =
        rows.value.any { it.userSub == userSub && it.postId == postId }

    override suspend fun upsert(entity: EntitlementEntity) {
        rows.value = rows.value.filterNot { it.userSub == entity.userSub && it.postId == entity.postId } + entity
    }

    override suspend fun clearForUser(userSub: String) {
        rows.value = rows.value.filterNot { it.userSub == userSub }
    }

    fun snapshot(): List<EntitlementEntity> = rows.value
}
