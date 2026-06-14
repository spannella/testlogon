package com.testlogon.android.core.data.paywall

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-177 — read/write surface for the [EntitlementEntity] cache (paywall unlock entitlements).
 *
 * [isEntitled] drives the feed/detail reveal (a row => the post is rendered unlocked without a network
 * call). [clearForUser] wipes the previous principal's rows on logout/account switch so a shared device
 * cannot reveal another user's paid content (AND-177 §8 / AC-7).
 */
@Dao
interface EntitlementDao {

    @Query("SELECT EXISTS(SELECT 1 FROM entitlement WHERE user_sub = :userSub AND post_id = :postId)")
    fun isEntitled(userSub: String, postId: String): Flow<Boolean>

    @Query("SELECT post_id FROM entitlement WHERE user_sub = :userSub")
    fun observeEntitledPosts(userSub: String): Flow<List<String>>

    @Query("SELECT EXISTS(SELECT 1 FROM entitlement WHERE user_sub = :userSub AND post_id = :postId)")
    suspend fun exists(userSub: String, postId: String): Boolean

    @Upsert
    suspend fun upsert(entity: EntitlementEntity)

    @Query("DELETE FROM entitlement WHERE user_sub = :userSub")
    suspend fun clearForUser(userSub: String)
}
