package com.testlogon.android.core.data.messaging

import androidx.room.Dao
import androidx.room.Embedded
import androidx.room.Query
import androidx.room.Relation
import androidx.room.Transaction
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-115 / AND-121..124 — DAOs for the messaging cache + outbox.
 *
 * DAO round-trip behaviour is exercised by instrumented androidTest (Room needs an Android runtime),
 * never by JVM unit tests.
 */
@Dao
interface ConversationDao {

    @Query("SELECT * FROM conversations ORDER BY lastActivityEpochSeconds DESC, conversationId ASC")
    fun observeAll(): Flow<List<ConversationEntity>>

    @Upsert
    suspend fun upsertAll(items: List<ConversationEntity>)

    @Query("SELECT * FROM conversations WHERE conversationId = :id LIMIT 1")
    suspend fun findById(id: String): ConversationEntity?

    /** AND-125 — optimistic local read clear: zeroes the unread badge for one conversation. */
    @Query("UPDATE conversations SET unreadCount = 0 WHERE conversationId = :id")
    suspend fun clearUnread(id: String)

    /** AND-125 — reactive aggregate: number of conversations with a non-zero unread count. */
    @Query("SELECT COALESCE(SUM(CASE WHEN unreadCount > 0 THEN 1 ELSE 0 END), 0) FROM conversations")
    fun observeUnreadConversationCount(): Flow<Int>

    /**
     * Delete ONE conversation row from the local cache by id. Used by the thread-level
     * "Delete conversation" action (DELETE /messaging/conversations/{id}); the reactive
     * [observeAll] stream drops it from the list at once. No-op if the id is absent.
     */
    @Query("DELETE FROM conversations WHERE conversationId = :id")
    suspend fun deleteById(id: String)

    @Query("DELETE FROM conversations")
    suspend fun clear()
}

/**
 * AND-158 — DAO for the cached group roster. The roster is the single source of truth for the
 * participants UI: [observe] drives a live Flow; mutations write through (optimistic + reconcile) so
 * add/remove/role-change reflect immediately and survive process death.
 */
@Dao
interface ParticipantDao {

    /** Live roster for a conversation, admins first then by display name (stable order). */
    @Query(
        "SELECT * FROM group_participant WHERE conversationId = :id " +
            "ORDER BY role ASC, displayName ASC, userId ASC",
    )
    fun observe(id: String): Flow<List<ParticipantEntity>>

    @Upsert
    suspend fun upsertAll(rows: List<ParticipantEntity>)

    @Query("DELETE FROM group_participant WHERE conversationId = :id AND userId = :userId")
    suspend fun delete(id: String, userId: String)

    @Query("UPDATE group_participant SET role = :role WHERE conversationId = :id AND userId = :userId")
    suspend fun updateRole(id: String, userId: String, role: String)

    @Query("DELETE FROM group_participant WHERE conversationId = :id")
    suspend fun clearForConversation(id: String)

    /** Replace the entire roster for one conversation in a single transaction (refresh path). */
    @Transaction
    suspend fun replaceRoster(id: String, rows: List<ParticipantEntity>) {
        clearForConversation(id)
        upsertAll(rows)
    }
}

@Dao
interface MessageDao {

    @Query(
        "SELECT * FROM messages WHERE conversationId = :conversationId " +
            "ORDER BY createdAtEpochSeconds ASC, messageId ASC",
    )
    fun observeForConversation(conversationId: String): Flow<List<MessageEntity>>

    @Upsert
    suspend fun upsert(message: MessageEntity)

    @Upsert
    suspend fun upsertAll(messages: List<MessageEntity>)

    @Query("SELECT * FROM messages WHERE messageId = :messageId LIMIT 1")
    suspend fun findById(messageId: String): MessageEntity?

    /** AND-140 — set the per-user hide flag without rewriting the rest of the row (merge-safe). */
    @Query("UPDATE messages SET isHidden = :hidden WHERE messageId = :messageId")
    suspend fun setHidden(messageId: String, hidden: Boolean)

    /** AND-140 — set the pinned flag without rewriting the rest of the row. */
    @Query("UPDATE messages SET isPinned = :pinned WHERE messageId = :messageId")
    suspend fun setPinned(messageId: String, pinned: Boolean)

    /** AND-140 — pinned messages for a conversation (newest pin order is resolved by the repo). */
    @Query("SELECT * FROM messages WHERE conversationId = :conversationId AND isPinned = 1")
    suspend fun pinnedForConversation(conversationId: String): List<MessageEntity>
}

/** AND-141 — per-conversation composer draft cache (single source of truth for restore). */
@Dao
interface DraftDao {

    @Query("SELECT * FROM drafts WHERE conversationId = :id LIMIT 1")
    fun observe(id: String): Flow<DraftEntity?>

    @Query("SELECT * FROM drafts WHERE conversationId = :id LIMIT 1")
    suspend fun get(id: String): DraftEntity?

    @Upsert
    suspend fun upsert(entity: DraftEntity)

    @Query("DELETE FROM drafts WHERE conversationId = :id")
    suspend fun delete(id: String)

    @Query("SELECT * FROM drafts WHERE pendingSync = 1")
    suspend fun pending(): List<DraftEntity>

    @Query("DELETE FROM drafts")
    suspend fun clear()
}

@Dao
interface OutboxDao {

    @Query("SELECT * FROM outbox_messages WHERE conversationId = :conversationId ORDER BY createdAtEpochSeconds ASC")
    fun observe(conversationId: String): Flow<List<OutboxMessageEntity>>

    @Upsert
    suspend fun upsert(entry: OutboxMessageEntity)

    @Query("DELETE FROM outbox_messages WHERE clientId = :clientId")
    suspend fun delete(clientId: String)

    @Query("SELECT * FROM outbox_messages WHERE clientId = :clientId LIMIT 1")
    suspend fun findById(clientId: String): OutboxMessageEntity?

    /** AND-130 — update the live upload progress (0..100) of an optimistic image row. */
    @Query("UPDATE outbox_messages SET uploadPercent = :percent WHERE clientId = :clientId")
    suspend fun updateUploadPercent(clientId: String, percent: Int)
}

/** AND-135 — custom-emoji catalog cache. */
@Dao
interface CustomEmojiDao {

    @Query("SELECT * FROM custom_emoji ORDER BY shortcode ASC")
    fun observeAll(): Flow<List<CustomEmojiEntity>>

    @Upsert
    suspend fun upsertAll(items: List<CustomEmojiEntity>)

    @Query("DELETE FROM custom_emoji WHERE fetchedAt < :before")
    suspend fun deleteStale(before: Long)

    @Query("DELETE FROM custom_emoji")
    suspend fun clear()
}

/** AND-136 — a poll with its slots (Room @Relation). */
data class MeetingPollWithSlots(
    @Embedded val poll: MeetingPollEntity,
    @Relation(parentColumn = "pollId", entityColumn = "pollId")
    val slots: List<MeetingPollSlotEntity>,
)

/** AND-136 — meeting-poll cache. */
@Dao
interface MeetingPollDao {

    @Transaction
    @Query("SELECT * FROM meeting_polls WHERE pollId = :pollId LIMIT 1")
    fun observePoll(pollId: String): Flow<MeetingPollWithSlots?>

    @Transaction
    @Query("SELECT * FROM meeting_polls WHERE pollId = :pollId LIMIT 1")
    suspend fun observePollOnce(pollId: String): MeetingPollWithSlots?

    @Upsert
    suspend fun upsertPoll(poll: MeetingPollEntity)

    @Upsert
    suspend fun upsertSlots(slots: List<MeetingPollSlotEntity>)

    @Query("DELETE FROM meeting_poll_slots WHERE pollId = :pollId")
    suspend fun deleteSlots(pollId: String)

    /** Replace the poll + its slots atomically (server state is authoritative). */
    @Transaction
    suspend fun replacePoll(poll: MeetingPollEntity, slots: List<MeetingPollSlotEntity>) {
        upsertPoll(poll)
        deleteSlots(poll.pollId)
        upsertSlots(slots)
    }

    @Query("DELETE FROM meeting_polls")
    suspend fun clearPolls()

    @Query("DELETE FROM meeting_poll_slots")
    suspend fun clearSlots()
}
