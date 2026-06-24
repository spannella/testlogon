package com.testlogon.android.data.messaging.group

import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
import com.testlogon.android.core.data.messaging.ParticipantDao
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.data.messaging.ConversationDto
import com.testlogon.android.data.messaging.ParticipantDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-157 / AND-158 / AND-159 — data layer for group conversations: create, participant roster
 * management, and per-member settings (mute/leave/accept).
 *
 * Kept SEPARATE from the (closed, very large) MessagingRepository as the specs allow; reuses the
 * shared [ConversationDao] cache (so new/updated groups reflect in the AND-121 list immediately) and
 * adds a dedicated [ParticipantDao] roster cache (AND-158, offline-first + persist-across-restart).
 *
 * Failures fold into [ApiResult.Failure] / [ApiResult.NetworkError]; CancellationException is always
 * re-thrown. No member names / ids are logged.
 */
interface GroupRepository {

    // ---- AND-157: create ----

    /**
     * Create a group conversation with [participantIds] (>= 2, the current user is implicit), an
     * optional [title], and an optional [icon] ref. Upserts the returned conversation into the cache
     * so the list shows the new group at once. Non-idempotent (no auto-retry).
     */
    suspend fun createGroup(
        title: String?,
        participantIds: List<String>,
        icon: String? = null,
    ): ApiResult<Conversation>

    // ---- AND-158: participants ----

    /** Observable roster backed by the Room cache (offline-first; live updates on every write). */
    fun observeRoster(conversationId: String): Flow<GroupRoster?>

    /** Network refresh of the roster; replaces the cached rows transactionally on success. */
    suspend fun refreshRoster(conversationId: String): ApiResult<GroupRoster>

    /**
     * Add [userIds] to the group. The endpoint returns only {ok, added_count}; rows are obtained via a
     * follow-up [refreshRoster] (so authoritative role/joined_at are correct).
     */
    suspend fun addParticipants(conversationId: String, userIds: List<String>): ApiResult<Unit>

    /** Remove [userId] from the group (optimistic delete; rolled back on failure). */
    suspend fun removeParticipant(conversationId: String, userId: String): ApiResult<Unit>

    /** Change [userId]'s [role] (optimistic role update; rolled back on failure). */
    suspend fun changeRole(conversationId: String, userId: String, role: GroupRole): ApiResult<Unit>

    // ---- AND-159: settings ----

    /** Read the group settings (membership + mute) from the conversation GET; writes through to cache. */
    suspend fun getGroupSettings(conversationId: String): ApiResult<GroupSettings>

    /**
     * Mute/unmute. [mutedUntilEpochSeconds] null => "forever" (server persists a sentinel). The mute
     * endpoint has an empty 200, so we re-GET the conversation to reconcile the authoritative state.
     */
    suspend fun setMute(
        conversationId: String,
        muted: Boolean,
        mutedUntilEpochSeconds: Long?,
    ): ApiResult<GroupSettings>

    /** Leave the group (non-optimistic). On success removes the conversation from the cache. */
    suspend fun leaveGroup(conversationId: String): ApiResult<Unit>

    /** Accept a pending invite; re-GETs the conversation so membership flips to active. */
    suspend fun acceptInvite(conversationId: String): ApiResult<GroupSettings>
}

@Singleton
class GroupRepositoryImpl @Inject constructor(
    private val api: GroupApi,
    private val conversationDao: ConversationDao,
    private val participantDao: ParticipantDao,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
) : GroupRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    // ---- AND-157: create ----

    override suspend fun createGroup(
        title: String?,
        participantIds: List<String>,
        icon: String?,
    ): ApiResult<Conversation> = withContext(io) {
        when (
            val r = apiCall {
                api.createGroup(
                    CreateGroupRequest(
                        title = title?.takeIf { it.isNotBlank() },
                        participantIds = participantIds,
                        icon = icon?.takeIf { it.isNotBlank() },
                    ),
                )
            }
        ) {
            is ApiResult.Success -> {
                val dto = r.data
                conversationDao.upsertAll(listOf(dto.toCacheEntity()))
                ApiResult.Success(dto.toConversation())
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    // ---- AND-158: participants ----

    override fun observeRoster(conversationId: String): Flow<GroupRoster?> =
        participantDao.observe(conversationId).map { rows ->
            if (rows.isEmpty()) {
                null
            } else {
                val me = authStateStore.userSub.value
                val participants = rows.map { it.toDomain() }
                GroupRoster(
                    conversationId = conversationId,
                    participants = participants,
                    currentUserRole = deriveRole(participants, me),
                    currentUserId = me,
                )
            }
        }

    override suspend fun refreshRoster(conversationId: String): ApiResult<GroupRoster> =
        withContext(io) {
            // Prefer the dedicated /participants GET; if it yields nothing, fall back to the
            // conversation GET (the web app derives the roster from ConversationOut.participants).
            val participantsResult = apiCall { api.listParticipants(conversationId) }
            val dtos: List<ParticipantDto> = when (participantsResult) {
                is ApiResult.Success -> participantsResult.data
                is ApiResult.Failure -> return@withContext participantsResult
                is ApiResult.NetworkError -> return@withContext participantsResult
            }.ifEmpty {
                when (val convo = apiCall { api.getConversation(conversationId) }) {
                    is ApiResult.Success -> convo.data.participants
                    is ApiResult.Failure -> return@withContext convo
                    is ApiResult.NetworkError -> return@withContext convo
                }
            }
            val me = authStateStore.userSub.value
            val participants = dtos.map { it.toGroupParticipant() }
            participantDao.replaceRoster(
                conversationId,
                participants.map { it.toEntity(conversationId) },
            )
            ApiResult.Success(
                GroupRoster(
                    conversationId = conversationId,
                    participants = participants,
                    currentUserRole = deriveRole(participants, me),
                    currentUserId = me,
                ),
            )
        }

    override suspend fun addParticipants(
        conversationId: String,
        userIds: List<String>,
    ): ApiResult<Unit> = withContext(io) {
        when (
            val r = apiCall { api.addParticipants(conversationId, AddParticipantsRequest(userIds)) }
        ) {
            is ApiResult.Success -> {
                // Add returns only {ok, added_count} — refresh to obtain authoritative rows.
                refreshRoster(conversationId)
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun removeParticipant(
        conversationId: String,
        userId: String,
    ): ApiResult<Unit> = withContext(io) {
        // Optimistic delete; capture the prior row so we can roll back on failure.
        val priorRows = currentEntities(conversationId)
        participantDao.delete(conversationId, userId)
        when (val r = apiCall { api.removeParticipant(conversationId, userId) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> { participantDao.upsertAll(priorRows.filter { it.userId == userId }); r }
            is ApiResult.NetworkError -> { participantDao.upsertAll(priorRows.filter { it.userId == userId }); r }
        }
    }

    override suspend fun changeRole(
        conversationId: String,
        userId: String,
        role: GroupRole,
    ): ApiResult<Unit> = withContext(io) {
        val priorRole = currentEntities(conversationId).firstOrNull { it.userId == userId }?.role
        // Optimistic role flip via a targeted column update.
        participantDao.updateRole(conversationId, userId, role.wire().uppercase())
        when (
            val r = apiCall { api.changeRole(conversationId, userId, ChangeRoleRequest(role.wire())) }
        ) {
            is ApiResult.Success -> {
                // Apply the server-confirmed role (defends against an unexpected echo).
                participantDao.updateRole(conversationId, userId, r.data.role.uppercase())
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> { rollbackRole(conversationId, userId, priorRole); r }
            is ApiResult.NetworkError -> { rollbackRole(conversationId, userId, priorRole); r }
        }
    }

    // ---- AND-159: settings ----

    override suspend fun getGroupSettings(conversationId: String): ApiResult<GroupSettings> =
        withContext(io) {
            when (val r = apiCall { api.getConversation(conversationId) }) {
                is ApiResult.Success -> {
                    conversationDao.upsertAll(listOf(r.data.toCacheEntity()))
                    ApiResult.Success(r.data.toGroupSettings(authStateStore.userSub.value))
                }
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun setMute(
        conversationId: String,
        muted: Boolean,
        mutedUntilEpochSeconds: Long?,
    ): ApiResult<GroupSettings> = withContext(io) {
        val body = MuteRequest(
            muted = muted,
            mutedUntil = if (muted) mutedUntilEpochSeconds else 0L,
        )
        when (val r = apiCall { api.mute(conversationId, body) }) {
            is ApiResult.Success -> getGroupSettings(conversationId) // empty 200 -> re-read
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun leaveGroup(conversationId: String): ApiResult<Unit> = withContext(io) {
        when (val r = apiCall { api.leave(conversationId) }) {
            is ApiResult.Success -> {
                participantDao.clearForConversation(conversationId)
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure ->
                // A 404 (already left / gone) is benign — treat as success.
                if (r.error.status == HTTP_NOT_FOUND) ApiResult.Success(Unit) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun acceptInvite(conversationId: String): ApiResult<GroupSettings> =
        withContext(io) {
            when (val r = apiCall { api.accept(conversationId) }) {
                is ApiResult.Success -> getGroupSettings(conversationId) // re-read -> active
                is ApiResult.Failure ->
                    // 409 already-a-member -> coalesce to success by re-reading state.
                    if (r.error.status == HTTP_CONFLICT) getGroupSettings(conversationId) else r
                is ApiResult.NetworkError -> r
            }
        }

    // ---- helpers ----

    private suspend fun currentEntities(conversationId: String) =
        participantDao.observe(conversationId).first()

    private suspend fun rollbackRole(conversationId: String, userId: String, priorRole: String?) {
        if (priorRole != null) participantDao.updateRole(conversationId, userId, priorRole)
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    companion object {
        const val HTTP_NOT_FOUND = 404
        const val HTTP_CONFLICT = 409
    }
}

// ---- pure mappers (JVM-testable) ----

/**
 * AND-158 — derive the current user's role from the roster. Absent (or null user) => MEMBER, so the UI
 * fails closed to read-only; the server remains the authoritative gate.
 */
internal fun deriveRole(participants: List<GroupParticipant>, currentUserId: String?): GroupRole {
    if (currentUserId == null) return GroupRole.MEMBER
    return participants.firstOrNull { it.userId == currentUserId }?.role ?: GroupRole.MEMBER
}

/** AND-157/159 — ConversationDto -> domain Conversation (subset used by the list/cache). */
internal fun ConversationDto.toConversation(): Conversation = Conversation(
    id = conversationId,
    title = title?.takeIf { it.isNotBlank() }
        ?: participants.firstNotNullOfOrNull { it.displayName?.takeIf(String::isNotBlank) }
        ?: "Group",
    iconUrl = icon,
    lastMessagePreview = lastMessagePreview ?: lastMessage?.preview ?: lastMessage?.text,
    lastActivityEpochSeconds = lastMessageAt ?: createdAt,
    unreadCount = unreadCount,
)

/** AND-157/159 — ConversationDto -> Room cache entity (so the AND-121 list reflects the change). */
internal fun ConversationDto.toCacheEntity(): ConversationEntity {
    val c = toConversation()
    return ConversationEntity(
        conversationId = c.id,
        title = c.title,
        iconUrl = c.iconUrl,
        lastMessagePreview = c.lastMessagePreview,
        lastActivityEpochSeconds = c.lastActivityEpochSeconds,
        unreadCount = c.unreadCount,
    )
}

/** AND-159 — ConversationDto -> GroupSettings; membership derived from the current user's entry. */
internal fun ConversationDto.toGroupSettings(currentUserId: String?): GroupSettings {
    val self = participants.firstOrNull { it.userId == currentUserId }
    val membership = when {
        self == null -> MembershipStatus.UNKNOWN
        self.leftAt > 0L -> MembershipStatus.LEFT
        else -> when (self.status.lowercase()) {
            "active" -> MembershipStatus.ACTIVE
            "invited", "pending_approval", "pending" -> MembershipStatus.INVITED
            "left" -> MembershipStatus.LEFT
            else -> MembershipStatus.UNKNOWN
        }
    }
    // Conversation-level mute wins; fall back to the self participant's mute_until.
    val muteUntil = if (mutedUntil > 0L) mutedUntil else (self?.mutedUntil ?: 0L)
    return GroupSettings(
        conversationId = conversationId,
        title = title?.takeIf { it.isNotBlank() } ?: "Group",
        iconUrl = icon,
        membership = membership,
        mutedUntilEpochSeconds = muteUntil,
    )
}
