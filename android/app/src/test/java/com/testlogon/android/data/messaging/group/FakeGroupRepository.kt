package com.testlogon.android.data.messaging.group

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Conversation
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.IOException

/** In-memory [GroupRepository] fake for ViewModel unit tests (AND-157/158/159). */
class FakeGroupRepository : GroupRepository {

    // ---- create ----
    var createCalls = mutableListOf<Triple<String?, List<String>, String?>>()
    var createResult: ApiResult<Conversation> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    override suspend fun createGroup(
        title: String?,
        participantIds: List<String>,
        icon: String?,
    ): ApiResult<Conversation> {
        createCalls += Triple(title, participantIds, icon)
        return createResult
    }

    // ---- roster ----
    private val roster = MutableStateFlow<GroupRoster?>(null)
    fun emitRoster(value: GroupRoster?) { roster.value = value }

    var refreshRosterResult: ApiResult<GroupRoster> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)
    var refreshCalls = 0

    var addCalls = mutableListOf<Pair<String, List<String>>>()
    var addResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var removeCalls = mutableListOf<Pair<String, String>>()
    var removeResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var changeRoleCalls = mutableListOf<Triple<String, String, GroupRole>>()
    var changeRoleResult: ApiResult<Unit> = ApiResult.Success(Unit)

    override fun observeRoster(conversationId: String): Flow<GroupRoster?> = roster

    override suspend fun refreshRoster(conversationId: String): ApiResult<GroupRoster> {
        refreshCalls++
        (refreshRosterResult as? ApiResult.Success)?.let { roster.value = it.data }
        return refreshRosterResult
    }

    override suspend fun addParticipants(
        conversationId: String,
        userIds: List<String>,
    ): ApiResult<Unit> {
        addCalls += conversationId to userIds
        return addResult
    }

    override suspend fun removeParticipant(conversationId: String, userId: String): ApiResult<Unit> {
        removeCalls += conversationId to userId
        return removeResult
    }

    override suspend fun changeRole(
        conversationId: String,
        userId: String,
        role: GroupRole,
    ): ApiResult<Unit> {
        changeRoleCalls += Triple(conversationId, userId, role)
        return changeRoleResult
    }

    // ---- settings ----
    var getSettingsResult: ApiResult<GroupSettings> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)
    var setMuteCalls = mutableListOf<Triple<String, Boolean, Long?>>()
    var setMuteResult: ApiResult<GroupSettings> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)
    var leaveCalls = 0
    var leaveResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var acceptCalls = 0
    var acceptResult: ApiResult<GroupSettings> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    override suspend fun getGroupSettings(conversationId: String): ApiResult<GroupSettings> =
        getSettingsResult

    override suspend fun setMute(
        conversationId: String,
        muted: Boolean,
        mutedUntilEpochSeconds: Long?,
    ): ApiResult<GroupSettings> {
        setMuteCalls += Triple(conversationId, muted, mutedUntilEpochSeconds)
        return setMuteResult
    }

    override suspend fun leaveGroup(conversationId: String): ApiResult<Unit> {
        leaveCalls++
        return leaveResult
    }

    override suspend fun acceptInvite(conversationId: String): ApiResult<GroupSettings> {
        acceptCalls++
        return acceptResult
    }

    var deleteCalls = mutableListOf<String>()
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)

    override suspend fun deleteConversation(conversationId: String): ApiResult<Unit> {
        deleteCalls += conversationId
        return deleteResult
    }
}
