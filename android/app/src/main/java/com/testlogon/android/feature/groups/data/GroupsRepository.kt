package com.testlogon.android.feature.groups.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.groups.GroupInviteIn
import com.testlogon.android.core.network.groups.GroupUpdateRoleIn
import com.testlogon.android.core.network.groups.GroupsApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-355 - data layer for the SOCIAL GROUPS surface (distinct from messaging group chats).
 *
 * REUSE: every call REUSES AND-355's [GroupsApi] (which returns RAW DTOs / Response<Unit>); this
 * repository unwraps the ENVELOPE responses ({groups}, {members,count}), maps the DTO to the core-model
 * domain BEFORE the typed [ApiResult], and wraps each call in [call] (mirrors AND-353 OrgsRepository). The
 * empty-body 200 mutations (invite / changeRole / removeMember / leave) are treated as
 * success-by-isSuccessful -> ApiResult.Success(Unit).
 *
 * There is NO Room / disk persistence (no migration) and NO poll loop here.
 */
interface GroupsRepository {

    /** GET the caller's groups (ENVELOPE {groups} -> mapped). Idempotent GET. */
    suspend fun listMyGroups(): ApiResult<List<Group>>

    /** GET one group's detail (mapped). Idempotent GET. */
    suspend fun getGroup(groupId: String): ApiResult<Group>

    /** GET one group's member roster (ENVELOPE {members,count} -> mapped). Idempotent GET. */
    suspend fun listMembers(groupId: String): ApiResult<List<GroupMember>>

    /** POST an invite (the invitee becomes status="invited" - a PENDING entry). 200/empty -> Success(Unit). */
    suspend fun invite(groupId: String, userId: String): ApiResult<Unit>

    /** PATCH a member's role (moderator|member only; admin is NOT assignable). 200/empty -> Success(Unit). */
    suspend fun changeRole(groupId: String, userId: String, role: GroupRole): ApiResult<Unit>

    /** DELETE a member. 200 -> Success(Unit). */
    suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit>

    /** POST leave (no body). 200 -> Success(Unit). */
    suspend fun leave(groupId: String): ApiResult<Unit>
}

@Singleton
class GroupsRepositoryImpl @Inject constructor(
    private val groupsApi: GroupsApi,
    private val errorParser: ApiErrorParser,
) : GroupsRepository {

    override suspend fun listMyGroups(): ApiResult<List<Group>> = withContext(Dispatchers.IO) {
        call { groupsApi.listMyGroups().groups.map { it.toDomain() } }
    }

    override suspend fun getGroup(groupId: String): ApiResult<Group> = withContext(Dispatchers.IO) {
        call { groupsApi.getGroup(groupId).toDomain() }
    }

    override suspend fun listMembers(groupId: String): ApiResult<List<GroupMember>> =
        withContext(Dispatchers.IO) {
            call { groupsApi.listMembers(groupId).members.map { it.toDomain() } }
        }

    override suspend fun invite(groupId: String, userId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { groupsApi.invite(groupId, GroupInviteIn(userId = userId)).requireSuccess() }
        }

    override suspend fun changeRole(
        groupId: String,
        userId: String,
        role: GroupRole,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call {
            // admin is NOT assignable here; the wire token is one of moderator|member.
            val token = role.wire?.takeIf { role != GroupRole.ADMIN } ?: GroupRole.MEMBER.wire!!
            groupsApi.changeRole(groupId, userId, GroupUpdateRoleIn(role = token)).requireSuccess()
        }
    }

    override suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { groupsApi.removeMember(groupId, userId).requireSuccess() }
        }

    override suspend fun leave(groupId: String): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call { groupsApi.leave(groupId).requireSuccess() }
    }

    /**
     * Folds an empty-body [Response] into Unit by HTTP success. A non-2xx response is rethrown as an
     * [HttpException] so [call] maps it to a Failure with the preserved status (mirrors how the typed
     * DTO calls surface errors).
     */
    private fun Response<Unit>.requireSuccess() {
        if (!isSuccessful) throw HttpException(this)
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. The
     * JsonEncodingException catch precedes the IOException catch (it is an IOException subtype).
     * Cancellation is re-thrown. Mirrors AND-353.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
