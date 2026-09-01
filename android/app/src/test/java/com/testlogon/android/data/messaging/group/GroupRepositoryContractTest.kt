package com.testlogon.android.data.messaging.group

import com.testlogon.android.testutil.testMoshi

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
import com.testlogon.android.core.data.messaging.ParticipantDao
import com.testlogon.android.core.data.messaging.ParticipantEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-157/158/159 — contract tests for [GroupRepositoryImpl] against MockWebServer, asserting the
 * REAL wire contract: create body (`title`/`participant_ids`/`icon`, not name/avatar_url), add body
 * (`participant_ids`), role PATCH, remove DELETE, mute body (integer `muted_until`), leave/accept,
 * the conversation-cache upsert, and the participant roster cache write-through.
 */
class GroupRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = testMoshi()
    private val conversationDao = FakeConversationDao()
    private val participantDao = FakeParticipantDao()
    private val auth = FakeAuthStateStore()

    private fun repo(): GroupRepositoryImpl {
        val api = backend.retrofit(moshi).create(GroupApi::class.java)
        return GroupRepositoryImpl(
            api = api,
            conversationDao = conversationDao,
            participantDao = participantDao,
            errorParser = ApiErrorParser(moshi),
            authStateStore = auth,
        )
    }

    // ---- AND-157: create ----

    @Test
    fun createGroup_postsTitleAndParticipantIds_andUpsertsCache() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"conversation_id":"conv_1","type":"group","title":"Weekend Trip","icon":null,
                 "created_at":1749132151,"created_by":"usr_self","participant_count":3,"status":"active",
                 "participants":[{"user_id":"usr_self","role":"admin","status":"active"}],
                 "unread_count":0,"last_message":null}
                """.trimIndent(),
            ),
        )
        val result = repo().createGroup(title = "Weekend Trip", participantIds = listOf("u1", "u2"))

        assertTrue(result is ApiResult.Success)
        assertEquals("conv_1", (result as ApiResult.Success).data.id)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/group", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("Weekend Trip", body["title"])
        assertEquals(listOf("u1", "u2"), body["participant_ids"])
        assertFalse(body.containsKey("name"))
        assertFalse(body.containsKey("avatar_url"))
        // Cache upsert so the AND-121 list reflects the new group.
        assertEquals("conv_1", conversationDao.rows.value.single().conversationId)
    }

    @Test
    fun createGroup_422_isFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","participant_ids"],"msg":"too few","type":"value_error"}]""", 422),
        )
        val result = repo().createGroup(title = "x", participantIds = listOf("u1"))
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    // ---- AND-158: participants ----

    @Test
    fun refreshRoster_mapsParticipants_andWritesCache() = runTest {
        auth.setAuthenticated("usr_self")
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"user_id":"usr_self","role":"admin","status":"active","joined_at":1,"display_name":"Me"},
                  {"user_id":"u2","role":"member","status":"active","joined_at":2,"display_name":"Bri"}
                ]
                """.trimIndent(),
            ),
        )
        val result = repo().refreshRoster("conv_1")

        assertTrue(result is ApiResult.Success)
        val roster = (result as ApiResult.Success).data
        assertEquals(2, roster.participants.size)
        assertEquals(GroupRole.ADMIN, roster.currentUserRole) // derived from usr_self entry
        assertTrue(roster.canManage)
        assertEquals(2, participantDao.rowsFor("conv_1").size)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/conversations/conv_1/participants", req.requestUrl?.encodedPath)
    }

    @Test
    fun addParticipants_postsParticipantIds_thenRefreshes() = runTest {
        auth.setAuthenticated("usr_self")
        backend.enqueue(Fixtures.okBody("""{"ok":true,"added_count":2}"""))
        // Follow-up refresh: prefer /participants GET.
        backend.enqueue(
            Fixtures.okBody(
                """[{"user_id":"usr_self","role":"admin","status":"active"},
                   {"user_id":"u7","role":"member","status":"active"},
                   {"user_id":"u8","role":"member","status":"active"}]""",
            ),
        )
        val result = repo().addParticipants("conv_1", listOf("u7", "u8"))

        assertTrue(result is ApiResult.Success)
        val addReq = backend.takeRequest()
        assertEquals("POST", addReq.method)
        assertEquals("/messaging/conversations/conv_1/participants", addReq.requestUrl?.encodedPath)
        assertEquals(listOf("u7", "u8"), addReq.bodyJson()["participant_ids"])
        // Roster cache now contains the added members (from the follow-up refresh).
        assertEquals(3, participantDao.rowsFor("conv_1").size)
    }

    @Test
    fun changeRole_patchesRole_andUpdatesCache() = runTest {
        participantDao.seed("conv_1", entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.okBody("""{"ok":true,"role":"admin"}"""))
        val result = repo().changeRole("conv_1", "u2", GroupRole.ADMIN)

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/messaging/conversations/conv_1/participants/u2", req.requestUrl?.encodedPath)
        assertEquals("admin", req.bodyJson()["role"])
        assertEquals("ADMIN", participantDao.rowsFor("conv_1").single { it.userId == "u2" }.role)
    }

    @Test
    fun changeRole_403_rollsBack() = runTest {
        participantDao.seed("conv_1", entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val result = repo().changeRole("conv_1", "u2", GroupRole.ADMIN)

        assertTrue(result is ApiResult.Failure)
        // Optimistic flip rolled back to MEMBER.
        assertEquals("MEMBER", participantDao.rowsFor("conv_1").single { it.userId == "u2" }.role)
    }

    @Test
    fun removeParticipant_deletes_andRemovesFromCache() = runTest {
        participantDao.seed("conv_1", entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().removeParticipant("conv_1", "u2")

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/conv_1/participants/u2", req.requestUrl?.encodedPath)
        assertTrue(participantDao.rowsFor("conv_1").none { it.userId == "u2" })
    }

    @Test
    fun removeParticipant_500_rollsBack() = runTest {
        participantDao.seed("conv_1", entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val result = repo().removeParticipant("conv_1", "u2")

        assertTrue(result is ApiResult.Failure)
        // Optimistic delete rolled back.
        assertTrue(participantDao.rowsFor("conv_1").any { it.userId == "u2" })
    }

    // ---- AND-159: settings ----

    @Test
    fun getGroupSettings_derivesMembershipAndMute() = runTest {
        auth.setAuthenticated("usr_self")
        backend.enqueue(
            Fixtures.okBody(
                """
                {"conversation_id":"conv_1","type":"group","status":"active","title":"Eng",
                 "icon":null,"muted_until":0,"created_at":1,"created_by":"usr_self",
                 "participant_count":2,
                 "participants":[{"user_id":"usr_self","status":"active","role":"member","left_at":0,"muted_until":0}]}
                """.trimIndent(),
            ),
        )
        val result = repo().getGroupSettings("conv_1")

        assertTrue(result is ApiResult.Success)
        val s = (result as ApiResult.Success).data
        assertEquals(MembershipStatus.ACTIVE, s.membership)
        assertFalse(s.isMuted(nowSeconds = 100))
    }

    @Test
    fun setMute_postsIntegerMutedUntil_thenReReads() = runTest {
        auth.setAuthenticated("usr_self")
        backend.enqueue(Fixtures.okBody("")) // empty 200 for mute
        backend.enqueue(
            Fixtures.okBody(
                """{"conversation_id":"conv_1","type":"group","status":"active","title":"Eng","icon":null,
                   "muted_until":9999999999,"created_at":1,"created_by":"x","participant_count":1,
                   "participants":[{"user_id":"usr_self","status":"active","role":"member"}]}""",
            ),
        )
        val result = repo().setMute("conv_1", muted = true, mutedUntilEpochSeconds = 1717635600L)

        assertTrue(result is ApiResult.Success)
        val muteReq = backend.takeRequest()
        assertEquals("POST", muteReq.method)
        assertEquals("/messaging/conversations/conv_1/mute", muteReq.requestUrl?.encodedPath)
        val body = muteReq.bodyJson()
        assertEquals(true, body["muted"])
        // muted_until is an integer epoch (Moshi decodes JSON numbers to Double in the loose map).
        assertEquals(1717635600.0, body["muted_until"])
        assertTrue((result as ApiResult.Success).data.isMuted(nowSeconds = 100))
    }

    @Test
    fun leaveGroup_postsLeave_andClearsRoster() = runTest {
        participantDao.seed("conv_1", entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().leaveGroup("conv_1")

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/conv_1/leave", req.requestUrl?.encodedPath)
        assertTrue(participantDao.rowsFor("conv_1").isEmpty())
    }

    @Test
    fun acceptInvite_postsAccept_thenReReadsActive() = runTest {
        auth.setAuthenticated("usr_self")
        backend.enqueue(Fixtures.okBody("")) // accept empty 200
        backend.enqueue(
            Fixtures.okBody(
                """{"conversation_id":"conv_1","type":"group","status":"active","title":"Eng","icon":null,
                   "muted_until":0,"created_at":1,"created_by":"x","participant_count":1,
                   "participants":[{"user_id":"usr_self","status":"active","role":"member"}]}""",
            ),
        )
        val result = repo().acceptInvite("conv_1")

        assertTrue(result is ApiResult.Success)
        assertEquals(MembershipStatus.ACTIVE, (result as ApiResult.Success).data.membership)
        val acceptReq = backend.takeRequest()
        assertEquals("POST", acceptReq.method)
        assertEquals("/messaging/conversations/conv_1/accept", acceptReq.requestUrl?.encodedPath)
    }

    @Test
    fun acceptInvite_409_coalescedToSuccess() = runTest {
        auth.setAuthenticated("usr_self")
        backend.enqueue(Fixtures.error("""{"code":"already_member"}""", 409))
        backend.enqueue(
            Fixtures.okBody(
                """{"conversation_id":"conv_1","type":"group","status":"active","title":"Eng","icon":null,
                   "muted_until":0,"created_at":1,"created_by":"x","participant_count":1,
                   "participants":[{"user_id":"usr_self","status":"active","role":"member"}]}""",
            ),
        )
        val result = repo().acceptInvite("conv_1")
        assertTrue(result is ApiResult.Success)
    }

    // ---- derive role pure ----

    @Test
    fun deriveRole_absentUser_defaultsToMember() {
        val role = deriveRole(
            listOf(GroupParticipant("a", "A", null, GroupRole.ADMIN, 0)),
            currentUserId = "other",
        )
        assertEquals(GroupRole.MEMBER, role)
    }

    private fun entity(userId: String, role: String) = ParticipantEntity(
        conversationId = "conv_1", userId = userId, displayName = userId,
        avatarUrl = null, role = role, joinedAtEpochSeconds = 0,
    )

    // ---- in-memory fakes ----

    private class FakeConversationDao : ConversationDao {
        val rows = MutableStateFlow<List<ConversationEntity>>(emptyList())
        override fun observeAll(): Flow<List<ConversationEntity>> = rows
        override suspend fun upsertAll(items: List<ConversationEntity>) {
            val byId = rows.value.associateBy { it.conversationId }.toMutableMap()
            items.forEach { byId[it.conversationId] = it }
            rows.value = byId.values.toList()
        }
        override suspend fun findById(id: String): ConversationEntity? =
            rows.value.firstOrNull { it.conversationId == id }
        override suspend fun clearUnread(id: String) {
            rows.value = rows.value.map { if (it.conversationId == id) it.copy(unreadCount = 0) else it }
        }
        override fun observeUnreadConversationCount(): Flow<Int> =
            rows.map { list -> list.count { it.unreadCount > 0 } }
        override suspend fun deleteById(id: String) {
            rows.value = rows.value.filterNot { it.conversationId == id }
        }
        override suspend fun clear() { rows.value = emptyList() }
    }

    private class FakeParticipantDao : ParticipantDao {
        val rows = MutableStateFlow<List<ParticipantEntity>>(emptyList())

        fun rowsFor(id: String): List<ParticipantEntity> = rows.value.filter { it.conversationId == id }
        fun seed(id: String, vararg entities: ParticipantEntity) = runBlocking {
            upsertAll(entities.map { it.copy(conversationId = id) })
        }

        override fun observe(id: String): Flow<List<ParticipantEntity>> =
            rows.map { list -> list.filter { it.conversationId == id } }

        override suspend fun upsertAll(rowsIn: List<ParticipantEntity>) {
            val key = { e: ParticipantEntity -> e.conversationId to e.userId }
            val byKey = rows.value.associateBy(key).toMutableMap()
            rowsIn.forEach { byKey[key(it)] = it }
            rows.value = byKey.values.toList()
        }

        override suspend fun delete(id: String, userId: String) {
            rows.value = rows.value.filterNot { it.conversationId == id && it.userId == userId }
        }

        override suspend fun updateRole(id: String, userId: String, role: String) {
            rows.value = rows.value.map {
                if (it.conversationId == id && it.userId == userId) it.copy(role = role) else it
            }
        }

        override suspend fun clearForConversation(id: String) {
            rows.value = rows.value.filterNot { it.conversationId == id }
        }
    }
}
