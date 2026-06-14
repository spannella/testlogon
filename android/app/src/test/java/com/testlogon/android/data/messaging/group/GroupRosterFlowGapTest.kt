package com.testlogon.android.data.messaging.group

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
import com.testlogon.android.core.data.messaging.ParticipantDao
import com.testlogon.android.core.data.messaging.ParticipantEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-165 — GAP-FILL tests for AND-158 group membership that the existing [GroupRepositoryContractTest]
 * does NOT cover (it asserts DAO rows but never collects the [GroupRepository.observeRoster] flow, and
 * has no socket-timeout case):
 *  - membership mutations RE-EMIT through the observed `GroupRoster` cache flow (FR §6 re-emission),
 *  - a newly-synced member appears in the next emission (member-gain via sync; groups have no add POST),
 *  - a socket timeout on a mutation maps to a NetworkError (no 20s wait — short test client timeout).
 *
 * Reuses the shared MockWebServer harness + a real [GroupRepositoryImpl]; in-memory DAO fakes mirror the
 * production write paths so the observed flow is well-defined.
 */
class GroupRosterFlowGapTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val conversationDao = FakeConversationDao()
    private val participantDao = FakeParticipantDao()
    private val auth = FakeAuthStateStore().apply { runBlocking { setAuthenticated("usr_self") } }

    private fun repo(): GroupRepositoryImpl = GroupRepositoryImpl(
        api = backend.retrofit(moshi).create(GroupApi::class.java),
        conversationDao = conversationDao,
        participantDao = participantDao,
        errorParser = ApiErrorParser(moshi),
        authStateStore = auth,
    )

    @Test
    fun changeRole_reEmitsRosterFlow_withNewRole() = runTest {
        participantDao.seed("conv_1", entity("usr_self", "ADMIN"), entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.okBody("""{"ok":true,"role":"admin"}"""))
        val repo = repo()

        val before = repo.observeRoster("conv_1").firstNonNull()
        assertEquals(GroupRole.MEMBER, before.participants.single { it.userId == "u2" }.role)

        val r = repo.changeRole("conv_1", "u2", GroupRole.ADMIN)
        assertTrue(r is ApiResult.Success)

        val after = repo.observeRoster("conv_1").firstNonNull()
        assertEquals(GroupRole.ADMIN, after.participants.single { it.userId == "u2" }.role)
    }

    @Test
    fun removeMember_reEmitsRosterFlow_withoutMember() = runTest {
        participantDao.seed("conv_1", entity("usr_self", "ADMIN"), entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val repo = repo()

        assertEquals(2, repo.observeRoster("conv_1").firstNonNull().participants.size)
        assertTrue(repo.removeParticipant("conv_1", "u2") is ApiResult.Success)
        assertTrue(repo.observeRoster("conv_1").firstNonNull().participants.none { it.userId == "u2" })
    }

    @Test
    fun syncedMember_appearsInNextEmission() = runTest {
        val repo = repo()
        // Empty cache => null roster.
        assertNull(repo.observeRoster("conv_1").first())
        // Member gained via the DAO sync path (no add-member POST for groups).
        participantDao.seed("conv_1", entity("usr_self", "ADMIN"), entity("u7", "MEMBER"))
        val roster = repo.observeRoster("conv_1").firstNonNull()
        assertTrue(roster.participants.any { it.userId == "u7" })
    }

    @Test
    fun changeRole_socketTimeout_mapsToNetworkError_andRollsBack() = runTest {
        participantDao.seed("conv_1", entity("u2", "MEMBER"))
        backend.enqueue(Fixtures.timeout()) // NO_RESPONSE + 2s test read timeout
        val repo = repo()
        val r = repo.changeRole("conv_1", "u2", GroupRole.ADMIN)
        assertTrue(r is ApiResult.NetworkError)
        assertTrue((r as ApiResult.NetworkError).isTimeout)
        // Optimistic role flip rolled back to MEMBER (no phantom change).
        assertEquals(GroupRole.MEMBER, repo.observeRoster("conv_1").firstNonNull().participants.single().role)
    }

    // ---- helpers ----

    // observeRoster maps a MutableStateFlow, so first() reflects the latest cache state.
    private suspend fun Flow<GroupRoster?>.firstNonNull(): GroupRoster =
        requireNotNull(first()) { "expected a non-null roster" }

    private fun entity(userId: String, role: String) = ParticipantEntity(
        conversationId = "conv_1", userId = userId, displayName = userId,
        avatarUrl = null, role = role, joinedAtEpochSeconds = 0,
    )

    // ---- in-memory fakes (local to this gap suite; mirror production write paths) ----

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
        override suspend fun clear() { rows.value = emptyList() }
    }

    private class FakeParticipantDao : ParticipantDao {
        val rows = MutableStateFlow<List<ParticipantEntity>>(emptyList())

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
