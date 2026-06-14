package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.messaging.DraftDao
import com.testlogon.android.core.data.messaging.DraftEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-141 / AND-142 — DraftRepository round-trips: save (POST/PATCH), restore/reconcile (list GET),
 * clear (DELETE / local-only), 404-as-success. MockWebServer + in-memory DraftDao fake.
 */
class DraftRepositoryTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private fun api(): DraftApi = backend.retrofit(moshi).create(DraftApi::class.java)

    private class FakeDraftDao : DraftDao {
        val rows = MutableStateFlow<Map<String, DraftEntity>>(emptyMap())
        override fun observe(id: String): Flow<DraftEntity?> = rows.map { it[id] }
        override suspend fun get(id: String): DraftEntity? = rows.value[id]
        override suspend fun upsert(entity: DraftEntity) { rows.value = rows.value + (entity.conversationId to entity) }
        override suspend fun delete(id: String) { rows.value = rows.value - id }
        override suspend fun pending(): List<DraftEntity> = rows.value.values.filter { it.pendingSync }
        override suspend fun clear() { rows.value = emptyMap() }
    }

    private val dao = FakeDraftDao()

    private fun repo() = DraftRepositoryImpl(
        api = api(),
        draftDao = dao,
        errorParser = ApiErrorParser(moshi),
    ).also { it.clock = { 1_000L } }

    private fun draftJson(id: String = "drf_1", text: String = "hello", version: Int = 1, updatedAt: Long = 500) =
        """{"draft":{"draft_id":"$id","conversation_id":"c1","owner_user_id":"u1","text":"$text",
            "version":$version,"created_at":1,"updated_at":$updatedAt}}"""

    @Test
    fun saveDraft_writesLocalPending_thenPostsCreate_andClearsPending() = runTest {
        backend.enqueue(Fixtures.okBody(draftJson(), code = 201))
        val r = repo().saveDraft("c1", "hello")

        assertTrue(r is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/drafts", req.requestUrl?.encodedPath)
        // NOTE: RecordedRequest.body.readUtf8() consumes the buffer, so read bodyJson() ONCE.
        val body = req.bodyJson()
        assertEquals("hello", body["text"])
        // client_updated_at echoes the clock (1000 ms); JSON numbers decode as Double.
        assertEquals(1_000L, (body["client_updated_at"] as Number).toLong())
        // Idempotency-Key follows the "<cid>:<clientUpdatedAt>" pattern from the web client.
        assertEquals("c1:1000", req.getHeader("Idempotency-Key"))
        // After 201: remoteId/version set, pendingSync cleared.
        val row = dao.get("c1")!!
        assertEquals("drf_1", row.remoteId)
        assertFalse(row.pendingSync)
    }

    @Test
    fun saveDraft_withRemoteId_patches() = runTest {
        dao.upsert(DraftEntity("c1", "old", updatedAtEpochMs = 1, version = 1, remoteId = "drf_1", pendingSync = false))
        backend.enqueue(Fixtures.okBody(draftJson(text = "new", version = 2)))
        repo().saveDraft("c1", "new")

        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/messaging/conversations/c1/drafts/drf_1", req.requestUrl?.encodedPath)
        assertEquals("new", req.bodyJson()["text"])
        assertEquals(2, dao.get("c1")!!.version)
    }

    @Test
    fun saveDraft_blankText_deletesInsteadOfStoringEmpty() = runTest {
        dao.upsert(DraftEntity("c1", "x", updatedAtEpochMs = 1, version = 1, remoteId = "drf_1", pendingSync = false))
        backend.enqueue(Fixtures.okBody("", code = 204))
        repo().saveDraft("c1", "   ")

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/c1/drafts/drf_1", req.requestUrl?.encodedPath)
        assertNull(dao.get("c1"))
    }

    @Test
    fun saveDraft_networkFailure_keepsLocalPending() = runTest {
        backend.enqueue(Fixtures.timeout())
        val r = repo().saveDraft("c1", "hello")
        // Local write succeeds even though the network POST timed out.
        assertTrue(r is ApiResult.Success)
        val row = dao.get("c1")!!
        assertEquals("hello", row.text)
        assertTrue(row.pendingSync)
        assertNull(row.remoteId)
    }

    @Test
    fun clearDraft_localOnly_skipsServerCall() = runTest {
        dao.upsert(DraftEntity("c1", "x", updatedAtEpochMs = 1, version = 1, remoteId = null, pendingSync = true))
        val r = repo().clearDraft("c1")
        assertTrue(r is ApiResult.Success)
        assertNull(dao.get("c1"))
        assertEquals(0, backend.requestCount) // no DELETE for a local-only draft
    }

    @Test
    fun clearDraft_remote_issuesDelete() = runTest {
        dao.upsert(DraftEntity("c1", "x", updatedAtEpochMs = 1, version = 1, remoteId = "drf_1", pendingSync = false))
        backend.enqueue(Fixtures.okBody("", code = 204))
        repo().clearDraft("c1")
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/c1/drafts/drf_1", req.requestUrl?.encodedPath)
        assertNull(dao.get("c1"))
    }

    @Test
    fun clearDraft_404OnDelete_treatedAsSuccess() = runTest {
        dao.upsert(DraftEntity("c1", "x", updatedAtEpochMs = 1, version = 1, remoteId = "drf_1", pendingSync = false))
        backend.enqueue(Fixtures.error("\"gone\"", 404))
        val r = repo().clearDraft("c1")
        assertTrue(r is ApiResult.Success)
        assertNull(dao.get("c1"))
    }

    @Test
    fun loadAndReconcile_emptyList_returnsNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null}"""))
        val r = repo().loadAndReconcile("c1")
        assertTrue(r is ApiResult.Success)
        assertNull((r as ApiResult.Success).data)
    }

    @Test
    fun loadAndReconcile_serverNewer_overwritesRoom() = runTest {
        dao.upsert(DraftEntity("c1", "local", updatedAtEpochMs = 100, version = 1, remoteId = "drf_1", pendingSync = false))
        backend.enqueue(Fixtures.okBody("""{"items":[${draftRow(text = "server", updatedAt = 999)}],"next_cursor":null}"""))
        val r = repo().loadAndReconcile("c1")
        assertTrue(r is ApiResult.Success)
        assertEquals("server", dao.get("c1")!!.text)
        assertFalse(dao.get("c1")!!.pendingSync)
    }

    @Test
    fun loadAndReconcile_localNewer_keepsLocal_andPushes() = runTest {
        dao.upsert(DraftEntity("c1", "localnew", updatedAtEpochMs = 2_000, version = 1, remoteId = "drf_1", pendingSync = true))
        // list-GET returns an older server copy...
        backend.enqueue(Fixtures.okBody("""{"items":[${draftRow(text = "old", updatedAt = 10)}],"next_cursor":null}"""))
        // ...then the push PATCH succeeds.
        backend.enqueue(Fixtures.okBody(draftJson(text = "localnew", version = 2)))
        val r = repo().loadAndReconcile("c1")
        assertTrue(r is ApiResult.Success)
        assertEquals("localnew", dao.get("c1")!!.text)
    }

    @Test
    fun loadAndReconcile_networkFailure_fallsBackToLocal() = runTest {
        dao.upsert(DraftEntity("c1", "cached", updatedAtEpochMs = 5, version = 1, remoteId = null, pendingSync = true))
        backend.enqueue(Fixtures.timeout())
        val r = repo().loadAndReconcile("c1")
        assertTrue(r is ApiResult.Success)
        assertEquals("cached", (r as ApiResult.Success).data?.text)
    }

    @Test
    fun flushPending_pushesPendingRows() = runTest {
        dao.upsert(DraftEntity("c1", "pending", updatedAtEpochMs = 1, version = 1, remoteId = null, pendingSync = true))
        backend.enqueue(Fixtures.okBody(draftJson(text = "pending"), code = 201))
        repo().flushPending()
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertFalse(dao.get("c1")!!.pendingSync)
    }

    private fun draftRow(id: String = "drf_1", text: String, updatedAt: Long) =
        """{"draft_id":"$id","conversation_id":"c1","owner_user_id":"u1","text":"$text",
            "version":1,"created_at":1,"updated_at":$updatedAt}"""
}
