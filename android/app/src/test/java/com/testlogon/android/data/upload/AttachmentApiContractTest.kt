package com.testlogon.android.data.upload

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

/**
 * AND-129 — MockWebServer contract tests for [AttachmentApi]: @Url routing, the real presign/confirm
 * request bodies and decoded responses (fs presign/complete + image presign shapes).
 */
class AttachmentApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): AttachmentApi = backend.retrofit(moshi).create(AttachmentApi::class.java)

    @Test
    fun presign_imageRoute_sendsContentTypeAndFilename_decodesPresignOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"upload_url":"https://store/x?sig=1","bucket":"tl-media",
                    "key":"conversations/c1/x.jpg","content_type":"image/jpeg"}""",
            ),
        )
        val resp = api().presign(
            "messaging/conversations/c1/images/presign",
            PresignBody(contentType = "image/jpeg", filename = "photo.jpg"),
        )
        assertEquals("tl-media", resp.bucket)
        assertEquals("conversations/c1/x.jpg", resp.key)
        assertNull(resp.ticketId) // image presign has no ticket_id

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/images/presign", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("image/jpeg", body["content_type"])
        assertEquals("photo.jpg", body["filename"])
        assertNull(body["size_bytes"]) // corrected: presign carries no size/category
        assertNull(body["category"])
    }

    @Test
    fun presign_fsRoute_sendsPathAndContentType_decodesFullPresignOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"upload_url":"https://store/y","bucket":"tl-up","key":"att/y.jpg",
                    "ticket_id":"tkt_9","path":"/att/y.jpg","content_type":"image/jpeg"}""",
            ),
        )
        val resp = api().presign(
            "v1/fs/presign-upload",
            PresignBody(contentType = "image/jpeg", path = "/att/y.jpg"),
        )
        assertEquals("tkt_9", resp.ticketId)
        assertEquals("/att/y.jpg", resp.path)

        val body = backend.takeRequest().bodyJson()
        assertEquals("/att/y.jpg", body["path"])
        assertEquals("image/jpeg", body["content_type"])
    }

    @Test
    fun confirm_sendsCompleteUploadIn_decodesResult() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"path":"/att/y.jpg","size":482133,"content_type":"image/jpeg"}""",
            ),
        )
        val resp = api().confirm(
            "v1/fs/complete-upload",
            ConfirmBody(path = "/att/y.jpg", key = "att/y.jpg", ticketId = "tkt_9", contentType = "image/jpeg"),
        )
        assertEquals(true, resp.ok)
        assertEquals(482133L, resp.size)

        val req = backend.takeRequest()
        assertEquals("/v1/fs/complete-upload", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("att/y.jpg", body["key"])
        assertEquals("tkt_9", body["ticket_id"])
        assertEquals(false, body["encrypted"])
    }
}
