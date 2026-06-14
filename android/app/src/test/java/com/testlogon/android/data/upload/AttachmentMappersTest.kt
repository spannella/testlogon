package com.testlogon.android.data.upload

import android.net.Uri
import org.junit.Assert.assertEquals
import org.junit.Test
import org.mockito.Mockito.mock

/**
 * AND-129 — pure tests for the uploader's request/response mappers (no Android I/O). A mocked [Uri]
 * is used only as an opaque token (never dereferenced), so these stay JVM-only.
 */
class AttachmentMappersTest {

    private val uri: Uri = mock(Uri::class.java)

    private fun request(
        confirmPath: String? = null,
        remotePath: String? = null,
    ) = UploadRequest(
        uri = uri,
        mimeType = "image/jpeg",
        category = "message",
        sizeBytes = 4096,
        displayName = "photo.jpg",
        presignPath = "messaging/conversations/c1/images/presign",
        confirmPath = confirmPath,
        remotePath = remotePath,
    )

    @Test
    fun toPresignBody_carriesMimeFilenamePath() {
        val body = request(remotePath = "/att/x.jpg").toPresignBody()
        assertEquals("image/jpeg", body.contentType)
        assertEquals("photo.jpg", body.filename)
        assertEquals("/att/x.jpg", body.path)
    }

    @Test
    fun toAttachmentRef_derivesS3Url_andUsesPresignKeyAsId() {
        val presign = PresignResponse(
            uploadUrl = "https://store/x?sig=1",
            bucket = "tl-media",
            key = "conversations/c1/x.jpg",
            contentType = "image/jpeg",
        )
        val ref = presign.toAttachmentRef(request(), confirm = null)
        assertEquals("conversations/c1/x.jpg", ref.id)
        assertEquals("tl-media", ref.bucket)
        assertEquals("https://tl-media.s3.amazonaws.com/conversations/c1/x.jpg", ref.url)
        // No confirm response -> fall back to the request size.
        assertEquals(4096L, ref.sizeBytes)
    }

    @Test
    fun toAttachmentRef_usesConfirmSize_whenPresent() {
        val presign = PresignResponse(
            uploadUrl = "https://store/x",
            bucket = "b",
            key = "k",
            contentType = "image/jpeg",
            ticketId = "tkt_1",
            path = "/att/x.jpg",
        )
        val confirm = ConfirmResponse(ok = true, size = 99999, contentType = "image/jpeg")
        val ref = presign.toAttachmentRef(request(confirmPath = "v1/fs/complete-upload"), confirm)
        assertEquals(99999L, ref.sizeBytes)
        assertEquals("tkt_1", ref.ticketId)
        assertEquals("/att/x.jpg", ref.remotePath)
    }

    @Test
    fun s3ObjectUrl_keepsSlashes_betweenSegments() {
        assertEquals(
            "https://b.s3.amazonaws.com/a/b/c.jpg",
            s3ObjectUrl("b", "a/b/c.jpg"),
        )
    }
}
