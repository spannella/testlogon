package com.testlogon.android.data.messaging

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

/** AND-130/131 — MockWebServer contract tests for image presign/create + video-share + list. */
class MediaMessagingApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun presignImage_postsContentTypeFilename() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"upload_url":"https://s/x","bucket":"b","key":"conversations/c1/x.jpg",
                    "content_type":"image/jpeg"}""",
            ),
        )
        val resp = api().presignImage("c1", ImagePresignReq("image/jpeg", "photo.jpg"))
        assertEquals("b", resp.bucket)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/images/presign", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("image/jpeg", body["content_type"])
        assertEquals("photo.jpg", body["filename"])
    }

    @Test
    fun createImageMessage_postsBucketKey_decodesMessageOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m1","conversation_id":"c1","sender_id":"u1","created_at":100,
                    "kind":"image","image":{"bucket":"b","key":"conversations/c1/x.jpg",
                    "content_type":"image/jpeg","width":1536,"height":2048}}""",
            ),
        )
        val msg = api().createImageMessage(
            "c1",
            CreateImageMessageReq(bucket = "b", key = "conversations/c1/x.jpg", width = 1536, height = 2048),
        )
        assertEquals("image", msg.kind)
        assertEquals("conversations/c1/x.jpg", msg.image?.key)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/image", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("b", body["bucket"])
        assertEquals("conversations/c1/x.jpg", body["key"])
        assertEquals("image", body["kind"])
        assertNull(body["client_msg_id"]) // no idempotency key on the wire
    }

    @Test
    fun createVideoShare_postsVideoIdAndText_decodesVideoShare() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m2","conversation_id":"c1","sender_id":"u1","created_at":200,
                    "kind":"video_share","video_share":{"video_id":"vid_1","title":"Clip",
                    "thumbnail_url":"https://t/p.jpg","duration_seconds":42,"drm_enabled":false,
                    "hls_manifest_url":"https://h/m.m3u8","playback_token":"tok"}}""",
            ),
        )
        val msg = api().createVideoShareMessage("c1", CreateVideoShareReq(videoId = "vid_1", text = "look"))
        assertEquals("video_share", msg.kind)
        assertEquals("vid_1", msg.videoShare?.videoId)
        assertEquals("tok", msg.videoShare?.playbackToken)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/video-share", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("vid_1", body["video_id"])
        assertEquals("look", body["text"])
        assertNull(body["attachment_id"]) // corrected: no attachment_id/poster/dimensions
        assertNull(body["poster_url"])
    }

    @Test
    fun listMyVideos_sendsStatusQuery_decodesItems() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"video_id":"vid_1","title":"Clip","status":"published",
                    "visibility":"published","duration_seconds":42,"thumbnail_url":"t"}],"cursor":null}""",
            ),
        )
        val resp = api().listMyVideos(status = "published")
        assertEquals(1, resp.items.size)
        assertEquals("vid_1", resp.items[0].videoId)

        val req = backend.takeRequest()
        assertEquals("/ui/videos", req.requestUrl?.encodedPath)
        assertEquals("published", req.requestUrl?.queryParameter("status"))
    }
}
