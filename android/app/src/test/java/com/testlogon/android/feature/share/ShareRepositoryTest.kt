package com.testlogon.android.feature.share

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.CreateShareLinkRequest
import com.testlogon.android.core.model.files.PublicDownloadRequest
import com.testlogon.android.core.model.files.PublicShareDto
import com.testlogon.android.core.model.files.RevokeShareLinkDto
import com.testlogon.android.core.model.files.ShareLinkListDto
import com.testlogon.android.core.model.files.ShareLinkOutDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.share.FileShareLinksApi
import com.testlogon.android.core.network.share.PublicShareApi
import com.testlogon.android.feature.share.data.ShareRepositoryImpl
import com.testlogon.android.feature.share.model.PublicShareState
import kotlinx.coroutines.test.runTest
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response

/**
 * AND-335 - unit tests for ShareRepositoryImpl with fake apis. listLinks filters by fileId; createLink
 * maps DTO -> domain; revoke maps to Unit; resolvePublic derives PublicShareState from the flags.
 */
class ShareRepositoryTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private class FakeOwnerApi(
        var list: ShareLinkListDto = ShareLinkListDto(),
        var created: ShareLinkOutDto = ShareLinkOutDto(link_id = "x", share_url = "u"),
        var revoke: RevokeShareLinkDto = RevokeShareLinkDto(ok = true, link_id = "x"),
    ) : FileShareLinksApi {
        var lastCreate: CreateShareLinkRequest? = null
        var lastRevoke: String? = null
        override suspend fun listLinks(): ShareLinkListDto = list
        override suspend fun createLink(body: CreateShareLinkRequest): ShareLinkOutDto {
            lastCreate = body
            return created
        }
        override suspend fun revokeLink(linkId: String): RevokeShareLinkDto {
            lastRevoke = linkId
            return revoke
        }
    }

    private class FakePublicApi(
        var info: PublicShareDto = PublicShareDto(link_id = "lnk"),
    ) : PublicShareApi {
        override suspend fun resolvePublic(linkId: String): PublicShareDto = info
        override suspend fun downloadPublic(
            linkId: String,
            body: PublicDownloadRequest,
        ): Response<ResponseBody> = Response.success("x".toResponseBody())
    }

    private fun repo(owner: FakeOwnerApi, public: FakePublicApi) =
        ShareRepositoryImpl(owner, public, errorParser)

    @Test
    fun listLinks_filtersByFileId() = runTest {
        val owner = FakeOwnerApi(
            list = ShareLinkListDto(
                links = listOf(
                    ShareLinkOutDto(link_id = "a", share_url = "ua", file_node_id = "f1"),
                    ShareLinkOutDto(link_id = "b", share_url = "ub", file_node_id = "f2"),
                    ShareLinkOutDto(link_id = "c", share_url = "uc", file_node_id = "f1"),
                ),
            ),
        )
        val result = repo(owner, FakePublicApi()).listLinks("f1")
        assertTrue(result is ApiResult.Success)
        val links = (result as ApiResult.Success).data
        assertEquals(listOf("a", "c"), links.map { it.linkId })
    }

    @Test
    fun createLink_mapsAndSendsOptions() = runTest {
        val owner = FakeOwnerApi(
            created = ShareLinkOutDto(
                link_id = "new",
                share_url = "https://host/s/new",
                expires_at = 1_700_000_000_000L,
                max_downloads = 3,
                password_protected = true,
            ),
        )
        val result = repo(owner, FakePublicApi()).createLink(
            fileId = "f1",
            options = com.testlogon.android.feature.share.model.ShareLinkOptions(
                expiryHours = 24,
                maxDownloads = 3,
                password = "secret",
            ),
        )
        assertTrue(result is ApiResult.Success)
        val link = (result as ApiResult.Success).data
        assertEquals("new", link.linkId)
        assertEquals("https://host/s/new", link.shareUrl)
        assertEquals(true, link.passwordProtected)
        assertEquals(1_700_000_000_000L, link.expiresAt?.toEpochMilli())
        // Options threaded into the request.
        assertEquals("f1", owner.lastCreate?.file_node_id)
        assertEquals(24, owner.lastCreate?.expiry_hours)
        assertEquals(3, owner.lastCreate?.max_downloads)
        assertEquals("secret", owner.lastCreate?.password)
    }

    @Test
    fun revoke_mapsToUnit() = runTest {
        val owner = FakeOwnerApi()
        val result = repo(owner, FakePublicApi()).revokeLink("lnk_9")
        assertTrue(result is ApiResult.Success)
        assertEquals("lnk_9", owner.lastRevoke)
    }

    @Test
    fun resolvePublic_derivesStateFromFlags() = runTest {
        suspend fun stateFor(dto: PublicShareDto): PublicShareState {
            val result = repo(FakeOwnerApi(), FakePublicApi(info = dto)).resolvePublic("lnk", null)
            return (result as ApiResult.Success).data.state
        }

        assertEquals(
            PublicShareState.AVAILABLE,
            stateFor(PublicShareDto(link_id = "l")),
        )
        assertEquals(
            PublicShareState.REVOKED,
            stateFor(PublicShareDto(link_id = "l", revoked = true, expired = true)),
        )
        assertEquals(
            PublicShareState.EXPIRED,
            stateFor(PublicShareDto(link_id = "l", expired = true)),
        )
        assertEquals(
            PublicShareState.EXHAUSTED,
            stateFor(PublicShareDto(link_id = "l", exhausted = true)),
        )
    }
}
