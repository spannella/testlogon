package com.testlogon.android.feature.delegates.testing

import com.testlogon.android.core.network.delegates.DelegateInviteOut
import com.testlogon.android.core.network.delegates.DelegateInviteRespondReq
import com.testlogon.android.core.network.delegates.DelegatesApi
import com.testlogon.android.core.network.delegates.ManagedCreatorOut
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-359 - an in-memory fake of [DelegatesApi] for app repository tests (NO Moshi).
 *
 * It also COUNTS how many times the network was hit (via [networkCallCount]) so a test can assert that
 * ENTER / EXIT perform NO network round-trip. The respond call RECORDS its args BEFORE honouring a
 * configured throw, so a test can assert the call happened even on the failure path. Configure [throwHttp]
 * to make the next call throw an [HttpException] with that status. Helper names are distinct and never
 * shadow an interface method.
 */
class FakeDelegatesApi(
    var managed: List<ManagedCreatorOut> = emptyList(),
    var invites: List<DelegateInviteOut> = emptyList(),
    var throwHttp: Int? = null,
) : DelegatesApi {

    /** Number of times ANY endpoint on this API was invoked - used to assert ENTER / EXIT hit no network. */
    var networkCallCount: Int = 0
        private set

    val respondCalls = mutableListOf<Pair<String, DelegateInviteRespondReq>>()

    private fun maybeThrow() {
        throwHttp?.let { status ->
            throw HttpException(
                Response.error<Any>(
                    status,
                    """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
                ),
            )
        }
    }

    override suspend fun listManagedCreators(): List<ManagedCreatorOut> {
        networkCallCount++
        maybeThrow()
        return managed
    }

    override suspend fun listInvites(): List<DelegateInviteOut> {
        networkCallCount++
        maybeThrow()
        return invites
    }

    override suspend fun respondInvite(
        inviteId: String,
        body: DelegateInviteRespondReq,
    ): Response<Unit> {
        networkCallCount++
        respondCalls += inviteId to body
        maybeThrow()
        return Response.success(Unit)
    }
}
