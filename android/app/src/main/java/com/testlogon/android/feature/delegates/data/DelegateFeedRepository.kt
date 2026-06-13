package com.testlogon.android.feature.delegates.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.DelegatePermission
import com.testlogon.android.core.model.delegates.canPostFeed
import com.testlogon.android.core.model.delegates.canReadFeed
import com.testlogon.android.core.network.delegates.DelegateFeedApi
import com.testlogon.android.core.network.delegates.DelegatedPostCreateIn
import com.testlogon.android.core.network.delegates.DelegatedPostOut
import com.testlogon.android.core.network.error.ApiErrorParser
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-360 - the delegate-PATH FEED overlay repository (manage-as-creator feed traffic).
 *
 * Every action: requires an active delegate context (else "not in delegate mode"); GATES on the typed
 * permission (PermissionDenied WITHOUT calling the API when absent); calls [DelegateFeedApi] with the
 * active creatorId (attribution = @Path); and AUTO-EXITS on a 403 (re-fetch context; exit if gone). The
 * capability flags ([canRead] / [canPost]) let the UI hide / disable affordances up front.
 *
 * APPROVAL: a delegate-created post may come back with an approval_status when the creator requires
 * approval - the delegate can NOT self-approve, so the approve / reject action is creator-only and not
 * built here (the read-back status is surfaced for the UI only).
 */
@Singleton
class DelegateFeedRepository @Inject constructor(
    private val api: DelegateFeedApi,
    private val contextProvider: DelegationContextProvider,
    delegationRepository: DelegationRepository,
    errorParser: ApiErrorParser,
) {

    private val guard = DelegateGuard(
        context = contextProvider::current,
        errorParser = errorParser,
        autoExit = DelegateAutoExit(contextProvider, delegationRepository),
    )

    /** True when the current context may READ the creator's feed (feed_read). */
    fun canRead(): Boolean = contextProvider.current().canReadFeed()

    /** True when the current context may CREATE / DELETE feed posts (feed_post). */
    fun canPost(): Boolean = contextProvider.current().canPostFeed()

    /** GET the managed creator's recent posts (BARE ARRAY). Gated by feed_read. */
    suspend fun listPosts(limit: Int = 50): ApiResult<List<DelegatedPostOut>> =
        guard.gated(DelegatePermission.FEED_READ) { creatorId -> api.listPosts(creatorId, limit) }

    /** POST a new post on the managed creator's feed. Gated by feed_post. */
    suspend fun createPost(text: String): ApiResult<DelegatedPostOut> =
        guard.gated(DelegatePermission.FEED_POST) { creatorId ->
            api.createPost(creatorId, DelegatedPostCreateIn(text = text))
        }

    /** DELETE one of the managed creator's posts. Gated by feed_post. Maps a 2xx empty body to Unit. */
    suspend fun deletePost(postId: String): ApiResult<Unit> =
        guard.gated(DelegatePermission.FEED_POST) { creatorId ->
            api.deletePost(creatorId, postId).let { response ->
                if (!response.isSuccessful) {
                    throw retrofit2.HttpException(response)
                }
                Unit
            }
        }
}
