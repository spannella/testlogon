package com.testlogon.android.feature.feed

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.Comment
import com.testlogon.android.data.feed.CommentPage
import com.testlogon.android.data.feed.CommentsRepository
import com.testlogon.android.data.bookmarks.FeedBookmarkRepository
import com.testlogon.android.data.feed.LikeState
import com.testlogon.android.data.feed.PollRepository
import com.testlogon.android.data.feed.PollVoteResult
import com.testlogon.android.data.feed.PostActionsRepository
import com.testlogon.android.data.feed.PostEngagementRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import java.io.IOException

/**
 * AND-173 — fake [PostEngagementRepository]. Records calls and returns a configurable result; can be
 * made to suspend (gated) so coalescing/supersede + optimistic-before-completion can be exercised.
 */
class FakeEngagementRepository(
    var result: (postId: String, liked: Boolean, count: Int) -> ApiResult<LikeState> =
        { _, liked, count -> ApiResult.Success(LikeState(liked, count)) },
) : PostEngagementRepository {

    val calls = mutableListOf<Triple<String, Boolean, Int>>()

    /** When non-null, setLiked awaits this gate before returning (to test in-flight states). */
    var gate: CompletableDeferred<Unit>? = null

    override suspend fun setLiked(postId: String, liked: Boolean, desiredCount: Int): ApiResult<LikeState> {
        calls += Triple(postId, liked, desiredCount)
        gate?.await()
        return result(postId, liked, desiredCount)
    }

    val reactionCalls = mutableListOf<Triple<String, String, Boolean>>()

    override suspend fun setReaction(postId: String, emoji: String, add: Boolean): ApiResult<Unit> {
        reactionCalls += Triple(postId, emoji, add)
        return ApiResult.Success(Unit)
    }
}

/**
 * AND-175 — fake [PostActionsRepository]. Backs [suppressed] with an in-memory set so the feed filter
 * can be exercised; hide/notInterested/unhide mutate it and return a configurable result.
 */
class FakePostActionsRepository(
    initial: Set<String> = emptySet(),
    var hideResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var unhideResult: ApiResult<Unit> = ApiResult.Success(Unit),
) : PostActionsRepository {

    val hideCalls = mutableListOf<String>()
    val notInterestedCalls = mutableListOf<String>()
    val unhideCalls = mutableListOf<String>()

    private val _suppressed = MutableStateFlow(initial)
    override val suppressed: StateFlow<Set<String>> = _suppressed

    override suspend fun hide(postId: String): ApiResult<Unit> {
        hideCalls += postId
        if (hideResult is ApiResult.Success) _suppressed.value = _suppressed.value + postId
        return hideResult
    }

    override suspend fun notInterested(postId: String): ApiResult<Unit> {
        notInterestedCalls += postId
        if (hideResult is ApiResult.Success) _suppressed.value = _suppressed.value + postId
        return hideResult
    }

    override suspend fun unhide(postId: String): ApiResult<Unit> {
        unhideCalls += postId
        if (unhideResult is ApiResult.Success) _suppressed.value = _suppressed.value - postId
        return unhideResult
    }
}

/**
 * AND-176 — fake [FeedBookmarkRepository]. Backs [savedIds] with an in-memory set; setBookmarked
 * mutates it and returns a configurable result; can be gated to test serialization.
 */
class FakeFeedBookmarkRepository(
    initial: Set<String> = emptySet(),
    var result: (postId: String, bookmarked: Boolean) -> ApiResult<Unit> = { _, _ -> ApiResult.Success(Unit) },
) : FeedBookmarkRepository {

    val setCalls = mutableListOf<Pair<String, Boolean>>()
    var gate: CompletableDeferred<Unit>? = null

    private val _saved = MutableStateFlow(initial)
    override val savedIds: Flow<Set<String>> = _saved

    override fun isBookmarked(postId: String): Flow<Boolean> = _saved.map { postId in it }

    override suspend fun setBookmarked(postId: String, bookmarked: Boolean): ApiResult<Unit> {
        setCalls += postId to bookmarked
        gate?.await()
        val r = result(postId, bookmarked)
        if (r is ApiResult.Success) {
            _saved.value = if (bookmarked) _saved.value + postId else _saved.value - postId
        }
        return r
    }

    override suspend fun hydrate(postIds: List<String>): ApiResult<Unit> = ApiResult.Success(Unit)

    // P0-consumer/bookmarks — generalised overloads (feed only exercises the post variants).
    override fun savedIdsFor(contentType: String): Flow<Set<String>> = _saved

    override fun isBookmarked(contentType: String, contentId: String): Flow<Boolean> = _saved.map { contentId in it }

    override suspend fun setBookmarked(contentType: String, contentId: String, bookmarked: Boolean): ApiResult<Unit> =
        setBookmarked(contentId, bookmarked)

    override suspend fun hydrate(contentType: String, contentIds: List<String>): ApiResult<Unit> = ApiResult.Success(Unit)
}

/**
 * AND-179 — fake [PollRepository]. Returns a configurable per-question result; records calls and can be
 * gated to test the in-flight double-tap guard.
 */
class FakePollRepository(
    var voteResult: (postId: String, questionId: String, optionId: String) -> ApiResult<PollVoteResult> =
        { _, questionId, optionId ->
            ApiResult.Success(
                PollVoteResult(
                    questionId = questionId,
                    voteCounts = mapOf(optionId to 1),
                    totalVotes = 1,
                    myVoteOptionIds = listOf(optionId),
                ),
            )
        },
) : PollRepository {

    val voteCalls = mutableListOf<Triple<String, String, String>>()
    val removeCalls = mutableListOf<Pair<String, String>>()
    var gate: CompletableDeferred<Unit>? = null

    override suspend fun vote(postId: String, questionId: String, optionId: String): ApiResult<PollVoteResult> {
        voteCalls += Triple(postId, questionId, optionId)
        gate?.await()
        return voteResult(postId, questionId, optionId)
    }

    override suspend fun removeVote(postId: String, questionId: String): ApiResult<PollVoteResult> {
        removeCalls += postId to questionId
        return voteResult(postId, questionId, "")
    }

    // Write-in program (poll write-in options + paginated results). Programmable; default success.
    val writeInCalls = mutableListOf<Triple<String, String, String>>()
    var writeInResult: (postId: String, questionId: String, text: String) -> ApiResult<com.testlogon.android.data.feed.PollWriteInResponseDto> =
        { _, questionId, text ->
            ApiResult.Success(
                com.testlogon.android.data.feed.PollWriteInResponseDto(
                    questionId = questionId,
                    created = true,
                    text = text,
                ),
            )
        }
    var pollResultsResult: ApiResult<com.testlogon.android.data.feed.PollResultsPage> =
        ApiResult.Success(
            com.testlogon.android.data.feed.PollResultsPage(
                questionId = "",
                options = emptyList(),
                counts = emptyMap(),
                totalOptions = 0,
                hasMore = false,
                nextOffset = null,
                totalVotes = 0,
                myVoteOptionIds = emptyList(),
            ),
        )

    override suspend fun writeIn(
        postId: String,
        questionId: String,
        text: String,
    ): ApiResult<com.testlogon.android.data.feed.PollWriteInResponseDto> {
        writeInCalls += Triple(postId, questionId, text)
        return writeInResult(postId, questionId, text)
    }

    override suspend fun pollResults(
        postId: String,
        questionId: String,
        offset: Int,
        topN: Int,
    ): ApiResult<com.testlogon.android.data.feed.PollResultsPage> = pollResultsResult
}

/**
 * AND-174 — fake [CommentsRepository]. Serves canned pages keyed by cursor and a configurable add /
 * delete result; records calls.
 */
class FakeCommentsRepository(
    private val pagesByCursor: Map<String?, CommentPage> = mapOf(null to CommentPage(emptyList(), null)),
    var addResult: ApiResult<Comment>? = null,
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit),
    override val repliesSupported: Boolean = false,
) : CommentsRepository {

    val addCalls = mutableListOf<Triple<String, String, String?>>()
    val deleteCalls = mutableListOf<Pair<String, String>>()
    var getCalls = 0
        private set

    override suspend fun getComments(postId: String, cursor: String?, limit: Int): ApiResult<CommentPage> {
        getCalls++
        return ApiResult.Success(pagesByCursor[cursor] ?: CommentPage(emptyList(), null))
    }

    val addImageWithTextCalls = mutableListOf<String?>()
    val tipCarryCalls = mutableListOf<Int?>()
    override suspend fun addComment(
        postId: String,
        body: String,
        parentId: String?,
        imageUrl: String?,
        imageAltText: String?,
        tipAmountCents: Int?,
        tipPaymentMethodId: String?,
    ): ApiResult<Comment> {
        addCalls += Triple(postId, body, parentId)
        addImageWithTextCalls += imageUrl
        tipCarryCalls += tipAmountCents
        return addResult ?: ApiResult.Success(
            comment(id = "srv_${addCalls.size}", postId = postId, body = body, parentId = parentId)
                .copy(imageUrl = imageUrl),
        )
    }

    override suspend fun deleteComment(postId: String, commentId: String): ApiResult<Unit> {
        deleteCalls += postId to commentId
        return deleteResult
    }

    val gifCalls = mutableListOf<Pair<String, String>>()
    val stickerCalls = mutableListOf<Pair<String, String>>()
    val tipCalls = mutableListOf<Triple<String, String, Int>>()
    val editCalls = mutableListOf<Triple<String, String, String>>()

    override suspend fun addGifComment(
        postId: String,
        gifUrl: String,
        altText: String?,
        parentId: String?,
    ): ApiResult<Comment> {
        gifCalls += postId to gifUrl
        return addResult ?: ApiResult.Success(
            comment(id = "srv_gif_${gifCalls.size}", postId = postId, body = gifUrl, parentId = parentId),
        )
    }

    override suspend fun addStickerComment(
        postId: String,
        stickerId: String,
        collectionId: String,
        stickerUrl: String,
        altText: String?,
        parentId: String?,
    ): ApiResult<Comment> {
        stickerCalls += postId to stickerId
        return addResult ?: ApiResult.Success(
            comment(id = "srv_sticker_${stickerCalls.size}", postId = postId, body = stickerUrl, parentId = parentId),
        )
    }

    val imageCalls = mutableListOf<Pair<String, String>>()
    val commentReactionCalls = mutableListOf<Triple<String, String, Boolean>>()

    override suspend fun addImageComment(
        postId: String,
        imageUrl: String,
        altText: String?,
        parentId: String?,
    ): ApiResult<Comment> {
        imageCalls += postId to imageUrl
        return addResult ?: ApiResult.Success(
            comment(id = "srv_img_${imageCalls.size}", postId = postId, body = imageUrl, parentId = parentId),
        )
    }

    override suspend fun tipComment(postId: String, commentId: String, amountCents: Int, paymentMethodId: String?): ApiResult<Unit> {
        tipCalls += Triple(postId, commentId, amountCents)
        return ApiResult.Success(Unit)
    }

    override suspend fun setCommentReaction(
        postId: String,
        commentId: String,
        emoji: String,
        add: Boolean,
    ): ApiResult<Unit> {
        commentReactionCalls += Triple(commentId, emoji, add)
        return ApiResult.Success(Unit)
    }

    val editImageCalls = mutableListOf<String?>()
    override suspend fun editComment(
        postId: String,
        commentId: String,
        body: String,
        imageUrl: String?,
        imageAltText: String?,
    ): ApiResult<Comment> {
        editCalls += Triple(postId, commentId, body)
        editImageCalls += imageUrl
        return addResult ?: ApiResult.Success(
            comment(id = commentId, postId = postId, body = body),
        )
    }

    companion object {
        fun comment(
            id: String,
            postId: String = "post_1",
            authorId: String = "u_other",
            body: String = "body $id",
            parentId: String? = null,
            canDelete: Boolean = false,
        ) = Comment(
            id = id,
            postId = postId,
            parentId = parentId,
            authorId = authorId,
            body = body,
            createdAtEpochSeconds = 1_780_000_000L,
            updatedAtEpochSeconds = null,
            canDelete = canDelete,
            localKey = id,
        )

        fun failure(status: Int) = ApiResult.Failure(ApiError(status = status, message = "err $status"))
        fun network() = ApiResult.NetworkError(IOException("offline"))
    }
}

/**
 * Minimal [com.testlogon.android.data.profile.ProfileRepository] fake for tests that only need a
 * [com.testlogon.android.data.profile.DisplayNameResolver] instance (whose `names` StateFlow must be
 * real, not a Mockito mock). Public-profile lookups resolve to NotFound, so `names` stays empty.
 */
class FakeProfileRepository : com.testlogon.android.data.profile.ProfileRepository {
    override suspend fun getOwnProfile(forceRefresh: Boolean) =
        ApiResult.Failure(ApiError(status = 0, message = "stub"))

    override fun cachedOwnProfile(): com.testlogon.android.core.model.profile.Profile? = null

    override suspend fun getPublicProfile(identifier: String) =
        com.testlogon.android.data.profile.ProfileResult.NotFound

    override suspend fun updateProfile(patch: com.testlogon.android.core.model.profile.ProfilePatch) =
        ApiResult.Failure(ApiError(status = 0, message = "stub"))

    override suspend fun uploadPhoto(
        kind: com.testlogon.android.data.profile.MediaKind,
        upload: com.testlogon.android.data.profile.ProfileMediaUploader.PreparedUpload,
    ) = ApiResult.Failure(ApiError(status = 0, message = "stub"))
}

/**
 * Real [com.testlogon.android.data.profile.DisplayNameResolver] over a stub repository, so the Feed /
 * comment ViewModels' `displayNames.names` StateFlow is valid (empty). Use in VM tests.
 */
fun fakeDisplayNameResolver() =
    com.testlogon.android.data.profile.DisplayNameResolver(FakeProfileRepository())

/**
 * P2 — fake [com.testlogon.android.data.feed.RepostRepository]. Records calls; returns a configurable
 * repost_count (default 1). Feed VM tests that don't exercise repost just take the default success.
 */
class FakeRepostRepository(
    var repostResult: ApiResult<Int?> = ApiResult.Success(1),
    var undoResult: ApiResult<Int?> = ApiResult.Success(0),
) : com.testlogon.android.data.feed.RepostRepository {
    val repostCalls = mutableListOf<Pair<String, String?>>()
    val undoCalls = mutableListOf<String>()
    override suspend fun repost(postId: String, quote: String?): ApiResult<Int?> {
        repostCalls += postId to quote
        return repostResult
    }
    override suspend fun undo(postId: String): ApiResult<Int?> {
        undoCalls += postId
        return undoResult
    }
}

/** P2 — no-op [com.testlogon.android.data.ads.AdTrackRepository]; ad beacons are best-effort. */
class FakeAdTrackRepository : com.testlogon.android.data.ads.AdTrackRepository {
    val trackCalls = mutableListOf<com.testlogon.android.data.ads.AdEvent>()
    val ctaCalls = mutableListOf<Pair<String, com.testlogon.android.data.ads.CtaAction>>()
    override suspend fun track(
        event: com.testlogon.android.data.ads.AdEvent,
        ad: com.testlogon.android.data.feed.SponsoredInfo,
    ): ApiResult<Unit> {
        trackCalls += event
        return ApiResult.Success(Unit)
    }
    override suspend fun clickCta(
        adClickId: String,
        action: com.testlogon.android.data.ads.CtaAction,
    ): ApiResult<Unit> {
        ctaCalls += adClickId to action
        return ApiResult.Success(Unit)
    }
}

/** P2 — no-op [SponsoredPostRepository]; the feed only fires best-effort impression/click beacons. */
class FakeSponsoredPostRepository : com.testlogon.android.feature.sponsoredpost.data.SponsoredPostRepository {
    override suspend fun createProposal(req: com.testlogon.android.core.network.sponsoredpost.SponsoredPostProposalReq) =
        ApiResult.Failure(ApiError(status = 0, message = "stub"))
    override suspend fun inbox() = ApiResult.Success(emptyList<com.testlogon.android.feature.sponsoredpost.data.SponsoredPostProposal>())
    override suspend fun outbox() = ApiResult.Success(emptyList<com.testlogon.android.feature.sponsoredpost.data.SponsoredPostProposal>())
    override suspend fun approve(proposalId: String) = ApiResult.Failure(ApiError(status = 0, message = "stub"))
    override suspend fun reject(proposalId: String, reason: String) = ApiResult.Failure(ApiError(status = 0, message = "stub"))
    override suspend fun placement(postId: String) = ApiResult.Failure(ApiError(status = 0, message = "stub"))
    override suspend fun fireImpression(postId: String) {}
    override suspend fun fireClick(postId: String) {}
}

/**
 * P2 — shared [FeedViewModel] factory. The five repos the feed tests actually vary are named params; the
 * ad/repost/refresh/current-user deps the shipped ads + repost programs added default to honest no-op
 * fakes so a test only wires what it asserts on.
 */
fun feedViewModel(
    repository: FakeFeedRepository,
    engagement: FakeEngagementRepository = FakeEngagementRepository(),
    actions: FakePostActionsRepository = FakePostActionsRepository(),
    bookmarks: FakeFeedBookmarkRepository = FakeFeedBookmarkRepository(),
    polls: FakePollRepository = FakePollRepository(),
    reposts: FakeRepostRepository = FakeRepostRepository(),
): FeedViewModel {
    val adTracker = FakeAdTrackRepository()
    val adAttribution = com.testlogon.android.data.ads.AdClickAttributionStore()
    return FeedViewModel(
        repository = repository,
        engagement = engagement,
        actions = actions,
        reposts = reposts,
        bookmarks = bookmarks,
        polls = polls,
        displayNames = fakeDisplayNameResolver(),
        currentUser = fakeCurrentUserRepository(),
        feedRefreshBus = com.testlogon.android.data.feed.FeedRefreshBus(),
        adTracker = adTracker,
        adAttribution = adAttribution,
        adCtaClicker = com.testlogon.android.data.ads.AdCtaClicker(adTracker, adAttribution),
        sponsoredPostRepo = FakeSponsoredPostRepository(),
    )
}

/** #24 — no-op [com.testlogon.android.data.feed.CommentImageUploader] for the comments VM test. */
class FakeCommentImageUploader(
    var result: ApiResult<String> = ApiResult.Success("/uploads/object?s3_key=test"),
) : com.testlogon.android.data.feed.CommentImageUploader {
    val calls = mutableListOf<android.net.Uri>()
    override suspend fun uploadImage(uri: android.net.Uri): ApiResult<String> {
        calls += uri
        return result
    }
}

/** #25 — real [com.testlogon.android.data.feed.CurrentUserRepository] over a canned `user_sub`. */
fun fakeCurrentUserRepository(sub: String? = "me") =
    com.testlogon.android.data.feed.CurrentUserRepository(
        api = object : com.testlogon.android.data.feed.CurrentUserApi {
            override suspend fun me() = com.testlogon.android.data.feed.CurrentUserDto(userSub = sub)
        },
        errorParser = com.testlogon.android.core.network.error.ApiErrorParser(
            com.squareup.moshi.Moshi.Builder().build(),
        ),
    )
