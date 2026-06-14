package com.testlogon.android.data.stories

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.Collections
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-199 / AND-200 — Stories data layer over [StoriesApi].
 *
 * - [trayFlow] emits the last-known tray (cached in-memory at the singleton) immediately, OR-merged
 *   with the session viewed-set so a ring restyles to "seen" the moment a story is viewed even before
 *   the next bar refresh lands. [refreshTray] triggers the network `GET /ui/stories/bar`.
 * - [loadAuthorStories] is a lazy per-author `GET /ui/stories/user/{user_id}` made when the viewer
 *   opens that author.
 * - [recordView] POSTs `/ui/stories/{story_id}/view`, deduped per story_id within the session and
 *   never retried; failures fold into ApiResult but the local viewed-set remains the UI source of
 *   truth (the optimistic mark is applied regardless).
 *
 * The viewed-set is intentionally in-memory (session-scoped) per AND-200 §6 — re-viewing across app
 * restarts may re-POST, which is acceptable (the server is idempotent and returns already_viewed).
 */
interface StoriesRepository {

    /** Cached-then-restyled tray. Emits the current cache OR-merged with the local viewed set. */
    fun trayFlow(): Flow<ApiResult<List<StoryBarItem>>>

    /** Triggers a network refresh of the tray and updates the cache the [trayFlow] reads. */
    suspend fun refreshTray(): ApiResult<List<StoryBarItem>>

    /** Loads one author's ordered story segments. */
    suspend fun loadAuthorStories(userId: String): ApiResult<List<StorySegment>>

    /** Records a view for [storyId] (deduped per session, not retried). Marks it locally first. */
    suspend fun recordView(storyId: String): ApiResult<Unit>

    /** True once [storyId] has been viewed in this session (local optimistic set). */
    fun isViewed(storyId: String): Boolean

    /** Optimistically mark an author's ring "seen" so the tray restyles immediately on viewer return. */
    fun markAuthorSeen(userId: String)
}

@Singleton
class StoriesRepositoryImpl @Inject constructor(
    private val api: StoriesApi,
    private val errorParser: ApiErrorParser,
) : StoriesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Last successfully-fetched tray (null = never fetched). */
    private val cache = MutableStateFlow<ApiResult<List<StoryBarItem>>?>(null)

    /** Session viewed story ids (drives view dedupe). */
    private val viewedIds: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    /** Authors whose ring has been optimistically marked "seen" this session (drives tray restyle). */
    private val seenAuthorIds: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    /** Bumped whenever the local seen state changes so [trayFlow] re-emits the restyled tray. */
    private val viewedVersion = MutableStateFlow(0)

    override fun trayFlow(): Flow<ApiResult<List<StoryBarItem>>> =
        combineCacheAndViewed()

    private fun combineCacheAndViewed(): Flow<ApiResult<List<StoryBarItem>>> =
        kotlinx.coroutines.flow.combine(cache.asStateFlow(), viewedVersion) { cached, _ ->
            when (cached) {
                null -> ApiResult.Success(emptyList())
                is ApiResult.Success -> ApiResult.Success(
                    // OR-merge: an author is "seen" if the server says so OR we marked it locally.
                    cached.data.map { entry ->
                        if (entry.hasUnseen && seenAuthorIds.contains(entry.userId)) {
                            entry.copy(hasUnseen = false)
                        } else {
                            entry
                        }
                    },
                )
                else -> cached
            }
        }

    override suspend fun refreshTray(): ApiResult<List<StoryBarItem>> = withContext(io) {
        val result = call { api.getStoryBar() }.map { dto -> dto.bar.map { it.toDomain() } }
        if (result is ApiResult.Success) {
            cache.value = result
        } else if (cache.value == null) {
            // No cache yet — surface the failure so the consumer can show offline/empty.
            cache.value = result
        }
        result
    }

    override suspend fun loadAuthorStories(userId: String): ApiResult<List<StorySegment>> =
        withContext(io) {
            call { api.getUserStories(userId) }.map { dto -> dto.stories.map { it.toDomain() } }
        }

    override suspend fun recordView(storyId: String): ApiResult<Unit> = withContext(io) {
        // Optimistic local mark first (UI source of truth); dedupe the network POST per session.
        val firstTime = viewedIds.add(storyId)
        if (firstTime) viewedVersion.update { it + 1 }
        if (!firstTime) return@withContext ApiResult.Success(Unit)
        // Fire-and-forget POST; not retried. Failures are swallowed into ApiResult (logged by caller).
        call { api.recordView(storyId) }.map { }
    }

    override fun isViewed(storyId: String): Boolean = viewedIds.contains(storyId)

    override fun markAuthorSeen(userId: String) {
        if (seenAuthorIds.add(userId)) viewedVersion.update { it + 1 }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
