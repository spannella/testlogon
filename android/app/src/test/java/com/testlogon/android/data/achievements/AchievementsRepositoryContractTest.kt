package com.testlogon.android.data.achievements

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-096 — contract tests for [AchievementsRepositoryImpl]. The catalog fans out to three concurrent
 * GETs (and the leaderboard to two), so a path-keyed Dispatcher is used rather than ordered enqueue.
 */
class AchievementsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): AchievementsRepositoryImpl {
        val api = backend.retrofit(moshi).create(AchievementsApi::class.java)
        return AchievementsRepositoryImpl(
            api = api,
            authStateStore = FakeAuthStateStore(),
            errorParser = ApiErrorParser(moshi),
        )
    }

    private fun jsonResponse(body: String) =
        MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body)

    @Test
    fun getCatalog_composesEarnedLockedProgress_acrossThreeGets() = runTest {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                return when (request.requestUrl?.encodedPath) {
                    "/ui/achievements" -> jsonResponse(
                        """{"achievements":[{"achievement_id":"first_login","label":"First","points":10,"unlocked_at":1748592662}],"total_points":10,"achievement_count":1}""",
                    )
                    "/ui/achievements/progress" -> jsonResponse(
                        """{"progress":[{"metric_key":"login_streak_days","current_value":7,"next_threshold":10}]}""",
                    )
                    "/ui/achievements/definitions" -> jsonResponse(
                        """{"definitions":[{"achievement_id":"first_login","label":"First","threshold":1,"metric_key":"logins"},{"achievement_id":"streak_10","label":"On a Roll","threshold":10,"metric_key":"login_streak_days"}]}""",
                    )
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        val result = repo().getCatalog()
        assertTrue(result is ApiResult.Success)
        val catalog = (result as ApiResult.Success).data
        assertEquals(1, catalog.earned.size)
        assertEquals(1, catalog.locked.size)
        assertEquals(2, catalog.total)
        assertEquals(0.7f, catalog.locked.first { it.id == "streak_10" }.progress?.fraction)
    }

    @Test
    fun getCatalog_degradedMode_whenSideCallsFail() = runTest {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                when (request.requestUrl?.encodedPath) {
                    "/ui/achievements" -> jsonResponse(
                        """{"achievements":[{"achievement_id":"a","label":"A"}],"total_points":5,"achievement_count":1}""",
                    )
                    else -> MockResponse().setResponseCode(500) // progress + definitions fail
                }
        }

        val result = repo().getCatalog()
        assertTrue(result is ApiResult.Success)
        val catalog = (result as ApiResult.Success).data
        assertEquals(1, catalog.earned.size)
        assertTrue(catalog.locked.isEmpty()) // degraded: earned-only
    }

    @Test
    fun getCatalog_primaryFailure_isFailure() = runTest {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                MockResponse().setResponseCode(500)
        }
        val result = repo().getCatalog()
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun getLeaderboard_mergesListAndMyRank() = runTest {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                when (request.requestUrl?.encodedPath) {
                    "/ui/achievements/leaderboard" -> {
                        assertEquals("alltime", request.requestUrl?.queryParameter("period"))
                        jsonResponse(
                            """{"entries":[{"rank":1,"user_sub":"u_a","display_name":"Ada","total_points":4200,"achievement_count":12,"display_badges":[]}],"next_cursor":null,"period":"alltime"}""",
                        )
                    }
                    "/ui/achievements/leaderboard/me" -> jsonResponse(
                        """{"rank":57,"user_sub":"u_self","display_name":"Sean","total_points":910,"achievement_count":4,"display_badges":[],"period":"alltime"}""",
                    )
                    else -> MockResponse().setResponseCode(404)
                }
        }

        val result = repo().getLeaderboard(period = "alltime")
        assertTrue(result is ApiResult.Success)
        val board = (result as ApiResult.Success).data
        assertEquals(1, board.entries.size)
        assertEquals("Ada", board.entries.first().name)
        assertEquals(57, board.me?.rank)
    }

    @Test
    fun getLeaderboard_meFailure_degradesGracefully() = runTest {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                when (request.requestUrl?.encodedPath) {
                    "/ui/achievements/leaderboard" -> jsonResponse(
                        """{"entries":[{"rank":1,"user_sub":"u_a","display_name":"Ada","total_points":1,"achievement_count":0,"display_badges":[]}],"next_cursor":null,"period":"alltime"}""",
                    )
                    else -> MockResponse().setResponseCode(500) // /me fails
                }
        }
        val result = repo().getLeaderboard(period = "alltime")
        assertTrue(result is ApiResult.Success)
        val board = (result as ApiResult.Success).data
        assertEquals(1, board.entries.size)
        assertEquals(null, board.me) // own rank hidden, list still renders
    }
}
