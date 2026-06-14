package com.testlogon.android.feature.notifications

import androidx.paging.PagingSource
import androidx.paging.testing.TestPager
import androidx.paging.PagingConfig
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.notifications.Notification
import com.testlogon.android.data.notifications.NotificationPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-090 — [NotificationsPagingSource] load/append/error tests via Paging's TestPager. */
class NotificationsPagingSourceTest {

    private val config = PagingConfig(pageSize = 20, initialLoadSize = 40, enablePlaceholders = false)

    @Test
    fun firstPage_returnsPageWithNextKey() = runTest {
        val repo = FakeNotificationRepository(
            pagesByCursor = mapOf(
                null to NotificationPage(
                    listOf(FakeNotificationRepository.notification("n1")),
                    nextCursor = "c2",
                ),
            ),
        )
        val pager = TestPager(config, NotificationsPagingSource(repo))
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("n1"), result.data.map(Notification::id))
        assertEquals("c2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun appendThenTerminalPage_nextKeyNull() = runTest {
        val repo = FakeNotificationRepository(
            pagesByCursor = mapOf(
                null to NotificationPage(listOf(FakeNotificationRepository.notification("n1")), "c2"),
                "c2" to NotificationPage(listOf(FakeNotificationRepository.notification("n2")), null),
            ),
        )
        val pager = TestPager(config, NotificationsPagingSource(repo))
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("n2"), appended.data.map(Notification::id))
        assertNull(appended.nextKey) // terminal
    }

    @Test
    fun failure_yieldsLoadResultError() = runTest {
        val repo = FakeNotificationRepository().apply { listResult = FakeNotificationRepository.failure(500) }
        val pager = TestPager(config, NotificationsPagingSource(repo))
        val result = pager.refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
    }

    @Test
    fun networkError_yieldsLoadResultError() = runTest {
        val repo = FakeNotificationRepository().apply {
            listResult = ApiResult.NetworkError(java.io.IOException("offline"), isTimeout = true)
        }
        val pager = TestPager(config, NotificationsPagingSource(repo))
        assertTrue(pager.refresh() is PagingSource.LoadResult.Error)
    }
}
