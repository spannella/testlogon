package com.testlogon.android.feature.notifications

import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.notifications.NotificationPage
import com.testlogon.android.data.notifications.NotificationType
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-090 — [NotificationsViewModel] badge + intent + paging-overlay unit tests. */
class NotificationsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun page(vararg notifs: com.testlogon.android.data.notifications.Notification) =
        NotificationPage(notifs.toList(), null)

    @Test
    fun badge_initializesFromServerCount_andFormats() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 5)
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        val badge = vm.badge.value
        assertEquals(5, badge.count)
        assertEquals("5", badge.display)
        assertFalse(badge.isLoading)
        assertTrue(badge.markAllEnabled)
    }

    @Test
    fun badge_displayCapsAt99Plus_andEmptyAtZero() = runTest {
        val vm = NotificationsViewModel(FakeNotificationRepository(initialUnread = 150))
        advanceUntilIdle()
        assertEquals("99+", vm.badge.value.display)

        val vm0 = NotificationsViewModel(FakeNotificationRepository(initialUnread = 0))
        advanceUntilIdle()
        assertEquals("", vm0.badge.value.display)
        assertFalse(vm0.badge.value.markAllEnabled)
    }

    @Test
    fun unreadCountFailure_marksStale_keepsLoadingFalse() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 0).apply {
            unreadResult = FakeNotificationRepository.failure(500)
        }
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.badge.value.isStale)
        assertFalse(vm.badge.value.isLoading)
    }

    @Test
    fun onItemClick_unreadRoutable_decrementsBadge_callsMarkRead_emitsNavigate() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 3)
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()

        val item = NotificationUi(
            id = "n1", type = NotificationType.SYSTEM, title = "t", body = "b",
            isRead = false, createdAtEpochSeconds = 1L, batchCount = 1,
            target = NotificationTarget.Settings,
        )
        vm.onItemClick(item)
        val event = vm.events.first()
        advanceUntilIdle()

        assertTrue(event is NotificationsEvent.Navigate)
        assertEquals(NotificationTarget.Settings, (event as NotificationsEvent.Navigate).target)
        assertEquals(listOf(listOf("n1")), repo.markReadCalls)
        assertEquals(2, vm.badge.value.count)
    }

    @Test
    fun onItemClick_unknownTarget_marksReadButDoesNotNavigate() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 1)
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        val item = NotificationUi(
            id = "n9", type = NotificationType.LIKE, title = "t", body = "b",
            isRead = false, createdAtEpochSeconds = 1L, batchCount = 1,
            target = NotificationTarget.Unknown,
        )
        vm.onItemClick(item)
        advanceUntilIdle()
        assertEquals(listOf(listOf("n9")), repo.markReadCalls)
        assertEquals(0, vm.badge.value.count)
    }

    @Test
    fun markRead_floorsAtZero_noNegative() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 0)
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        val item = NotificationUi(
            id = "x", type = NotificationType.SYSTEM, title = "t", body = "b",
            isRead = false, createdAtEpochSeconds = 1L, batchCount = 1, target = NotificationTarget.Unknown,
        )
        vm.onItemClick(item)
        advanceUntilIdle()
        assertEquals(0, vm.badge.value.count)
    }

    @Test
    fun markAllRead_success_zeroesBadge() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 7).apply { markAllResult = ApiResult.Success(7) }
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        vm.onMarkAllRead()
        advanceUntilIdle()
        assertEquals(1, repo.markAllCalls)
        assertEquals(0, vm.badge.value.count)
    }

    @Test
    fun markAllRead_failure_rollsBack_andEmitsError() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 4).apply {
            markAllResult = FakeNotificationRepository.failure(500)
        }
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        vm.onMarkAllRead()
        val event = vm.events.first()
        advanceUntilIdle()
        assertTrue(event is NotificationsEvent.Error)
        assertEquals(4, vm.badge.value.count) // restored
    }

    @Test
    fun concurrentMarkRead_serialized_noNegative() = runTest {
        val repo = FakeNotificationRepository(initialUnread = 3)
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()
        repeat(5) { i ->
            vm.onItemClick(
                NotificationUi(
                    id = "n$i", type = NotificationType.SYSTEM, title = "t", body = "b",
                    isRead = false, createdAtEpochSeconds = 1L, batchCount = 1, target = NotificationTarget.Unknown,
                ),
            )
        }
        advanceUntilIdle()
        assertEquals(5, repo.markReadCalls.size)
        assertEquals(0, vm.badge.value.count)
    }

    @Test
    fun pagedNotifications_mapsDomain_andAppliesReadOverlayAfterClick() = runTest {
        val repo = FakeNotificationRepository(
            initialUnread = 1,
            pagesByCursor = mapOf(
                null to page(
                    FakeNotificationRepository.notification("n1", read = false),
                    FakeNotificationRepository.notification("n2", read = true),
                ),
            ),
        )
        val vm = NotificationsViewModel(repo)
        advanceUntilIdle()

        val snapshot = vm.pagedNotifications.asSnapshot()
        assertEquals(listOf("n1", "n2"), snapshot.map { it.id })
        assertFalse(snapshot.first { it.id == "n1" }.isRead)

        // Mark n1 read; overlay should reflect it without a server round-trip.
        vm.onItemClick(snapshot.first { it.id == "n1" })
        advanceUntilIdle()
        val after = vm.pagedNotifications.asSnapshot()
        assertTrue(after.first { it.id == "n1" }.isRead)
    }
}
