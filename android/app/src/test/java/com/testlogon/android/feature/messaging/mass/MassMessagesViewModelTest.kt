package com.testlogon.android.feature.messaging.mass

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.mass.CampaignCounters
import com.testlogon.android.data.messaging.mass.CampaignMode
import com.testlogon.android.data.messaging.mass.CampaignStatus
import com.testlogon.android.data.messaging.mass.MassCampaign
import com.testlogon.android.data.messaging.mass.MassCampaignCreateResult
import com.testlogon.android.data.messaging.mass.RejectedDestination
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class MassMessagesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMassMessageRepository()
    private val config = FakeMassMessageConfigRepository(enabled = true)
    private val messaging = FakeMessagingRepository()

    private fun vm() = MassMessagesViewModel(repo, config, messaging)

    private fun campaign(id: String, status: CampaignStatus) = MassCampaign(
        id = id, status = status, mode = CampaignMode.IMMEDIATE,
        sendAtEpochSeconds = null, createdAtEpochSeconds = 1, updatedAtEpochSeconds = 1,
        counters = CampaignCounters(total = 2, cancelled = 1),
    )

    @Test
    fun gate_disabledHidesCreator() = runTest {
        config.enabled = false
        val viewModel = vm()
        advanceUntilIdle()
        assertFalse(viewModel.uiState.value.isCreator)
    }

    @Test
    fun canSubmit_gatesOnTextRecipientsAndSchedule() = runTest {
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.openCreate()
        assertFalse(viewModel.uiState.value.createSheet.canSubmit) // empty

        viewModel.onTextChange("hello")
        assertFalse(viewModel.uiState.value.createSheet.canSubmit) // no recipients

        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("c1", "Ann")))
        viewModel.onQueryChange("a")
        advanceTimeBy(400)
        advanceUntilIdle()
        viewModel.onToggleRecipient("c1")
        assertTrue(viewModel.uiState.value.createSheet.canSubmit) // immediate + text + 1 recipient

        viewModel.onModeChange(CampaignMode.SCHEDULED)
        assertFalse(viewModel.uiState.value.createSheet.canSubmit) // scheduled needs send_at
        viewModel.onSendAtChange(1760003600)
        assertTrue(viewModel.uiState.value.createSheet.canSubmit)
    }

    @Test
    fun submitCreate_successEmitsSnackAndInvalidatesList() = runTest {
        repo.createResult = ApiResult.Success(
            MassCampaignCreateResult(
                campaign = campaign("mmc_1", CampaignStatus.PENDING),
                acceptedCount = 2,
                acceptedConversationIds = listOf("c1", "c2"),
                rejected = listOf(RejectedDestination("c3", "not_a_participant")),
            ),
        )
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.openCreate()
        viewModel.onTextChange("hi")
        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("c1", "Ann")))
        viewModel.onQueryChange("a")
        advanceTimeBy(400)
        advanceUntilIdle()
        viewModel.onToggleRecipient("c1")

        val events = mutableListOf<MassMessagesEvent>()
        val job = launch { viewModel.events.collect { events += it } }
        viewModel.submitCreate()
        advanceUntilIdle()
        job.cancel()

        val created = events.first()
        assertTrue(created is MassMessagesEvent.CreatedSnack)
        assertEquals(2, (created as MassMessagesEvent.CreatedSnack).acceptedCount)
        assertEquals(1, created.rejectedCount)
        assertTrue(events.contains(MassMessagesEvent.InvalidateList))
        // Sheet dismissed and the create draft carried an idempotency key.
        assertFalse(viewModel.uiState.value.createSheet.visible)
        assertTrue(repo.createDrafts.single().idempotencyKey?.isNotBlank() == true)
    }

    @Test
    fun confirmCancel_optimisticThenReconcile() = runTest {
        repo.cancelResult = ApiResult.Success(campaign("mmc_1", CampaignStatus.CANCELLED))
        val viewModel = vm()
        advanceUntilIdle()

        viewModel.requestCancel("mmc_1")
        assertEquals("mmc_1", viewModel.uiState.value.pendingCancelId)

        viewModel.confirmCancel("mmc_1", prior = campaign("mmc_1", CampaignStatus.PROCESSING))
        // Optimistic overlay applied immediately.
        assertTrue(viewModel.uiState.value.inFlightCancelIds.contains("mmc_1"))

        advanceUntilIdle()
        // Reconciled: removed from in-flight, overlay = CANCELLED.
        assertFalse(viewModel.uiState.value.inFlightCancelIds.contains("mmc_1"))
        assertEquals(CampaignStatusOverlay.CANCELLED, viewModel.uiState.value.cancelledOverlay["mmc_1"])
        assertTrue(repo.cancelledIds.contains("mmc_1"))
    }

    @Test
    fun confirmCancel_rollsBackOnError() = runTest {
        repo.cancelResult = ApiResult.Failure(ApiError(status = 409, message = "nope"))
        val viewModel = vm()
        advanceUntilIdle()

        val events = mutableListOf<MassMessagesEvent>()
        val job = launch { viewModel.events.collect { events += it } }
        viewModel.confirmCancel("mmc_2")
        advanceUntilIdle()
        job.cancel()
        assertTrue(events.any { it is MassMessagesEvent.ErrorSnack })
        // Overlay reverted, not in-flight.
        assertFalse(viewModel.uiState.value.inFlightCancelIds.contains("mmc_2"))
        assertFalse(viewModel.uiState.value.cancelledOverlay.containsKey("mmc_2"))
    }
}
