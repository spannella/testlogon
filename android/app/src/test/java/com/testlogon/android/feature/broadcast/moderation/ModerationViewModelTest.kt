package com.testlogon.android.feature.broadcast.moderation

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.chat.ChatMessage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-313 — unit tests for [ModerationViewModel]. Uses MainDispatcherRule + runCurrent (NEVER
 * advanceUntilIdle). uiState is a plain MutableStateFlow so optimistic state is synchronous; the optimistic
 * in-flight window is observed by PARKing the fake repo on a CompletableDeferred gate, asserting inFlight,
 * then releasing the gate + runCurrent. Verifies: optimistic delete adds then clears inFlight + emits Success;
 * failure rollback + Failure event; confirmBan passes the reason; confirmMute passes the chosen duration; pin
 * sets pinnedMessage from the response; the canModerate gate (true default, false after a 403); and the log
 * load success / empty / error.
 */
class ModerationViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun message(id: String = "cm_1", senderId: String = "usr_9") = ChatMessage(
        id = id,
        sessionId = SESSION,
        senderId = senderId,
        senderDisplayName = "Ada",
        text = "hi",
        createdAtEpochSeconds = 0L,
    )

    private class FakeRepo : FakeModerationRepository()

    private fun vm(
        repo: ModerationRepository,
        creatorId: String = CREATOR,
    ): ModerationViewModel {
        val saved = SavedStateHandle(
            mapOf(
                ModerationViewModel.ARG_SESSION_ID to SESSION,
                ModerationViewModel.ARG_CREATOR_ID to creatorId,
            ),
        )
        return ModerationViewModel(repo, saved)
    }

    @Test
    fun deleteMessage_optimisticInFlight_thenClearsOnSuccess() = runTest {
        val repo = FakeRepo()
        repo.deleteGate = CompletableDeferred()
        val sut = vm(repo)

        sut.deleteMessage("cm_1")
        runCurrent()
        // The optimistic in-flight key is present while the repo is parked.
        assertTrue(sut.uiState.value.inFlight.contains("delete:cm_1"))

        repo.deleteGate!!.complete(Unit)
        runCurrent()
        assertFalse(sut.uiState.value.inFlight.contains("delete:cm_1"))
        assertEquals(ModerationEvent.Success(ModerationActionType.DELETE), sut.uiState.value.event)
    }

    @Test
    fun deleteMessage_failure_rollsBack_andEmitsFailure() = runTest {
        val repo = FakeRepo()
        repo.deleteResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val sut = vm(repo)

        sut.deleteMessage("cm_1")
        runCurrent()
        assertFalse(sut.uiState.value.inFlight.contains("delete:cm_1"))
        assertTrue(sut.uiState.value.event is ModerationEvent.Failure)
        assertEquals("boom", (sut.uiState.value.event as ModerationEvent.Failure).message)
    }

    @Test
    fun confirmBan_passesReason() = runTest {
        val repo = FakeRepo()
        val sut = vm(repo)

        sut.confirmBan("usr_9", reason = "spam")
        runCurrent()
        assertEquals("usr_9", repo.lastBanUserId)
        assertEquals("spam", repo.lastBanReason)
        assertEquals(ModerationEvent.Success(ModerationActionType.BAN), sut.uiState.value.event)
    }

    @Test
    fun confirmMute_passesChosenDuration() = runTest {
        val repo = FakeRepo()
        val sut = vm(repo)

        sut.confirmMute("usr_9", MuteSpec.ONE_HOUR)
        runCurrent()
        assertEquals("usr_9", repo.lastMuteUserId)
        assertEquals(3_600L, repo.lastMuteSpec?.durationSeconds)
        assertEquals(ModerationEvent.Success(ModerationActionType.MUTE), sut.uiState.value.event)
    }

    @Test
    fun confirmMute_hostPath_whenNoCreatorId() = runTest {
        val repo = FakeRepo()
        val sut = vm(repo, creatorId = "")

        sut.confirmMute("usr_9", MuteSpec.FIVE_MINUTES)
        runCurrent()
        // The VM passes null creatorId so the repo routes host-side.
        assertNull(repo.lastMuteCreatorId)
    }

    @Test
    fun pin_setsPinnedMessageFromResponse() = runTest {
        val repo = FakeRepo()
        repo.pinResult = ApiResult.Success(true)
        val sut = vm(repo)
        val msg = message(id = "cm_3")

        sut.pin(msg)
        runCurrent()
        assertEquals("cm_3", sut.uiState.value.pinnedMessage?.id)
        assertEquals(ModerationEvent.Success(ModerationActionType.PIN), sut.uiState.value.event)
    }

    @Test
    fun authError_403_hidesControls_andEmitsAuthDenied() = runTest {
        val repo = FakeRepo()
        repo.banResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val sut = vm(repo)
        assertTrue(sut.canModerate.value)

        sut.confirmBan("usr_9", reason = null)
        runCurrent()
        assertFalse(sut.canModerate.value)
        assertEquals(ModerationEvent.AuthDenied, sut.uiState.value.event)
    }

    @Test
    fun loadLog_success_populatesContent() = runTest {
        val repo = FakeRepo()
        repo.logResult = ApiResult.Success(
            listOf(
                ModerationLogEntry(
                    id = "ev_1",
                    action = ModerationActionType.BAN,
                    moderatorId = "mod_1",
                    moderatorName = "Mod One",
                    target = ModerationTarget(userId = "usr_9"),
                    targetLabel = "usr_9",
                    reason = "spam",
                    createdAt = Instant.EPOCH,
                ),
            ),
        )
        val sut = vm(repo)

        sut.loadLog()
        runCurrent()
        val state = sut.logState.value
        assertTrue(state is ModerationLogUiState.Content)
        assertEquals(1, (state as ModerationLogUiState.Content).entries.size)
    }

    @Test
    fun loadLog_empty_showsEmpty() = runTest {
        val repo = FakeRepo()
        repo.logResult = ApiResult.Success(emptyList())
        repo.bansResult = ApiResult.Success(emptyList())
        val sut = vm(repo)

        sut.loadLog()
        runCurrent()
        assertEquals(ModerationLogUiState.Empty, sut.logState.value)
    }

    @Test
    fun loadLog_error_showsError() = runTest {
        val repo = FakeRepo()
        repo.logResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val sut = vm(repo)

        sut.loadLog()
        runCurrent()
        assertTrue(sut.logState.value is ModerationLogUiState.Error)
    }

    @Test
    fun loadLog_unavailable_whenNoCreatorId() = runTest {
        val sut = vm(FakeRepo(), creatorId = "")
        sut.loadLog()
        runCurrent()
        assertTrue(sut.logState.value is ModerationLogUiState.Error)
    }

    private companion object {
        const val SESSION = "bcs_1"
        const val CREATOR = "cr_5"
    }
}

/**
 * AND-313 — fake [ModerationRepository] for [ModerationViewModelTest]. Defaults every call to success; each
 * call records its arguments; [deleteGate] optionally PARKs deleteMessage so a test can observe the
 * optimistic in-flight window. Kept SEPARATE (no shared fake) so other features' fakes are untouched.
 */
open class FakeModerationRepository : ModerationRepository {

    var muteResult: ApiResult<Instant> = ApiResult.Success(Instant.EPOCH)
    var banResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var unbanResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var pinResult: ApiResult<Boolean> = ApiResult.Success(true)
    var unpinResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var bansResult: ApiResult<List<ModerationBan>> = ApiResult.Success(emptyList())
    var logResult: ApiResult<List<ModerationLogEntry>> = ApiResult.Success(emptyList())

    var lastMuteUserId: String? = null
    var lastMuteCreatorId: String? = null
    var lastMuteSpec: MuteSpec? = null
    var lastBanUserId: String? = null
    var lastBanReason: String? = null

    /** Optional gate to PARK deleteMessage so a test can observe the in-flight window; null = immediate. */
    var deleteGate: CompletableDeferred<Unit>? = null

    override suspend fun mute(
        sessionId: String,
        creatorId: String?,
        userId: String,
        spec: MuteSpec,
    ): ApiResult<Instant> {
        lastMuteUserId = userId
        lastMuteCreatorId = creatorId
        lastMuteSpec = spec
        return muteResult
    }

    override suspend fun ban(
        sessionId: String,
        creatorId: String,
        userId: String,
        reason: String?,
    ): ApiResult<Unit> {
        lastBanUserId = userId
        lastBanReason = reason
        return banResult
    }

    override suspend fun unban(sessionId: String, creatorId: String, userId: String): ApiResult<Unit> =
        unbanResult

    override suspend fun deleteMessage(
        sessionId: String,
        creatorId: String?,
        messageId: String,
    ): ApiResult<Unit> {
        deleteGate?.await()
        return deleteResult
    }

    override suspend fun pin(sessionId: String, creatorId: String, messageId: String): ApiResult<Boolean> =
        pinResult

    override suspend fun unpin(sessionId: String, creatorId: String, messageId: String): ApiResult<Unit> =
        unpinResult

    override suspend fun listBans(sessionId: String, creatorId: String): ApiResult<List<ModerationBan>> =
        bansResult

    override suspend fun moderationLog(
        sessionId: String,
        creatorId: String,
        limit: Int,
    ): ApiResult<List<ModerationLogEntry>> = logResult
}
