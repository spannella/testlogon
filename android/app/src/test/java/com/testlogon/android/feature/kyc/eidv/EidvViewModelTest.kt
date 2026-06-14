package com.testlogon.android.feature.kyc.eidv

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.eidv.data.EidvRepository
import com.testlogon.android.feature.kyc.eidv.model.EidAssuranceLevel
import com.testlogon.android.feature.kyc.eidv.model.EidAuthFlow
import com.testlogon.android.feature.kyc.eidv.model.EidDiscrepancy
import com.testlogon.android.feature.kyc.eidv.model.EidDiscrepancySeverity
import com.testlogon.android.feature.kyc.eidv.model.EidScheme
import com.testlogon.android.feature.kyc.eidv.model.EidStatusResult
import com.testlogon.android.feature.kyc.eidv.model.EidVerification
import com.testlogon.android.feature.kyc.eidv.model.SchemeInfo
import com.testlogon.android.feature.kyc.eidv.model.StartEidSession
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-325 - unit tests for [EidvViewModel].
 *
 * ANTI-HANG DISCIPLINE: the status poll is a cancellable Job that is NOT auto-started in init. Tests set
 * [EidvViewModel.pollIntervalMillis], drive a SINGLE iteration with runCurrent, then stop - NEVER
 * advanceUntilIdle. A fake clock ([EidvViewModel.nowProvider]) simulates expiry. The fake repo serves
 * queued status results so one poll iteration produces a deterministic outcome.
 */
class EidvViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : EidvRepository {
        var schemesResult: ApiResult<List<SchemeInfo>> =
            ApiResult.Success(listOf(scheme(EidScheme.EIDAS), scheme(EidScheme.DIGID)))
        var ensureResult: ApiResult<String> = ApiResult.Success("kyc_new")
        var startResult: ApiResult<StartEidSession> = ApiResult.Success(
            StartEidSession("sess_1", "https://eid.example/redirect/abc", Instant.ofEpochSecond(FAR_FUTURE)),
        )

        // status() is served from this deque; an empty deque falls back to a null-verification success.
        val statusResults: ArrayDeque<ApiResult<EidStatusResult>> = ArrayDeque()
        var ensureCalls = 0
        var startCalls = 0

        override suspend fun listSchemes(country: String?): ApiResult<List<SchemeInfo>> = schemesResult

        override suspend fun ensureDraftCase(): ApiResult<String> {
            ensureCalls++
            return ensureResult
        }

        override suspend fun start(caseId: String, scheme: String): ApiResult<StartEidSession> {
            startCalls++
            return startResult
        }

        override suspend fun status(caseId: String): ApiResult<EidStatusResult> =
            if (statusResults.isEmpty()) {
                ApiResult.Success(EidStatusResult(verification = null, autoTierUpgrade = false))
            } else {
                statusResults.removeFirst()
            }
    }

    private fun vm(repo: FakeRepo = FakeRepo(), caseId: String? = null): EidvViewModel {
        val saved = SavedStateHandle().apply {
            if (caseId != null) set(EidvViewModel.ARG_CASE_ID, caseId)
        }
        return EidvViewModel(repo, saved)
    }

    @Test
    fun init_loadsSchemes_intoSchemeSelection() = runTest {
        val viewModel = vm()
        assertTrue(viewModel.uiState.value is EidvUiState.Loading)

        runCurrent()
        val state = viewModel.uiState.value as EidvUiState.SchemeSelection
        assertEquals(2, state.schemes.size)
        assertFalse(state.canStart)
    }

    @Test
    fun onSchemeSelected_enablesCanStart() = runTest {
        val viewModel = vm()
        runCurrent()

        viewModel.onSchemeSelected(EidScheme.EIDAS)
        val state = viewModel.uiState.value as EidvUiState.SchemeSelection
        assertEquals(EidScheme.EIDAS, state.selected)
        assertTrue(state.canStart)
    }

    @Test
    fun start_ensuresCase_thenEntersAwaiting_withRedirectUrl() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo)
        runCurrent()
        viewModel.onSchemeSelected(EidScheme.EIDAS)

        viewModel.start()
        runCurrent()

        val state = viewModel.uiState.value as EidvUiState.AwaitingProvider
        assertEquals("kyc_new", state.caseId)
        assertEquals("https://eid.example/redirect/abc", state.redirectUrl)
        assertEquals(1, repo.ensureCalls)
        assertEquals(1, repo.startCalls)

        viewModel.stopPolling()
    }

    @Test
    fun poll_oneIteration_withVerification_movesToResult_withCritical() = runTest {
        val repo = FakeRepo().apply {
            statusResults.addLast(
                ApiResult.Success(
                    EidStatusResult(
                        verification = verification(
                            discrepancies = listOf(
                                EidDiscrepancy("dob", "1990-01-01", "1990-02-01", EidDiscrepancySeverity.CRITICAL),
                            ),
                        ),
                        autoTierUpgrade = true,
                    ),
                ),
            )
        }
        val viewModel = vm(repo)
        viewModel.pollIntervalMillis = 10L
        runCurrent()
        viewModel.onSchemeSelected(EidScheme.EIDAS)
        viewModel.start()
        runCurrent() // enters AwaitingProvider + first poll iteration finds the assertion.

        val state = viewModel.uiState.value as EidvUiState.Result
        assertTrue(state.hasCriticalDiscrepancy)
        assertTrue(state.autoTierUpgrade)

        viewModel.stopPolling()
    }

    @Test
    fun poll_whenExpired_andNullVerification_movesToExpired() = runTest {
        val repo = FakeRepo().apply {
            startResult = ApiResult.Success(
                StartEidSession("sess_1", "https://eid.example/redirect/abc", Instant.ofEpochSecond(1_000L)),
            )
        }
        val viewModel = vm(repo)
        viewModel.nowProvider = { 5_000L } // already past the 1000 expiry.
        viewModel.pollIntervalMillis = 10L
        runCurrent()
        viewModel.onSchemeSelected(EidScheme.EIDAS)
        viewModel.start()
        runCurrent() // enters AwaitingProvider; first poll iteration sees expiry -> Expired.

        assertTrue(viewModel.uiState.value is EidvUiState.Expired)
        viewModel.stopPolling()
    }

    @Test
    fun resume_existingVerificationOnInit_skipsToResult() = runTest {
        val repo = FakeRepo().apply {
            statusResults.addLast(
                ApiResult.Success(EidStatusResult(verification = verification(), autoTierUpgrade = false)),
            )
        }
        val viewModel = vm(repo, caseId = "kyc_existing")
        runCurrent()

        val state = viewModel.uiState.value as EidvUiState.Result
        assertEquals("kyc_existing", state.caseId)
    }

    @Test
    fun start_422_setsErrorStart() = runTest {
        val repo = FakeRepo().apply {
            startResult = ApiResult.Failure(ApiError(422, "scheme invalid"))
        }
        val viewModel = vm(repo)
        runCurrent()
        viewModel.onSchemeSelected(EidScheme.EIDAS)

        viewModel.start()
        runCurrent()

        val state = viewModel.uiState.value as EidvUiState.Error
        assertEquals(EidvUiState.Retry.START, state.retry)
        assertEquals("scheme invalid", state.message)
    }

    private companion object {
        const val FAR_FUTURE = 9_999_999_999L

        fun scheme(scheme: EidScheme) = SchemeInfo(
            scheme = scheme,
            name = scheme.wire,
            assuranceLevel = EidAssuranceLevel.SUBSTANTIAL,
            authFlow = EidAuthFlow.BROWSER_REDIRECT,
            countries = listOf("NL"),
            description = null,
        )

        fun verification(
            discrepancies: List<EidDiscrepancy> = emptyList(),
        ) = EidVerification(
            assertionId = "assertion_1",
            assuranceLevel = EidAssuranceLevel.HIGH,
            verifiedAt = Instant.ofEpochSecond(1_779_990_000L),
            discrepancies = discrepancies,
        )
    }
}
