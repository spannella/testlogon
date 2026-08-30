package com.testlogon.android.feature.tradingdocs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.tradingdocs.TradingDocsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * FE-171 — outcome of a report-generation request, surfaced inline by [ReportRequestSection]:
 *  - [Idle]        : no request in flight.
 *  - [Submitting]  : POST in flight (button disabled).
 *  - [Success]     : backend accepted — point the user at Trading Documents.
 *  - [Unavailable] : degrade-on-404 — the backend rejected/absent; honest "not available yet".
 */
sealed interface ReportSubmissionState {
    data object Idle : ReportSubmissionState
    data object Submitting : ReportSubmissionState
    data object Success : ReportSubmissionState
    data object Unavailable : ReportSubmissionState
}

/**
 * FE-171 — drives the "Statements & reports" request flow over [TradingDocsRepository]. Validation is
 * done in the composable via the PURE [validateReportRequest]; this VM just performs the (already
 * validated) request and maps repo success/failure to [ReportSubmissionState]. The repo degrades on 404
 * to `false`, which we surface as [ReportSubmissionState.Unavailable] — never a crash.
 */
@HiltViewModel
class ReportRequestViewModel @Inject constructor(
    private val repository: TradingDocsRepository,
) : ViewModel() {

    private val _submission = MutableStateFlow<ReportSubmissionState>(ReportSubmissionState.Idle)
    val submission: StateFlow<ReportSubmissionState> = _submission.asStateFlow()

    /** Submit an already-validated report request; maps the degrade-on-404 repo result to the UI state. */
    fun generate(type: String, periodStart: Long?, periodEnd: Long?, taxYear: Int?) {
        _submission.update { ReportSubmissionState.Submitting }
        viewModelScope.launch {
            val ok = repository.requestTradingDocument(type, periodStart, periodEnd, taxYear)
            _submission.update {
                if (ok) ReportSubmissionState.Success else ReportSubmissionState.Unavailable
            }
        }
    }

    /** Reset back to idle (e.g. after navigating away to Trading Documents). */
    fun reset() {
        _submission.update { ReportSubmissionState.Idle }
    }
}
