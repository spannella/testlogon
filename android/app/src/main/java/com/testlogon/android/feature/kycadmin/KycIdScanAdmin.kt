package com.testlogon.android.feature.kycadmin

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycIdScanAdminRepository
import com.testlogon.android.data.kycadmin.KycIdScanDto
import com.testlogon.android.data.kycadmin.KycIdScanSummaryDto
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/** A7 — ID-scanner review queue (adjudicate approve/decline). */
@HiltViewModel
class KycIdScanAdminViewModel @Inject constructor(
    private val repo: KycIdScanAdminRepository,
) : KycReviewViewModelBase(initialStatus = "flagged") {

    init { start() }

    override suspend fun loadList(status: String): ApiResult<List<KycReviewItemUi>> =
        when (val r = repo.byStatus(status)) {
            is ApiResult.Success -> ApiResult.Success(r.data.map { it.toItem() })
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }

    override suspend fun loadDetail(id: String): ApiResult<KycReviewDetailUi> =
        when (val r = repo.detail(id)) {
            is ApiResult.Success -> ApiResult.Success(r.data.toDetail())
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }

    override suspend fun decide(id: String, decision: String, note: String): ApiResult<*> =
        repo.adjudicate(id, decision, note)

    private fun KycIdScanSummaryDto.toItem() = KycReviewItemUi(
        id = scanId,
        title = "${documentType.replace('_', ' ')} (${fileType.replace('_', ' ')})".ifBlank { scanId },
        subtitle = "MRZ ${if (mrzValid) "valid" else "invalid"}${matchScore?.let { " - match ${(it * 100).toInt()}%" } ?: ""}",
        badge = status,
    )

    private fun KycIdScanDto.toDetail() = KycReviewDetailUi(
        id = scanId,
        title = "${documentType.replace('_', ' ')} - ${fileType.replace('_', ' ')}".ifBlank { scanId },
        status = status,
        imageUrl = imageUrl,
        fields = buildList {
            userSub?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("User", it)) }
            caseId.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("Case", it)) }
            add(KycReviewFieldUi("MRZ valid", if (mrzValid) "yes" else "no"))
            extraction?.let { e ->
                e.documentNumber?.let { add(KycReviewFieldUi("Doc number", it)) }
                e.surname?.let { add(KycReviewFieldUi("Surname", it)) }
                e.givenNames?.let { add(KycReviewFieldUi("Given names", it)) }
                e.nationality?.let { add(KycReviewFieldUi("Nationality", it)) }
                e.dateOfBirth?.let { add(KycReviewFieldUi("DOB", it)) }
                e.expiryDate?.let { add(KycReviewFieldUi("Expiry", it)) }
            }
            reviewDecision?.let { add(KycReviewFieldUi("Prior decision", it)) }
        },
        actionable = status.equals("flagged", true) || status.equals("matched", true),
    )
}

val KYC_IDSCAN_STATUSES = listOf("flagged", "matched", "approved", "declined", "rejected")
val KYC_IDSCAN_DECISIONS = listOf("approve", "decline")

@Composable
fun KycIdScanAdminRoute(onBack: () -> Unit, viewModel: KycIdScanAdminViewModel = hiltViewModel(), modifier: Modifier = Modifier) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    KycReviewQueueScreen(
        moduleKey = "idscanner",
        title = "ID scanner review",
        statuses = KYC_IDSCAN_STATUSES,
        decisionOptions = KYC_IDSCAN_DECISIONS,
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetStatus = viewModel::setStatus,
        onOpenDetail = viewModel::openDetail,
        onDecide = viewModel::submitDecision,
        onCloseDetail = viewModel::closeDetail,
        onMessageShown = viewModel::clearMessage,
        modifier = modifier,
    )
}
