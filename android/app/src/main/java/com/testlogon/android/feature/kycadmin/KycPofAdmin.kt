package com.testlogon.android.feature.kycadmin

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycPofAdminRepository
import com.testlogon.android.data.kycadmin.KycPofDto
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/** A4 — proof-of-funds review queue (adjudicate approve/reject/request_more_info). */
@HiltViewModel
class KycPofAdminViewModel @Inject constructor(
    private val repo: KycPofAdminRepository,
) : KycReviewViewModelBase(initialStatus = "pending") {

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

    private fun KycPofDto.amountText(): String? =
        declaredAmountCents?.let { "${centsUsd(it)} ${currency ?: ""}".trim() }

    private fun KycPofDto.toItem() = KycReviewItemUi(
        id = submissionId,
        title = userSub.ifBlank { submissionId },
        subtitle = listOfNotNull(sourceCategory?.replace('_', ' '), amountText()).joinToString(" - ").ifBlank { "submission" },
        badge = status,
    )

    private fun KycPofDto.toDetail() = KycReviewDetailUi(
        id = submissionId,
        title = userSub.ifBlank { submissionId },
        status = status,
        imageUrl = null,
        fields = buildList {
            documentS3Key?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("Document", it)) }
            sourceCategory?.let { add(KycReviewFieldUi("Source", it.replace('_', ' '))) }
            amountText()?.let { add(KycReviewFieldUi("Declared amount", it)) }
            add(KycReviewFieldUi("Score", score.toString()))
            add(KycReviewFieldUi("Risk contribution", riskContribution.toString()))
            note?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("Applicant note", it)) }
            reviewerNote?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("Reviewer note", it)) }
        },
        actionable = status.equals("pending", true) || status.equals("under_review", true),
    )
}

val KYC_POF_STATUSES = listOf("pending", "under_review", "verified", "rejected")
val KYC_POF_DECISIONS = listOf("approve", "reject", "request_more_info")

@Composable
fun KycPofAdminRoute(onBack: () -> Unit, viewModel: KycPofAdminViewModel = hiltViewModel(), modifier: Modifier = Modifier) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    KycReviewQueueScreen(
        moduleKey = "prooffunds",
        title = "Proof of funds review",
        statuses = KYC_POF_STATUSES,
        decisionOptions = KYC_POF_DECISIONS,
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
