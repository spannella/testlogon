package com.testlogon.android.feature.kycadmin

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycDocAdminRepository
import com.testlogon.android.data.kycadmin.KycDocDto
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/** A2 — KYC document review queue (by-status list + detail w/ image + approve/reject). */
@HiltViewModel
class KycDocAdminViewModel @Inject constructor(
    private val repo: KycDocAdminRepository,
) : KycReviewViewModelBase(initialStatus = "extracted") {

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
        repo.review(id, decision, note)

    private fun KycDocDto.toItem() = KycReviewItemUi(
        id = documentId,
        title = (userSub ?: documentType).ifBlank { documentId },
        subtitle = "${documentType.replace('_', ' ')} - ${fileName}",
        badge = status,
    )

    private fun KycDocDto.toDetail() = KycReviewDetailUi(
        id = documentId,
        title = documentType.replace('_', ' ').ifBlank { documentId },
        status = status,
        imageUrl = imageUrl,
        fields = buildList {
            userSub?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("User", it)) }
            caseId?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("Case", it)) }
            add(KycReviewFieldUi("File", fileName))
            overallConfidence?.let { add(KycReviewFieldUi("Confidence", it)) }
            extractedFields.forEach { (k, v) -> add(KycReviewFieldUi(k.replace('_', ' '), v)) }
            reviewDecision?.let { add(KycReviewFieldUi("Prior decision", it)) }
        },
        actionable = status.equals("extracted", true) || status.equals("pending", true) || status.equals("failed", true),
    )
}

val KYC_DOC_STATUSES = listOf("extracted", "pending", "failed", "approved", "rejected")
val KYC_DOC_DECISIONS = listOf("approve", "reject")

@Composable
fun KycDocAdminRoute(onBack: () -> Unit, viewModel: KycDocAdminViewModel = hiltViewModel(), modifier: Modifier = Modifier) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    KycReviewQueueScreen(
        moduleKey = "documents",
        title = "Document review",
        statuses = KYC_DOC_STATUSES,
        decisionOptions = KYC_DOC_DECISIONS,
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
