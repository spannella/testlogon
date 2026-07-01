package com.testlogon.android.feature.kycadmin

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycResidencyAdminRepository
import com.testlogon.android.data.kycadmin.KycResidencyDto
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/** A3 — proof-of-residency review queue. */
@HiltViewModel
class KycResidencyAdminViewModel @Inject constructor(
    private val repo: KycResidencyAdminRepository,
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
        repo.review(id, decision, note)

    private fun KycResidencyDto.toItem() = KycReviewItemUi(
        id = documentId,
        title = (userSub ?: documentType).ifBlank { documentId },
        subtitle = "${documentType.replace('_', ' ')}${issuingEntity?.let { " - $it" } ?: ""}",
        badge = status,
    )

    private fun KycResidencyDto.toDetail() = KycReviewDetailUi(
        id = documentId,
        title = documentType.replace('_', ' ').ifBlank { documentId },
        status = status,
        imageUrl = documentUrl,
        fields = buildList {
            userSub?.takeIf { it.isNotBlank() }?.let { add(KycReviewFieldUi("User", it)) }
            issuingEntity?.let { add(KycReviewFieldUi("Issuer", it)) }
            documentDate?.let { add(KycReviewFieldUi("Document date", it)) }
            add(KycReviewFieldUi("Recency", if (recencyValid) "Valid ($recencyDays d)" else "Stale ($recencyDays d)"))
            add(KycReviewFieldUi("File", fileName))
            extractedAddress?.forEach { (k, v) -> add(KycReviewFieldUi(k.replace('_', ' '), v)) }
        },
        actionable = status.equals("pending", true),
    )
}

val KYC_RESIDENCY_STATUSES = listOf("pending", "verified", "rejected", "expired")

@Composable
fun KycResidencyAdminRoute(onBack: () -> Unit, viewModel: KycResidencyAdminViewModel = hiltViewModel(), modifier: Modifier = Modifier) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    KycReviewQueueScreen(
        moduleKey = "residency",
        title = "Residency review",
        statuses = KYC_RESIDENCY_STATUSES,
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
