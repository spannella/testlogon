package com.testlogon.android.feature.signing.packetlist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * SUX-008 — presentation logic for the signing INBOX ("list packets" surface).
 *
 * Loads the four browse buckets (awaiting / sent / completed / drafts) IN PARALLEL, folds each into a
 * [BucketLoad], and builds the [SigningInboxUiState] via the pure [buildInboxState]. There is NO poll
 * loop — refresh is manual (pull-to-refresh / retry). DEGRADE-ON-404: a 404 (or any failure) on one
 * bucket drops that bucket only; the surface renders from whatever loaded, and only collapses to Empty /
 * Error when every bucket is empty / failed respectively.
 *
 * Tapping a row opens the EXISTING packet DETAIL screen (view + SIGN + mark-done already live there), so
 * this VM only emits an OpenPacket nav event; it owns no write.
 */
@HiltViewModel
class SigningInboxViewModel @Inject constructor(
    private val repository: SigningInboxRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<SigningInboxUiState>(SigningInboxUiState.Loading)
    val uiState: StateFlow<SigningInboxUiState> = _uiState.asStateFlow()

    /** Single in-flight load guard. */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** Initial read: flashes the spinner, then lands on Content / Empty / Error. */
    fun load() {
        if (_uiState.value !is SigningInboxUiState.Content) {
            _uiState.value = SigningInboxUiState.Loading
        }
        refreshInternal(showRefreshing = false)
    }

    /** Manual refresh: keeps prior content visible with the refreshing flag while the loads run. */
    fun refresh() {
        val current = _uiState.value
        if (current is SigningInboxUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        }
        refreshInternal(showRefreshing = true)
    }

    private fun refreshInternal(showRefreshing: Boolean) {
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            val loads = coroutineScope {
                val awaiting = async { toBucketLoad(SigningInboxBucket.AWAITING, repository.awaiting()) }
                val sent = async { toBucketLoad(SigningInboxBucket.SENT, repository.sent()) }
                val completed =
                    async { toBucketLoad(SigningInboxBucket.COMPLETED, repository.completedForMe()) }
                val drafts = async { toBucketLoad(SigningInboxBucket.DRAFTS, repository.drafts()) }
                listOf(awaiting.await(), sent.await(), completed.await(), drafts.await())
            }
            _uiState.value = buildInboxState(loads, isRefreshing = false)
        }
    }

    private fun toBucketLoad(
        bucket: SigningInboxBucket,
        result: ApiResult<List<SigningInboxItem>>,
    ): BucketLoad = when (result) {
        is ApiResult.Success -> BucketLoad(bucket, items = result.data)
        is ApiResult.Failure -> BucketLoad(bucket, failure = result.error)
        is ApiResult.NetworkError -> BucketLoad(
            bucket,
            failure = ApiError(status = ApiError.STATUS_NETWORK, message = NETWORK_MESSAGE),
        )
    }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Try again."
    }
}
