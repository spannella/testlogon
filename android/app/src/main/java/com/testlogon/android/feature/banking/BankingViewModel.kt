package com.testlogon.android.feature.banking

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.banking.AccountBalance
import com.testlogon.android.data.banking.BankAccount
import com.testlogon.android.data.banking.BankAccounts
import com.testlogon.android.data.banking.BankTransaction
import com.testlogon.android.data.banking.BankTransactions
import com.testlogon.android.data.banking.BankingRepository
import com.testlogon.android.data.banking.TransactionMetadata
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A generic async slice: loading / error(message) / data. */
data class BankingAsync<out T>(
    val loading: Boolean = false,
    val error: String? = null,
    val data: T? = null,
)

/** Linked-accounts list state. [unavailable] is set when the feature-flag-gated router 404s. */
data class AccountsUiState(
    val accounts: BankingAsync<List<BankAccount>> = BankingAsync(loading = true),
    val unavailable: Boolean = false,
)

/** Account-detail state: the account, its balance, and its first page of transactions. */
data class AccountDetailUiState(
    val accountId: String = "",
    val account: BankingAsync<BankAccount> = BankingAsync(loading = true),
    val balance: BankingAsync<AccountBalance> = BankingAsync(loading = true),
    val transactions: BankingAsync<List<BankTransaction>> = BankingAsync(loading = true),
    val txnUnavailable: Boolean = false,
    val cursor: String? = null,
    val loadingMore: Boolean = false,
)

/** Transaction-metadata editing state (narrative / tags / comments). */
data class TxnMetadataUiState(
    val accountId: String = "",
    val transactionId: String = "",
    val transaction: BankingAsync<BankTransaction> = BankingAsync(loading = true),
    val metadata: BankingAsync<TransactionMetadata> = BankingAsync(loading = true),
    val narrativeDraft: String = "",
    val tagDraft: String = "",
    val commentDraft: String = "",
    val savingNarrative: Boolean = false,
    val addingTag: Boolean = false,
    val addingComment: Boolean = false,
    val mutationError: String? = null,
) {
    val canSaveNarrative: Boolean get() = !savingNarrative && BankingMath.isValidNarrative(narrativeDraft)
    val canAddTag: Boolean get() = !addingTag && BankingMath.isValidTag(tagDraft)
    val canAddComment: Boolean get() = !addingComment && BankingMath.isValidComment(commentDraft)
}

/**
 * ViewModel for the native banking-accounts surface. All three screens (accounts list, account detail
 * + transactions, transaction-metadata editing) share this ViewModel; the navigation graph scopes an
 * instance per route. Reads degrade-on-404 (the repository returns soft-unavailable success for the
 * feature-flag-off case); the [AccountsUiState.unavailable] / [AccountDetailUiState.txnUnavailable]
 * flags drive the honest "banking is not available" empty state. Mutations surface errors inline.
 */
@HiltViewModel
class BankingViewModel @Inject constructor(
    private val repository: BankingRepository,
) : ViewModel() {

    private val _accounts = MutableStateFlow(AccountsUiState())
    val accounts: StateFlow<AccountsUiState> = _accounts.asStateFlow()

    private val _detail = MutableStateFlow(AccountDetailUiState())
    val detail: StateFlow<AccountDetailUiState> = _detail.asStateFlow()

    private val _metadata = MutableStateFlow(TxnMetadataUiState())
    val metadata: StateFlow<TxnMetadataUiState> = _metadata.asStateFlow()

    // ─── Accounts list ────────────────────────────────────────────────────────

    fun loadAccounts() {
        _accounts.update { it.copy(accounts = it.accounts.copy(loading = true, error = null)) }
        viewModelScope.launch {
            when (val res = repository.getAccounts()) {
                is ApiResult.Success -> _accounts.value = AccountsUiState(
                    accounts = BankingAsync(data = res.data.accounts),
                    unavailable = res.data.unavailable,
                )
                is ApiResult.Failure -> _accounts.update {
                    it.copy(accounts = it.accounts.copy(loading = false, error = res.error.message))
                }
                is ApiResult.NetworkError -> _accounts.update {
                    it.copy(accounts = it.accounts.copy(loading = false, error = "Network error"))
                }
            }
        }
    }

    // ─── Account detail + transactions ─────────────────────────────────────────

    fun loadDetail(accountId: String) {
        _detail.value = AccountDetailUiState(accountId = accountId)
        viewModelScope.launch {
            when (val res = repository.getAccount(accountId)) {
                is ApiResult.Success -> _detail.update { it.copy(account = BankingAsync(data = res.data)) }
                is ApiResult.Failure -> _detail.update { it.copy(account = BankingAsync(error = res.error.message)) }
                is ApiResult.NetworkError -> _detail.update { it.copy(account = BankingAsync(error = "Network error")) }
            }
        }
        viewModelScope.launch {
            when (val res = repository.getBalance(accountId)) {
                is ApiResult.Success -> _detail.update { it.copy(balance = BankingAsync(data = res.data)) }
                is ApiResult.Failure -> _detail.update { it.copy(balance = BankingAsync(error = res.error.message)) }
                is ApiResult.NetworkError -> _detail.update { it.copy(balance = BankingAsync(error = "Network error")) }
            }
        }
        loadTransactions(accountId)
    }

    private fun loadTransactions(accountId: String) {
        viewModelScope.launch {
            when (val res = repository.getTransactions(accountId, limit = 50, order = "desc")) {
                is ApiResult.Success -> _detail.update {
                    it.copy(
                        transactions = BankingAsync(data = res.data.transactions),
                        txnUnavailable = res.data.unavailable,
                        cursor = res.data.cursor,
                    )
                }
                is ApiResult.Failure -> _detail.update {
                    it.copy(transactions = it.transactions.copy(loading = false, error = res.error.message))
                }
                is ApiResult.NetworkError -> _detail.update {
                    it.copy(transactions = it.transactions.copy(loading = false, error = "Network error"))
                }
            }
        }
    }

    fun loadMoreTransactions() {
        val state = _detail.value
        val cursor = state.cursor ?: return
        if (state.loadingMore) return
        _detail.update { it.copy(loadingMore = true) }
        viewModelScope.launch {
            when (val res = repository.getTransactions(state.accountId, limit = 50, cursor = cursor, order = "desc")) {
                is ApiResult.Success -> _detail.update {
                    val merged = (it.transactions.data.orEmpty()) + res.data.transactions
                    it.copy(
                        transactions = BankingAsync(data = merged),
                        cursor = res.data.cursor,
                        loadingMore = false,
                    )
                }
                is ApiResult.Failure -> _detail.update { it.copy(loadingMore = false) }
                is ApiResult.NetworkError -> _detail.update { it.copy(loadingMore = false) }
            }
        }
    }

    // ─── Transaction metadata editing ──────────────────────────────────────────

    fun loadTransaction(accountId: String, transactionId: String) {
        _metadata.value = TxnMetadataUiState(accountId = accountId, transactionId = transactionId)
        viewModelScope.launch {
            when (val res = repository.getTransaction(accountId, transactionId)) {
                is ApiResult.Success -> _metadata.update { it.copy(transaction = BankingAsync(data = res.data)) }
                is ApiResult.Failure -> _metadata.update { it.copy(transaction = BankingAsync(error = res.error.message)) }
                is ApiResult.NetworkError -> _metadata.update { it.copy(transaction = BankingAsync(error = "Network error")) }
            }
        }
        refreshMetadata(accountId, transactionId)
    }

    private fun refreshMetadata(accountId: String, transactionId: String) {
        viewModelScope.launch {
            when (val res = repository.getMetadata(accountId, transactionId)) {
                is ApiResult.Success -> _metadata.update {
                    it.copy(
                        metadata = BankingAsync(data = res.data),
                        narrativeDraft = if (it.narrativeDraft.isEmpty()) res.data.narrative?.text.orEmpty() else it.narrativeDraft,
                    )
                }
                is ApiResult.Failure -> _metadata.update { it.copy(metadata = it.metadata.copy(loading = false, error = res.error.message)) }
                is ApiResult.NetworkError -> _metadata.update { it.copy(metadata = it.metadata.copy(loading = false, error = "Network error")) }
            }
        }
    }

    fun onNarrativeDraftChange(text: String) = _metadata.update { it.copy(narrativeDraft = text) }
    fun onTagDraftChange(text: String) = _metadata.update { it.copy(tagDraft = text) }
    fun onCommentDraftChange(text: String) = _metadata.update { it.copy(commentDraft = text) }

    fun saveNarrative() {
        val state = _metadata.value
        if (!state.canSaveNarrative) return
        _metadata.update { it.copy(savingNarrative = true, mutationError = null) }
        viewModelScope.launch {
            val res = repository.putNarrative(state.accountId, state.transactionId, state.narrativeDraft)
            handleMutation(res) { refreshMetadata(state.accountId, state.transactionId) }
            _metadata.update { it.copy(savingNarrative = false) }
        }
    }

    fun addTag() {
        val state = _metadata.value
        if (!state.canAddTag) return
        _metadata.update { it.copy(addingTag = true, mutationError = null) }
        viewModelScope.launch {
            val res = repository.addTag(state.accountId, state.transactionId, state.tagDraft)
            handleMutation(res) {
                _metadata.update { it.copy(tagDraft = "") }
                refreshMetadata(state.accountId, state.transactionId)
            }
            _metadata.update { it.copy(addingTag = false) }
        }
    }

    fun removeTag(tagId: String) {
        val state = _metadata.value
        viewModelScope.launch {
            val res = repository.removeTag(state.accountId, state.transactionId, tagId)
            handleMutation(res) { refreshMetadata(state.accountId, state.transactionId) }
        }
    }

    fun addComment() {
        val state = _metadata.value
        if (!state.canAddComment) return
        _metadata.update { it.copy(addingComment = true, mutationError = null) }
        viewModelScope.launch {
            val res = repository.addComment(state.accountId, state.transactionId, state.commentDraft)
            handleMutation(res) {
                _metadata.update { it.copy(commentDraft = "") }
                refreshMetadata(state.accountId, state.transactionId)
            }
            _metadata.update { it.copy(addingComment = false) }
        }
    }

    fun deleteComment(commentId: String) {
        val state = _metadata.value
        viewModelScope.launch {
            val res = repository.deleteComment(state.accountId, state.transactionId, commentId)
            handleMutation(res) { refreshMetadata(state.accountId, state.transactionId) }
        }
    }

    private inline fun <T> handleMutation(res: ApiResult<T>, onSuccess: () -> Unit) {
        when (res) {
            is ApiResult.Success -> onSuccess()
            is ApiResult.Failure -> _metadata.update { it.copy(mutationError = res.error.message) }
            is ApiResult.NetworkError -> _metadata.update { it.copy(mutationError = "Network error") }
        }
    }
}
