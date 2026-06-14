package com.testlogon.android.feature.broadcasthost.manage

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.tips.Goal
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-314 — presentation logic for the host goals + products authoring surface.
 *
 * Loads goals + products with a SINGLE non-looping refresh on init; thereafter refresh is pull-to-refresh
 * only. There is NO poll loop (no while(isActive){delay()}) so runTest never hangs. [uiState] is a plain
 * MutableStateFlow so optimistic updates are reflected synchronously (no combine().stateIn window).
 *
 * Mutations: createGoal prepends on success; deleteGoal / removeProduct remove after a confirm; reorder is
 * OPTIMISTIC (the local list is reordered immediately + PATCHed, rolled back to the prior order on failure);
 * setPrice client pre-checks the price < catalog before the PATCH; clearPrice reverts the row. A control is
 * disabled while its mutation is in flight (the inFlight key, FR-X1). After every successful mutation the state
 * is reconciled from the response body / re-fetch (the server is source of truth, FR-X2).
 */
@HiltViewModel
class GoalsProductsViewModel @Inject constructor(
    private val repository: BroadcastManageRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    private val _uiState = MutableStateFlow(ManageUiState())
    val uiState: StateFlow<ManageUiState> = _uiState.asStateFlow()

    init {
        // SINGLE non-looping load (NOT a delay loop) of both tabs on first construction.
        refreshGoals()
        refreshProducts()
    }

    // ---- tab + form + dialog control ----

    fun selectTab(tab: ManageTab) {
        _uiState.update { it.copy(selectedTab = tab) }
    }

    fun consumeEvent() {
        _uiState.update { it.copy(event = null) }
    }

    fun updateGoalForm(transform: (GoalForm) -> GoalForm) {
        _uiState.update { it.copy(goalForm = transform(it.goalForm)) }
    }

    fun openPriceDialog(product: ShelfProduct) {
        _uiState.update {
            it.copy(
                priceForm = PriceForm(
                    itemId = product.itemId,
                    catalogPriceCents = product.catalogPriceCents,
                    currency = product.currency,
                ),
            )
        }
    }

    fun updatePriceForm(transform: (PriceForm) -> PriceForm) {
        _uiState.update { state -> state.copy(priceForm = state.priceForm?.let(transform)) }
    }

    fun dismissPriceDialog() {
        _uiState.update { it.copy(priceForm = null) }
    }

    fun requestDeleteGoal(goalId: String, label: String) {
        _uiState.update { it.copy(confirm = ConfirmTarget.DeleteGoal(goalId, label)) }
    }

    fun requestRemoveProduct(itemId: String, name: String) {
        _uiState.update { it.copy(confirm = ConfirmTarget.RemoveProduct(itemId, name)) }
    }

    fun dismissConfirm() {
        _uiState.update { it.copy(confirm = null) }
    }

    // ---- goals ----

    /** Single non-looping load of goals (cold). Used on init + Retry. */
    fun refreshGoals(pullToRefresh: Boolean = false) {
        if (sessionId.isBlank()) {
            _uiState.update { it.copy(goals = GoalsState.Error(SESSION_MISSING)) }
            return
        }
        if (pullToRefresh) {
            _uiState.update {
                val current = it.goals
                if (current is GoalsState.Content) it.copy(goals = current.copy(isRefreshing = true)) else it
            }
        } else {
            _uiState.update { it.copy(goals = GoalsState.Loading) }
        }
        viewModelScope.launch {
            _uiState.update { it.copy(goals = goalsStateFrom(repository.goals(sessionId))) }
        }
    }

    /** Validate the goal form, then create; on success prepend the new goal + reset the form. */
    fun submitGoal() {
        val form = _uiState.value.goalForm
        val targetCents = form.targetCents
        if (!form.isValid || targetCents == null) {
            // Client validation blocks the network call entirely (FR-G4).
            _uiState.update { it.copy(event = ManageEvent.Failure(VALIDATION_GOAL)) }
            return
        }
        val key = GOAL_CREATE_KEY
        if (!begin(key)) return
        viewModelScope.launch {
            val result = repository.createGoal(sessionId, form.label.trim(), targetCents, form.sortOrder)
            when (result) {
                is ApiResult.Success -> _uiState.update {
                    val list = currentGoals().let { listOf(result.data) + it }
                    it.copy(
                        goals = GoalsState.Content(list),
                        goalForm = GoalForm(),
                        inFlight = it.inFlight - key,
                        event = ManageEvent.GoalCreated(result.data.label),
                    )
                }
                is ApiResult.Failure -> failKey(key, result.error.message)
                is ApiResult.NetworkError -> failKey(key, OFFLINE)
            }
        }
    }

    /** Delete a goal (after the confirm dialog). On success removes it from the local list. */
    fun deleteGoal(goalId: String) {
        val key = goalDeleteKey(goalId)
        if (!begin(key)) return
        _uiState.update { it.copy(confirm = null) }
        viewModelScope.launch {
            when (val result = repository.deleteGoal(sessionId, goalId)) {
                is ApiResult.Success -> _uiState.update {
                    val list = currentGoals().filterNot { g -> g.goalId == goalId }
                    it.copy(
                        goals = if (list.isEmpty()) GoalsState.Empty else GoalsState.Content(list),
                        inFlight = it.inFlight - key,
                        event = ManageEvent.GoalDeleted,
                    )
                }
                is ApiResult.Failure -> failKey(key, result.error.message)
                is ApiResult.NetworkError -> failKey(key, OFFLINE)
            }
        }
    }

    // ---- products ----

    /** Single non-looping load of products (cold). Used on init + Retry. */
    fun refreshProducts(pullToRefresh: Boolean = false) {
        if (sessionId.isBlank()) {
            _uiState.update { it.copy(products = ProductsState.Error(SESSION_MISSING)) }
            return
        }
        if (pullToRefresh) {
            _uiState.update {
                val current = it.products
                if (current is ProductsState.Content) {
                    it.copy(products = current.copy(isRefreshing = true))
                } else {
                    it
                }
            }
        } else {
            _uiState.update { it.copy(products = ProductsState.Loading) }
        }
        viewModelScope.launch {
            _uiState.update { it.copy(products = productsStateFrom(repository.products(sessionId))) }
        }
    }

    /** Add a product; on success appends it (reconciled from the response body). */
    fun addProduct(itemId: String, categoryId: String, displayOrder: Int) {
        if (itemId.isBlank() || categoryId.isBlank()) {
            _uiState.update { it.copy(event = ManageEvent.Failure(VALIDATION_PRODUCT)) }
            return
        }
        val key = PRODUCT_ADD_KEY
        if (!begin(key)) return
        viewModelScope.launch {
            val result = repository.addProduct(sessionId, itemId.trim(), categoryId.trim(), displayOrder)
            when (result) {
                is ApiResult.Success -> _uiState.update {
                    val list = currentProducts().filterNot { p -> p.itemId == result.data.itemId } +
                        result.data
                    it.copy(
                        products = ProductsState.Content(list),
                        inFlight = it.inFlight - key,
                        event = ManageEvent.ProductAdded(result.data.itemId),
                    )
                }
                is ApiResult.Failure -> failKey(key, result.error.message)
                is ApiResult.NetworkError -> failKey(key, OFFLINE)
            }
        }
    }

    /** Remove a product (after the confirm dialog). On success removes it from the local list. */
    fun removeProduct(itemId: String) {
        val key = productRemoveKey(itemId)
        if (!begin(key)) return
        _uiState.update { it.copy(confirm = null) }
        viewModelScope.launch {
            when (val result = repository.removeProduct(sessionId, itemId)) {
                is ApiResult.Success -> _uiState.update {
                    val list = currentProducts().filterNot { p -> p.itemId == itemId }
                    it.copy(
                        products = if (list.isEmpty()) ProductsState.Empty else ProductsState.Content(list),
                        inFlight = it.inFlight - key,
                        event = ManageEvent.ProductRemoved,
                    )
                }
                is ApiResult.Failure -> failKey(key, result.error.message)
                is ApiResult.NetworkError -> failKey(key, OFFLINE)
            }
        }
    }

    /**
     * OPTIMISTIC move-up / move-down: swaps the two adjacent items locally, then PATCHes the new order. On
     * failure the prior order is restored and a Failure event is emitted. A no-op when indices are invalid.
     */
    fun moveProduct(fromIndex: Int, toIndex: Int) {
        val current = currentProducts()
        if (fromIndex !in current.indices || toIndex !in current.indices || fromIndex == toIndex) return
        val previous = current
        val reordered = current.toMutableList().apply {
            val moved = removeAt(fromIndex)
            add(toIndex, moved)
        }
        val key = REORDER_KEY
        if (_uiState.value.isInFlight(key)) return
        // Apply the optimistic order immediately + mark the reorder in flight.
        _uiState.update {
            it.copy(products = ProductsState.Content(reordered), inFlight = it.inFlight + key)
        }
        viewModelScope.launch {
            when (val result = repository.reorder(sessionId, reordered.map { p -> p.itemId })) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        products = ProductsState.Content(result.data),
                        inFlight = it.inFlight - key,
                        event = ManageEvent.Reordered,
                    )
                }
                is ApiResult.Failure -> rollbackReorder(key, previous, result.error.message)
                is ApiResult.NetworkError -> rollbackReorder(key, previous, OFFLINE)
            }
        }
    }

    /** Set a broadcast price (from the dialog). Client pre-checks cents < catalog before the PATCH. */
    fun submitPrice() {
        val form = _uiState.value.priceForm ?: return
        val cents = form.priceCents
        if (!form.isValid || cents == null) {
            _uiState.update { it.copy(event = ManageEvent.Failure(VALIDATION_PRICE)) }
            return
        }
        val key = priceKey(form.itemId)
        if (!begin(key)) return
        viewModelScope.launch {
            val result = repository.setPrice(sessionId, form.itemId, cents, form.expiresInSeconds)
            when (result) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        products = reconcileProduct(result.data),
                        priceForm = null,
                        inFlight = it.inFlight - key,
                        event = ManageEvent.PriceSet,
                    )
                }
                is ApiResult.Failure -> failKey(key, result.error.message)
                is ApiResult.NetworkError -> failKey(key, OFFLINE)
            }
        }
    }

    /** Clear a broadcast price; the row reverts to the catalog price (reconciled via a re-fetch). */
    fun clearPrice(itemId: String) {
        val key = priceKey(itemId)
        if (!begin(key)) return
        viewModelScope.launch {
            when (val result = repository.clearPrice(sessionId, itemId)) {
                is ApiResult.Success -> {
                    // Reconcile from the server: the cleared row reverts to its catalog price.
                    val refreshed = repository.products(sessionId)
                    _uiState.update {
                        val next = (refreshed as? ApiResult.Success)?.let { ok ->
                            ProductsState.Content(ok.data)
                        } ?: it.products
                        it.copy(
                            products = next,
                            inFlight = it.inFlight - key,
                            event = ManageEvent.PriceCleared,
                        )
                    }
                }
                is ApiResult.Failure -> failKey(key, result.error.message)
                is ApiResult.NetworkError -> failKey(key, OFFLINE)
            }
        }
    }

    // ---- helpers ----

    private fun currentGoals(): List<Goal> =
        (_uiState.value.goals as? GoalsState.Content)?.goals.orEmpty()

    private fun currentProducts(): List<ShelfProduct> =
        (_uiState.value.products as? ProductsState.Content)?.products.orEmpty()

    /** Replaces the matching product (by itemId) with the reconciled server copy, preserving order. */
    private fun reconcileProduct(updated: ShelfProduct): ProductsState {
        val list = currentProducts()
        val replaced = list.map { if (it.itemId == updated.itemId) updated else it }
        val next = if (replaced.any { it.itemId == updated.itemId }) replaced else replaced + updated
        return ProductsState.Content(next)
    }

    private fun rollbackReorder(key: String, previous: List<ShelfProduct>, message: String) {
        _uiState.update {
            it.copy(
                products = ProductsState.Content(previous),
                inFlight = it.inFlight - key,
                event = ManageEvent.Failure(message),
            )
        }
    }

    /** Adds [key] to inFlight unless blank session / already running. Returns false if it is a no-op. */
    private fun begin(key: String): Boolean {
        if (sessionId.isBlank()) return false
        if (_uiState.value.inFlight.contains(key)) return false
        _uiState.update { it.copy(inFlight = it.inFlight + key) }
        return true
    }

    private fun failKey(key: String, message: String) {
        _uiState.update {
            it.copy(inFlight = it.inFlight - key, event = ManageEvent.Failure(message))
        }
    }

    private fun goalsStateFrom(result: ApiResult<List<Goal>>): GoalsState = when (result) {
        is ApiResult.Success ->
            if (result.data.isEmpty()) GoalsState.Empty else GoalsState.Content(result.data)
        is ApiResult.Failure -> GoalsState.Error(result.error.message)
        is ApiResult.NetworkError -> GoalsState.Error(OFFLINE, offline = true)
    }

    private fun productsStateFrom(result: ApiResult<List<ShelfProduct>>): ProductsState = when (result) {
        is ApiResult.Success ->
            if (result.data.isEmpty()) ProductsState.Empty else ProductsState.Content(result.data)
        is ApiResult.Failure -> ProductsState.Error(result.error.message)
        is ApiResult.NetworkError -> ProductsState.Error(OFFLINE, offline = true)
    }

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        // Stable inFlight / testTag keys.
        const val GOAL_CREATE_KEY = "goal_create"
        const val PRODUCT_ADD_KEY = "product_add"
        const val REORDER_KEY = "product_reorder"

        fun goalDeleteKey(goalId: String): String = "goal_delete:$goalId"
        fun productRemoveKey(itemId: String): String = "product_remove:$itemId"
        fun priceKey(itemId: String): String = "price:$itemId"

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val SESSION_MISSING = "This broadcast is unavailable."
        private const val VALIDATION_GOAL = "Enter a label and a target amount."
        private const val VALIDATION_PRODUCT = "Enter an item id and a category id."
        private const val VALIDATION_PRICE = "Enter a price below the catalog price."
    }
}
