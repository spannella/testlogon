package com.testlogon.android.feature.broadcasthost.manage

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.tips.Goal
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-314 — unit tests for [GoalsProductsViewModel]. Uses MainDispatcherRule + runCurrent (NEVER
 * advanceUntilIdle; there is NO poll loop so nothing to drive). uiState is a plain MutableStateFlow so
 * optimistic state is synchronous; the in-flight window is observed by PARKing the fake repo on a
 * CompletableDeferred gate. Verifies: goal-create validation blocks bad input with no network; create prepends;
 * delete removes; product add/remove; optimistic reorder updates the order then rolls back on failure; the
 * set-price client pre-check (>= catalog blocked); and inFlight disables a control during a mutation.
 */
class GoalsProductsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun vm(repo: BroadcastManageRepository): GoalsProductsViewModel {
        val saved = SavedStateHandle(mapOf(GoalsProductsViewModel.ARG_SESSION_ID to SESSION))
        return GoalsProductsViewModel(repo, saved)
    }

    private fun goal(id: String, label: String = "Goal $id") = Goal(
        goalId = id,
        sessionId = SESSION,
        label = label,
        currentCents = 0L,
        targetCents = 10_000L,
        reached = false,
        reachedAt = null,
        sortOrder = 0,
    )

    private fun product(id: String, catalog: Long = 1000L) = ShelfProduct(
        itemId = id,
        categoryId = "c1",
        name = "Item $id",
        priceCents = catalog,
        currency = "USD",
        imageUrl = null,
        originalPriceCents = null,
        catalogPriceCents = catalog,
    )

    @Test
    fun init_loadsGoalsAndProducts() = runTest {
        val repo = FakeManageRepo().apply {
            goalsResult = ApiResult.Success(listOf(goal("g1")))
            productsResult = ApiResult.Success(listOf(product("i1")))
        }
        val sut = vm(repo)
        runCurrent()
        assertTrue(sut.uiState.value.goals is GoalsState.Content)
        assertTrue(sut.uiState.value.products is ProductsState.Content)
    }

    @Test
    fun submitGoal_invalidInput_blocksNetwork() = runTest {
        val repo = FakeManageRepo()
        val sut = vm(repo)
        runCurrent()
        // Empty label + no target -> invalid; no createGoal call.
        sut.submitGoal()
        runCurrent()
        assertEquals(0, repo.createGoalCalls)
        assertTrue(sut.uiState.value.event is ManageEvent.Failure)
    }

    @Test
    fun submitGoal_valid_prepends() = runTest {
        val repo = FakeManageRepo().apply {
            goalsResult = ApiResult.Success(listOf(goal("g1")))
            createGoalResult = ApiResult.Success(goal("g9", "Car"))
        }
        val sut = vm(repo)
        runCurrent()
        sut.updateGoalForm { it.copy(label = "Car", targetDollars = "50.00") }
        sut.submitGoal()
        runCurrent()
        val list = (sut.uiState.value.goals as GoalsState.Content).goals
        assertEquals("g9", list.first().goalId)
        assertEquals(2, list.size)
    }

    @Test
    fun deleteGoal_removesFromList() = runTest {
        val repo = FakeManageRepo().apply {
            goalsResult = ApiResult.Success(listOf(goal("g1"), goal("g2")))
        }
        val sut = vm(repo)
        runCurrent()
        sut.deleteGoal("g1")
        runCurrent()
        val list = (sut.uiState.value.goals as GoalsState.Content).goals
        assertEquals(listOf("g2"), list.map { it.goalId })
    }

    @Test
    fun addProduct_appends() = runTest {
        val repo = FakeManageRepo().apply {
            productsResult = ApiResult.Success(listOf(product("i1")))
            addProductResult = ApiResult.Success(product("i9"))
        }
        val sut = vm(repo)
        runCurrent()
        sut.addProduct("i9", "c1", 0)
        runCurrent()
        val list = (sut.uiState.value.products as ProductsState.Content).products
        assertEquals(listOf("i1", "i9"), list.map { it.itemId })
    }

    @Test
    fun removeProduct_removesFromList() = runTest {
        val repo = FakeManageRepo().apply {
            productsResult = ApiResult.Success(listOf(product("i1"), product("i2")))
        }
        val sut = vm(repo)
        runCurrent()
        sut.removeProduct("i1")
        runCurrent()
        val list = (sut.uiState.value.products as ProductsState.Content).products
        assertEquals(listOf("i2"), list.map { it.itemId })
    }

    @Test
    fun moveProduct_optimisticReorder_thenServerOrderWins() = runTest {
        val repo = FakeManageRepo().apply {
            productsResult = ApiResult.Success(listOf(product("i1"), product("i2"), product("i3")))
            reorderResult = ApiResult.Success(listOf(product("i2"), product("i1"), product("i3")))
        }
        val sut = vm(repo)
        runCurrent()
        // Move i2 (index 1) up to index 0.
        sut.moveProduct(1, 0)
        // Optimistic order applied synchronously.
        assertEquals(
            listOf("i2", "i1", "i3"),
            (sut.uiState.value.products as ProductsState.Content).products.map { it.itemId },
        )
        runCurrent()
        // Server re-fetch order wins (here identical).
        assertEquals(
            listOf("i2", "i1", "i3"),
            (sut.uiState.value.products as ProductsState.Content).products.map { it.itemId },
        )
    }

    @Test
    fun moveProduct_failure_rollsBack() = runTest {
        val repo = FakeManageRepo().apply {
            productsResult = ApiResult.Success(listOf(product("i1"), product("i2")))
            reorderResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val sut = vm(repo)
        runCurrent()
        sut.moveProduct(0, 1)
        // Optimistic swap applied.
        assertEquals(
            listOf("i2", "i1"),
            (sut.uiState.value.products as ProductsState.Content).products.map { it.itemId },
        )
        runCurrent()
        // Rolled back to the prior order on failure.
        assertEquals(
            listOf("i1", "i2"),
            (sut.uiState.value.products as ProductsState.Content).products.map { it.itemId },
        )
        assertTrue(sut.uiState.value.event is ManageEvent.Failure)
    }

    @Test
    fun submitPrice_atOrAboveCatalog_blockedNoNetwork() = runTest {
        val repo = FakeManageRepo().apply {
            productsResult = ApiResult.Success(listOf(product("i1", catalog = 1000L)))
        }
        val sut = vm(repo)
        runCurrent()
        sut.openPriceDialog(product("i1", catalog = 1000L))
        // 10.00 == catalog -> invalid (must be strictly below).
        sut.updatePriceForm { it.copy(priceDollars = "10.00") }
        sut.submitPrice()
        runCurrent()
        assertEquals(0, repo.setPriceCalls)
        assertTrue(sut.uiState.value.event is ManageEvent.Failure)
    }

    @Test
    fun submitPrice_belowCatalog_setsPrice() = runTest {
        val repo = FakeManageRepo().apply {
            productsResult = ApiResult.Success(listOf(product("i1", catalog = 1000L)))
            setPriceResult = ApiResult.Success(product("i1").copy(isBroadcastPrice = true, discountPct = 20))
        }
        val sut = vm(repo)
        runCurrent()
        sut.openPriceDialog(product("i1", catalog = 1000L))
        sut.updatePriceForm { it.copy(priceDollars = "8.00") }
        sut.submitPrice()
        runCurrent()
        assertEquals(1, repo.setPriceCalls)
        assertEquals(800L, repo.lastSetPriceCents)
    }

    @Test
    fun deleteGoal_inFlight_disablesDuringMutation() = runTest {
        val repo = FakeManageRepo().apply {
            goalsResult = ApiResult.Success(listOf(goal("g1")))
            deleteGoalGate = CompletableDeferred()
        }
        val sut = vm(repo)
        runCurrent()
        sut.deleteGoal("g1")
        runCurrent()
        // Parked: the delete key is in flight.
        assertTrue(sut.uiState.value.isInFlight(GoalsProductsViewModel.goalDeleteKey("g1")))
        repo.deleteGoalGate!!.complete(Unit)
        runCurrent()
        assertFalse(sut.uiState.value.isInFlight(GoalsProductsViewModel.goalDeleteKey("g1")))
    }

    private companion object {
        const val SESSION = "bcs_1"
    }
}

/**
 * AND-314 — fake [BroadcastManageRepository] for [GoalsProductsViewModelTest]. Defaults every call to success;
 * records call counts / last args; [deleteGoalGate] optionally PARKs deleteGoal so a test can observe the
 * optimistic in-flight window. Kept SEPARATE (no shared fake) so other features' fakes are untouched.
 */
open class FakeManageRepo : BroadcastManageRepository {

    var goalsResult: ApiResult<List<Goal>> = ApiResult.Success(emptyList())
    var createGoalResult: ApiResult<Goal> = ApiResult.Success(
        Goal("g0", "bcs_1", "Goal", 0L, 10_000L, false, null, 0),
    )
    var deleteGoalResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var productsResult: ApiResult<List<ShelfProduct>> = ApiResult.Success(emptyList())
    var addProductResult: ApiResult<ShelfProduct> =
        ApiResult.Success(ShelfProduct("i0", "c1", "Item", 1000L, "USD", null, null))
    var removeProductResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var reorderResult: ApiResult<List<ShelfProduct>> = ApiResult.Success(emptyList())
    var setPriceResult: ApiResult<ShelfProduct> =
        ApiResult.Success(ShelfProduct("i0", "c1", "Item", 800L, "USD", null, null))
    var clearPriceResult: ApiResult<Unit> = ApiResult.Success(Unit)

    var createGoalCalls = 0
    var setPriceCalls = 0
    var lastSetPriceCents: Long? = null

    var deleteGoalGate: CompletableDeferred<Unit>? = null

    override suspend fun goals(sessionId: String): ApiResult<List<Goal>> = goalsResult

    override suspend fun createGoal(
        sessionId: String,
        label: String,
        targetCents: Long,
        sortOrder: Int,
    ): ApiResult<Goal> {
        createGoalCalls++
        return createGoalResult
    }

    override suspend fun deleteGoal(sessionId: String, goalId: String): ApiResult<Unit> {
        deleteGoalGate?.await()
        return deleteGoalResult
    }

    override suspend fun products(sessionId: String): ApiResult<List<ShelfProduct>> = productsResult

    override suspend fun addProduct(
        sessionId: String,
        itemId: String,
        categoryId: String,
        displayOrder: Int,
    ): ApiResult<ShelfProduct> = addProductResult

    override suspend fun removeProduct(sessionId: String, itemId: String): ApiResult<Unit> =
        removeProductResult

    override suspend fun reorder(sessionId: String, order: List<String>): ApiResult<List<ShelfProduct>> =
        reorderResult

    override suspend fun setPrice(
        sessionId: String,
        itemId: String,
        cents: Long,
        expiresInSeconds: Long?,
    ): ApiResult<ShelfProduct> {
        setPriceCalls++
        lastSetPriceCents = cents
        return setPriceResult
    }

    override suspend fun clearPrice(sessionId: String, itemId: String): ApiResult<Unit> = clearPriceResult
}
