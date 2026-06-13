package com.testlogon.android.feature.broadcasthost.manage

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.tips.Goal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-314 — Compose UI tests for the stateless [ManageScreen] driven by an in-test reducer over
 * [ManageUiState]. Asserts: the screen renders; tabs switch; a goal row + create form + delete-confirm; a
 * product row shows the broadcast price; add / remove / reorder / set-price / clear-price affordances exist;
 * empty / error states render. useUnmergedTree for nested nodes; remember{mutableStateOf}; assertDoesNotExist
 * is a MEMBER (not imported).
 */
@RunWith(AndroidJUnit4::class)
class ManageScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun goal(id: String) = Goal(
        goalId = id,
        sessionId = "bcs_1",
        label = "Goal $id",
        currentCents = 500L,
        targetCents = 1000L,
        reached = false,
        reachedAt = null,
        sortOrder = 0,
    )

    private fun product(id: String, broadcast: Boolean = false) = ShelfProduct(
        itemId = id,
        categoryId = "c1",
        name = "Item $id",
        priceCents = if (broadcast) 800L else 1000L,
        currency = "USD",
        imageUrl = null,
        originalPriceCents = if (broadcast) 1000L else null,
        catalogPriceCents = 1000L,
        isBroadcastPrice = broadcast,
        broadcastPriceCents = if (broadcast) 800L else null,
        discountPct = if (broadcast) 20 else 0,
    )

    /** Mounts the screen over a remembered [ManageUiState] with a minimal in-test reducer. */
    private fun launch(initial: ManageUiState) {
        rule.setContent {
            var state by remember { mutableStateOf(initial) }
            TestLogonTheme {
                ManageScreen(
                    state = state,
                    onBack = {},
                    onSelectTab = { state = state.copy(selectedTab = it) },
                    onGoalFormChange = { state = state.copy(goalForm = it(state.goalForm)) },
                    onSubmitGoal = {},
                    onRequestDeleteGoal = { id, label ->
                        state = state.copy(confirm = ConfirmTarget.DeleteGoal(id, label))
                    },
                    onConfirmDeleteGoal = {},
                    onDismissConfirm = { state = state.copy(confirm = null) },
                    onRefreshGoals = {},
                    onRetryGoals = {},
                    onAddProduct = { _, _, _ -> },
                    onRequestRemoveProduct = { id, name ->
                        state = state.copy(confirm = ConfirmTarget.RemoveProduct(id, name))
                    },
                    onConfirmRemoveProduct = {},
                    onMoveProduct = { _, _ -> },
                    onOpenPriceDialog = { p ->
                        state = state.copy(
                            priceForm = PriceForm(p.itemId, p.catalogPriceCents, p.currency),
                        )
                    },
                    onPriceFormChange = { state = state.copy(priceForm = state.priceForm?.let(it)) },
                    onSubmitPrice = {},
                    onDismissPriceDialog = { state = state.copy(priceForm = null) },
                    onClearPrice = {},
                    onRefreshProducts = {},
                    onRetryProducts = {},
                    onConsumeEvent = { state = state.copy(event = null) },
                )
            }
        }
    }

    @Test
    fun screen_renders() {
        launch(ManageUiState(goals = GoalsState.Content(listOf(goal("g1")))))
        rule.onNodeWithTag(ManageTestTags.SCREEN).assertIsDisplayed()
    }

    @Test
    fun tabs_switchToProducts() {
        launch(
            ManageUiState(
                goals = GoalsState.Content(listOf(goal("g1"))),
                products = ProductsState.Content(listOf(product("i1"))),
            ),
        )
        rule.onNodeWithTag(ManageTestTags.TAB_PRODUCTS).performClick()
        rule.onNodeWithTag(ManageTestTags.productRow("i1"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun goalsTab_showsRow_andCreateForm() {
        launch(ManageUiState(goals = GoalsState.Content(listOf(goal("g1")))))
        rule.onNodeWithTag(ManageTestTags.goalRow("g1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.GOAL_CREATE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun goalDelete_opensConfirm() {
        launch(ManageUiState(goals = GoalsState.Content(listOf(goal("g1")))))
        rule.onNodeWithTag(ManageTestTags.GOAL_DELETE, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(ManageTestTags.GOAL_DELETE_CONFIRM, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun productRow_broadcastPrice_showsClearPriceAffordance() {
        launch(
            ManageUiState(
                selectedTab = ManageTab.PRODUCTS,
                products = ProductsState.Content(listOf(product("i1", broadcast = true))),
            ),
        )
        rule.onNodeWithTag(ManageTestTags.productRow("i1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.PRODUCT_CLEAR_PRICE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun productRow_catalogPrice_showsSetPriceAffordance() {
        launch(
            ManageUiState(
                selectedTab = ManageTab.PRODUCTS,
                products = ProductsState.Content(listOf(product("i1"))),
            ),
        )
        rule.onNodeWithTag(ManageTestTags.PRODUCT_SET_PRICE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.PRODUCT_ADD, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.PRODUCT_REORDER_UP, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.PRODUCT_REORDER_DOWN, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun setPrice_opensPriceDialog() {
        launch(
            ManageUiState(
                selectedTab = ManageTab.PRODUCTS,
                products = ProductsState.Content(listOf(product("i1"))),
            ),
        )
        rule.onNodeWithTag(ManageTestTags.PRODUCT_SET_PRICE, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(ManageTestTags.PRICE_DIALOG, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun productRemove_opensConfirm() {
        launch(
            ManageUiState(
                selectedTab = ManageTab.PRODUCTS,
                products = ProductsState.Content(listOf(product("i1"))),
            ),
        )
        rule.onNodeWithTag(ManageTestTags.PRODUCT_REMOVE, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(ManageTestTags.PRODUCT_REMOVE_CONFIRM, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun goalsEmpty_rendersEmptyState_andCreateForm() {
        launch(ManageUiState(goals = GoalsState.Empty))
        // No goal rows in the empty state, but the create form is still present.
        rule.onNodeWithTag(ManageTestTags.GOAL_CREATE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.goalRow("g1"), useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun productsError_rendersScreen() {
        launch(
            ManageUiState(
                selectedTab = ManageTab.PRODUCTS,
                products = ProductsState.Error("boom"),
            ),
        )
        rule.onNodeWithTag(ManageTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(ManageTestTags.productRow("i1"), useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun parseDollarsToCents_pureChecks() {
        assertEquals(1000L, parseDollarsToCents("10"))
        assertEquals(1050L, parseDollarsToCents("10.50"))
        assertEquals(1000L, parseDollarsToCents("$10.00"))
        assertTrue(parseDollarsToCents("abc") == null)
        assertTrue(parseDollarsToCents("-5") == null)
    }
}
