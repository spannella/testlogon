package com.testlogon.android.feature.sponsorship

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.sponsorship.ui.SponsorshipFilter
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxScreen
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxTestTags
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-365 - Compose UI tests for the stateless [SponsorshipInboxScreen]. An in-test reducer holds the sorted
 * full list, applies the filter CLIENT-SIDE (mirroring the VM) and records the tapped dealId, so the rows /
 * chips / empty / tap behaviour render without Hilt. assertDoesNotExist is chained (a member), not imported;
 * the tree is used unmerged for the row + status testTags.
 */
@RunWith(AndroidJUnit4::class)
class SponsorshipInboxScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun deal(id: String, status: String) = SponsorshipDeal(
        dealId = id,
        advertiserSub = "adv_$id",
        brief = "brief $id",
        status = status,
        statusEnum = SponsorshipDealStatus.from(status),
        compensationCents = 100000L,
        deadline = "2026-07-01",
        createdAt = 100L,
    )

    /** Drives [SponsorshipInboxScreen] from a small in-test reducer over [all] (the sorted full list). */
    private fun launch(all: List<SponsorshipDeal>, onTapped: (String) -> Unit = {}) {
        rule.setContent {
            TestLogonTheme {
                val allDeals = remember { all }
                var filter by remember { mutableStateOf(SponsorshipFilter.ALL) }
                val visible = allDeals.filter { filter.matches(it) }
                val state = if (allDeals.isEmpty()) {
                    SponsorshipInboxUiState.Empty
                } else {
                    SponsorshipInboxUiState.Content(deals = visible, filter = filter)
                }
                SponsorshipInboxScreen(
                    state = state,
                    onBack = {},
                    onRefresh = {},
                    onRetry = {},
                    onFilterSelected = { filter = it },
                    onDealClick = onTapped,
                )
            }
        }
    }

    @Test
    fun rendersRows_andStatusChips() {
        launch(listOf(deal("d1", "proposed"), deal("d2", "accepted")))
        rule.onNodeWithTag(SponsorshipInboxTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipInboxTestTags.row("d1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipInboxTestTags.row("d2"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipInboxTestTags.status("d1"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun filterChip_pending_windowsToProposedAndNegotiating() {
        launch(
            listOf(
                deal("p1", "proposed"),
                deal("n1", "negotiating"),
                deal("a1", "accepted"),
            ),
        )
        rule.onNodeWithTag(SponsorshipInboxTestTags.filter("pending")).performClick()

        rule.onNodeWithTag(SponsorshipInboxTestTags.row("p1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipInboxTestTags.row("n1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipInboxTestTags.row("a1"), useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun emptyList_showsEmptyState() {
        launch(emptyList())
        rule.onNodeWithTag(SponsorshipInboxTestTags.EMPTY).assertIsDisplayed()
        rule.onNodeWithText("No sponsorship offers yet").assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipInboxTestTags.row("d1"), useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun tappingRow_emitsDealId() {
        val tapped = mutableListOf<String>()
        launch(listOf(deal("d1", "proposed")), onTapped = { tapped += it })
        rule.onNodeWithTag(SponsorshipInboxTestTags.row("d1"), useUnmergedTree = true).performClick()
        assertEquals(listOf("d1"), tapped)
    }
}
