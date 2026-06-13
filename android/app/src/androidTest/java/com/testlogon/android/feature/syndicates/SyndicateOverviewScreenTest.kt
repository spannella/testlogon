package com.testlogon.android.feature.syndicates

import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.paging.LoadState
import androidx.paging.LoadStates
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewScreen
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewTestTags
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewUiState
import com.testlogon.android.feature.syndicates.ui.TabState
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-356 - Compose UI tests for the stateless [SyndicateOverviewScreen]: header + role badge, the three
 * tabs switch, treasury amounts render, the weighted split-mismatch banner shows, and the not-member empty
 * state. Paging flows use PagingData.from with terminal NotLoading LoadStates so the content / empty state
 * renders in tests. assertDoesNotExist is chained (a member), not imported. useUnmergedTree where needed.
 */
@RunWith(AndroidJUnit4::class)
class SyndicateOverviewScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun overview(isAdmin: Boolean = true) = SyndicateOverview(
        id = "syn_1", name = "Aces", memberCount = 4, isAdmin = isAdmin, isMember = true, currency = "USD",
    )

    private fun feedItems(vararg items: SyndicateFeedItem) = flowOf(
        PagingData.from(
            items.toList(),
            sourceLoadStates = terminalLoadStates(items.isEmpty()),
        ),
    )

    private fun ledgerItems(vararg items: TreasuryEntry) = flowOf(
        PagingData.from(
            items.toList(),
            sourceLoadStates = terminalLoadStates(items.isEmpty()),
        ),
    )

    private fun terminalLoadStates(empty: Boolean) = LoadStates(
        refresh = LoadState.NotLoading(endOfPaginationReached = empty),
        prepend = LoadState.NotLoading(endOfPaginationReached = true),
        append = LoadState.NotLoading(endOfPaginationReached = true),
    )

    private fun launch(
        state: SyndicateOverviewUiState,
        feed: kotlinx.coroutines.flow.Flow<PagingData<SyndicateFeedItem>> = feedItems(),
        ledger: kotlinx.coroutines.flow.Flow<PagingData<TreasuryEntry>> = ledgerItems(),
    ) {
        rule.setContent {
            TestLogonTheme {
                val feedItems = remember { feed }.collectAsLazyPagingItems()
                val ledgerItems = remember { ledger }.collectAsLazyPagingItems()
                SyndicateOverviewScreen(
                    state = state,
                    feed = feedItems,
                    ledger = ledgerItems,
                    onBack = {},
                    onOpenLicensing = {},
                    onRetry = {},
                    onRefresh = {},
                )
            }
        }
    }

    private fun contentState(
        split: TabState<RevenueSplitPolicy> = TabState.Content(
            RevenueSplitPolicy(mode = SplitMode.EQUAL, platformFeeBps = 0),
        ),
        treasury: TabState<TreasurySummary> = TabState.Content(
            TreasurySummary(balanceCents = 150000, depositedCents = 200000, disbursedCents = 50000,
                currency = "USD"),
        ),
        isAdmin: Boolean = true,
    ) = SyndicateOverviewUiState.Content(
        overview = overview(isAdmin), treasury = treasury, split = split, isStale = false,
    )

    @Test
    fun rendersHeader_andThreeTabs_withAdminBadge() {
        launch(contentState())
        rule.onNodeWithTag(SyndicateOverviewTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(SyndicateOverviewTestTags.HEADER_NAME).assertIsDisplayed()
        rule.onNodeWithTag(SyndicateOverviewTestTags.ROLE_BADGE).assertIsDisplayed()
        rule.onNodeWithTag(SyndicateOverviewTestTags.TAB_FEED).assertIsDisplayed()
        rule.onNodeWithTag(SyndicateOverviewTestTags.TAB_TREASURY).assertIsDisplayed()
        rule.onNodeWithTag(SyndicateOverviewTestTags.TAB_SPLIT).assertIsDisplayed()
        rule.onNodeWithText("Admin").assertIsDisplayed()
    }

    @Test
    fun feedTab_rendersPostRows() {
        launch(
            contentState(),
            feed = feedItems(
                SyndicateFeedItem(postId = "p1", authorName = "Ann", createdAt = 1L, text = "hi"),
                SyndicateFeedItem(postId = "p2", authorName = "Bob", createdAt = 2L, text = "yo"),
            ),
        )
        rule.onAllNodesWithTag(SyndicateOverviewTestTags.feedItem("p1"))
            .assertCountEquals(1)
        rule.onNodeWithTag(SyndicateOverviewTestTags.feedItem("p2")).assertIsDisplayed()
    }

    @Test
    fun treasuryTab_showsFormattedAmounts() {
        launch(contentState())
        rule.onNodeWithTag(SyndicateOverviewTestTags.TAB_TREASURY).performClick()
        // Assert against the same formatter the screen uses, so the test is locale-independent.
        rule.onNodeWithText(formatCents(150000, "USD")).assertIsDisplayed()
        rule.onNodeWithText(formatCents(200000, "USD")).assertIsDisplayed()
    }

    @Test
    fun splitTab_weightedMismatch_showsBanner() {
        val mismatched = RevenueSplitPolicy(
            mode = SplitMode.WEIGHTED,
            platformFeeBps = 500,
            weightsBps = mapOf("usr_a" to 6000, "usr_b" to 3000), // sums 9000, off by 1000bps
        )
        launch(contentState(split = TabState.Content(mismatched)))
        rule.onNodeWithTag(SyndicateOverviewTestTags.TAB_SPLIT).performClick()
        rule.onNodeWithTag(SyndicateOverviewTestTags.SPLIT_MISMATCH).assertIsDisplayed()
        rule.onNodeWithTag(SyndicateOverviewTestTags.splitRow("usr_a")).assertIsDisplayed()
    }

    @Test
    fun splitTab_weightedBalanced_noBanner() {
        val balanced = RevenueSplitPolicy(
            mode = SplitMode.WEIGHTED,
            platformFeeBps = 500,
            weightsBps = mapOf("usr_a" to 6000, "usr_b" to 4000),
        )
        launch(contentState(split = TabState.Content(balanced)))
        rule.onNodeWithTag(SyndicateOverviewTestTags.TAB_SPLIT).performClick()
        rule.onNodeWithTag(SyndicateOverviewTestTags.SPLIT_MISMATCH).assertDoesNotExist()
    }

    @Test
    fun notMember_showsEmptyState() {
        launch(SyndicateOverviewUiState.NotMember)
        rule.onNodeWithTag(SyndicateOverviewTestTags.NOT_MEMBER).assertIsDisplayed()
    }
}
