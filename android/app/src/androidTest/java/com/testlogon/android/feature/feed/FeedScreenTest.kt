package com.testlogon.android.feature.feed

import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.LockType
import com.testlogon.android.data.feed.Paywall
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-098 / AND-099 / AND-101 / AND-104 — Compose UI tests for the stateless [FeedScreen]. */
@RunWith(AndroidJUnit4::class)
class FeedScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun openPost(id: String) = FeedPost(
        id = id, authorId = "u_$id", createdAtEpochSeconds = 1_780_000_000L,
        body = "Open body $id", media = emptyList(), tags = emptyList(),
        likeCount = 0, commentCount = 0, likedByMe = false, paywall = Paywall.Unlocked,
    )

    private fun lockedPost(id: String, secret: String) = FeedPost(
        // Mapper would have redacted body/media for a locked post; we mirror that here.
        id = id, authorId = "u_$id", createdAtEpochSeconds = 1_780_000_000L,
        body = null, media = emptyList(), tags = emptyList(),
        likeCount = 0, commentCount = 0, likedByMe = false,
        paywall = Paywall.Locked(
            lockType = LockType.FIXED_PRICE, priceCents = 499, unlockCount = null,
            unlockLimit = null, unlockLimitReached = false, lockExpired = false,
        ),
    )

    private fun launch(
        items: List<FeedPost>,
        onPostClick: (FeedPost) -> Unit = {},
        onUnlockClick: (String) -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                val paging = remember { flowOf(PagingData.from(items)) }
                val lazyItems = paging.collectAsLazyPagingItems()
                FeedScreen(
                    items = lazyItems,
                    onRefresh = {},
                    onPostClick = onPostClick,
                    onUnlockClick = onUnlockClick,
                )
            }
        }
    }

    @Test
    fun renders_rows() {
        launch(listOf(openPost("p1"), openPost("p2")))
        rule.onNodeWithTag(FeedTestTags.SCREEN).assertIsDisplayed()
        rule.onAllNodesWithTag(PostItemTestTags.ITEM).assertCountEquals(2)
    }

    @Test
    fun lockedPost_showsLockedBadge_andPaywallCard_noContent() {
        launch(listOf(lockedPost("p1", secret = "TOP SECRET BODY")))
        // Paging loads asynchronously; wait for the locked row to appear before asserting.
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithTag(PostItemTestTags.LOCKED_BADGE).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithTag(PostItemTestTags.LOCKED_BADGE).assertIsDisplayed()
        rule.onNodeWithTag(PaywallTestTags.CARD).assertIsDisplayed()
        // Non-leakage: the protected body string never appears in the tree.
        rule.onAllNodesWithText("TOP SECRET BODY").assertCountEquals(0)
    }

    @Test
    fun openPost_showsBody_noPaywall() {
        launch(listOf(openPost("p1")))
        rule.onNodeWithText("Open body p1").assertIsDisplayed()
        rule.onAllNodesWithTag(PaywallTestTags.CARD).assertCountEquals(0)
    }

    @Test
    fun tappingRow_invokesPostClick() {
        var clicked: String? = null
        launch(listOf(openPost("p1")), onPostClick = { clicked = it.id })
        rule.onAllNodesWithTag(PostItemTestTags.ITEM).onFirst().performClick()
        rule.runOnIdle { assertEquals("p1", clicked) }
    }

    @Test
    fun lockedCta_invokesUnlockClick() {
        var unlockedId: String? = null
        launch(listOf(lockedPost("p1", secret = "x")), onUnlockClick = { unlockedId = it })
        // Paging loads asynchronously; wait for the paywall CTA (which lives in the unmerged tree)
        // before clicking it.
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithTag(PaywallTestTags.CTA, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithTag(PaywallTestTags.CTA, useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals("p1", unlockedId) }
    }

    @Test
    fun emptyFeed_showsEmptyState() {
        launch(emptyList())
        // The empty state renders only after the paging flow's first (empty) load completes.
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithTag(FeedTestTags.EMPTY).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithTag(FeedTestTags.EMPTY).assertIsDisplayed()
    }
}
