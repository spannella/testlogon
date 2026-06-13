package com.testlogon.android.feature.kyc.cases

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.MonitoringState
import com.testlogon.android.feature.kyc.cases.model.TimelineEvent
import com.testlogon.android.feature.kyc.cases.model.TimelineKind
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-329 - Compose UI smoke tests for the stateless [KycCaseListScreen] + [KycCaseDetailScreen] driven by
 * fixed UI states (no VM / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is a MEMBER.
 */
@RunWith(AndroidJUnit4::class)
class KycCaseScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun summary(id: String, status: KycCaseStatus = KycCaseStatus.SUBMITTED) = KycCaseSummary(
        caseId = id,
        status = status,
        createdAt = Instant.ofEpochSecond(1_780_000_000L),
        updatedAt = Instant.ofEpochSecond(1_780_000_100L),
    )

    private fun activeMonitoring() = MonitoringState(
        active = true,
        status = "needs_review",
        nextReviewDate = Instant.ofEpochSecond(1_790_000_000L),
        graceDeadline = null,
        caseId = "c1",
        message = "schedule:needs_review",
    )

    private fun launchList(state: KycCaseListUiState) {
        rule.setContent {
            TestLogonTheme {
                KycCaseListScreen(
                    state = state,
                    onOpenCase = {},
                    onStartVerification = {},
                    onBack = {},
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    private fun launchDetail(state: KycCaseDetailUiState) {
        rule.setContent {
            TestLogonTheme {
                KycCaseDetailScreen(
                    state = state,
                    onBack = {},
                    onReVerify = {},
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun list_rendersRows_andMonitoringBanner_whenActive() {
        launchList(
            KycCaseListUiState.Content(
                cases = listOf(summary("c1"), summary("c2")),
                monitoring = activeMonitoring(),
            ),
        )
        rule.onNodeWithTag(KycCaseListTestTags.MONITORING_BANNER, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(KycCaseListTestTags.row("c1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(KycCaseListTestTags.row("c2"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun list_noBanner_whenMonitoringInactive() {
        launchList(
            KycCaseListUiState.Content(
                cases = listOf(summary("c1")),
                monitoring = MonitoringState.INACTIVE,
            ),
        )
        rule.onNodeWithTag(KycCaseListTestTags.MONITORING_BANNER, useUnmergedTree = true)
            .assertDoesNotExist()
        rule.onNodeWithTag(KycCaseListTestTags.row("c1"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun list_empty_showsEmptyCta() {
        launchList(KycCaseListUiState.Empty(monitoring = MonitoringState.INACTIVE))
        rule.onNodeWithTag(KycCaseListTestTags.EMPTY, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun detail_showsStatus_timeline_andReasonCodes() {
        launchDetail(
            KycCaseDetailUiState.Content(
                case = summary("c1", status = KycCaseStatus.REJECTED),
                timeline = listOf(
                    TimelineEvent(
                        at = Instant.ofEpochSecond(1_780_000_000L),
                        kind = TimelineKind.CREATED,
                        label = "created",
                    ),
                    TimelineEvent(
                        at = Instant.ofEpochSecond(1_780_000_100L),
                        kind = TimelineKind.CURRENT,
                        label = "current",
                    ),
                ),
                reasonCodes = listOf("doc_unreadable"),
            ),
        )
        rule.onNodeWithTag(KycCaseDetailTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(KycCaseDetailTestTags.REASON_CODES, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(KycCaseDetailTestTags.timelineEvent(0), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(KycCaseDetailTestTags.timelineEvent(1), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun detail_expiredCase_showsReVerifyCta() {
        launchDetail(
            KycCaseDetailUiState.Content(
                case = summary("c1", status = KycCaseStatus.EXPIRED),
                timeline = listOf(
                    TimelineEvent(
                        at = Instant.ofEpochSecond(1_780_000_000L),
                        kind = TimelineKind.CREATED,
                        label = "created",
                    ),
                ),
                reasonCodes = emptyList(),
            ),
        )
        rule.onNodeWithTag(KycCaseDetailTestTags.REVERIFY, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(KycCaseDetailTestTags.REASON_CODES, useUnmergedTree = true).assertDoesNotExist()
    }
}
