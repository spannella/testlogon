package com.testlogon.android.feature.signing

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PacketSigner
import com.testlogon.android.feature.signing.model.SignaturePacket
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-340 - Compose UI smoke tests for the stateless [PacketDetailScreen] driven by fixed UI states (no
 * VM / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is a MEMBER. An in-test reducer
 * (a mutableStateOf swap) is used to verify the open-pdf affordance fires its callback.
 */
@RunWith(AndroidJUnit4::class)
class PacketDetailScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun signer(id: String, status: String = "pending") = PacketSigner(signerId = id, status = status)

    private fun field(id: String, assignedToViewer: Boolean = false) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.SIGNATURE,
        page = 0,
        x = 1f,
        y = 2f,
        width = 3f,
        height = 4f,
        required = true,
        isAssignedToViewer = assignedToViewer,
    )

    private fun packet(
        status: PacketStatus = PacketStatus.SENT,
        role: PacketRole = PacketRole.SENDER,
        signers: List<PacketSigner> = listOf(signer("sgn_1")),
        fields: List<PacketField> = listOf(field("fld_1")),
    ) = SignaturePacket(
        packetId = "pkt_1",
        status = status,
        ownerUserId = "usr_owner",
        sourcePath = "files/doc.pdf",
        role = role,
        createdAt = Instant.ofEpochSecond(1_780_000_000L),
        signers = signers,
        fields = fields,
    )

    private fun launch(
        state: PacketDetailUiState,
        onOpenPdf: (String) -> Unit = {},
        onPrimaryAction: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                PacketDetailScreen(
                    state = state,
                    onBack = {},
                    onOpenPdf = onOpenPdf,
                    onPrimaryAction = onPrimaryAction,
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun content_showsStatus_signers_fields_andEvents() {
        launch(
            PacketDetailUiState.Content(
                packet = packet(),
                events = listOf(
                    PacketEvent(
                        eventId = "ev_1",
                        eventType = "created",
                        actorUserId = "usr_1",
                        createdAt = Instant.ofEpochSecond(1_780_000_000L),
                    ),
                ),
            ),
        )
        rule.onNodeWithTag(PacketDetailTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(PacketDetailTestTags.signer("sgn_1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(PacketDetailTestTags.field("fld_1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(PacketDetailTestTags.event(0), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun draftSender_showsSendAction() {
        launch(
            PacketDetailUiState.Content(
                packet = packet(status = PacketStatus.DRAFT, role = PacketRole.SENDER),
                events = emptyList(),
            ),
        )
        rule.onNodeWithTag(PacketDetailTestTags.ACTION, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun completedPacket_hasNoPrimaryAction() {
        launch(
            PacketDetailUiState.Content(
                packet = packet(status = PacketStatus.COMPLETED, role = PacketRole.SENDER),
                events = emptyList(),
            ),
        )
        rule.onNodeWithTag(PacketDetailTestTags.ACTION, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun openDocument_invokesCallback_withSourcePath() {
        var opened: String? = null
        launch(
            state = PacketDetailUiState.Content(packet = packet(), events = emptyList()),
            onOpenPdf = { opened = it },
        )
        rule.onNodeWithTag(PacketDetailTestTags.OPEN_PDF, useUnmergedTree = true).performClick()
        assertEquals("files/doc.pdf", opened)
    }

    @Test
    fun primaryAction_click_firesThroughInTestReducer() {
        var clicks = 0
        // In-test reducer: tapping the action flips the captured count via the hoisted callback.
        var state by mutableStateOf<PacketDetailUiState>(
            PacketDetailUiState.Content(
                packet = packet(status = PacketStatus.DRAFT, role = PacketRole.SENDER),
                events = emptyList(),
            ),
        )
        rule.setContent {
            TestLogonTheme {
                PacketDetailScreen(
                    state = state,
                    onBack = {},
                    onOpenPdf = {},
                    onPrimaryAction = {
                        clicks++
                        state = PacketDetailUiState.Content(
                            packet = packet(status = PacketStatus.SENT, role = PacketRole.SENDER),
                            events = emptyList(),
                        )
                    },
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
        rule.onNodeWithTag(PacketDetailTestTags.ACTION, useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(1, clicks) }
        // After the reducer swap to SENT+SENDER (a non-actionable state), the button is gone.
        rule.onNodeWithTag(PacketDetailTestTags.ACTION, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun error_showsRetry_whenRetryable() {
        launch(PacketDetailUiState.Error(message = "boom", retryable = true))
        rule.onNodeWithTag(PacketDetailTestTags.RETRY, useUnmergedTree = true).assertIsDisplayed()
    }
}
