@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.common.poll.PollComposer
import com.testlogon.android.feature.common.poll.PollDraft

/**
 * Arbitrary TEXT-option poll composer for messaging (custom question + 2..N options + single/multi +
 * optional auto-close). Distinct from the meeting-time / find-a-time pickers. Emits a [PollDraft] to send.
 */
@Composable
fun TextPollComposerSheet(
    onSubmit: (PollDraft) -> Unit,
    onDismiss: () -> Unit,
) {
    var draft by remember { mutableStateOf(PollDraft()) }
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag("text_poll_composer_sheet")) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("New poll", style = MaterialTheme.typography.titleMedium)
            PollComposer(draft = draft, onChange = { draft = it })
            Button(
                onClick = { onSubmit(draft) },
                enabled = draft.isValid,
                modifier = Modifier.fillMaxWidth().testTag("text_poll_send"),
            ) { Text("Send poll") }
        }
    }
}
