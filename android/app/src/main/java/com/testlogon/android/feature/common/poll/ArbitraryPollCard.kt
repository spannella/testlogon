package com.testlogon.android.feature.common.poll

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.poll.ArbitraryPoll
import com.testlogon.android.core.model.poll.ArbitraryPollOption
import com.testlogon.android.core.model.poll.ArbitraryPollQuestion
import com.testlogon.android.data.poll.PollVoter
import kotlinx.coroutines.launch

/** Stable test tags for the arbitrary-poll card. */
object ArbitraryPollCardTestTags {
    const val CARD = "poll_card"
    const val TOTAL = "poll_total"
    const val CLOSED = "poll_closed"
    const val CLOSE_BUTTON = "poll_close"
    const val ERROR = "poll_error"
    fun option(optionId: String) = "poll_option_$optionId"
}

/**
 * Self-contained renderer for an ARBITRARY text-option poll embedded in a message / group post /
 * syndicate post. Supports single-choice AND multi-select voting (a re-tap toggles a multi option off),
 * shows live counts + percentages, a closed state, and an owner-only Close-poll action. All state is
 * kept internally; voting delegates to [voter] which returns the fresh snapshot.
 */
@Composable
fun ArbitraryPollCard(
    initial: ArbitraryPoll,
    isOwner: Boolean,
    voter: PollVoter,
    modifier: Modifier = Modifier,
) {
    var poll by remember(initial.pollId) { mutableStateOf(initial) }
    var busyOptionId by remember(initial.pollId) { mutableStateOf<String?>(null) }
    var error by remember(initial.pollId) { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    // Re-sync when the host feeds a newer snapshot (e.g. a paging refresh).
    LaunchedEffect(initial) { poll = initial }

    fun onResult(r: ApiResult<ArbitraryPoll>) {
        when (r) {
            is ApiResult.Success -> {
                poll = r.data
                error = null
            }
            is ApiResult.Failure -> error = r.error.message
            is ApiResult.NetworkError -> error = "Couldn't reach the server. Try again."
        }
        busyOptionId = null
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
            .padding(12.dp)
            .testTag(ArbitraryPollCardTestTags.CARD),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        poll.questions.forEach { q ->
            QuestionBlock(
                question = q,
                interactive = poll.isInteractive && busyOptionId == null,
                busyOptionId = busyOptionId,
                onOptionClick = { optionId ->
                    if (poll.isInteractive) {
                        busyOptionId = optionId
                        error = null
                        scope.launch { onResult(voter.vote(poll.pollId, q.id, optionId)) }
                    }
                },
            )
        }

        val voteLabel = if (poll.totalVotes == 1) "1 vote" else "${poll.totalVotes} votes"
        Text(
            text = voteLabel,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(ArbitraryPollCardTestTags.TOTAL),
        )

        if (poll.closed) {
            Text(
                text = "Poll closed",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(ArbitraryPollCardTestTags.CLOSED),
            )
        } else if (isOwner) {
            TextButton(
                onClick = { scope.launch { onResult(voter.close(poll.pollId)) } },
                modifier = Modifier.testTag(ArbitraryPollCardTestTags.CLOSE_BUTTON),
            ) { Text("Close poll") }
        }

        val err = error
        if (err != null) {
            Text(
                text = err,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag(ArbitraryPollCardTestTags.ERROR),
            )
        }
    }
}

@Composable
private fun QuestionBlock(
    question: ArbitraryPollQuestion,
    interactive: Boolean,
    busyOptionId: String?,
    onOptionClick: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        if (question.text.isNotBlank()) {
            Text(
                text = question.text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
        if (question.multiSelect) {
            Text(
                text = "Select one or more",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        question.options.forEach { option ->
            OptionRow(
                question = question,
                option = option,
                interactive = interactive,
                busy = option.id == busyOptionId,
                onClick = { onOptionClick(option.id) },
            )
        }
    }
}

@Composable
private fun OptionRow(
    question: ArbitraryPollQuestion,
    option: ArbitraryPollOption,
    interactive: Boolean,
    busy: Boolean,
    onClick: () -> Unit,
) {
    val selected = question.isSelected(option.id)
    val percent = question.percentFor(option.id)
    val fraction by animateFloatAsState(targetValue = percent / 100f, label = "pollBar")

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(44.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surface)
            .selectable(
                selected = selected,
                enabled = interactive,
                role = if (question.multiSelect) Role.Checkbox else Role.RadioButton,
                onClick = onClick,
            )
            .testTag(ArbitraryPollCardTestTags.option(option.id)),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(44.dp)
                .background(
                    if (selected) {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
                    } else {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                    },
                ),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).height(44.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = option.text,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                modifier = Modifier.weight(1f),
            )
            if (busy) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
            } else {
                Text(
                    text = "$percent% (${option.count})",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
