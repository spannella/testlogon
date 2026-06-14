package com.testlogon.android.data.feed

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-179 — pure mapper + percentage tests (no Android/network). */
class PollMapperTest {

    private val moshi = Moshi.Builder().build()

    private fun postWithPoll(json: String): PostDto =
        requireNotNull(moshi.adapter(PostDto::class.java).fromJson(json))

    @Test
    fun mapsPerQuestionShape_countsAndMyVotes() {
        val dto = postWithPoll(
            """
            {"post_id":"p1","author_id":"a1",
             "poll_data":{"questions":[
                {"question_id":"q1","text":"Best?","choice_mode":"single",
                 "options":[{"option_id":"o1","text":"A"},{"option_id":"o2","text":"B"}]}
             ],"closed":false,"anonymous":false,"allow_vote_change":true,"total_votes":60,"closes_at":1780000000},
             "poll_vote_counts":{"q1":{"o1":12,"o2":48}},
             "poll_my_votes":{"q1":["o2"]}}
            """.trimIndent(),
        )
        val poll = requireNotNull(dto.toPoll())
        assertEquals("p1", poll.postId)
        assertEquals(60, poll.totalVotes)
        assertEquals(1780000000L, poll.closesAtEpochSeconds)
        assertTrue(poll.allowVoteChange)
        val q = poll.questions.single()
        assertEquals(ChoiceMode.SINGLE, q.choiceMode)
        assertEquals(60, q.questionTotal)
        assertTrue(q.isOptionSelected("o2"))
        assertFalse(q.isOptionSelected("o1"))
        assertEquals(80, q.percentFor("o2")) // 48/60
        assertEquals(20, q.percentFor("o1")) // 12/60
    }

    @Test
    fun unknownChoiceMode_degradesToSingle() {
        val dto = postWithPoll(
            """
            {"post_id":"p1","author_id":"a1",
             "poll_data":{"questions":[
                {"question_id":"q1","text":"Q","choice_mode":"ranked","options":[]}
             ],"closed":false,"anonymous":false,"allow_vote_change":false,"total_votes":0}}
            """.trimIndent(),
        )
        val poll = requireNotNull(dto.toPoll())
        assertEquals(ChoiceMode.SINGLE, poll.questions.single().choiceMode)
    }

    @Test
    fun emptyCounts_percentIsZero_noDivideByZero() {
        val q = PollQuestion(
            id = "q1", text = "Q", choiceMode = ChoiceMode.SINGLE, maxSelections = null,
            options = listOf(PollOption("o1", "A")), counts = emptyMap(), myVoteOptionIds = emptyList(),
        )
        assertEquals(0, q.percentFor("o1"))
        assertEquals(0, q.questionTotal)
    }

    @Test
    fun noPollData_mapsToNull() {
        val dto = postWithPoll("""{"post_id":"p1","author_id":"a1"}""")
        assertNull(dto.toPoll())
    }

    @Test
    fun applyVote_mergesPerQuestionResult() {
        val poll = Poll(
            postId = "p1",
            questions = listOf(
                PollQuestion("q1", "Q", ChoiceMode.SINGLE, null, listOf(PollOption("o1", "A"), PollOption("o2", "B")), mapOf("o1" to 1), emptyList()),
            ),
            totalVotes = 1, closed = false, closesAtEpochSeconds = null, anonymous = false, allowVoteChange = false,
        )
        val merged = poll.applyVote(
            PollVoteResult("q1", mapOf("o1" to 1, "o2" to 1), totalVotes = 2, myVoteOptionIds = listOf("o2")),
        )
        assertEquals(2, merged.totalVotes)
        val q = merged.questions.single()
        assertTrue(q.isOptionSelected("o2"))
        assertEquals(1, q.countFor("o2"))
    }

    @Test
    fun voteResponse_singleMode_mapsMyVote() {
        val dto = PollVoteResponseDto(questionId = "q1", myVote = "o1", myVotes = null, voteCounts = mapOf("o1" to 1), totalVotes = 1)
        assertEquals(listOf("o1"), dto.toDomain().myVoteOptionIds)
    }
}
