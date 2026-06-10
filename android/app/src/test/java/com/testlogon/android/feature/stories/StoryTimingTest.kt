package com.testlogon.android.feature.stories

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-200 — pure timing/navigation math tests (no coroutines, no Android). */
class StoryTimingTest {

    @Test
    fun timer_fills_to_complete_over_duration() {
        val t = StorySegmentTimer(durationMs = 5_000L)
        assertEquals(0f, t.progress, 0.0001f)
        assertFalse(t.tick(2_500L))
        assertEquals(0.5f, t.progress, 0.0001f)
        assertFalse(t.complete)
        assertTrue(t.tick(2_500L))
        assertEquals(1f, t.progress, 0.0001f)
        assertTrue(t.complete)
    }

    @Test
    fun timer_clamps_progress_at_one() {
        val t = StorySegmentTimer(durationMs = 1_000L)
        assertTrue(t.tick(5_000L))
        assertEquals(1f, t.progress, 0.0001f)
        assertEquals(1_000L, t.elapsedMs)
    }

    @Test
    fun timer_reset_starts_new_segment() {
        val t = StorySegmentTimer(durationMs = 1_000L)
        t.tick(1_000L)
        t.reset(2_000L)
        assertEquals(0f, t.progress, 0.0001f)
        assertFalse(t.complete)
        assertFalse(t.tick(1_000L))
        assertEquals(0.5f, t.progress, 0.0001f)
    }

    @Test
    fun timer_setProgress_drives_bar_from_player_position() {
        val t = StorySegmentTimer(durationMs = 10_000L)
        t.setProgress(0.25f)
        assertEquals(0.25f, t.progress, 0.0001f)
        assertEquals(2_500L, t.elapsedMs)
    }

    @Test
    fun timer_degenerate_zero_duration_is_complete() {
        val t = StorySegmentTimer(durationMs = 0L)
        assertEquals(1f, t.progress, 0.0001f)
        assertTrue(t.complete)
    }

    @Test
    fun navigator_next_within_author() {
        val pos = StoryNavigator.next(authorIndex = 0, segmentIndex = 0, currentAuthorSegmentCount = 3, authorCount = 2)
        assertEquals(StoryNavigator.Position(0, 1), pos)
    }

    @Test
    fun navigator_next_rolls_to_next_author() {
        val pos = StoryNavigator.next(authorIndex = 0, segmentIndex = 2, currentAuthorSegmentCount = 3, authorCount = 2)
        assertEquals(StoryNavigator.Position(1, 0), pos)
    }

    @Test
    fun navigator_next_past_last_author_is_done() {
        val pos = StoryNavigator.next(authorIndex = 1, segmentIndex = 0, currentAuthorSegmentCount = 1, authorCount = 2)
        assertTrue(pos.done)
    }

    @Test
    fun navigator_previous_within_author() {
        val pos = StoryNavigator.previous(authorIndex = 1, segmentIndex = 2, prevAuthorSegmentCount = 3)
        assertEquals(StoryNavigator.Position(1, 1), pos)
    }

    @Test
    fun navigator_previous_crosses_to_prev_author_last_segment() {
        val pos = StoryNavigator.previous(authorIndex = 1, segmentIndex = 0, prevAuthorSegmentCount = 4)
        assertEquals(StoryNavigator.Position(0, 3), pos)
    }

    @Test
    fun navigator_previous_from_first_of_first_restarts() {
        val pos = StoryNavigator.previous(authorIndex = 0, segmentIndex = 0, prevAuthorSegmentCount = 1)
        assertEquals(StoryNavigator.Position(0, 0), pos)
    }
}
