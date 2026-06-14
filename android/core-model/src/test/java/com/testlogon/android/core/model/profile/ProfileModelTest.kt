package com.testlogon.android.core.model.profile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-070 — pure domain-model behavior (no Android/Moshi deps). */
class ProfileModelTest {

    @Test
    fun empty_hasNullScalars_andNoLanguages() {
        assertNull(Profile.EMPTY.displayName)
        assertTrue(Profile.EMPTY.languages.isEmpty())
        assertNull(Profile.EMPTY.bestName)
    }

    @Test
    fun bestName_prefersDisplayName_thenNameParts() {
        assertEquals("Sean P.", Profile.EMPTY.copy(displayName = "Sean P.").bestName)
        assertEquals("Sean Pannella", Profile.EMPTY.copy(firstName = "Sean", lastName = "Pannella").bestName)
    }

    @Test
    fun crossUser_viewerIsOwner_onlyForOwnerAudience() {
        val base = CrossUserProfile("id", null, "sub", ProfileAudience.OWNER, Profile.EMPTY)
        assertTrue(base.viewerIsOwner)
        assertFalse(base.copy(audience = ProfileAudience.PUBLIC).viewerIsOwner)
    }

    @Test
    fun profilePatch_isEmpty_whenNoFields() {
        assertTrue(ProfilePatch().isEmpty)
        assertFalse(ProfilePatch(displayName = "x").isEmpty)
    }
}
