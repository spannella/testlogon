package com.testlogon.android.data.profile

import com.testlogon.android.core.model.profile.ProfileAudience
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-070 / AND-076 — DTO -> domain mapper coverage (total, never-throwing). */
class ProfileMapperTest {

    @Test
    fun profileDto_mapsAllFields_andTrimsBlanks() {
        val dto = ProfileDto(
            displayName = "  Sean  ",
            firstName = "Sean",
            lastName = "Pannella",
            description = "  Builder.  ",
            location = "Pittsburgh, PA",
            displayedEmail = "spannella@gmail.com",
            languages = listOf(LanguageDto("English", "native"), LanguageDto("  ", "x")),
            profilePhotoUrl = "https://x/a.png",
        )
        val p = dto.toDomain()
        assertEquals("Sean", p.displayName)
        assertEquals("Builder.", p.description)
        assertEquals("spannella@gmail.com", p.displayedEmail)
        assertEquals(1, p.languages.size) // blank-name language dropped
        assertEquals("English", p.languages.first().name)
        assertEquals("native", p.languages.first().level)
    }

    @Test
    fun profileDto_emptyBody_mapsToAllNullScalars_andEmptyLanguages() {
        val p = ProfileDto().toDomain()
        assertNull(p.displayName)
        assertNull(p.description)
        assertNull(p.coverPhotoUrl)
        assertTrue(p.languages.isEmpty())
    }

    @Test
    fun crossUser_publicAudience_mapsAndPreservesAudience() {
        val dto = CrossUserProfileDto(
            identifier = "ada",
            canonicalIdentifier = "ada",
            userSub = "auth0|abc",
            audience = "public",
            profile = ProfileDto(displayName = "Ada"),
        )
        val domain = dto.toDomain()
        assertEquals(ProfileAudience.PUBLIC, domain.audience)
        assertEquals("Ada", domain.profile.displayName)
        assertTrue(domain.profile.languages.isEmpty())
    }

    @Test
    fun crossUser_unknownAudience_mapsToUnknown() {
        val dto = CrossUserProfileDto(
            identifier = "x",
            userSub = "s",
            audience = "vip",
            profile = ProfileDto(),
        )
        assertEquals(ProfileAudience.UNKNOWN, dto.toDomain().audience)
    }

    @Test
    fun crossUser_ownerAudience_setsViewerIsOwner() {
        val dto = CrossUserProfileDto(identifier = "me", userSub = "s", audience = "owner", profile = ProfileDto())
        assertTrue(dto.toDomain().viewerIsOwner)
    }

    @Test
    fun publicProfile_createdAtEpoch_andAbsent() {
        val withEpoch = PublicProfileDataDto(
            userId = "u",
            identifier = "ada",
            displayName = "Ada",
            createdAt = 1730538900,
        ).toDomain()
        assertEquals(1730538900L, withEpoch.createdAtEpochSeconds)

        val absent = PublicProfileDataDto(userId = "u", identifier = "ada", displayName = "Ada", createdAt = null).toDomain()
        assertNull(absent.createdAtEpochSeconds)
    }

    @Test
    fun profilePatch_toReqDto_passesThroughNulls() {
        val req = com.testlogon.android.core.model.profile.ProfilePatch(displayName = "New", description = "Bio")
            .toReqDto()
        assertEquals("New", req.displayName)
        assertEquals("Bio", req.description)
        assertNull(req.location)
    }
}
