package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.AccentColor
import com.testlogon.android.core.model.Density
import com.testlogon.android.core.model.FontSizePref
import com.testlogon.android.core.model.PreferencesPatch
import com.testlogon.android.core.model.ThemeModePref
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-083 — pure mapper tests: lenient read, strict write, null-omission. */
class PreferencesMapperTest {

    @Test
    fun toDomain_mapsKnownTokens() {
        val dto = PreferencesDto(
            theme = "dark",
            accentColor = "teal",
            fontSize = "xlarge",
            density = "spacious",
            highContrast = true,
        )
        val domain = dto.toDomain()
        assertEquals(ThemeModePref.DARK, domain.theme)
        assertEquals(AccentColor.TEAL, domain.accentColor)
        assertEquals(FontSizePref.XLARGE, domain.fontSize)
        assertEquals(Density.SPACIOUS, domain.density)
        assertEquals(true, domain.highContrast)
    }

    @Test
    fun toDomain_unknownTokens_fallBackToDefaults() {
        val dto = PreferencesDto(
            theme = "ultraviolet",
            accentColor = "chartreuse",
            fontSize = "huge",
            density = "airy",
        )
        val domain = dto.toDomain()
        assertEquals(ThemeModePref.SYSTEM, domain.theme)
        assertEquals(AccentColor.BLUE, domain.accentColor)
        assertEquals(FontSizePref.DEFAULT, domain.fontSize)
        assertEquals(Density.COMFORTABLE, domain.density)
    }

    @Test
    fun toRequestDto_lowercasesEnums_andOmitsNulls() {
        val dto = PreferencesPatch(theme = ThemeModePref.LIGHT, accentColor = AccentColor.PURPLE)
            .toRequestDto()
        assertEquals("light", dto.theme)
        assertEquals("purple", dto.accentColor)
        assertNull(dto.fontSize)
        assertNull(dto.density)
        assertNull(dto.highContrast)
    }
}
