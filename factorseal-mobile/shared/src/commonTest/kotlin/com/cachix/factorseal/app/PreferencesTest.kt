package com.cachix.factorseal.app

import com.cachix.factorseal.core.GeneratorOptions
import com.cachix.factorseal.core.GeneratorStyle
import com.cachix.factorseal.core.Lease
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PreferencesTest {
    @Test
    fun defaults_match_the_desktop_lease_and_generator() {
        val preferences = Preferences()
        assertEquals(Lease(idleSeconds = 300, maximumSeconds = 28_800), preferences.lease)
        assertEquals(GeneratorOptions(GeneratorStyle.Words, length = 20, words = 12, digits = true, symbols = true), preferences.generator)
        assertTrue(preferences.idleSeconds in IdleChoices)
        assertTrue(preferences.maximumSeconds in MaximumChoices)
    }

    @Test
    fun saved_preferences_read_back_unchanged() {
        val preferences =
            Preferences(
                idleSeconds = 60,
                maximumSeconds = 3_600,
                reducedMotion = true,
                generator = GeneratorOptions(GeneratorStyle.Random, length = 32, words = 15, digits = false, symbols = true),
                deviceName = "Yurii’s phone",
            )
        assertEquals(preferences, Preferences.decode(preferences.encode()))
    }

    @Test
    fun missing_broken_or_unsafe_files_fall_back_to_defaults() {
        assertEquals(Preferences(), Preferences.decode(null))
        assertEquals(Preferences(), Preferences.decode(""))
        assertEquals(Preferences(), Preferences.decode("{not json"))
        assertEquals(Preferences(), Preferences.decode("""{"idleSeconds": 7200, "maximumSeconds": 900}"""))
        assertEquals(Preferences(), Preferences.decode("""{"idleSeconds": 0}"""))
    }

    @Test
    fun files_from_newer_versions_keep_the_settings_this_version_knows() {
        val decoded = Preferences.decode("""{"idleSeconds": 900, "reducedMotion": true, "theme": "dark"}""")
        assertEquals(Preferences(idleSeconds = 900, reducedMotion = true), decoded)
    }

    @Test
    fun the_idle_timeout_cannot_exceed_the_maximum_unlock_duration() {
        assertTrue(Preferences(idleSeconds = 900, maximumSeconds = 900).valid)
        assertFalse(Preferences(idleSeconds = 3_600, maximumSeconds = 900).valid)
        assertFalse(Preferences(idleSeconds = 0).valid)
    }

    @Test
    fun device_names_are_short_visible_text() {
        assertTrue(validDeviceName("Pixel 9"))
        assertTrue(validDeviceName("Телефон Юрія"))
        assertFalse(validDeviceName(""))
        assertFalse(validDeviceName("   "))
        assertFalse(validDeviceName("line\nbreak"))
        assertFalse(validDeviceName("x".repeat(81)))
        assertTrue(validDeviceName("x".repeat(80)))
        assertFalse(validDeviceName("ї".repeat(41)))
    }
}
