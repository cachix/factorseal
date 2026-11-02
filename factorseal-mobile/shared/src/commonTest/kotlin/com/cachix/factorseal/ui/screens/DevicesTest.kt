package com.cachix.factorseal.ui.screens

import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.device_name_empty
import com.cachix.factorseal.resources.device_name_invalid
import com.cachix.factorseal.resources.device_name_too_long
import kotlin.test.Test
import kotlin.test.assertEquals

class DevicesTest {
    @Test
    fun device_names_must_be_present_short_and_plain() {
        assertEquals(Res.string.device_name_empty, deviceNameProblem(""))
        assertEquals(Res.string.device_name_too_long, deviceNameProblem("a".repeat(81)))
        assertEquals(Res.string.device_name_too_long, deviceNameProblem("ä".repeat(41)))
        assertEquals(Res.string.device_name_invalid, deviceNameProblem("Work\u0007phone"))
        assertEquals(null, deviceNameProblem("a".repeat(80)))
        assertEquals(null, deviceNameProblem("Yurii’s phone"))
    }

    @Test
    fun last_sync_reads_as_time_since_the_last_exchange() {
        assertEquals(null, syncAge(1_000, 1_059))
        assertEquals(null, syncAge(1_000, 900))
        assertEquals(SyncAge.Minutes to 1, syncAge(1_000, 1_060))
        assertEquals(SyncAge.Minutes to 59, syncAge(1_000, 4_599))
        assertEquals(SyncAge.Hours to 1, syncAge(1_000, 4_600))
        assertEquals(SyncAge.Days to 1, syncAge(1_000, 87_400))
        assertEquals(SyncAge.Days to 3, syncAge(1_000, 260_200))
    }
}
