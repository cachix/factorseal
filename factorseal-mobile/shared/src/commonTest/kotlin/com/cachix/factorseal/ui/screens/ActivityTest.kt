package com.cachix.factorseal.ui.screens

import com.cachix.factorseal.core.Access
import com.cachix.factorseal.core.Requester
import kotlin.test.Test
import kotlin.test.assertEquals

class ActivityTest {
    private fun named(
        requester: Requester,
        name: String,
    ) = Access(at = 0, count = 1, allowed = true, requester = requester, name = name, item = null).requesterName()

    @Test
    fun requesters_read_as_the_site_app_or_program_they_are() {
        assertEquals("github.com", named(Requester.Website, "https://github.com/"))
        assertEquals("github.com", named(Requester.Browser, "https://github.com"))
        assertEquals("com.example.bank", named(Requester.App, "com.example.bank"))
        assertEquals("git", named(Requester.Program, "/usr/bin/git"))
        assertEquals("Evil bank", named(Requester.App, "Evil‮\n  bank\u0007"))
    }

    @Test
    fun reads_of_one_secret_by_one_app_share_a_row() {
        fun read(
            at: Long,
            count: Int,
            allowed: Boolean = true,
        ) = Access(at = at, count = count, allowed = allowed, requester = Requester.App, name = "com.example", item = "token")
        val groups = listOf(read(700, 2), read(650, 1, allowed = false), read(600, 3)).merged()
        assertEquals(listOf(5 to (600L to 700L), 1 to (650L to 650L)), groups.map { it.count to (it.first to it.last) })
    }

    @Test
    fun an_open_row_keeps_every_read_when_new_ones_arrive() {
        fun read(
            at: Long,
            name: String = "com.example",
        ) = Access(at = at, count = 1, allowed = true, requester = Requester.App, name = name, item = "token")
        val opened = read(600)
        val row = listOf(read(800, name = "com.other"), read(700), opened).row(opened)
        assertEquals(listOf(700L, 600L), row?.reads?.map { it.at })
        assertEquals(null, listOf(read(800, name = "com.other")).row(opened))
    }

    @Test
    fun avatars_show_the_apps_first_letter() {
        assertEquals("S", avatarLetter("secret-tool"))
        assertEquals("P", avatarLetter("python3.14"))
        assertEquals("Ü", avatarLetter("über"))
        assertEquals("?", avatarLetter("--"))
    }
}
