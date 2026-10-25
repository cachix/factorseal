@file:OptIn(ExperimentalCoroutinesApi::class)

package com.cachix.factorseal.app

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.cachix.factorseal.core.CoreBridge
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Factor
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Platform
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.Summary
import com.cachix.factorseal.core.Vault
import com.cachix.factorseal.core.VaultState
import com.cachix.factorseal.core.protocol
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val PASSWORD = "orbit lantern velvet harbor quiet"
private const val EPOCH = 1_800_000_000L

private class FakeCore(
    var state: VaultState = VaultState.Absent,
) : CoreBridge {
    val requests = mutableListOf<Request>()
    var items = listOf(Summary("github", "GitHub", Kind.Login, username = "yurii@example.com"))
    var absoluteDeadline: Long? = null
    var lastExchange: Long? = null
    var seals = 0

    private fun status() = Response.Status(state, listOf(listOf(Factor.Password)), "android", paired = false, idleDeadline = null, absoluteDeadline = absoluteDeadline)

    private fun respond(request: Request): Response = when (request) {
        is Request.Start, Request.Status, Request.Touch -> {
            status()
        }

        is Request.Create -> {
            state = VaultState.Unsealed
            status()
        }

        is Request.Unlock -> {
            if (request.password == PASSWORD) {
                state = VaultState.Unsealed
                status()
            } else {
                Response.Error(ErrorCode.PasswordRejected, "Incorrect password. Please try again.")
            }
        }

        Request.Seal -> {
            state = VaultState.Sealed
            status()
        }

        Request.Items -> {
            if (state == VaultState.Unsealed) Response.Items(items) else Response.Error(ErrorCode.Sealed, "The vault is sealed.")
        }

        is Request.SyncStart, Request.SyncView, Request.SyncStop -> {
            Response.Sync(lastExchange = lastExchange)
        }

        else -> {
            Response.Error(ErrorCode.Invalid, "unexpected request")
        }
    }

    override fun call(request: String): String {
        val decoded = protocol.decodeFromString(Request.serializer(), request)
        requests += decoded
        return protocol.encodeToString(Response.serializer(), respond(decoded))
    }

    override fun sealVault() {
        seals++
        state = VaultState.Sealed
    }
}

private class FakeHost(
    var saved: String? = null,
) : Host {
    override val platform = Platform.Android
    override val directory = "/data/factorseal"
    override val biometric = false
    override val deviceName = "Pixel"
    override val autofill = null
    var clipboard: String? = null
    var readable = true

    override fun copy(text: String) {
        clipboard = text
    }

    override fun clearClipboard(text: String): Boolean {
        if (!readable) return false
        if (clipboard == text) clipboard = null
        return true
    }

    override fun paste(): String? = clipboard

    override fun open(url: String) = Unit

    override fun load(): String? = saved

    override fun save(text: String) {
        saved = text
    }

    @Composable
    override fun rememberFiles(): Files = error("no files in tests")

    @Composable
    override fun Scanner(
        vault: Vault,
        onScan: (Scan) -> Unit,
        onUnavailable: () -> Unit,
        modifier: Modifier,
    ) = Unit
}

private data class Fixture(
    val app: FactorSeal,
    val core: FakeCore,
    val host: FakeHost,
)

private fun TestScope.fixture(
    core: FakeCore = FakeCore(),
    host: FakeHost = FakeHost(),
): Fixture {
    val clock =
        object : Clock {
            override fun now(): Instant = Instant.fromEpochMilliseconds(EPOCH * 1000 + testScheduler.currentTime)
        }
    val app = FactorSeal(Vault(core, StandardTestDispatcher(testScheduler)), host, backgroundScope, testScheduler.timeSource, clock)
    app.start()
    runCurrent()
    return Fixture(app, core, host)
}

private fun TestScope.unlocked(
    core: FakeCore = FakeCore(VaultState.Sealed),
    host: FakeHost = FakeHost(),
): Fixture {
    val fixture = fixture(core, host)
    fixture.app.unlock(listOf(Factor.Password), PASSWORD)
    runCurrent()
    assertEquals(Phase.Unsealed, fixture.app.phase)
    return fixture
}

private fun TestScope.wait(duration: Duration) {
    advanceTimeBy(duration)
    runCurrent()
}

class FactorSealTest {
    @Test
    fun without_a_vault_the_app_offers_setup_and_creating_opens_it() = runTest {
        val (app, core, _) = fixture()
        assertEquals(Phase.Setup, app.phase)
        app.create(SetupMethod.Password.groups, PASSWORD)
        runCurrent()
        assertEquals(Phase.Unsealed, app.phase)
        assertEquals(listOf("github"), app.items?.map { it.id })
        assertEquals(Request.Create(SetupMethod.Password.groups, PASSWORD, Preferences().lease), core.requests.first { it is Request.Create })
    }

    @Test
    fun a_wrong_password_keeps_the_vault_sealed_and_says_why() = runTest {
        val app = fixture(FakeCore(VaultState.Sealed)).app
        assertEquals(Phase.Sealed(), app.phase)
        app.unlock(listOf(Factor.Password), "wrong password")
        runCurrent()
        assertEquals(Phase.Sealed(), app.phase)
        assertEquals(ErrorCode.PasswordRejected, app.unlockError?.code)
    }

    @Test
    fun the_vault_seals_itself_after_the_idle_timeout() = runTest {
        val (app, core, _) = unlocked()
        wait(299.seconds)
        assertEquals(Phase.Unsealed, app.phase)
        wait(2.seconds)
        assertEquals(Phase.Sealed(), app.phase)
        assertEquals(1, core.seals)
    }

    @Test
    fun recent_activity_keeps_the_lease_alive() = runTest {
        val (app, core, _) = unlocked()
        repeat(40) {
            wait(10.seconds)
            app.active()
        }
        assertEquals(Phase.Unsealed, app.phase)
        assertTrue(core.requests.count { it == Request.Touch } >= 10)
        assertEquals(0, core.seals)
    }

    @Test
    fun the_maximum_unlock_duration_ends_the_session_even_while_active() = runTest {
        val app = unlocked(FakeCore(VaultState.Sealed).apply { absoluteDeadline = EPOCH + 60 }).app
        repeat(5) {
            wait(10.seconds)
            app.active()
        }
        assertEquals(Phase.Unsealed, app.phase)
        repeat(2) {
            wait(10.seconds)
            app.active()
        }
        assertEquals(Phase.Sealed(), app.phase)
    }

    @Test
    fun unsaved_changes_are_saved_once_before_the_maximum_duration_ends() = runTest {
        val app = unlocked(FakeCore(VaultState.Sealed).apply { absoluteDeadline = EPOCH + 60 }).app
        var saves = 0
        app.salvage = { saves++ }
        repeat(6) {
            wait(10.seconds)
            app.active()
        }
        assertEquals(Phase.Sealed(), app.phase)
        assertEquals(1, saves)
    }

    @Test
    fun copied_secrets_leave_the_clipboard_after_thirty_seconds() = runTest {
        val (app, _, host) = unlocked()
        app.copy("hunter2")
        assertNotNull(app.clip)
        wait(29.seconds)
        assertEquals("hunter2", host.clipboard)
        wait(2.seconds)
        assertNull(host.clipboard)
        assertNull(app.clip)
    }

    @Test
    fun a_clipboard_the_app_cannot_read_is_cleared_once_the_app_has_focus() = runTest {
        val (app, _, host) = unlocked()
        app.copy("hunter2")
        host.readable = false
        wait(31.seconds)
        assertEquals("hunter2", host.clipboard)
        assertNull(app.clip)
        host.readable = true
        app.focused()
        assertNull(host.clipboard)
    }

    @Test
    fun something_else_on_the_clipboard_is_left_alone() = runTest {
        val (app, _, host) = unlocked()
        app.copy("hunter2")
        host.clipboard = "a shopping list"
        wait(31.seconds)
        assertEquals("a shopping list", host.clipboard)
    }

    @Test
    fun sealing_clears_the_clipboard_and_unlocking_returns_to_the_same_page() = runTest {
        val (app, core, host) = unlocked()
        app.open(Page.Personal)
        app.open(Page.Entry("github"))
        app.copy("hunter2")
        app.seal()
        runCurrent()
        assertEquals(Phase.Sealed(), app.phase)
        assertNull(host.clipboard)
        assertTrue(app.pages.isEmpty())
        assertNull(app.items)
        app.unlock(listOf(Factor.Password), PASSWORD)
        runCurrent()
        assertEquals(listOf(Page.Personal, Page.Entry("github")), app.pages.toList())
        app.seal()
        runCurrent()
        core.items = emptyList()
        app.unlock(listOf(Factor.Password), PASSWORD)
        runCurrent()
        assertEquals(listOf<Page>(Page.Personal), app.pages.toList())
    }

    @Test
    fun locking_the_screen_seals_right_away() = runTest {
        val (app, core, _) = unlocked()
        app.lock()
        runCurrent()
        assertEquals(Phase.Sealed(), app.phase)
        assertEquals(1, core.seals)
    }

    @Test
    fun locking_the_screen_while_unlocking_seals_once_unlocking_finishes() = runTest {
        val (app, core, _) = fixture(FakeCore(VaultState.Sealed))
        app.unlock(listOf(Factor.Password), PASSWORD)
        app.lock()
        runCurrent()
        assertEquals(Phase.Sealed(), app.phase)
        assertEquals(1, core.seals)
    }

    @Test
    fun a_synced_change_reloads_items_only_while_someone_uses_the_app() = runTest {
        val (app, core, _) = unlocked(host = FakeHost(Preferences(deviceName = "Pixel").encode()))
        wait(40.seconds)
        val before = core.requests.size
        core.lastExchange = EPOCH
        wait(5.seconds)
        assertTrue(core.requests.drop(before).none { it == Request.Items })
        app.active()
        runCurrent()
        assertEquals(1, core.requests.drop(before).count { it == Request.Items })
    }

    @Test
    fun sync_runs_only_in_the_foreground_once_the_device_has_a_name() = runTest {
        val unnamed = fixture(FakeCore(VaultState.Sealed)).core
        assertTrue(unnamed.requests.none { it is Request.SyncStart })

        val (app, core, _) = fixture(FakeCore(VaultState.Sealed), FakeHost(Preferences(deviceName = "Pixel").encode()))
        assertEquals(Request.SyncStart("Pixel"), core.requests.last { it is Request.SyncStart })
        app.background()
        runCurrent()
        assertEquals(Request.SyncStop, core.requests.last())
        val before = core.requests.size
        wait(10.seconds)
        assertTrue(core.requests.drop(before).none { it == Request.SyncView })
        app.foreground()
        runCurrent()
        assertEquals(Request.SyncStart("Pixel"), core.requests.last())
    }

    @Test
    fun preference_changes_are_saved_only_when_valid() = runTest {
        val (app, _, host) = fixture()
        app.update(Preferences(idleSeconds = 60))
        assertEquals(Preferences(idleSeconds = 60), Preferences.decode(host.saved))
        app.update(Preferences(idleSeconds = 3_600, maximumSeconds = 900))
        assertEquals(Preferences(idleSeconds = 60), app.preferences)
    }
}
