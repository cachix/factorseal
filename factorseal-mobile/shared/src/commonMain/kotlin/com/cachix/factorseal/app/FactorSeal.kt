package com.cachix.factorseal.app

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Factor
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Summary
import com.cachix.factorseal.core.Vault
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.core.VaultState
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.could_not_seal
import com.cachix.factorseal.ui.components.Layers
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

enum class UnlockStep { Verifying, Loading }

sealed interface Phase {
    data object Starting : Phase

    data object Setup : Phase

    data object Creating : Phase

    data class Sealed(
        val step: UnlockStep? = null,
        val biometric: Boolean = false,
    ) : Phase

    data object Sealing : Phase

    data class Unavailable(
        val failure: VaultException,
    ) : Phase

    data object Unsealed : Phase
}

enum class SettingsSection { Appearance, Security }

sealed interface Page {
    data object Personal : Page

    data object Search : Page

    data class Entry(
        val id: String,
    ) : Page

    data object New : Page

    data object Devices : Page

    data class Device(
        val name: String,
    ) : Page

    data class Transfer(
        val backup: Boolean,
    ) : Page

    data class TransferForm(
        val backup: Boolean,
        val import: Boolean,
    ) : Page

    data object Settings : Page

    data class Section(
        val section: SettingsSection,
    ) : Page
}

class ToastAction(
    val label: Message,
    val run: suspend () -> Unit,
)

class Toast(
    val id: Long,
    val message: Message,
    val error: Boolean,
    val action: ToastAction?,
)

class Clip(
    val text: String,
    val copied: TimeMark,
)

const val CLIPBOARD_SECONDS = 30
const val SECURITY_URL = "https://factorseal.dev/security"

enum class SetupMethod(
    val groups: List<List<Factor>>,
) {
    Password(listOf(listOf(Factor.Password))),
    Biometric(listOf(listOf(Factor.Biometric))),
    PasswordAndBiometric(listOf(listOf(Factor.Password, Factor.Biometric))),
    PasswordOrBiometric(listOf(listOf(Factor.Password), listOf(Factor.Biometric))),
    ;

    val password: Boolean get() = groups.any { Factor.Password in it }
}

class SetupForm {
    val password = TextFieldState()
    val confirmation = TextFieldState()
    var revealed by mutableStateOf(false)
    var method by mutableStateOf(SetupMethod.Password)
    var passwordError by mutableStateOf<Message?>(null)
    var confirmationError by mutableStateOf<Message?>(null)

    fun clear() {
        password.clearText()
        confirmation.clearText()
        revealed = false
        passwordError = null
        confirmationError = null
    }
}

class UnlockForm {
    val password = TextFieldState()
    var revealed by mutableStateOf(false)
    var group by mutableIntStateOf(0)
}

class FactorSeal(
    val vault: Vault,
    val host: Host,
    private val scope: CoroutineScope,
    private val time: TimeSource = TimeSource.Monotonic,
    private val clock: Clock = Clock.System,
) {
    var phase by mutableStateOf<Phase>(Phase.Starting)
        private set
    var status by mutableStateOf<Response.Status?>(null)
        private set
    var preferences by mutableStateOf(Preferences.decode(host.load()))
        private set
    var items by mutableStateOf<List<Summary>?>(null)
        private set
    var itemsError by mutableStateOf<String?>(null)
        private set
    var setupError by mutableStateOf<VaultException?>(null)
        private set
    var unlockError by mutableStateOf<VaultException?>(null)
    var sync by mutableStateOf<Response.Sync?>(null)
        private set
    var revision by mutableIntStateOf(0)
        private set
    var clip by mutableStateOf<Clip?>(null)
        private set
    var settingsOpen by mutableStateOf(false)
    var salvage: (suspend () -> Unit)? = null

    val setup = SetupForm()
    val unlocking = UnlockForm()
    val pages = mutableStateListOf<Page>()
    val editors = mutableStateMapOf<Page, Editor>()
    val toasts = mutableStateListOf<Toast>()
    val query = TextFieldState()
    val layers = Layers()

    private var restore: List<Page> = emptyList()
    private var activity: TimeMark = time.markNow()
    private var request: TimeMark = time.markNow()
    private var foreground = true
    private var started = false
    private var toastIds = 0L
    private var clipJob: Job? = null
    private var stale: String? = null
    private var syncJob: Job? = null
    private var syncChanged = false
    private var lockPending = false
    private var salvaged: Long? = null

    val unlockGroups: List<List<Factor>> get() = status?.groups.orEmpty()

    fun start() {
        if (started) return
        started = true
        scope.launch {
            try {
                apply(call<Response.Status>(Request.Start(host.directory, host.platform)))
                startSync()
            } catch (failure: VaultException) {
                phase = Phase.Unavailable(failure)
            }
        }
        scope.launch {
            while (isActive) {
                delay(1.seconds)
                tick()
            }
        }
    }

    fun retry() {
        phase = Phase.Starting
        scope.launch {
            try {
                apply(call<Response.Status>(Request.Status))
            } catch (failure: VaultException) {
                phase = Phase.Unavailable(failure)
            }
        }
    }

    suspend inline fun <reified T : Response> call(
        request: Request,
        touches: Boolean = true,
    ): T {
        if (touches) touched()
        try {
            return vault.ask(request)
        } catch (failure: VaultException) {
            if (failure.code == ErrorCode.Sealed && phase == Phase.Unsealed) expired()
            throw failure
        }
    }

    fun touched() {
        request = time.markNow()
    }

    fun active() {
        activity = time.markNow()
        if (syncChanged) {
            syncChanged = false
            changed()
        }
    }

    private suspend fun apply(status: Response.Status) {
        this.status = status
        when (status.vault) {
            VaultState.Absent -> phase = Phase.Setup
            VaultState.Sealed -> phase = Phase.Sealed()
            VaultState.Unsealed -> if (phase != Phase.Unsealed) opened()
        }
    }

    fun create(
        groups: List<List<Factor>>,
        password: String?,
    ) {
        setupError = null
        lockPending = false
        phase = Phase.Creating
        scope.launch {
            try {
                status = call<Response.Status>(Request.Create(groups, password, preferences.lease))
                setup.clear()
                pages.clear()
                opened()
                startSync()
            } catch (failure: VaultException) {
                if (failure.code == ErrorCode.WeakPassword) {
                    setup.passwordError = Message.Raw(failure.message)
                } else {
                    setupError = failure
                }
                phase = Phase.Setup
            }
        }
    }

    fun unlock(
        group: List<Factor>,
        password: String?,
    ) {
        unlockError = null
        lockPending = false
        val biometric = Factor.Biometric in group
        phase = Phase.Sealed(UnlockStep.Verifying, biometric)
        scope.launch {
            try {
                status = call<Response.Status>(Request.Unlock(group, password, preferences.lease))
                phase = Phase.Sealed(UnlockStep.Loading, biometric)
                opened()
            } catch (failure: VaultException) {
                unlockError = failure
                phase = Phase.Sealed()
            }
        }
    }

    private suspend fun opened() {
        active()
        refresh()
        val known = items.orEmpty().map { it.id }.toSet()
        pages.clear()
        pages.addAll(restore.filter { page -> page !is Page.Entry || page.id in known })
        restore = emptyList()
        settingsOpen = false
        phase = Phase.Unsealed
        if (lockPending) {
            lockPending = false
            lock()
        }
    }

    suspend fun refresh() {
        try {
            items = call<Response.Items>(Request.Items).items
            itemsError = null
        } catch (failure: VaultException) {
            if (failure.code != ErrorCode.Sealed) itemsError = failure.message
        }
    }

    fun changed() {
        revision++
        scope.launch { refresh() }
    }

    fun seal() {
        if (phase != Phase.Unsealed) return
        scope.launch {
            runCatching { salvage?.invoke() }
            phase = Phase.Sealing
            try {
                status = call<Response.Status>(Request.Seal)
                closed()
            } catch (failure: VaultException) {
                phase = Phase.Unsealed
                toast(message(Res.string.could_not_seal, failure.message), error = true)
            }
        }
    }

    fun lock() {
        if (phase != Phase.Unsealed) {
            lockPending = phase == Phase.Creating || (phase as? Phase.Sealed)?.step != null
            return
        }
        scope.launch {
            runCatching { salvage?.invoke() }
            vault.sealNow()
            status = runCatching { vault.ask<Response.Status>(Request.Status) }.getOrNull() ?: status
            closed()
        }
    }

    fun expired() {
        if (phase != Phase.Unsealed) return
        closed()
        scope.launch { status = runCatching { vault.ask<Response.Status>(Request.Status) }.getOrNull() ?: status }
    }

    private fun closed() {
        restore = pages.toList()
        pages.clear()
        editors.clear()
        layers.entries.clear()
        items = null
        salvage = null
        syncChanged = false
        query.clearText()
        toasts.clear()
        clip?.let { clearClipboard(it.text) }
        clip = null
        clipJob?.cancel()
        phase = Phase.Sealed()
    }

    private suspend fun tick() {
        if (phase != Phase.Unsealed) return
        val idle = preferences.idleSeconds.seconds
        if (activity.elapsedNow() >= idle) {
            lock()
            return
        }
        val now = clock.now().epochSeconds
        val absolute = status?.absoluteDeadline
        if (absolute != null && now >= absolute - SALVAGE_MARGIN && salvaged != absolute) {
            salvaged = absolute
            runCatching { salvage?.invoke() }
        }
        if (absolute != null && now >= absolute) {
            expired()
            return
        }
        val touchDue = request.elapsedNow() >= TOUCH_EVERY
        val idleSoon = status?.idleDeadline?.let { now >= it - SALVAGE_MARGIN } ?: false
        if (activity.elapsedNow() < TOUCH_EVERY && (touchDue || idleSoon)) {
            runCatching { status = call<Response.Status>(Request.Touch) }
        }
    }

    fun foreground() {
        foreground = true
        scope.launch {
            tick()
            startSync()
        }
    }

    fun background() {
        foreground = false
        syncJob?.cancel()
        scope.launch { runCatching { sync = vault.ask<Response.Sync>(Request.SyncStop) } }
    }

    fun open(page: Page) {
        pages.add(page)
    }

    fun back(): Boolean {
        if (pages.isEmpty()) return false
        val page = pages.removeAt(pages.lastIndex)
        if (page !in pages) editors.remove(page)
        if (page == Page.Search) query.clearText()
        return true
    }

    fun replace(page: Page) {
        if (pages.isNotEmpty()) {
            val previous = pages.removeAt(pages.lastIndex)
            if (previous !in pages) editors.remove(previous)
        }
        pages.add(page)
    }

    fun toast(
        message: Message,
        error: Boolean = false,
        action: ToastAction? = null,
    ) {
        val toast = Toast(++toastIds, message, error, action)
        toasts.add(toast)
        scope.launch {
            delay(TOAST_LIFETIME)
            toasts.remove(toast)
        }
    }

    fun dismiss(toast: Toast) {
        toasts.remove(toast)
    }

    fun run(action: suspend () -> Unit) {
        scope.launch { action() }
    }

    fun copy(text: String) {
        clip?.let { previous -> if (previous.text != text) host.clearClipboard(previous.text) }
        host.copy(text)
        stale = null
        val copied = Clip(text, time.markNow())
        clip = copied
        clipJob?.cancel()
        clipJob =
            scope.launch {
                delay(CLIPBOARD_SECONDS.seconds)
                clearClipboard(copied.text)
                if (clip === copied) clip = null
            }
    }

    fun dismissClip() {
        clip = null
    }

    fun focused() {
        stale?.let(host::clearClipboard)
        stale = null
    }

    private fun clearClipboard(text: String) {
        stale = text.takeUnless(host::clearClipboard)
    }

    fun update(change: Preferences) {
        if (!change.valid) return
        val reconnect = change.deviceName != preferences.deviceName
        preferences = change
        host.save(change.encode())
        if (reconnect) scope.launch { startSync() }
    }

    private suspend fun startSync() {
        val name = preferences.deviceName ?: return
        val state = status?.vault ?: return
        if (state == VaultState.Absent || !foreground) return
        try {
            sync = vault.ask<Response.Sync>(Request.SyncStart(name))
        } catch (failure: VaultException) {
            sync = Response.Sync(error = failure.message)
        }
        syncJob?.cancel()
        syncJob =
            scope.launch {
                while (isActive && foreground) {
                    delay(SYNC_POLL)
                    pollSync()
                }
            }
    }

    suspend fun pollSync() {
        val previous = sync
        val next = runCatching { vault.ask<Response.Sync>(Request.SyncView) }.getOrNull() ?: return
        sync = next
        if (phase == Phase.Unsealed && previous != null && next.lastExchange != previous.lastExchange) {
            if (activity.elapsedNow() < TOUCH_EVERY) changed() else syncChanged = true
        }
    }

    suspend fun syncing(request: Request): Response.Sync {
        val next = call<Response.Sync>(request)
        sync = next
        return next
    }

    companion object {
        private val TOUCH_EVERY = 30.seconds
        private val TOAST_LIFETIME = 5.seconds
        private val SYNC_POLL = 3.seconds
        private const val SALVAGE_MARGIN = 15L
    }
}
