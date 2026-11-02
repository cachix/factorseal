package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Message
import com.cachix.factorseal.app.Page
import com.cachix.factorseal.app.message
import com.cachix.factorseal.app.text
import com.cachix.factorseal.app.validDeviceName
import com.cachix.factorseal.core.Device
import com.cachix.factorseal.core.Invitation
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Review
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.access
import com.cachix.factorseal.resources.access_personal
import com.cachix.factorseal.resources.access_storage
import com.cachix.factorseal.resources.approval_sent
import com.cachix.factorseal.resources.back
import com.cachix.factorseal.resources.cancel
import com.cachix.factorseal.resources.close
import com.cachix.factorseal.resources.codes_match
import com.cachix.factorseal.resources.compare_code
import com.cachix.factorseal.resources.conflicts
import com.cachix.factorseal.resources.connect_a_device
import com.cachix.factorseal.resources.connect_another
import com.cachix.factorseal.resources.connect_these_devices
import com.cachix.factorseal.resources.continue_button
import com.cachix.factorseal.resources.copy_pairing_code
import com.cachix.factorseal.resources.could_not_verify
import com.cachix.factorseal.resources.create_pairing_code
import com.cachix.factorseal.resources.creating_code
import com.cachix.factorseal.resources.device_name
import com.cachix.factorseal.resources.device_name_empty
import com.cachix.factorseal.resources.device_name_invalid
import com.cachix.factorseal.resources.device_name_too_long
import com.cachix.factorseal.resources.devices
import com.cachix.factorseal.resources.expires_in
import com.cachix.factorseal.resources.glyph_paste
import com.cachix.factorseal.resources.glyph_qr_code
import com.cachix.factorseal.resources.glyph_refresh
import com.cachix.factorseal.resources.icon_arrow_right
import com.cachix.factorseal.resources.icon_check
import com.cachix.factorseal.resources.icon_chevron_left
import com.cachix.factorseal.resources.icon_chevron_right
import com.cachix.factorseal.resources.icon_close
import com.cachix.factorseal.resources.icon_copy
import com.cachix.factorseal.resources.icon_network
import com.cachix.factorseal.resources.icon_plus
import com.cachix.factorseal.resources.last_synced
import com.cachix.factorseal.resources.loading_devices
import com.cachix.factorseal.resources.name_this_device
import com.cachix.factorseal.resources.name_this_device_lead
import com.cachix.factorseal.resources.new_pairing_code
import com.cachix.factorseal.resources.not_a_pairing_code
import com.cachix.factorseal.resources.pairing_choose
import com.cachix.factorseal.resources.pairing_code
import com.cachix.factorseal.resources.pairing_code_expired
import com.cachix.factorseal.resources.pairing_paste_detail
import com.cachix.factorseal.resources.pairing_scan_detail
import com.cachix.factorseal.resources.pairing_scan_hint
import com.cachix.factorseal.resources.pairing_show_detail
import com.cachix.factorseal.resources.paste_pairing_code
import com.cachix.factorseal.resources.rename
import com.cachix.factorseal.resources.review_connection
import com.cachix.factorseal.resources.review_explanation
import com.cachix.factorseal.resources.save
import com.cachix.factorseal.resources.scan_pairing_code
import com.cachix.factorseal.resources.show_pairing_code
import com.cachix.factorseal.resources.sync_now
import com.cachix.factorseal.resources.sync_runs
import com.cachix.factorseal.resources.synced_days_ago
import com.cachix.factorseal.resources.synced_hours_ago
import com.cachix.factorseal.resources.synced_just_now
import com.cachix.factorseal.resources.synced_minutes_ago
import com.cachix.factorseal.resources.synced_never
import com.cachix.factorseal.resources.syncing
import com.cachix.factorseal.resources.this_device
import com.cachix.factorseal.resources.view_connection
import com.cachix.factorseal.resources.waiting_for_other
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.Caption
import com.cachix.factorseal.ui.components.Dialog
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.FieldError
import com.cachix.factorseal.ui.components.Icon
import com.cachix.factorseal.ui.components.IconButton
import com.cachix.factorseal.ui.components.IconTile
import com.cachix.factorseal.ui.components.InfoBox
import com.cachix.factorseal.ui.components.KeyValueRow
import com.cachix.factorseal.ui.components.Labeled
import com.cachix.factorseal.ui.components.ListHeader
import com.cachix.factorseal.ui.components.ListRow
import com.cachix.factorseal.ui.components.PageHeader
import com.cachix.factorseal.ui.components.RowText
import com.cachix.factorseal.ui.components.SecretInput
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.TextInput
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.pluralStringResource
import org.jetbrains.compose.resources.stringResource
import kotlin.time.Clock

private enum class Pairing { Choose, Show, Paste }

@Composable
private fun Device.access(): String = stringResource(if (reader) Res.string.access_personal else Res.string.access_storage)

@Composable
private fun Device.detail(): String = if (local) stringResource(Res.string.this_device) else access()

internal fun deviceNameProblem(name: String): StringResource? = when {
    name.isBlank() -> Res.string.device_name_empty
    name.encodeToByteArray().size > 80 -> Res.string.device_name_too_long
    !validDeviceName(name) -> Res.string.device_name_invalid
    else -> null
}

private fun Response.Sync?.pending(): Boolean = this?.review != null || this?.invitation != null || this?.joining == true

private fun Response.Sync?.firstScreen(): Pairing = when {
    this?.joining == true -> Pairing.Paste
    this?.invitation != null -> Pairing.Show
    else -> Pairing.Choose
}

internal enum class SyncAge { Minutes, Hours, Days }

internal fun syncAge(
    last: Long,
    now: Long,
): Pair<SyncAge, Int>? {
    val elapsed = (now - last).coerceAtLeast(0)
    return when {
        elapsed < 60 -> null
        elapsed < 3_600 -> SyncAge.Minutes to (elapsed / 60).toInt()
        elapsed < 86_400 -> SyncAge.Hours to (elapsed / 3_600).toInt()
        else -> SyncAge.Days to (elapsed / 86_400).toInt()
    }
}

@Composable
private fun lastSynced(
    last: Long?,
    now: Long,
): String {
    if (last == null) return stringResource(Res.string.synced_never)
    val (unit, count) = syncAge(last, now) ?: return stringResource(Res.string.synced_just_now)
    val plural =
        when (unit) {
            SyncAge.Minutes -> Res.plurals.synced_minutes_ago
            SyncAge.Hours -> Res.plurals.synced_hours_ago
            SyncAge.Days -> Res.plurals.synced_days_ago
        }
    return pluralStringResource(plural, count, count)
}

private fun Response.Sync.onlyThisDevice(): Boolean = devices.isNotEmpty() && devices.all { it.local }

@Composable
private fun ConnectFirstDevice(
    pending: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(Res.string.connect_another), color = Theme.colors.mutedForeground)
        Button(
            stringResource(if (pending) Res.string.view_connection else Res.string.connect_a_device),
            onClick = onClick,
            variant = Variant.Primary,
            icon = Res.drawable.icon_plus,
        )
    }
}

@Composable
fun DevicesPage(app: FactorSeal) {
    var pairing by remember { mutableStateOf<Pairing?>(null) }
    val sync = app.sync
    LaunchedEffect(Unit) { app.pollSync() }
    MainPage {
        BackRow(app)
        if (app.preferences.deviceName == null) {
            NameDevice(app)
            return@MainPage
        }
        ListHeader(stringResource(Res.string.devices)) {
            IconButton(
                Res.drawable.icon_plus,
                stringResource(if (sync.pending()) Res.string.view_connection else Res.string.connect_a_device),
                onClick = { pairing = sync.firstScreen() },
                variant = Variant.Primary,
            )
        }
        if (sync == null) {
            Text(stringResource(Res.string.loading_devices), Modifier.padding(16.dp), color = Theme.colors.mutedForeground)
        } else {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                sync.devices.forEach { device ->
                    ListRow(onClick = { app.open(Page.Device(device.name)) }, chevron = true) {
                        IconTile(Res.drawable.icon_network)
                        RowText(device.name, device.detail())
                    }
                }
                if (sync.onlyThisDevice()) {
                    ConnectFirstDevice(sync.pending(), onClick = { pairing = sync.firstScreen() }, Modifier.padding(16.dp))
                }
            }
        }
    }
    pairing?.let { screen -> PairingDialog(app, screen, onScreen = { pairing = it }, onClose = { pairing = null }) }
}

@Composable
private fun NameDevice(app: FactorSeal) {
    val name = remember { TextFieldState(app.host.deviceName) }
    var problem by remember { mutableStateOf<Message?>(null) }
    fun submit() {
        val text = name.text.toString().trim()
        deviceNameProblem(text)?.let { return run { problem = message(it) } }
        app.update(app.preferences.copy(deviceName = text))
    }
    Column(
        Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 24.dp)
            .widthIn(max = 448.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text(stringResource(Res.string.name_this_device), style = Type.title)
        Text(stringResource(Res.string.name_this_device_lead), style = Type.lead, color = Theme.colors.mutedForeground)
        Labeled(stringResource(Res.string.device_name)) {
            TextInput(
                state = name,
                placeholder = stringResource(Res.string.device_name),
                error = problem != null,
                keyboard = KeyboardOptions(capitalization = KeyboardCapitalization.Words, imeAction = ImeAction.Done),
                onSubmit = ::submit,
            )
            FieldError(problem?.text())
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            Button(
                stringResource(Res.string.continue_button),
                onClick = ::submit,
                variant = Variant.Primary,
                icon = Res.drawable.icon_arrow_right,
            )
        }
    }
}

@Composable
fun DevicePage(
    app: FactorSeal,
    name: String,
) {
    val sync = app.sync
    val device = sync?.devices?.firstOrNull { it.name == name } ?: sync?.devices?.firstOrNull { it.local && name == app.preferences.deviceName }
    var renaming by remember { mutableStateOf(false) }
    var pairing by remember { mutableStateOf<Pairing?>(null) }
    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<Message?>(null) }
    val scope = rememberCoroutineScope()
    val alone = sync?.devices.orEmpty().none { !it.local }
    var now by remember { mutableLongStateOf(Clock.System.now().epochSeconds) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = Clock.System.now().epochSeconds
        }
    }
    MainPage {
        BackRow(app)
        if (device == null || sync == null) return@MainPage
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            PageHeader(Res.drawable.icon_network, device.name, detail = device.detail()) {
                if (device.local && alone && !renaming) {
                    Button(stringResource(Res.string.rename), onClick = {
                        problem = null
                        renaming = true
                    }, variant = Variant.Ghost)
                }
            }
            if (renaming) {
                val field = remember { TextFieldState(device.name) }
                val focus = remember { FocusRequester() }
                LaunchedEffect(Unit) { focus.requestFocus() }
                fun save() {
                    val text = field.text.toString().trim()
                    deviceNameProblem(text)?.let { return run { problem = message(it) } }
                    problem = null
                    renaming = false
                    app.update(app.preferences.copy(deviceName = text))
                    app.replace(Page.Device(text))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    TextInput(field, stringResource(Res.string.device_name), Modifier.weight(1f).focusRequester(focus), onSubmit = ::save)
                    Button(stringResource(Res.string.save), onClick = ::save, variant = Variant.Primary, icon = Res.drawable.icon_check)
                    IconButton(Res.drawable.icon_close, stringResource(Res.string.cancel), onClick = {
                        problem = null
                        renaming = false
                    })
                }
                FieldError(problem?.text())
            }
            if (sync.conflicts > 0) {
                InfoBox(fill = Theme.colors.secondary) { Text(pluralStringResource(Res.plurals.conflicts, sync.conflicts, sync.conflicts)) }
            }
            KeyValueRow(stringResource(Res.string.access), device.access())
            if (device.local && !alone) KeyValueRow(stringResource(Res.string.last_synced), lastSynced(sync.lastExchange, now))
            if (alone) {
                ConnectFirstDevice(sync.pending(), onClick = { pairing = sync.firstScreen() })
            } else {
                Button(
                    stringResource(if (busy) Res.string.syncing else Res.string.sync_now),
                    onClick = {
                        busy = true
                        scope.launch {
                            runCatching { app.syncing(Request.SyncRefresh) }
                            busy = false
                        }
                    },
                    icon = Res.drawable.glyph_refresh,
                    loading = busy,
                )
            }
            sync.error?.let { Text(it, color = Theme.colors.danger) }
            if (!alone) Caption(stringResource(Res.string.sync_runs))
        }
    }
    pairing?.let { screen -> PairingDialog(app, screen, onScreen = { pairing = it }, onClose = { pairing = null }) }
}

@Composable
private fun PairingDialog(
    app: FactorSeal,
    screen: Pairing,
    onScreen: (Pairing) -> Unit,
    onClose: () -> Unit,
) {
    val sync = app.sync ?: Response.Sync()
    val name = app.preferences.deviceName.orEmpty()
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(Clock.System.now().epochSeconds) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = Clock.System.now().epochSeconds
            app.pollSync()
        }
    }
    val review = sync.review
    val invitation = sync.invitation
    val showing = review == null && screen == Pairing.Show && invitation != null && invitation.expires > now
    var joined by remember { mutableStateOf(false) }
    LaunchedEffect(sync.joining) {
        if (sync.joining) {
            joined = true
        } else if (joined && sync.paired) {
            onClose()
        }
    }
    fun act(
        request: Request,
        done: () -> Unit = {},
    ) {
        busy = true
        problem = null
        scope.launch {
            try {
                app.syncing(request)
                done()
            } catch (failure: VaultException) {
                if (request !is Request.SyncJoin || app.sync?.review == null) problem = failure.message
            }
            busy = false
        }
    }
    fun join(ticket: String) = act(Request.SyncJoin(ticket, name))
    Dialog(
        title = stringResource(if (review != null) Res.string.review_connection else Res.string.connect_a_device),
        onDismiss = onClose,
        leading = {
            if (screen != Pairing.Choose && review == null && !sync.joining) {
                Button(
                    stringResource(Res.string.back),
                    onClick = {
                        if (invitation != null) scope.launch { runCatching { app.syncing(Request.SyncCancel) } }
                        problem = null
                        onScreen(Pairing.Choose)
                    },
                    variant = Variant.Ghost,
                    icon = Res.drawable.icon_chevron_left,
                )
            }
        },
        actions = {
            val approved = review?.approvedHere == true
            Button(
                stringResource(if (approved) Res.string.close else Res.string.cancel),
                onClick = {
                    if (!approved) scope.launch { runCatching { app.syncing(Request.SyncCancel) } }
                    onClose()
                },
                icon = Res.drawable.icon_close,
            )
        },
    ) {
        if (showing) {
            val left = (invitation.expires - now).coerceAtLeast(0)
            Text(
                stringResource(Res.string.expires_in, "${left / 60}:${(left % 60).toString().padStart(2, '0')}"),
                color = Theme.colors.mutedForeground,
            )
        }
        when {
            review != null ->
                ReviewBody(review, busy) {
                    val joining = sync.joining
                    act(Request.SyncApprove(review.request)) { if (!joining) onClose() }
                }

            screen == Pairing.Choose -> {
                Text(stringResource(Res.string.pairing_choose))
                PairingChoice(Res.drawable.glyph_qr_code, stringResource(Res.string.show_pairing_code), stringResource(Res.string.pairing_show_detail)) {
                    onScreen(Pairing.Show)
                    act(Request.SyncInvite(name))
                }
                PairingChoice(Res.drawable.glyph_qr_code, stringResource(Res.string.scan_pairing_code), stringResource(Res.string.pairing_scan_detail)) {
                    scanning = true
                }
                PairingChoice(Res.drawable.glyph_paste, stringResource(Res.string.paste_pairing_code), stringResource(Res.string.pairing_paste_detail)) {
                    onScreen(Pairing.Paste)
                }
            }

            screen == Pairing.Show -> ShowBody(invitation, now, busy, onCopy = { invitation?.let { app.copy(it.ticket) } }) { act(Request.SyncInvite(name)) }

            else -> PasteBody(busy, ::join)
        }
        (problem ?: sync.error)?.let { Text(it, color = Theme.colors.danger) }
        if (review?.approvedHere == true && sync.joining) {
            Text(stringResource(Res.string.approval_sent), color = Theme.colors.mutedForeground)
        }
    }
    if (scanning) {
        Scanner(
            app,
            onDismiss = { scanning = false },
            accept = { it is Scan.Pairing },
            rejected = message(Res.string.not_a_pairing_code),
        ) { scan ->
            scanning = false
            (scan as? Scan.Pairing)?.let { join(it.ticket) }
        }
    }
}

@Composable
private fun PairingChoice(
    icon: DrawableResource,
    title: String,
    detail: String,
    onClick: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val colors = Theme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .clip(Shapes.tile)
            .border(1.dp, colors.border, Shapes.tile)
            .background(if (pressed) colors.selection else Color.Transparent)
            .clickable(interaction, indication = null, role = Role.Button, onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconTile(icon)
        Column(Modifier.weight(1f)) {
            Text(title, weight = Semibold)
            Caption(detail)
        }
        Icon(Res.drawable.icon_chevron_right, tint = colors.mutedForeground)
    }
}

@Composable
private fun ShowBody(
    invitation: Invitation?,
    now: Long,
    busy: Boolean,
    onCopy: () -> Unit,
    onCreate: () -> Unit,
) {
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when {
            invitation == null ->
                Button(
                    stringResource(if (busy) Res.string.creating_code else Res.string.create_pairing_code),
                    onClick = onCreate,
                    icon = Res.drawable.glyph_refresh,
                    loading = busy,
                )

            invitation.expires <= now -> {
                Text(stringResource(Res.string.pairing_code_expired), align = TextAlign.Center)
                Button(
                    stringResource(Res.string.new_pairing_code),
                    onClick = onCreate,
                    variant = Variant.Primary,
                    icon = Res.drawable.glyph_refresh,
                    loading = busy,
                )
            }

            else -> {
                QrCode(invitation.modules, stringResource(Res.string.pairing_code), Modifier.widthIn(max = 320.dp).fillMaxWidth())
                Text(stringResource(Res.string.pairing_scan_hint), color = Theme.colors.mutedForeground, align = TextAlign.Center)
                Button(stringResource(Res.string.copy_pairing_code), onClick = onCopy, icon = Res.drawable.icon_copy)
            }
        }
    }
}

@Composable
private fun PasteBody(
    busy: Boolean,
    onJoin: (String) -> Unit,
) {
    val ticket = remember { TextFieldState() }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    fun submit() {
        val text = ticket.text.toString()
        ticket.clearText()
        if (text.isNotBlank()) onJoin(text)
    }
    Labeled(stringResource(Res.string.pairing_code)) {
        SecretInput(
            state = ticket,
            placeholder = stringResource(Res.string.paste_pairing_code),
            revealed = false,
            modifier = Modifier.focusRequester(focus),
            onSubmit = ::submit,
        )
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        Button(
            stringResource(Res.string.review_connection),
            onClick = ::submit,
            variant = Variant.Primary,
            icon = Res.drawable.icon_arrow_right,
            enabled = !busy,
            loading = busy,
        )
    }
}

@Composable
private fun ReviewBody(
    review: Review,
    busy: Boolean,
    onApprove: () -> Unit,
) {
    val colors = Theme.colors
    Text(stringResource(Res.string.connect_these_devices, review.devices.size), weight = Semibold)
    Text(stringResource(Res.string.review_explanation))
    Column(
        Modifier
            .fillMaxWidth()
            .border(1.dp, colors.border, Shapes.tile),
    ) {
        review.devices.forEachIndexed { index, device ->
            if (index > 0) Divider()
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(device.name, Modifier.weight(1f), maxLines = 1)
                if (device.local) Caption(stringResource(Res.string.this_device))
            }
        }
    }
    Text(stringResource(Res.string.compare_code))
    Text(review.code, style = Type.title.copy(fontFamily = Type.mono.fontFamily))
    if (!review.verified) {
        Text(stringResource(Res.string.could_not_verify), color = colors.danger)
    } else {
        Button(
            stringResource(
                if (review.approvedHere || review.waiting) Res.string.waiting_for_other else Res.string.codes_match,
            ),
            onClick = onApprove,
            modifier = Modifier.fillMaxWidth(),
            variant = Variant.Primary,
            icon = Res.drawable.icon_check,
            enabled = !review.approvedHere && !review.waiting,
            loading = busy,
        )
    }
}

@Composable
private fun QrCode(
    modules: List<List<Boolean>>,
    description: String,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier
            .aspectRatio(1f)
            .background(Color.White, Shapes.tile)
            .semantics { contentDescription = description },
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val count = modules.size + 8
            val module = size.minDimension / count
            modules.forEachIndexed { y, row ->
                row.forEachIndexed { x, dark ->
                    if (dark) {
                        drawRect(Color.Black, Offset((x + 4) * module, (y + 4) * module), Size(module + 0.5f, module + 0.5f))
                    }
                }
            }
        }
    }
}
