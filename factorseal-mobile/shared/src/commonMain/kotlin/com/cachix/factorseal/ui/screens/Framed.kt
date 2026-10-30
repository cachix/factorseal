package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Message
import com.cachix.factorseal.app.Phase
import com.cachix.factorseal.app.SECURITY_URL
import com.cachix.factorseal.app.SetupMethod
import com.cachix.factorseal.app.UnlockStep
import com.cachix.factorseal.app.backendLabel
import com.cachix.factorseal.app.groupLabel
import com.cachix.factorseal.app.label
import com.cachix.factorseal.app.message
import com.cachix.factorseal.app.text
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Factor
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.about_device_protection
import com.cachix.factorseal.resources.back_to_vault
import com.cachix.factorseal.resources.choose_unlock
import com.cachix.factorseal.resources.confirm_password
import com.cachix.factorseal.resources.continue_with_biometrics
import com.cachix.factorseal.resources.copied
import com.cachix.factorseal.resources.copy_details
import com.cachix.factorseal.resources.create_vault
import com.cachix.factorseal.resources.create_your_vault
import com.cachix.factorseal.resources.creating_description
import com.cachix.factorseal.resources.creating_vault
import com.cachix.factorseal.resources.error_empty_password
import com.cachix.factorseal.resources.error_password_mismatch
import com.cachix.factorseal.resources.hardware_unavailable
import com.cachix.factorseal.resources.hide_details
import com.cachix.factorseal.resources.hide_password
import com.cachix.factorseal.resources.how_protection_works
import com.cachix.factorseal.resources.icon_chevron_right
import com.cachix.factorseal.resources.icon_settings
import com.cachix.factorseal.resources.method_biometric
import com.cachix.factorseal.resources.method_password
import com.cachix.factorseal.resources.method_password_and_biometric
import com.cachix.factorseal.resources.method_password_or_biometric
import com.cachix.factorseal.resources.missing_unlock_password
import com.cachix.factorseal.resources.password
import com.cachix.factorseal.resources.placeholder_confirm_password
import com.cachix.factorseal.resources.placeholder_password
import com.cachix.factorseal.resources.protected_by
import com.cachix.factorseal.resources.sealing_description
import com.cachix.factorseal.resources.sealing_vault
import com.cachix.factorseal.resources.settings
import com.cachix.factorseal.resources.setup_protection_choose
import com.cachix.factorseal.resources.setup_protection_password
import com.cachix.factorseal.resources.setup_subtitle
import com.cachix.factorseal.resources.show_details
import com.cachix.factorseal.resources.show_password
import com.cachix.factorseal.resources.step_biometric
import com.cachix.factorseal.resources.step_loading
import com.cachix.factorseal.resources.step_verifying
import com.cachix.factorseal.resources.tagline
import com.cachix.factorseal.resources.try_again
import com.cachix.factorseal.resources.unknown_cause
import com.cachix.factorseal.resources.unlock_description
import com.cachix.factorseal.resources.unlock_vault
import com.cachix.factorseal.resources.unlocking
import com.cachix.factorseal.resources.unlocking_title
import com.cachix.factorseal.resources.vault_is_sealed
import com.cachix.factorseal.resources.vault_unavailable
import com.cachix.factorseal.resources.wordmark
import com.cachix.factorseal.ui.components.Banner
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.ButtonSize
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.FieldError
import com.cachix.factorseal.ui.components.FieldHeight
import com.cachix.factorseal.ui.components.Icon
import com.cachix.factorseal.ui.components.InfoBox
import com.cachix.factorseal.ui.components.Labeled
import com.cachix.factorseal.ui.components.Mark
import com.cachix.factorseal.ui.components.PasswordField
import com.cachix.factorseal.ui.components.SecretInput
import com.cachix.factorseal.ui.components.Spinner
import com.cachix.factorseal.ui.components.StrengthMeter
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.components.VaultCard
import com.cachix.factorseal.ui.components.entering
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import kotlinx.coroutines.delay
import org.jetbrains.compose.resources.stringResource

@Composable
fun Brand(
    compact: Boolean,
    onHome: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val label = stringResource(Res.string.back_to_vault)
    Row(
        modifier.then(
            if (onHome == null) {
                Modifier
            } else {
                Modifier
                    .clickable(remember { MutableInteractionSource() }, indication = null, role = Role.Button, onClick = onHome)
                    .semantics { contentDescription = label }
            },
        ),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Mark(36.dp)
        if (!compact) Text(stringResource(Res.string.wordmark), style = Type.title, maxLines = 1)
    }
}

@Composable
fun Link(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    style: TextStyle = Type.caption,
) {
    Text(
        text,
        modifier
            .clickable(remember { MutableInteractionSource() }, indication = null, role = Role.Button, onClick = onClick)
            .padding(vertical = 6.dp),
        style = style.copy(textDecoration = TextDecoration.Underline),
        color = Theme.colors.foreground,
    )
}

@Composable
fun ProtectionLink(
    app: FactorSeal,
    style: TextStyle = Type.caption,
) {
    val backend = app.status?.backend
    Link(
        if (backend == null) {
            stringResource(Res.string.about_device_protection)
        } else {
            stringResource(Res.string.protected_by, backendLabel(backend))
        },
        onClick = { app.host.open(SECURITY_URL) },
        style = style,
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun Footer(app: FactorSeal) {
    Column(Modifier.fillMaxWidth()) {
        Divider()
        FlowRow(
            Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 48.dp)
                .padding(horizontal = 16.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalArrangement = Arrangement.Center,
            itemVerticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(Res.string.tagline),
                Modifier.padding(vertical = 6.dp, horizontal = 0.dp),
                style = Type.caption,
                color = Theme.colors.mutedForeground,
            )
            ProtectionLink(app)
        }
    }
}

@Composable
fun Framed(
    app: FactorSeal,
    width: Dp = 440.dp,
    settings: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
        Column(Modifier.fillMaxWidth()) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 64.dp)
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (app.settingsOpen) {
                    Brand(compact = true, onHome = { app.settingsOpen = false })
                    Icon(Res.drawable.icon_chevron_right, tint = Theme.colors.mutedForeground)
                    Text(stringResource(Res.string.settings), Modifier.weight(1f), style = Type.heading, maxLines = 1)
                } else {
                    Brand(compact = false, onHome = null, modifier = Modifier.weight(1f))
                    if (settings && app.phase != Phase.Starting) {
                        Button(
                            stringResource(Res.string.settings),
                            onClick = { app.settingsOpen = true },
                            icon = Res.drawable.icon_settings,
                        )
                    }
                }
            }
            Divider()
        }
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
            if (app.settingsOpen) {
                Box(Modifier.widthIn(max = 640.dp).fillMaxSize()) { FramedSettings(app) }
            } else {
                Column(
                    Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Column(Modifier.widthIn(max = width).fillMaxWidth(), content = content)
                }
            }
        }
        if (WindowInsets.ime.getBottom(LocalDensity.current) == 0) Footer(app)
    }
}

@Composable
fun ErrorNotice(
    failure: VaultException,
    app: FactorSeal,
    retry: (() -> Unit)? = null,
) {
    when (failure.code) {
        ErrorCode.Cancelled -> return

        ErrorCode.HardwareUnavailable -> {
            Banner(stringResource(Res.string.hardware_unavailable))
            return
        }

        in PlainErrors -> {
            Banner(failure.message)
            return
        }

        else -> Unit
    }
    var open by remember(failure) { mutableStateOf(false) }
    var copied by remember(failure) { mutableStateOf(false) }
    LaunchedEffect(copied) {
        if (copied) {
            delay(2000)
            copied = false
        }
    }
    val colors = Theme.colors
    Column(
        Modifier
            .entering(failure)
            .fillMaxWidth()
            .background(colors.danger.copy(alpha = 0.1f), Shapes.tile)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(Res.string.unknown_cause), color = colors.danger)
        if (open) {
            Text(
                failure.message,
                Modifier
                    .fillMaxWidth()
                    .background(colors.background, Shapes.input)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                style = Type.mono.copy(fontSize = Type.caption.fontSize),
                color = colors.mutedForeground,
            )
        }
        Actions {
            if (retry != null) Button(stringResource(Res.string.try_again), onClick = retry, size = ButtonSize.Small)
            Button(
                stringResource(if (open) Res.string.hide_details else Res.string.show_details),
                onClick = { open = !open },
                variant = Variant.Ghost,
                size = ButtonSize.Small,
            )
            Button(
                stringResource(if (copied) Res.string.copied else Res.string.copy_details),
                onClick = {
                    app.copy(failure.message)
                    copied = true
                },
                variant = Variant.Ghost,
                size = ButtonSize.Small,
            )
        }
    }
}

private val PlainErrors =
    setOf(
        ErrorCode.PasswordRejected,
        ErrorCode.PasswordRequired,
        ErrorCode.WeakPassword,
    )

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun Actions(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    FlowRow(
        modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) { content() }
}

@Composable
private fun CardHeader(
    title: String,
    line: String?,
    reserve: Boolean = false,
    mark: @Composable () -> Unit,
) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        mark()
        Text(title, style = Type.title, align = TextAlign.Center)
        if (line != null) {
            Text(
                line,
                if (reserve) Modifier.heightIn(min = 48.dp) else Modifier,
                style = Type.lead,
                color = Theme.colors.mutedForeground,
                align = TextAlign.Center,
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SetupScreen(app: FactorSeal) {
    val form = app.setup
    val methods = if (app.host.biometric) SetupMethod.entries else listOf(SetupMethod.Password)
    val strength = rememberStrength(app, form.password)
    val confirmation = remember { FocusRequester() }
    LaunchedEffect(form.password) {
        snapshotFlow { form.password.text.toString() }.collect { form.passwordError = null }
    }
    LaunchedEffect(form.confirmation) {
        snapshotFlow { form.confirmation.text.toString() }.collect { form.confirmationError = null }
    }
    fun submit() {
        val password = form.password.text.toString()
        if (form.method.password) {
            if (password.isEmpty()) {
                form.passwordError = message(Res.string.error_empty_password)
                return
            }
            if (password != form.confirmation.text.toString()) {
                form.confirmationError = message(Res.string.error_password_mismatch)
                return
            }
        }
        app.create(form.method.groups, password.takeIf { form.method.password })
    }
    Framed(app, width = 520.dp) {
        VaultCard {
            CardHeader(stringResource(Res.string.create_your_vault), stringResource(Res.string.setup_subtitle)) { Mark(72.dp) }
            InfoBox {
                Text(
                    stringResource(if (methods.size > 1) Res.string.setup_protection_choose else Res.string.setup_protection_password),
                    color = Theme.colors.mutedForeground,
                )
                Link(stringResource(Res.string.how_protection_works), onClick = { app.host.open(SECURITY_URL) }, style = Type.body)
            }
            if (methods.size > 1) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    methods.forEach { method ->
                        Button(
                            stringResource(method.label()),
                            onClick = {
                                form.clear()
                                form.method = method
                            },
                            selected = form.method == method,
                        )
                    }
                }
            }
            if (form.method.password) {
                Labeled(stringResource(Res.string.password)) {
                    PasswordField(
                        state = form.password,
                        placeholder = stringResource(Res.string.placeholder_password),
                        revealed = form.revealed,
                        show = stringResource(Res.string.show_password),
                        hide = stringResource(Res.string.hide_password),
                        onReveal = { form.revealed = !form.revealed },
                        error = form.passwordError != null,
                        imeAction = ImeAction.Next,
                        onSubmit = { confirmation.requestFocus() },
                    )
                    strength?.let { StrengthMeter(it, stringResource(it.label())) }
                    FieldError(form.passwordError?.text())
                }
                Labeled(stringResource(Res.string.confirm_password)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        SecretInput(
                            state = form.confirmation,
                            placeholder = stringResource(Res.string.placeholder_confirm_password),
                            revealed = form.revealed,
                            modifier = Modifier.weight(1f).focusRequester(confirmation),
                            error = form.confirmationError != null,
                            onSubmit = ::submit,
                        )
                        Spacer(Modifier.widthIn(min = ButtonSize.Medium.height))
                    }
                    FieldError(form.confirmationError?.text())
                }
            }
            app.setupError?.let { ErrorNotice(it, app) }
            Button(
                stringResource(Res.string.create_vault),
                onClick = ::submit,
                modifier = Modifier.fillMaxWidth(),
                variant = Variant.Primary,
                size = ButtonSize.Large,
            )
        }
    }
}

private fun SetupMethod.label() = when (this) {
    SetupMethod.Password -> Res.string.method_password
    SetupMethod.Biometric -> Res.string.method_biometric
    SetupMethod.PasswordAndBiometric -> Res.string.method_password_and_biometric
    SetupMethod.PasswordOrBiometric -> Res.string.method_password_or_biometric
}

@Composable
fun ProgressScreen(
    app: FactorSeal,
    creating: Boolean,
) {
    Framed(app) {
        VaultCard(Modifier.semantics(mergeDescendants = true) {}) {
            Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Mark(56.dp)
                Spinner(size = 32.dp)
                Text(
                    stringResource(if (creating) Res.string.creating_vault else Res.string.sealing_vault),
                    style = Type.title,
                    align = TextAlign.Center,
                )
                Text(
                    stringResource(if (creating) Res.string.creating_description else Res.string.sealing_description),
                    color = Theme.colors.mutedForeground,
                    align = TextAlign.Center,
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SealedScreen(
    app: FactorSeal,
    settings: Boolean = true,
) {
    val phase = app.phase as? Phase.Sealed ?: Phase.Sealed()
    val form = app.unlocking
    val groups = app.unlockGroups.ifEmpty { listOf(listOf(Factor.Password)) }
    val group = groups[form.group.coerceIn(0, groups.lastIndex)]
    val needsPassword = Factor.Password in group
    val busy = phase.step != null
    var missing by remember { mutableStateOf<Message?>(null) }
    fun submit() {
        val password = form.password.text.toString()
        if (needsPassword && password.isEmpty()) {
            missing = message(Res.string.missing_unlock_password)
            return
        }
        missing = null
        form.password.edit { replace(0, length, "") }
        app.unlock(group, password.takeIf { needsPassword })
    }
    Framed(app, settings = settings) {
        VaultCard {
            CardHeader(
                stringResource(if (busy) Res.string.unlocking_title else Res.string.vault_is_sealed),
                stringResource(
                    when {
                        phase.step == null -> Res.string.unlock_description
                        phase.step == UnlockStep.Loading -> Res.string.step_loading
                        phase.biometric -> Res.string.step_biometric
                        else -> Res.string.step_verifying
                    },
                ),
                reserve = true,
            ) { UnlockMark(busy) }
            if (groups.size > 1) {
                Text(stringResource(Res.string.choose_unlock), color = Theme.colors.mutedForeground)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    groups.forEachIndexed { index, candidate ->
                        Button(
                            stringResource(groupLabel(candidate)),
                            onClick = {
                                form.password.edit { replace(0, length, "") }
                                missing = null
                                app.unlockError = null
                                form.group = index
                            },
                            selected = index == form.group,
                            enabled = !busy,
                        )
                    }
                }
            }
            if (needsPassword) {
                if (busy) {
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .height(FieldHeight)
                            .background(Theme.colors.muted.copy(alpha = 0.5f), Shapes.input)
                            .border(1.dp, Theme.colors.border.copy(alpha = 0.5f), Shapes.input),
                    )
                } else {
                    PasswordField(
                        state = form.password,
                        placeholder = stringResource(Res.string.placeholder_password),
                        revealed = form.revealed,
                        show = stringResource(Res.string.show_password),
                        hide = stringResource(Res.string.hide_password),
                        onReveal = { form.revealed = !form.revealed },
                        onSubmit = ::submit,
                    )
                }
            }
            missing?.let { Banner(it.text()) }
            app.unlockError?.let { ErrorNotice(it, app) }
            Button(
                stringResource(
                    when {
                        busy -> Res.string.unlocking
                        needsPassword -> Res.string.unlock_vault
                        else -> Res.string.continue_with_biometrics
                    },
                ),
                onClick = ::submit,
                modifier = Modifier.fillMaxWidth(),
                variant = Variant.Primary,
                size = ButtonSize.Large,
                loading = busy,
            )
        }
    }
}

@Composable
fun UnavailableScreen(
    app: FactorSeal,
    failure: VaultException,
    settings: Boolean = true,
) {
    Framed(app, settings = settings) {
        VaultCard {
            Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Mark(56.dp)
                Text(stringResource(Res.string.vault_unavailable), style = Type.title, align = TextAlign.Center)
            }
            ErrorNotice(failure, app, retry = app::retry)
        }
    }
}
