package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.cachix.factorseal.app.Autofill
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.IdleChoices
import com.cachix.factorseal.app.MaximumChoices
import com.cachix.factorseal.app.Page
import com.cachix.factorseal.app.Preferences
import com.cachix.factorseal.app.SettingsSection
import com.cachix.factorseal.app.durationLabel
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.appearance
import com.cachix.factorseal.resources.applies_next_unlock
import com.cachix.factorseal.resources.autofill
import com.cachix.factorseal.resources.autofill_line
import com.cachix.factorseal.resources.autofill_on
import com.cachix.factorseal.resources.glyph_lock
import com.cachix.factorseal.resources.icon_palette
import com.cachix.factorseal.resources.icon_undo_2
import com.cachix.factorseal.resources.idle_exceeds_maximum
import com.cachix.factorseal.resources.idle_lock_timeout
import com.cachix.factorseal.resources.maximum_unlock_duration
import com.cachix.factorseal.resources.reduced_motion
import com.cachix.factorseal.resources.reset_to_defaults
import com.cachix.factorseal.resources.security
import com.cachix.factorseal.resources.settings
import com.cachix.factorseal.resources.turn_on
import com.cachix.factorseal.ui.components.Back
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.IconTile
import com.cachix.factorseal.ui.components.ListHeader
import com.cachix.factorseal.ui.components.ListRow
import com.cachix.factorseal.ui.components.Menu
import com.cachix.factorseal.ui.components.MenuItem
import com.cachix.factorseal.ui.components.PageHeader
import com.cachix.factorseal.ui.components.RowText
import com.cachix.factorseal.ui.components.SettingRow
import com.cachix.factorseal.ui.components.Switch
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource

private fun SettingsSection.label(): StringResource = when (this) {
    SettingsSection.Appearance -> Res.string.appearance
    SettingsSection.Security -> Res.string.security
}

private fun SettingsSection.icon(): DrawableResource = when (this) {
    SettingsSection.Appearance -> Res.drawable.icon_palette
    SettingsSection.Security -> Res.drawable.glyph_lock
}

@Composable
fun SettingsList(
    app: FactorSeal,
    footer: Boolean,
    onOpen: (SettingsSection) -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        ListHeader(stringResource(Res.string.settings))
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            SettingsSection.entries.forEach { section ->
                ListRow(onClick = { onOpen(section) }, chevron = true) {
                    IconTile(section.icon())
                    RowText(stringResource(section.label()), null)
                }
            }
        }
        if (footer) Footer(app)
    }
}

@Composable
fun FramedSettings(app: FactorSeal) {
    var section by remember { mutableStateOf<SettingsSection?>(null) }
    Back {
        if (section != null) section = null else app.settingsOpen = false
    }
    val open = section
    if (open == null) {
        SettingsList(app, footer = false) { section = it }
    } else {
        Column(Modifier.fillMaxSize()) {
            BackRow(app, onBack = { section = null })
            SectionContent(app, open)
        }
    }
}

@Composable
fun SettingsPage(app: FactorSeal) {
    MainPage {
        BackRow(app)
        SettingsList(app, footer = true) { app.open(Page.Section(it)) }
    }
}

@Composable
fun SectionPage(
    app: FactorSeal,
    section: SettingsSection,
) {
    MainPage {
        BackRow(app)
        SectionContent(app, section)
    }
}

@Composable
private fun SectionContent(
    app: FactorSeal,
    section: SettingsSection,
) {
    var problem by remember { mutableStateOf(false) }
    Column(
        Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        PageHeader(section.icon(), stringResource(section.label()))
        val preferences = app.preferences
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            when (section) {
                SettingsSection.Appearance -> {
                    SettingRow(stringResource(Res.string.reduced_motion)) {
                        Switch(
                            preferences.reducedMotion,
                            { app.update(preferences.copy(reducedMotion = it)) },
                            stringResource(Res.string.reduced_motion),
                        )
                    }
                    val defaults = Preferences()
                    Button(
                        stringResource(Res.string.reset_to_defaults),
                        onClick = { app.update(preferences.copy(reducedMotion = defaults.reducedMotion)) },
                        icon = Res.drawable.icon_undo_2,
                        enabled = preferences.reducedMotion != defaults.reducedMotion,
                    )
                }

                SettingsSection.Security -> {
                    Column {
                        SettingRow(stringResource(Res.string.idle_lock_timeout)) {
                            Select(IdleChoices, preferences.idleSeconds, stringResource(Res.string.idle_lock_timeout)) { seconds ->
                                val next = preferences.copy(idleSeconds = seconds)
                                problem = !next.valid
                                app.update(next)
                            }
                        }
                        SettingRow(stringResource(Res.string.maximum_unlock_duration)) {
                            Select(MaximumChoices, preferences.maximumSeconds, stringResource(Res.string.maximum_unlock_duration)) { seconds ->
                                val next = preferences.copy(maximumSeconds = seconds)
                                problem = !next.valid
                                app.update(next)
                            }
                        }
                    }
                    Text(stringResource(Res.string.applies_next_unlock), color = Theme.colors.mutedForeground)
                    ProtectionLink(app, Type.body)
                    if (problem) Text(stringResource(Res.string.idle_exceeds_maximum), color = Theme.colors.danger)
                    app.host.autofill?.let { AutofillSetting(it) }
                }
            }
        }
    }
}

@Composable
fun autofillEnabled(autofill: Autofill): Boolean {
    var enabled by remember(autofill) { mutableStateOf(autofill.enabled) }
    LifecycleResumeEffect(autofill) {
        enabled = autofill.enabled
        onPauseOrDispose {}
    }
    return enabled
}

@Composable
private fun AutofillSetting(autofill: Autofill) {
    val enabled = autofillEnabled(autofill)
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SettingRow(stringResource(Res.string.autofill)) {
            if (enabled) {
                Text(stringResource(Res.string.autofill_on))
            } else {
                Button(stringResource(Res.string.turn_on), onClick = autofill::enable)
            }
        }
        Text(stringResource(Res.string.autofill_line), color = Theme.colors.mutedForeground)
    }
}

@Composable
private fun Select(
    choices: List<Long>,
    selected: Long,
    description: String,
    onSelect: (Long) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    val labels = choices.associateWith { durationLabel(it) }
    Box {
        Button(
            labels[selected] ?: durationLabel(selected),
            onClick = { open = true },
            description = description,
            caret = true,
        )
        Menu(
            expanded = open,
            onDismiss = { open = false },
            items = choices.map { choice -> MenuItem(labels.getValue(choice), { onSelect(choice) }, checked = choice == selected) },
        )
    }
}
