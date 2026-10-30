package com.cachix.factorseal.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.Autofill
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Page
import com.cachix.factorseal.app.icon
import com.cachix.factorseal.app.label
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Summary
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.autofill_chrome
import com.cachix.factorseal.resources.autofill_line
import com.cachix.factorseal.resources.autofill_offer
import com.cachix.factorseal.resources.back
import com.cachix.factorseal.resources.back_up_vault
import com.cachix.factorseal.resources.clear_search
import com.cachix.factorseal.resources.could_not_load
import com.cachix.factorseal.resources.devices
import com.cachix.factorseal.resources.glyph_close
import com.cachix.factorseal.resources.glyph_lock
import com.cachix.factorseal.resources.glyph_search
import com.cachix.factorseal.resources.glyph_transfer
import com.cachix.factorseal.resources.icon_chevron_left
import com.cachix.factorseal.resources.icon_hard_drive
import com.cachix.factorseal.resources.icon_network
import com.cachix.factorseal.resources.icon_plus
import com.cachix.factorseal.resources.icon_settings
import com.cachix.factorseal.resources.icon_star_fill
import com.cachix.factorseal.resources.icon_user
import com.cachix.factorseal.resources.item_count
import com.cachix.factorseal.resources.new_item
import com.cachix.factorseal.resources.no_matching_items
import com.cachix.factorseal.resources.no_personal_secrets
import com.cachix.factorseal.resources.no_personal_secrets_line
import com.cachix.factorseal.resources.not_now
import com.cachix.factorseal.resources.personal_secrets
import com.cachix.factorseal.resources.seal
import com.cachix.factorseal.resources.search_results
import com.cachix.factorseal.resources.search_secrets
import com.cachix.factorseal.resources.settings
import com.cachix.factorseal.resources.transfer_credentials
import com.cachix.factorseal.resources.try_different_search
import com.cachix.factorseal.resources.turn_on
import com.cachix.factorseal.resources.unsealed
import com.cachix.factorseal.resources.wordmark
import com.cachix.factorseal.ui.components.Back
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.ButtonSize
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.Dot
import com.cachix.factorseal.ui.components.EmptyState
import com.cachix.factorseal.ui.components.FieldHeight
import com.cachix.factorseal.ui.components.Icon
import com.cachix.factorseal.ui.components.IconButton
import com.cachix.factorseal.ui.components.IconTile
import com.cachix.factorseal.ui.components.InfoBox
import com.cachix.factorseal.ui.components.ListHeader
import com.cachix.factorseal.ui.components.ListRow
import com.cachix.factorseal.ui.components.Mark
import com.cachix.factorseal.ui.components.Pill
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.TextInput
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.components.fieldFrame
import com.cachix.factorseal.ui.theme.Medium
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.pluralStringResource
import org.jetbrains.compose.resources.stringResource

private data class Screen(
    val depth: Int,
    val page: Page?,
)

@Composable
fun VaultScreen(app: FactorSeal) {
    val travel = with(LocalDensity.current) { 20.dp.roundToPx() }
    val motion = Theme.motion
    Back(enabled = app.pages.isNotEmpty()) { app.back() }
    AnimatedContent(
        targetState = Screen(app.pages.size, app.pages.lastOrNull()),
        transitionSpec = {
            val direction = targetState.depth.compareTo(initialState.depth)
            val enter =
                if (direction == 0) {
                    fadeIn(motion.enter()) + slideInVertically(motion.enter()) { travel / 3 }
                } else {
                    fadeIn(motion.navigate()) + slideInHorizontally(motion.navigate()) { direction * travel }
                }
            enter togetherWith fadeOut(motion.leave())
        },
        contentKey = { it.page },
    ) { screen ->
        when (val page = screen.page) {
            null -> Home(app)
            Page.Personal -> PersonalList(app)
            Page.Search -> SearchPage(app)
            is Page.Entry -> ItemPage(app, page.id)
            Page.New -> NewItemPage(app)
            Page.Devices -> DevicesPage(app)
            is Page.Device -> DevicePage(app, page.name)
            is Page.Transfer -> TransferPage(app, page.backup)
            is Page.TransferForm -> TransferFormPage(app, page.backup, page.import)
            Page.Settings -> SettingsPage(app)
            is Page.Section -> SectionPage(app, page.section)
        }
    }
}

@Composable
fun BackRow(
    app: FactorSeal,
    onBack: () -> Unit = { app.back() },
    trailing: (@Composable RowScope.() -> Unit)? = null,
) {
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 56.dp)
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(
                stringResource(Res.string.back),
                onClick = onBack,
                variant = Variant.Ghost,
                size = ButtonSize.Small,
                icon = Res.drawable.icon_chevron_left,
            )
            if (trailing != null) trailing() else Spacer(Modifier.weight(1f))
        }
        Divider()
    }
}

@Composable
fun MainPage(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier
            .fillMaxSize()
            .background(Theme.colors.surface)
            .windowInsetsPadding(WindowInsets.safeDrawing),
        content = content,
    )
}

@Composable
fun SearchInput(
    state: TextFieldState,
    modifier: Modifier = Modifier,
    focus: FocusRequester? = null,
) {
    val keyboard = LocalSoftwareKeyboardController.current
    TextInput(
        state = state,
        placeholder = stringResource(Res.string.search_secrets),
        modifier = modifier.then(if (focus == null) Modifier else Modifier.focusRequester(focus)),
        keyboard = KeyboardOptions(imeAction = ImeAction.Search),
        onSubmit = { keyboard?.hide() },
        leading = { Icon(Res.drawable.glyph_search, size = 16.dp, tint = Theme.colors.mutedForeground) },
        trailing =
        if (state.text.isEmpty()) {
            null
        } else {
            {
                IconButton(
                    Res.drawable.glyph_close,
                    stringResource(Res.string.clear_search),
                    onClick = { state.clearText() },
                    size = ButtonSize.Small,
                    tint = Theme.colors.mutedForeground,
                )
            }
        },
    )
}

@Composable
private fun SearchLauncher(app: FactorSeal) {
    val interaction = remember { MutableInteractionSource() }
    Row(
        Modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = FieldHeight)
            .then(fieldFrame(interaction, error = false))
            .clickable(interaction, indication = null, role = Role.Button) { app.open(Page.Search) }
            .padding(horizontal = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Res.drawable.glyph_search, size = 16.dp, tint = Theme.colors.mutedForeground)
        Text(stringResource(Res.string.search_secrets), color = Theme.colors.mutedForeground, maxLines = 1)
    }
}

@Composable
private fun SidebarItem(
    label: String,
    icon: DrawableResource,
    onClick: () -> Unit,
    badge: String? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    Row(
        Modifier
            .fillMaxWidth()
            .background(if (pressed) Theme.colors.secondaryHover else Color.Transparent, Shapes.tile)
            .clickable(interaction, indication = null, role = Role.Button, onClick = onClick)
            .defaultMinSize(minHeight = 48.dp)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, size = 18.dp)
        Text(label, Modifier.weight(1f), maxLines = 1)
        if (badge != null) {
            Box(
                Modifier
                    .widthIn(min = 28.dp)
                    .background(Theme.colors.background.copy(alpha = 0.65f), Shapes.pill)
                    .padding(horizontal = 8.dp, vertical = 2.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(badge, color = Theme.colors.mutedForeground, maxLines = 1)
            }
        }
    }
}

@Composable
private fun Home(app: FactorSeal) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Theme.colors.muted)
            .windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                Modifier.padding(top = 20.dp, bottom = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Mark(52.dp)
                Text(stringResource(Res.string.wordmark), style = Type.wordmark, maxLines = 1)
            }
            SearchLauncher(app)
            SidebarItem(
                stringResource(Res.string.personal_secrets),
                Res.drawable.icon_user,
                onClick = { app.open(Page.Personal) },
                badge = app.items?.size?.toString(),
            )
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                SidebarItem(stringResource(Res.string.devices), Res.drawable.icon_network, onClick = { app.open(Page.Devices) })
                SidebarItem(stringResource(Res.string.transfer_credentials), Res.drawable.glyph_transfer, onClick = { app.open(Page.Transfer(backup = false)) })
                SidebarItem(stringResource(Res.string.back_up_vault), Res.drawable.icon_hard_drive, onClick = { app.open(Page.Transfer(backup = true)) })
                SidebarItem(stringResource(Res.string.settings), Res.drawable.icon_settings, onClick = { app.open(Page.Settings) })
            }
            app.host.autofill
                ?.takeIf { app.preferences.offerAutofill }
                ?.let { AutofillOffer(it, onDismiss = { app.update(app.preferences.copy(offerAutofill = false)) }) }
        }
        Column(Modifier.padding(horizontal = 12.dp)) {
            Divider()
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Dot(Theme.colors.success)
                Text(stringResource(Res.string.unsealed), Modifier.weight(1f), maxLines = 1)
                Button(
                    stringResource(Res.string.seal),
                    onClick = app::seal,
                    size = ButtonSize.Small,
                    icon = Res.drawable.glyph_lock,
                )
            }
        }
    }
}

@Composable
private fun AutofillOffer(
    autofill: Autofill,
    onDismiss: () -> Unit,
) {
    if (autofillEnabled(autofill)) return
    InfoBox(fill = Theme.colors.surface) {
        Text(stringResource(Res.string.autofill_offer), weight = Medium)
        Text(stringResource(Res.string.autofill_line), color = Theme.colors.mutedForeground)
        Text(stringResource(Res.string.autofill_chrome), color = Theme.colors.mutedForeground)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)) {
            Button(stringResource(Res.string.not_now), onClick = onDismiss, size = ButtonSize.Small, variant = Variant.Ghost)
            Button(stringResource(Res.string.turn_on), onClick = autofill::enable, size = ButtonSize.Small, variant = Variant.Primary)
        }
    }
}

@Composable
private fun kindLabels(): Map<Kind, String> = Kind.entries.associateWith { stringResource(it.label()) }

private fun Summary.detail(kinds: Map<Kind, String>): String = username ?: kinds.getValue(kind)

@Composable
private fun EntryRow(
    summary: Summary,
    detail: String,
    onClick: () -> Unit,
    query: String = "",
) {
    ListRow(onClick) {
        IconTile(summary.kind.icon())
        Column(Modifier.weight(1f)) {
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                if (summary.favorite) Icon(Res.drawable.icon_star_fill, size = 12.dp, tint = Theme.colors.mutedForeground)
                Text(highlighted(summary.title, query), weight = Semibold, maxLines = 1)
            }
            Text(highlighted(detail, query), style = Type.caption, color = Theme.colors.mutedForeground, maxLines = 1)
        }
    }
}

@Composable
private fun highlighted(
    text: String,
    query: String,
): AnnotatedString {
    val start = if (query.isEmpty()) -1 else text.lowercase().indexOf(query)
    if (start < 0) return AnnotatedString(text)
    val color = Theme.colors.warning.copy(alpha = 0.35f)
    return buildAnnotatedString {
        append(text.substring(0, start))
        withStyle(SpanStyle(background = color)) { append(text.substring(start, start + query.length)) }
        append(text.substring(start + query.length))
    }
}

@Composable
private fun PersonalList(app: FactorSeal) {
    val items = app.items
    val kinds = kindLabels()
    MainPage {
        BackRow(app)
        ListHeader(stringResource(Res.string.personal_secrets)) {
            if (!items.isNullOrEmpty()) {
                IconButton(
                    Res.drawable.icon_plus,
                    stringResource(Res.string.new_item),
                    onClick = { app.open(Page.New) },
                    variant = Variant.Primary,
                )
            }
        }
        app.itemsError?.let {
            Text(stringResource(Res.string.could_not_load, it), Modifier.padding(16.dp), color = Theme.colors.danger)
        }
        if (items != null && items.isEmpty()) {
            EmptyState(
                stringResource(Res.string.no_personal_secrets),
                stringResource(Res.string.no_personal_secrets_line),
            ) {
                Button(
                    stringResource(Res.string.new_item),
                    onClick = { app.open(Page.New) },
                    variant = Variant.Primary,
                    icon = Res.drawable.icon_plus,
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(items.orEmpty(), key = { it.id }) { summary ->
                    EntryRow(summary, summary.detail(kinds), onClick = { app.open(Page.Entry(summary.id)) })
                }
            }
        }
    }
}

@Composable
private fun SearchPage(app: FactorSeal) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    val kinds = kindLabels()
    val query = app.query.text.toString().trim().lowercase()
    val title = stringResource(Res.string.personal_secrets)
    val results =
        app.items.orEmpty().filter { summary ->
            title.lowercase().contains(query) ||
                summary.title.lowercase().contains(query) ||
                summary.detail(kinds).lowercase().contains(query)
        }
    MainPage {
        BackRow(app) { SearchInput(app.query, Modifier.weight(1f), focus) }
        ListHeader(stringResource(Res.string.search_results)) {
            Pill(pluralStringResource(Res.plurals.item_count, results.size, results.size))
        }
        if (results.isEmpty()) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(stringResource(Res.string.no_matching_items), weight = Semibold)
                Text(stringResource(Res.string.try_different_search), color = Theme.colors.mutedForeground)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                item {
                    Column(Modifier.fillMaxWidth()) {
                        Text(
                            highlighted(title, query),
                            Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 8.dp),
                            style = Type.caption,
                            color = Theme.colors.mutedForeground,
                            weight = Semibold,
                        )
                        Divider()
                    }
                }
                items(results, key = { it.id }) { summary ->
                    EntryRow(
                        summary,
                        summary.detail(kinds),
                        onClick = { app.open(Page.Entry(summary.id)) },
                        query = query,
                    )
                }
            }
        }
    }
}
