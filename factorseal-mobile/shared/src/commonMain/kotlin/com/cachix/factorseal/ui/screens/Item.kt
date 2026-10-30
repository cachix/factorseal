package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.Addable
import com.cachix.factorseal.app.CustomFieldTypes
import com.cachix.factorseal.app.Editor
import com.cachix.factorseal.app.EditorRow
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Labels
import com.cachix.factorseal.app.Message
import com.cachix.factorseal.app.NOTES_ID
import com.cachix.factorseal.app.Page
import com.cachix.factorseal.app.ToastAction
import com.cachix.factorseal.app.USERNAME_ID
import com.cachix.factorseal.app.dateLabel
import com.cachix.factorseal.app.fieldIcon
import com.cachix.factorseal.app.grouped
import com.cachix.factorseal.app.icon
import com.cachix.factorseal.app.label
import com.cachix.factorseal.app.message
import com.cachix.factorseal.app.text
import com.cachix.factorseal.core.Code
import com.cachix.factorseal.core.Draft
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Field
import com.cachix.factorseal.core.FieldType
import com.cachix.factorseal.core.Item
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.add_a_value
import com.cachix.factorseal.resources.add_field
import com.cachix.factorseal.resources.add_to_favorites
import com.cachix.factorseal.resources.already_has_otp
import com.cachix.factorseal.resources.cancel
import com.cachix.factorseal.resources.change_undone
import com.cachix.factorseal.resources.changes_not_saved
import com.cachix.factorseal.resources.copied
import com.cachix.factorseal.resources.copy
import com.cachix.factorseal.resources.could_not_delete
import com.cachix.factorseal.resources.could_not_undo
import com.cachix.factorseal.resources.custom_field
import com.cachix.factorseal.resources.custom_fields
import com.cachix.factorseal.resources.delete
import com.cachix.factorseal.resources.delete_body
import com.cachix.factorseal.resources.delete_title
import com.cachix.factorseal.resources.discard
import com.cachix.factorseal.resources.edit
import com.cachix.factorseal.resources.field_name
import com.cachix.factorseal.resources.field_type
import com.cachix.factorseal.resources.generate_password
import com.cachix.factorseal.resources.glyph_generate
import com.cachix.factorseal.resources.glyph_pencil
import com.cachix.factorseal.resources.glyph_qr_code
import com.cachix.factorseal.resources.glyph_trash
import com.cachix.factorseal.resources.hidden
import com.cachix.factorseal.resources.hide
import com.cachix.factorseal.resources.icon_check
import com.cachix.factorseal.resources.icon_chevron_down
import com.cachix.factorseal.resources.icon_close
import com.cachix.factorseal.resources.icon_copy
import com.cachix.factorseal.resources.icon_ellipsis
import com.cachix.factorseal.resources.icon_external_link
import com.cachix.factorseal.resources.icon_eye
import com.cachix.factorseal.resources.icon_eye_off
import com.cachix.factorseal.resources.icon_file
import com.cachix.factorseal.resources.icon_globe
import com.cachix.factorseal.resources.icon_plus
import com.cachix.factorseal.resources.icon_star
import com.cachix.factorseal.resources.icon_star_fill
import com.cachix.factorseal.resources.icon_undo_2
import com.cachix.factorseal.resources.invalid_setup_key
import com.cachix.factorseal.resources.item_changed
import com.cachix.factorseal.resources.item_deleted
import com.cachix.factorseal.resources.item_type
import com.cachix.factorseal.resources.keep_editing
import com.cachix.factorseal.resources.loading_item
import com.cachix.factorseal.resources.modified
import com.cachix.factorseal.resources.more_actions
import com.cachix.factorseal.resources.name_placeholder
import com.cachix.factorseal.resources.new_item
import com.cachix.factorseal.resources.not_saved
import com.cachix.factorseal.resources.notes
import com.cachix.factorseal.resources.open
import com.cachix.factorseal.resources.remove_field
import com.cachix.factorseal.resources.remove_from_favorites
import com.cachix.factorseal.resources.replaces_otp
import com.cachix.factorseal.resources.restore
import com.cachix.factorseal.resources.reveal
import com.cachix.factorseal.resources.save
import com.cachix.factorseal.resources.save_changes_title
import com.cachix.factorseal.resources.saved
import com.cachix.factorseal.resources.scan_qr_code
import com.cachix.factorseal.resources.setup_key_placeholder
import com.cachix.factorseal.resources.type_one_time_password
import com.cachix.factorseal.resources.type_website
import com.cachix.factorseal.resources.undo
import com.cachix.factorseal.ui.components.Back
import com.cachix.factorseal.ui.components.Banner
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.ButtonSize
import com.cachix.factorseal.ui.components.Caption
import com.cachix.factorseal.ui.components.Dialog
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.FieldError
import com.cachix.factorseal.ui.components.FieldHeight
import com.cachix.factorseal.ui.components.Icon
import com.cachix.factorseal.ui.components.IconButton
import com.cachix.factorseal.ui.components.IconTile
import com.cachix.factorseal.ui.components.Menu
import com.cachix.factorseal.ui.components.MenuItem
import com.cachix.factorseal.ui.components.Ring
import com.cachix.factorseal.ui.components.SecretInput
import com.cachix.factorseal.ui.components.Spinner
import com.cachix.factorseal.ui.components.StrengthMeter
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.TextInput
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.components.afterAMoment
import com.cachix.factorseal.ui.components.entering
import com.cachix.factorseal.ui.components.fieldFrame
import com.cachix.factorseal.ui.components.outdent
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.stringResource
import kotlin.time.TimeSource

@Composable
private fun labels() = Labels(
    customFields = stringResource(Res.string.custom_fields),
    customField = stringResource(Res.string.custom_field),
    website = stringResource(Res.string.type_website),
    oneTimePassword = stringResource(Res.string.type_one_time_password),
    notes = stringResource(Res.string.notes),
)

private const val MASK = "••••••••"

private fun Item.draft() = Draft(id, kind, title, favorite, notes, sections)

private fun Field.empty(): Boolean = !filled && value.text().isEmpty()

private fun generates(
    kind: Kind,
    row: EditorRow,
): Boolean = row.type == FieldType.Concealed && (kind == Kind.Generic || row.id == "password" || row.id == "passphrase")

private class Saving(
    val app: FactorSeal,
    val labels: Labels,
    val invalidKey: Message,
)

private suspend fun Saving.save(editor: Editor): Response.Saved? {
    if (!editor.validate()) return null
    for (row in editor.rows.filter { it.type == FieldType.Totp && !it.removed && !it.empty }) {
        val key = runCatching { app.call<Response.SetupKey>(Request.SetupKey(row.value.text.toString())) }.getOrNull()
        if (key?.value == null) {
            row.problem = invalidKey
            return null
        }
    }
    return try {
        app.call<Response.Saved>(Request.Save(editor.draft(labels), editor.version))
    } catch (failure: VaultException) {
        editor.problem =
            if (failure.code == ErrorCode.Changed || failure.code == ErrorCode.Conflict) {
                message(Res.string.item_changed)
            } else {
                message(Res.string.not_saved, failure.message)
            }
        null
    }
}

@Composable
private fun Salvage(
    app: FactorSeal,
    editor: Editor?,
    saving: Saving,
    onSaved: suspend (Response.Saved) -> Unit,
) {
    DisposableEffect(editor) {
        app.salvage = editor?.let { { if (it.dirty) saving.save(it)?.let { saved -> onSaved(saved) } } }
        onDispose { app.salvage = null }
    }
}

@Composable
private fun UnsavedDialog(
    name: String?,
    onDismiss: () -> Unit,
    onDiscard: () -> Unit,
    onSave: () -> Unit,
) {
    Dialog(
        title = stringResource(Res.string.save_changes_title, name ?: stringResource(Res.string.new_item)),
        onDismiss = onDismiss,
        leading = {
            Button(stringResource(Res.string.discard), onClick = {
                onDismiss()
                onDiscard()
            }, icon = Res.drawable.glyph_trash)
        },
        actions = {
            Button(stringResource(Res.string.keep_editing), onClick = onDismiss, icon = Res.drawable.glyph_pencil)
            Button(stringResource(Res.string.save), onClick = {
                onDismiss()
                onSave()
            }, variant = Variant.Primary, icon = Res.drawable.icon_check)
        },
    ) { Text(stringResource(Res.string.changes_not_saved)) }
}

@Composable
fun ItemPage(
    app: FactorSeal,
    id: String,
) {
    val page = Page.Entry(id)
    var item by remember(id) { mutableStateOf<Item?>(null) }
    var error by remember(id) { mutableStateOf<Message?>(null) }
    val editor = app.editors[page]
    var leaving by remember { mutableStateOf<(() -> Unit)?>(null) }
    var deleting by remember { mutableStateOf(false) }
    val revealed = remember(id, item?.version) { mutableStateMapOf<Pair<String, String>, String>() }
    val scope = rememberCoroutineScope()
    val labels = labels()
    val saving = Saving(app, labels, message(Res.string.invalid_setup_key))
    suspend fun load() {
        if (app.pages.lastOrNull() != Page.Entry(id)) return
        try {
            item = app.call<Response.Shown>(Request.OpenItem(id)).item
            error = null
        } catch (failure: VaultException) {
            if (failure.code == ErrorCode.NotFound) {
                app.back()
                app.toast(message(Res.string.item_changed), error = true)
            } else if (failure.code != ErrorCode.Sealed) {
                error = Message.Raw(failure.message)
            }
        }
    }
    LaunchedEffect(id, app.revision) { load() }
    suspend fun startEditing(add: Addable? = null) {
        val current = item ?: return
        try {
            val drafted = app.call<Response.Drafted>(Request.Edit(id)).item
            val next = Editor.of(drafted, isNew = false)
            next.template = runCatching { app.call<Response.Drafted>(Request.Template(drafted.kind)).item }.getOrNull()
            current.sections.forEach { section ->
                section.fields.forEach { field ->
                    if ((section.id to field.id) in revealed) {
                        next.sections.firstOrNull { it.id == section.id }?.rows?.firstOrNull { it.id == field.id }?.revealed = true
                    }
                }
            }
            if (add != null) {
                when (add) {
                    is Addable.Hidden -> next.rows.firstOrNull { it.id == add.row.id }?.hidden = false
                    else -> next.add(add, labels)
                }
            }
            next.original = drafted
            app.editors[page] = next
        } catch (failure: VaultException) {
            if (failure.code != ErrorCode.Sealed) error = Message.Raw(failure.message)
        }
    }
    fun close() {
        app.editors.remove(page)
    }
    fun leave(then: () -> Unit) {
        val current = app.editors[page]
        if (current != null && current.dirty) leaving = then else then()
    }
    suspend fun commit(current: Editor): Boolean {
        if (!current.dirty) {
            close()
            return true
        }
        val before = current.original
        val saved = saving.save(current) ?: return false
        close()
        load()
        app.changed()
        if (before != null) {
            app.toast(
                message(Res.string.saved),
                action =
                ToastAction(message(Res.string.undo)) {
                    try {
                        app.call<Response.Saved>(Request.Save(before.draft(), saved.version))
                        load()
                        app.changed()
                        app.toast(message(Res.string.change_undone))
                    } catch (failure: VaultException) {
                        app.toast(message(Res.string.could_not_undo, failure.message), error = true)
                    }
                },
            )
        }
        return true
    }
    Salvage(app, editor, saving) {
        close()
        load()
    }
    Back(enabled = editor != null) { leave(::close) }
    MainPage {
        BackRow(app, onBack = { leave { app.back() } })
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            val current = item
            val editing = editor
            if (current == null) {
                error?.let { Banner(it.text()) }
                if (error == null) {
                    Row(Modifier.afterAMoment(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Spinner()
                        Text(stringResource(Res.string.loading_item), color = Theme.colors.mutedForeground)
                    }
                }
                return@Column
            }
            Header(
                kind = current.kind,
                title = { modifier ->
                    if (editing == null) {
                        Row(modifier, horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(current.title, Modifier.weight(1f, fill = false), style = Type.title, maxLines = 2)
                            IconButton(
                                if (current.favorite) Res.drawable.icon_star_fill else Res.drawable.icon_star,
                                stringResource(if (current.favorite) Res.string.remove_from_favorites else Res.string.add_to_favorites),
                                onClick = {
                                    scope.launch {
                                        try {
                                            app.call<Response.Saved>(Request.Favorite(id, !current.favorite))
                                            load()
                                            app.changed()
                                        } catch (failure: VaultException) {
                                            error = message(Res.string.not_saved, failure.message)
                                        }
                                    }
                                },
                                size = ButtonSize.Small,
                            )
                        }
                    } else {
                        TitleInput(editing, modifier)
                    }
                },
                subtitle = { Text(stringResource(current.kind.label()), color = Theme.colors.mutedForeground, maxLines = 1) },
                actions =
                if (editing == null) {
                    {
                        Button(
                            stringResource(Res.string.edit),
                            onClick = { scope.launch { startEditing() } },
                            icon = Res.drawable.glyph_pencil,
                        )
                        var more by remember { mutableStateOf(false) }
                        Box {
                            IconButton(Res.drawable.icon_ellipsis, stringResource(Res.string.more_actions), onClick = { more = true })
                            Menu(
                                expanded = more,
                                onDismiss = { more = false },
                                items = listOf(MenuItem(stringResource(Res.string.delete), { deleting = true }, Res.drawable.glyph_trash)),
                            )
                        }
                    }
                } else {
                    null
                },
            )
            error?.let { Banner(it.text()) }
            if (editing != null) {
                EditorBody(app, editing, labels)
            } else {
                Fields(app, current, revealed)
                AddField(
                    addable = Editor.of(current, isNew = false).addable(),
                    labels = labels,
                    onAdd = { addable -> scope.launch { startEditing(addable) } },
                )
                app.items
                    ?.firstOrNull { it.id == id }
                    ?.updatedAt
                    ?.takeIf { it > 0 }
                    ?.let { Caption(stringResource(Res.string.modified, dateLabel(it)), Modifier.padding(horizontal = 4.dp)) }
            }
        }
        editor?.let { editing -> EditBar(onCancel = { leave(::close) }, onSave = { scope.launch { commit(editing) } }) }
    }
    leaving?.let { then ->
        val current = app.editors[page]
        UnsavedDialog(
            name = current?.title?.text?.toString()?.trim()?.ifEmpty { null } ?: item?.title,
            onDismiss = { leaving = null },
            onDiscard = {
                close()
                then()
            },
            onSave = { if (current != null) scope.launch { if (commit(current)) then() } },
        )
    }
    if (deleting) {
        val current = item
        Dialog(
            title = stringResource(Res.string.delete_title, current?.title.orEmpty()),
            onDismiss = { deleting = false },
            actions = {
                Button(stringResource(Res.string.cancel), onClick = { deleting = false }, icon = Res.drawable.icon_close)
                Button(stringResource(Res.string.delete), onClick = {
                    deleting = false
                    val version = current?.version ?: return@Button
                    scope.launch {
                        try {
                            app.call<Response.Deleted>(Request.Delete(id, version))
                            app.back()
                            app.changed()
                            app.toast(
                                message(Res.string.item_deleted),
                                action =
                                ToastAction(message(Res.string.undo)) {
                                    try {
                                        val restored = app.call<Response.Saved>(Request.Restore)
                                        app.changed()
                                        app.open(Page.Entry(restored.id))
                                        app.toast(message(Res.string.change_undone))
                                    } catch (failure: VaultException) {
                                        app.toast(message(Res.string.could_not_undo, failure.message), error = true)
                                    }
                                },
                            )
                        } catch (failure: VaultException) {
                            error = message(Res.string.could_not_delete, failure.message)
                        }
                    }
                }, variant = Variant.Danger, icon = Res.drawable.glyph_trash)
            },
        ) { Text(stringResource(Res.string.delete_body)) }
    }
}

@Composable
private fun EditBar(
    onCancel: () -> Unit,
    onSave: () -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Divider()
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(stringResource(Res.string.cancel), onClick = onCancel, modifier = Modifier.weight(1f), icon = Res.drawable.icon_close)
            Button(
                stringResource(Res.string.save),
                onClick = onSave,
                modifier = Modifier.weight(1f),
                variant = Variant.Primary,
                icon = Res.drawable.icon_check,
            )
        }
    }
}

@Composable
private fun Header(
    kind: Kind,
    title: @Composable (Modifier) -> Unit,
    subtitle: @Composable () -> Unit,
    actions: (@Composable RowScope.() -> Unit)?,
) {
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val wide = maxWidth >= 520.dp
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.CenterVertically) {
                IconTile(kind.icon(), size = 56.dp)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    title(Modifier.fillMaxWidth())
                    subtitle()
                }
                if (wide && actions != null) Row(horizontalArrangement = Arrangement.spacedBy(8.dp), content = actions)
            }
            if (!wide && actions != null) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End), content = actions)
            }
        }
    }
}

@Composable
private fun TitleInput(
    editor: Editor,
    modifier: Modifier,
) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        TextInput(
            state = editor.title,
            placeholder = stringResource(Res.string.name_placeholder),
            modifier = Modifier.outdent(12.dp),
            style = Type.title,
            plain = true,
            error = editor.titleProblem != null,
            keyboard = KeyboardOptions(capitalization = KeyboardCapitalization.Words, imeAction = ImeAction.Next),
        )
        FieldError(editor.titleProblem?.text())
    }
}

@Composable
private fun FieldLabel(
    icon: DrawableResource,
    label: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier.defaultMinSize(minHeight = 28.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, tint = Theme.colors.mutedForeground)
        Text(label, color = Theme.colors.mutedForeground, maxLines = 1)
    }
}

@Composable
private fun Group(
    heading: String?,
    content: @Composable () -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        if (heading != null) Text(heading, Modifier.padding(bottom = 4.dp), color = Theme.colors.mutedForeground, weight = Semibold)
        content()
    }
}

@Composable
private fun Fields(
    app: FactorSeal,
    item: Item,
    revealed: MutableMap<Pair<String, String>, String>,
) {
    val scope = rememberCoroutineScope()
    val kindLabel = stringResource(item.kind.label())
    val hidden = stringResource(Res.string.hidden)
    val groups = item.sections.filter { section -> section.fields.any { !it.empty() } }
    val hasTotp = item.sections.any { section -> section.fields.any { it.type == FieldType.Totp && it.filled } }
    var codes by remember(item) { mutableStateOf<List<Code>>(emptyList()) }
    var elapsed by remember(item) { mutableIntStateOf(0) }
    var copied by remember { mutableStateOf<Pair<String, String>?>(null) }
    LaunchedEffect(item, hasTotp) {
        if (!hasTotp) return@LaunchedEffect
        while (true) {
            codes = runCatching { app.call<Response.Codes>(Request.Codes(item.id), touches = false).codes }.getOrDefault(emptyList())
            val fetched = TimeSource.Monotonic.markNow()
            elapsed = 0
            val wait = codes.minOfOrNull { it.remaining } ?: return@LaunchedEffect
            while (elapsed < wait) {
                delay(1000 - fetched.elapsedNow().inWholeMilliseconds % 1000)
                elapsed = fetched.elapsedNow().inWholeSeconds.toInt()
            }
        }
    }
    LaunchedEffect(copied) {
        if (copied != null) {
            delay(2000)
            copied = null
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        groups.forEach { section ->
            val heading = section.label.takeIf { groups.size > 1 && !it.equals(kindLabel, ignoreCase = true) }
            Group(heading) {
                section.fields.filter { !it.empty() }.forEach { field ->
                    val key = section.id to field.id
                    val code = codes.firstOrNull { it.section == section.id && it.field == field.id }
                    val shown = revealed[key]
                    ViewRow(
                        icon = fieldIcon(field.id, field.type),
                        label = field.label,
                        copied = copied == key,
                        onCopy = {
                            scope.launch {
                                val text =
                                    when {
                                        code != null -> code.value
                                        !field.concealed -> field.value.text()
                                        else -> shown ?: runCatching { app.call<Response.Value>(Request.Reveal(item.id, section.id, field.id)).value }.getOrNull()
                                    }
                                if (text != null) {
                                    app.copy(text)
                                    copied = key
                                }
                            }
                        },
                        onOpen = field.link?.let { url -> { app.host.open(url) } },
                        revealed = shown != null,
                        onReveal =
                        if (field.concealed && code == null) {
                            {
                                if (shown != null) {
                                    revealed.remove(key)
                                } else {
                                    scope.launch {
                                        runCatching { app.call<Response.Value>(Request.Reveal(item.id, section.id, field.id)).value }
                                            .onSuccess { revealed[key] = it }
                                    }
                                }
                            }
                        } else {
                            null
                        },
                    ) {
                        when {
                            code != null -> LiveCode(code, elapsed)
                            field.concealed -> Text(shown ?: MASK, Modifier.semantics { if (shown == null) contentDescription = hidden }, style = if (shown == null) Type.body else Type.mono, maxLines = if (shown == null) 1 else Int.MAX_VALUE)
                            else -> Text(field.value.text())
                        }
                    }
                }
            }
        }
        if (item.notesFilled) {
            val key = "" to NOTES_ID
            val shown = revealed[key]
            suspend fun notes() = shown ?: runCatching { app.call<Response.Value>(Request.Reveal(item.id, NOTES_ID, NOTES_ID)).value }.getOrNull()
            Group(null) {
                ViewRow(
                    icon = Res.drawable.icon_file,
                    label = stringResource(Res.string.notes),
                    copied = copied == key,
                    onCopy = {
                        scope.launch {
                            notes()?.let { text ->
                                app.copy(text)
                                copied = key
                            }
                        }
                    },
                    onOpen = null,
                    revealed = shown != null,
                    onReveal = {
                        if (shown != null) {
                            revealed.remove(key)
                        } else {
                            scope.launch { notes()?.let { revealed[key] = it } }
                        }
                    },
                ) { Text(shown ?: MASK, Modifier.semantics { if (shown == null) contentDescription = hidden }) }
            }
        }
    }
}

@Composable
private fun LiveCode(
    code: Code,
    elapsed: Int,
) {
    val remaining = (code.remaining - elapsed).coerceAtLeast(0)
    val color = if (remaining <= 5) Theme.colors.danger else Theme.colors.mutedForeground
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(grouped(code.value), style = Type.code, maxLines = 1)
        Ring(remaining.toFloat() / code.period.coerceAtLeast(1), color)
        Text(remaining.toString(), color = Theme.colors.mutedForeground)
    }
}

@Composable
private fun ViewRow(
    icon: DrawableResource,
    label: String,
    copied: Boolean,
    onCopy: () -> Unit,
    onOpen: (() -> Unit)?,
    revealed: Boolean,
    onReveal: (() -> Unit)?,
    value: @Composable () -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(vertical = 6.dp)) {
            FieldLabel(icon, label)
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Box(
                    Modifier.weight(1f).defaultMinSize(minHeight = 42.dp).padding(start = 24.dp, end = 8.dp),
                    contentAlignment = Alignment.CenterStart,
                ) { value() }
                if (onOpen != null) IconButton(Res.drawable.icon_external_link, stringResource(Res.string.open), onClick = onOpen)
                if (onReveal != null) {
                    IconButton(
                        if (revealed) Res.drawable.icon_eye_off else Res.drawable.icon_eye,
                        stringResource(if (revealed) Res.string.hide else Res.string.reveal),
                        onClick = onReveal,
                    )
                }
                IconButton(
                    if (copied) Res.drawable.icon_check else Res.drawable.icon_copy,
                    stringResource(if (copied) Res.string.copied else Res.string.copy),
                    onClick = onCopy,
                )
            }
        }
        Divider()
    }
}

@Composable
private fun AddField(
    addable: List<Addable>,
    labels: Labels,
    onAdd: (Addable) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    val customLabel = stringResource(Res.string.custom_field)
    val typeLabels = CustomFieldTypes.associateWith { stringResource(it.label()) }
    val items =
        buildList {
            addable.forEach { candidate ->
                when (candidate) {
                    is Addable.Hidden -> add(MenuItem(candidate.row.label.text.toString().ifEmpty { customLabel }, { onAdd(candidate) }, fieldIcon(candidate.row.id, candidate.row.type)))
                    is Addable.Template -> add(MenuItem(candidate.field.label, { onAdd(candidate) }, fieldIcon(candidate.field.id, candidate.field.type)))
                    Addable.Website -> add(MenuItem(labels.website, { onAdd(candidate) }, Res.drawable.icon_globe))
                    is Addable.Custom -> Unit
                }
            }
            add(MenuItem(customLabel, {}, header = true))
            addable.filterIsInstance<Addable.Custom>().forEach { candidate ->
                add(MenuItem(typeLabels.getValue(candidate.type), { onAdd(candidate) }, fieldIcon("", candidate.type), indent = true))
            }
        }
    Box {
        Button(stringResource(Res.string.add_field), onClick = { open = true }, variant = Variant.Ghost, icon = Res.drawable.icon_plus)
        Menu(expanded = open, onDismiss = { open = false }, items = items, end = false)
    }
}

@Composable
private fun EditorBody(
    app: FactorSeal,
    editor: Editor,
    labels: Labels,
) {
    val kindLabel = stringResource(editor.kind.label())
    var generating by remember { mutableStateOf<EditorRow?>(null) }
    var scanning by remember { mutableStateOf<EditorRow?>(null) }
    val scope = rememberCoroutineScope()
    val visible = editor.sections.filter { section -> section.visible.isNotEmpty() }
    val grouped = visible.count { it.id != NOTES_ID } > 1
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        visible.forEach { section ->
            val heading = section.label.takeIf { grouped && section.id != NOTES_ID && !it.equals(kindLabel, ignoreCase = true) }
            Group(heading) {
                section.visible.forEach { row ->
                    key(row.key) {
                        EditRow(
                            app = app,
                            editor = editor,
                            row = row,
                            onGenerate = { generating = row },
                            onScan = { scanning = row },
                        )
                    }
                }
            }
        }
        AddField(editor.addable(), labels) { addable -> editor.add(addable, labels).focusing = true }
        editor.problem?.let { Banner(it.text()) }
    }
    generating?.let { row ->
        Generator(app, onDismiss = { generating = null }) { password ->
            row.value.setTextAndPlaceCursorAtEnd(password)
            generating = null
        }
    }
    scanning?.let { row ->
        val already = message(Res.string.already_has_otp)
        Scanner(app, onDismiss = { scanning = null }, accept = { it is Scan.OneTimePassword }) { scan ->
            scanning = null
            val found = scan as? Scan.OneTimePassword ?: return@Scanner
            scope.launch {
                suspend fun sameAs(key: String) = key.isNotEmpty() && runCatching { app.call<Response.SetupKey>(Request.SetupKey(found.value, key)).same }.getOrDefault(false)
                if (sameAs(row.value.text.toString())) {
                    row.notice = already
                    return@launch
                }
                row.replacing = row.original.isNotEmpty() && !sameAs(row.original)
                row.value.setTextAndPlaceCursorAtEnd(found.value)
                row.revealed = false
                if (editor.isNew) {
                    if (editor.title.text.isEmpty()) found.issuer?.let { editor.title.setTextAndPlaceCursorAtEnd(it) }
                    editor.rows.firstOrNull { it.id == USERNAME_ID && it.empty }?.let { username ->
                        found.account?.let { username.value.setTextAndPlaceCursorAtEnd(it) }
                    }
                }
            }
        }
    }
}

@Composable
private fun EditRow(
    app: FactorSeal,
    editor: Editor,
    row: EditorRow,
    onGenerate: () -> Unit,
    onScan: () -> Unit,
) {
    val colors = Theme.colors
    if (row.removed) {
        Column(Modifier.fillMaxWidth().entering(row.removed)) {
            Row(
                Modifier.fillMaxWidth().defaultMinSize(minHeight = 48.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    row.label.text.toString(),
                    Modifier.weight(1f).alpha(0.55f),
                    style = Type.body.copy(textDecoration = TextDecoration.LineThrough),
                    color = colors.mutedForeground,
                    maxLines = 1,
                )
                Button(stringResource(Res.string.restore), onClick = { row.removed = false }, variant = Variant.Ghost, icon = Res.drawable.icon_undo_2)
            }
            Divider()
        }
        return
    }
    val rated = generates(editor.kind, row)
    val strength = if (rated) rememberStrength(app, row.value) else null
    LaunchedEffect(row) {
        snapshotFlow { row.value.text.toString() }.collect {
            row.problem = null
            row.notice = null
        }
    }
    Column(Modifier.fillMaxWidth().entering(row.key)) {
        Column(Modifier.padding(vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            val labelColor = if (row.changed && !editor.isNew) colors.warning else colors.mutedForeground
            if (row.custom) {
                var picking by remember { mutableStateOf(false) }
                val focus = remember { FocusRequester() }
                LaunchedEffect(row.focusing) {
                    if (row.focusing) {
                        focus.requestFocus()
                        row.focusing = false
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(fieldIcon(row.id, row.type), tint = labelColor)
                    TextInput(
                        state = row.label,
                        placeholder = stringResource(Res.string.field_name),
                        modifier = Modifier.weight(1f).focusRequester(focus),
                        plain = true,
                        keyboard = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences, imeAction = ImeAction.Next),
                    )
                    Box {
                        IconButton(Res.drawable.icon_chevron_down, stringResource(Res.string.field_type), onClick = { picking = true }, size = ButtonSize.Small)
                        Menu(
                            expanded = picking,
                            onDismiss = { picking = false },
                            items =
                            CustomFieldTypes.map { type ->
                                MenuItem(stringResource(type.label()), { row.type = type }, fieldIcon("", type), checked = row.type == type)
                            },
                        )
                    }
                }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(fieldIcon(row.id, row.type), tint = labelColor)
                    Text(row.label.text.toString(), color = labelColor, maxLines = 1)
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.Top) {
                Box(Modifier.weight(1f)) { ValueInput(row) }
                if (row.concealed || row.type == FieldType.Totp) {
                    IconButton(
                        if (row.revealed) Res.drawable.icon_eye_off else Res.drawable.icon_eye,
                        stringResource(if (row.revealed) Res.string.hide else Res.string.reveal),
                        onClick = { row.revealed = !row.revealed },
                    )
                }
                when {
                    row.type == FieldType.Totp -> IconButton(Res.drawable.glyph_qr_code, stringResource(Res.string.scan_qr_code), onClick = onScan)
                    rated -> IconButton(Res.drawable.glyph_generate, stringResource(Res.string.generate_password), onClick = onGenerate)
                }
                IconButton(Res.drawable.glyph_trash, stringResource(Res.string.remove_field), onClick = { editor.remove(row) })
            }
            strength?.let { StrengthMeter(it, stringResource(it.label()), Modifier.widthIn(max = 240.dp)) }
            val problem = row.problem
            val notice = row.notice
            when {
                problem != null -> Caption(problem.text(), color = colors.danger)
                notice != null -> Caption(notice.text())
                row.replacing -> Caption(stringResource(Res.string.replaces_otp), color = colors.warning)
            }
        }
        Divider()
    }
}

@Composable
private fun ValueInput(row: EditorRow) {
    val placeholder = stringResource(if (row.type == FieldType.Totp) Res.string.setup_key_placeholder else Res.string.add_a_value)
    val prose = row.type in setOf(FieldType.Text, FieldType.Multiline) && row.id != USERNAME_ID
    val keyboard =
        KeyboardOptions(
            capitalization = if (prose) KeyboardCapitalization.Sentences else KeyboardCapitalization.None,
            autoCorrectEnabled = !row.concealed && prose,
            keyboardType =
            when {
                row.type == FieldType.Url -> KeyboardType.Uri
                row.type == FieldType.Email || row.id == USERNAME_ID -> KeyboardType.Email
                row.type == FieldType.Phone -> KeyboardType.Phone
                row.concealed -> KeyboardType.Password
                else -> KeyboardType.Text
            },
            imeAction = if (row.multiline) ImeAction.Default else ImeAction.Next,
        )
    val focus = remember { FocusRequester() }
    val hidden = stringResource(Res.string.hidden)
    val masked = row.concealed && row.multiline && !row.revealed
    LaunchedEffect(row.focusing, masked) {
        when {
            !row.focusing || row.custom -> Unit

            masked -> row.revealed = true

            else -> {
                focus.requestFocus()
                row.focusing = false
            }
        }
    }
    when {
        row.concealed && !row.multiline ->
            SecretInput(
                state = row.value,
                placeholder = placeholder,
                revealed = row.revealed,
                modifier = Modifier.focusRequester(focus),
                error = row.problem != null,
                imeAction = ImeAction.Next,
            )

        masked -> {
            val interaction = remember { MutableInteractionSource() }
            Box(
                Modifier
                    .fillMaxWidth()
                    .defaultMinSize(minHeight = FieldHeight)
                    .then(fieldFrame(interaction, row.problem != null))
                    .clickable(interaction, indication = null, role = Role.Button) { row.focusing = true }
                    .padding(horizontal = 12.dp, vertical = 11.dp),
            ) {
                Text(if (row.empty) placeholder else MASK, Modifier.semantics { if (!row.empty) contentDescription = hidden }, color = if (row.empty) Theme.colors.mutedForeground else Theme.colors.foreground)
            }
        }

        else ->
            TextInput(
                state = row.value,
                placeholder = placeholder,
                modifier = Modifier.focusRequester(focus),
                multiline = row.multiline,
                error = row.problem != null,
                style = if (row.structured || row.type == FieldType.SshKey) Type.mono else Type.body,
                keyboard = keyboard,
            )
    }
}

@Composable
fun NewItemPage(app: FactorSeal) {
    val editor = app.editors[Page.New]
    var leaving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val labels = labels()
    val saving = Saving(app, labels, message(Res.string.invalid_setup_key))
    LaunchedEffect(Unit) {
        if (Page.New in app.editors) return@LaunchedEffect
        runCatching { app.call<Response.Drafted>(Request.Template(Kind.Login)).item }.onSuccess { template ->
            app.editors[Page.New] = Editor.of(template, isNew = true).also { it.template = template }
        }
    }
    Salvage(app, editor, saving) { saved -> app.replace(Page.Entry(saved.id)) }
    fun leave() {
        if (app.editors[Page.New]?.dirty == true) leaving = true else app.back()
    }
    suspend fun create(current: Editor): Boolean {
        val saved = saving.save(current) ?: return false
        app.changed()
        app.replace(Page.Entry(saved.id))
        return true
    }
    Back { leave() }
    MainPage {
        BackRow(app, onBack = ::leave)
        val current = editor ?: return@MainPage
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Header(
                kind = current.kind,
                title = { modifier -> TitleInput(current, modifier) },
                subtitle = {
                    var picking by remember { mutableStateOf(false) }
                    Box {
                        Button(
                            stringResource(current.kind.label()),
                            onClick = { picking = true },
                            variant = Variant.Ghost,
                            modifier = Modifier.outdent(10.dp),
                            size = ButtonSize.Small,
                            description = stringResource(Res.string.item_type),
                            tint = Theme.colors.mutedForeground,
                            caret = true,
                        )
                        Menu(
                            expanded = picking,
                            onDismiss = { picking = false },
                            end = false,
                            items =
                            Kind.entries.map { kind ->
                                MenuItem(
                                    stringResource(kind.label()),
                                    {
                                        scope.launch {
                                            runCatching { app.call<Response.Drafted>(Request.Template(kind)).item }
                                                .onSuccess { current.switched(kind, it, labels) }
                                        }
                                    },
                                    kind.icon(),
                                    checked = kind == current.kind,
                                )
                            },
                        )
                    }
                },
                actions = null,
            )
            EditorBody(app, current, labels)
        }
        EditBar(onCancel = ::leave, onSave = { scope.launch { create(current) } })
    }
    if (leaving) {
        val current = editor
        UnsavedDialog(
            name = current?.title?.text?.toString()?.trim()?.ifEmpty { null },
            onDismiss = { leaving = false },
            onDiscard = app::back,
            onSave = { if (current != null) scope.launch { create(current) } },
        )
    }
}
