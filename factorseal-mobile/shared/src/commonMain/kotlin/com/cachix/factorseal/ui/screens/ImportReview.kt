package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.ImportSession
import com.cachix.factorseal.core.ImportChange
import com.cachix.factorseal.core.ImportChoice
import com.cachix.factorseal.core.ImportComparison
import com.cachix.factorseal.core.ImportValue
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.RetainedData
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.done
import com.cachix.factorseal.resources.glyph_upload
import com.cachix.factorseal.resources.hidden
import com.cachix.factorseal.resources.import_action
import com.cachix.factorseal.resources.import_another
import com.cachix.factorseal.resources.import_changed_archived
import com.cachix.factorseal.resources.import_changed_favorite
import com.cachix.factorseal.resources.import_changed_folder
import com.cachix.factorseal.resources.import_changed_kind
import com.cachix.factorseal.resources.import_changed_notes
import com.cachix.factorseal.resources.import_changed_other
import com.cachix.factorseal.resources.import_changed_source
import com.cachix.factorseal.resources.import_changed_tags
import com.cachix.factorseal.resources.import_changed_title
import com.cachix.factorseal.resources.import_complete
import com.cachix.factorseal.resources.import_counts
import com.cachix.factorseal.resources.import_current
import com.cachix.factorseal.resources.import_deselect_all
import com.cachix.factorseal.resources.import_empty
import com.cachix.factorseal.resources.import_empty_value
import com.cachix.factorseal.resources.import_existing
import com.cachix.factorseal.resources.import_field_types
import com.cachix.factorseal.resources.import_hide_details
import com.cachix.factorseal.resources.import_hide_value
import com.cachix.factorseal.resources.import_incoming
import com.cachix.factorseal.resources.import_keep_all
import com.cachix.factorseal.resources.import_keep_source
import com.cachix.factorseal.resources.import_new
import com.cachix.factorseal.resources.import_no_matches
import com.cachix.factorseal.resources.import_other_data
import com.cachix.factorseal.resources.import_passkeys
import com.cachix.factorseal.resources.import_password_history
import com.cachix.factorseal.resources.import_replace
import com.cachix.factorseal.resources.import_replace_all
import com.cachix.factorseal.resources.import_replace_guide
import com.cachix.factorseal.resources.import_reprompt
import com.cachix.factorseal.resources.import_result_counts
import com.cachix.factorseal.resources.import_retained_guide
import com.cachix.factorseal.resources.import_retained_result
import com.cachix.factorseal.resources.import_review_guide
import com.cachix.factorseal.resources.import_saved_data
import com.cachix.factorseal.resources.import_saving
import com.cachix.factorseal.resources.import_search
import com.cachix.factorseal.resources.import_select_all
import com.cachix.factorseal.resources.import_select_one
import com.cachix.factorseal.resources.import_selected
import com.cachix.factorseal.resources.import_show_value
import com.cachix.factorseal.resources.import_unchanged
import com.cachix.factorseal.resources.import_view_details
import com.cachix.factorseal.resources.import_website_matching
import com.cachix.factorseal.resources.restore_complete
import com.cachix.factorseal.resources.restore_saving
import com.cachix.factorseal.resources.restore_selected
import com.cachix.factorseal.resources.review_import
import com.cachix.factorseal.resources.review_restore
import com.cachix.factorseal.ui.components.Back
import com.cachix.factorseal.ui.components.Banner
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.ButtonSize
import com.cachix.factorseal.ui.components.Checkbox
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.PageHeader
import com.cachix.factorseal.ui.components.Spinner
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.TextInput
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.pluralStringResource
import org.jetbrains.compose.resources.stringResource

@Composable
private fun RetainedData.label(): String = stringResource(
    when (this) {
        RetainedData.Passkeys -> Res.string.import_passkeys
        RetainedData.PasswordHistory -> Res.string.import_password_history
        RetainedData.WebsiteMatching -> Res.string.import_website_matching
        RetainedData.PasswordReprompt -> Res.string.import_reprompt
        RetainedData.FieldTypes -> Res.string.import_field_types
        RetainedData.Other -> Res.string.import_other_data
    },
)

@Composable
private fun ImportChange.label(): String = if (type == "field") {
    field.orEmpty()
} else {
    stringResource(
        when (type) {
            "title" -> Res.string.import_changed_title
            "kind" -> Res.string.import_changed_kind
            "notes" -> Res.string.import_changed_notes
            "folder" -> Res.string.import_changed_folder
            "tags" -> Res.string.import_changed_tags
            "favorite" -> Res.string.import_changed_favorite
            "archived" -> Res.string.import_changed_archived
            "source" -> Res.string.import_changed_source
            else -> Res.string.import_changed_other
        },
    )
}

@Composable
fun SavedImportData(retained: List<RetainedData>, guide: Boolean = false) {
    if (retained.isEmpty()) return
    val names = retained.map { it.label() }.joinToString(", ")
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(Res.string.import_saved_data), weight = Semibold)
        Text(if (guide) stringResource(Res.string.import_retained_guide, names) else names, color = Theme.colors.mutedForeground)
    }
}

@Composable
fun ImportReviewPage(
    app: FactorSeal,
    session: ImportSession,
    backup: Boolean,
    busy: Boolean,
    onCancel: () -> Unit,
    onCommit: (List<ImportChoice>) -> Unit,
) {
    val largeText = LocalDensity.current.fontScale > 1.3f
    val review = session.review
    val choices = session.choices
    val expanded = remember(review.review) { mutableStateListOf<Int>() }
    val search = session.search
    val query = search.text.toString().trim()
    val visible = remember(review.review, query) {
        review.items.indices.filter { index ->
            val item = review.items[index]
            listOfNotNull(item.title, item.username, item.website).any { it.contains(query, ignoreCase = true) }
        }
    }
    val added = choices.count { it == ImportChoice.Add }
    val replaced = choices.count { it == ImportChoice.Replace }
    val skipped = choices.size - added - replaced
    Back { if (!busy) onCancel() }
    MainPage {
        BackRow(app, onBack = { if (!busy) onCancel() })
        LazyColumn(Modifier.weight(1f).fillMaxWidth(), contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)) {
            item {
                Column(Modifier.padding(bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(if (backup) Res.string.review_restore else Res.string.review_import), style = Type.title)
                    Text(stringResource(Res.string.import_review_guide), style = Type.caption, color = Theme.colors.mutedForeground)
                    if (review.items.isNotEmpty()) TextInput(search, placeholder = stringResource(Res.string.import_search), keyboard = KeyboardOptions.Default, modifier = Modifier.fillMaxWidth())
                }
            }
            if (visible.isEmpty()) item { Text(stringResource(if (review.items.isEmpty()) Res.string.import_empty else Res.string.import_no_matches)) }
            listOf(false, true).forEach { existing ->
                val indices = visible.filter { review.items[it].existing == existing }
                val selectable = indices.filter { !existing || review.items[it].changes.isNotEmpty() }
                if (indices.isNotEmpty()) {
                    item {
                        Column(Modifier.padding(top = 8.dp, bottom = 4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(stringResource(if (existing) Res.string.import_existing else Res.string.import_new), Modifier.align(Alignment.CenterVertically), weight = Semibold)
                                val selected = selectable.all { choices[it] != ImportChoice.Skip }
                                if (selectable.isNotEmpty()) {
                                    Button(
                                        stringResource(
                                            when {
                                                existing && selected -> Res.string.import_keep_all
                                                existing -> Res.string.import_replace_all
                                                selected -> Res.string.import_deselect_all
                                                else -> Res.string.import_select_all
                                            },
                                        ),
                                        onClick = {
                                            selectable.forEach {
                                                choices[it] = if (selected) {
                                                    ImportChoice.Skip
                                                } else if (existing) {
                                                    ImportChoice.Replace
                                                } else {
                                                    ImportChoice.Add
                                                }
                                            }
                                        },
                                        enabled = !busy,
                                        variant = Variant.Ghost,
                                        size = ButtonSize.Large,
                                    )
                                }
                            }
                            if (existing) Text(stringResource(Res.string.import_replace_guide), style = Type.caption, color = Theme.colors.mutedForeground)
                            Divider()
                        }
                    }
                    items(indices, key = { it }) { index ->
                        val item = review.items[index]
                        Column(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (existing && item.changes.isEmpty()) {
                                    Text(item.title, Modifier.weight(1f).padding(start = 30.dp, top = 12.dp, bottom = 12.dp), weight = Semibold)
                                } else {
                                    Checkbox(
                                        choices[index] != ImportChoice.Skip,
                                        { checked ->
                                            choices[index] = if (!checked) {
                                                ImportChoice.Skip
                                            } else if (existing) {
                                                ImportChoice.Replace
                                            } else {
                                                ImportChoice.Add
                                            }
                                        },
                                        item.title,
                                        modifier = Modifier.weight(1f).semantics { contentDescription = item.title },
                                        enabled = !busy,
                                    )
                                }
                                if (!largeText && (!existing || item.changes.isNotEmpty())) Text(stringResource(if (existing) Res.string.import_replace else Res.string.import_action), style = Type.caption, color = Theme.colors.mutedForeground)
                            }
                            Column(Modifier.fillMaxWidth().padding(start = 30.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                if (largeText && (!existing || item.changes.isNotEmpty())) Text(stringResource(if (existing) Res.string.import_replace else Res.string.import_action), style = Type.caption, color = Theme.colors.mutedForeground)
                                val metadata = listOfNotNull(item.username?.takeIf { it.isNotBlank() }, item.website?.takeIf { it.isNotBlank() }, item.kind).distinct()
                                Text(metadata.joinToString(" · "), style = Type.caption, color = Theme.colors.mutedForeground, maxLines = 2)
                                if (item.retained.isNotEmpty()) {
                                    Text(stringResource(Res.string.import_retained_guide, item.retained.map { it.label() }.joinToString(", ")), style = Type.caption, color = Theme.colors.mutedForeground)
                                }
                                if (existing && item.changes.isEmpty()) Text(stringResource(Res.string.import_unchanged), style = Type.caption, color = Theme.colors.mutedForeground)
                                if (item.changes.isNotEmpty()) {
                                    val open = index in expanded
                                    Button(stringResource(if (open) Res.string.import_hide_details else Res.string.import_view_details), { if (open) expanded.remove(index) else expanded.add(index) }, modifier = Modifier.align(Alignment.Start), variant = Variant.Ghost, size = ButtonSize.Large)
                                    if (open) {
                                        ImportItemDetails(app, review.review, index, busy)
                                    }
                                }
                            }
                            Divider()
                        }
                    }
                }
            }
            item { Text(stringResource(Res.string.import_keep_source), Modifier.padding(vertical = 12.dp), style = Type.caption, color = Theme.colors.mutedForeground) }
        }
        Divider()
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(Res.string.import_counts, added, replaced, skipped), style = Type.caption)
            if (added + replaced == 0 && review.items.isNotEmpty()) Text(stringResource(Res.string.import_select_one), style = Type.caption, color = Theme.colors.mutedForeground)
            Button(
                if (busy) stringResource(if (backup) Res.string.restore_saving else Res.string.import_saving) else pluralStringResource(if (backup) Res.plurals.restore_selected else Res.plurals.import_selected, added + replaced, added + replaced),
                onClick = { onCommit(choices.toList()) },
                modifier = Modifier.fillMaxWidth(),
                variant = Variant.Primary,
                loading = busy,
                size = ButtonSize.Large,
                enabled = added + replaced > 0 && !busy,
            )
        }
    }
}

@Composable
private fun ImportItemDetails(app: FactorSeal, review: Long, index: Int, busy: Boolean) {
    var revealed by remember(review, index) { mutableStateOf(emptyList<Int>()) }
    var details by remember(review, index) { mutableStateOf<List<ImportComparison>?>(null) }
    var error by remember(review, index) { mutableStateOf<String?>(null) }
    var loading by remember(review, index) { mutableStateOf(true) }
    LaunchedEffect(review, index, revealed) {
        loading = true
        error = null
        try {
            details = app.call<Response.ImportDetails>(Request.ImportDetails(review, index, revealed)).comparisons
        } catch (failure: VaultException) {
            error = failure.message
        } finally {
            loading = false
        }
    }
    Column(Modifier.fillMaxWidth().background(Theme.colors.background, Shapes.tile).padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (details == null && loading) Spinner()
        error?.let { Banner(it) }
        details?.forEachIndexed { position, comparison ->
            if (position > 0) Divider()
            Text(listOfNotNull(comparison.section, comparison.change.label()).joinToString(" · "), weight = Semibold)
            ImportComparedValue(stringResource(Res.string.import_current), comparison.current)
            ImportComparedValue(stringResource(Res.string.import_incoming), comparison.incoming)
            if ((comparison.current.concealed || comparison.incoming.concealed) && (comparison.current.filled || comparison.incoming.filled)) {
                val visible = position in revealed
                Button(
                    stringResource(if (visible) Res.string.import_hide_value else Res.string.import_show_value),
                    onClick = {
                        details = details?.map { row -> row.copy(current = if (row.current.concealed) row.current.copy(value = null) else row.current, incoming = if (row.incoming.concealed) row.incoming.copy(value = null) else row.incoming) }
                        revealed = if (visible) revealed - position else revealed + position
                    },
                    modifier = Modifier.align(Alignment.Start),
                    variant = Variant.Ghost,
                    size = ButtonSize.Large,
                    enabled = !busy,
                    loading = loading,
                )
            }
        }
    }
}

@Composable
private fun ImportComparedValue(label: String, value: ImportValue) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = Type.caption, color = Theme.colors.mutedForeground)
        value.context?.let { Text(it, style = Type.caption, color = Theme.colors.mutedForeground) }
        Text(value.value ?: stringResource(if (value.filled) Res.string.hidden else Res.string.import_empty_value))
    }
}

@Composable
fun ImportCompletePage(app: FactorSeal, result: Response.Imported, backup: Boolean, onAnother: () -> Unit) {
    MainPage {
        BackRow(app)
        Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            PageHeader(Res.drawable.glyph_upload, stringResource(if (backup) Res.string.restore_complete else Res.string.import_complete))
            Text(stringResource(Res.string.import_result_counts, result.added, result.replaced, result.skipped + result.kept))
            if (result.preserved > 0) Text(stringResource(Res.string.import_retained_result), color = Theme.colors.mutedForeground)
            Text(stringResource(Res.string.import_keep_source), color = Theme.colors.mutedForeground)
        }
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(stringResource(Res.string.done), { app.back() }, Modifier.fillMaxWidth(), variant = Variant.Primary)
            Button(stringResource(Res.string.import_another), onAnother, Modifier.fillMaxWidth())
        }
    }
}
