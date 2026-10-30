package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Message
import com.cachix.factorseal.app.Page
import com.cachix.factorseal.app.PickedFile
import com.cachix.factorseal.app.message
import com.cachix.factorseal.app.text
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Format
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.TransferKey
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.back_up_vault
import com.cachix.factorseal.resources.backup_explanation
import com.cachix.factorseal.resources.backup_failed
import com.cachix.factorseal.resources.backup_lead
import com.cachix.factorseal.resources.backup_passphrase
import com.cachix.factorseal.resources.backup_saved
import com.cachix.factorseal.resources.cancel
import com.cachix.factorseal.resources.choose_file_and_review
import com.cachix.factorseal.resources.choose_private_identity
import com.cachix.factorseal.resources.choose_private_key
import com.cachix.factorseal.resources.choose_public_key
import com.cachix.factorseal.resources.choose_public_recipient
import com.cachix.factorseal.resources.confirm_passphrase
import com.cachix.factorseal.resources.confirm_plaintext
import com.cachix.factorseal.resources.create_backup
import com.cachix.factorseal.resources.cxf_explanation
import com.cachix.factorseal.resources.encrypted_backup
import com.cachix.factorseal.resources.encrypted_credential_file
import com.cachix.factorseal.resources.encrypted_transfer
import com.cachix.factorseal.resources.enter_backup_passphrase
import com.cachix.factorseal.resources.enter_transfer_passphrase
import com.cachix.factorseal.resources.export_credentials
import com.cachix.factorseal.resources.export_explanation
import com.cachix.factorseal.resources.export_failed
import com.cachix.factorseal.resources.export_lead
import com.cachix.factorseal.resources.file_type
import com.cachix.factorseal.resources.format_1password_1pux
import com.cachix.factorseal.resources.format_1password_csv
import com.cachix.factorseal.resources.format_bitwarden_json
import com.cachix.factorseal.resources.format_keepass_csv
import com.cachix.factorseal.resources.glyph_download
import com.cachix.factorseal.resources.glyph_upload
import com.cachix.factorseal.resources.hide_password
import com.cachix.factorseal.resources.icon_folder_open
import com.cachix.factorseal.resources.import_credentials
import com.cachix.factorseal.resources.import_explanation
import com.cachix.factorseal.resources.import_failed
import com.cachix.factorseal.resources.import_in_progress
import com.cachix.factorseal.resources.import_lead
import com.cachix.factorseal.resources.imported_summary
import com.cachix.factorseal.resources.ok
import com.cachix.factorseal.resources.passphrase
import com.cachix.factorseal.resources.passphrases_differ
import com.cachix.factorseal.resources.placeholder_archive_passphrase
import com.cachix.factorseal.resources.placeholder_confirm_archive_passphrase
import com.cachix.factorseal.resources.post_quantum_key
import com.cachix.factorseal.resources.preparing_backup
import com.cachix.factorseal.resources.preparing_export
import com.cachix.factorseal.resources.preserved_summary
import com.cachix.factorseal.resources.private_key_explanation
import com.cachix.factorseal.resources.public_key_explanation
import com.cachix.factorseal.resources.replace_existing
import com.cachix.factorseal.resources.restore_backup
import com.cachix.factorseal.resources.restore_explanation
import com.cachix.factorseal.resources.restore_failed
import com.cachix.factorseal.resources.restore_in_progress
import com.cachix.factorseal.resources.restore_lead
import com.cachix.factorseal.resources.restored_summary
import com.cachix.factorseal.resources.review_import
import com.cachix.factorseal.resources.review_import_keep
import com.cachix.factorseal.resources.review_import_replace
import com.cachix.factorseal.resources.review_restore
import com.cachix.factorseal.resources.review_restore_keep
import com.cachix.factorseal.resources.review_restore_replace
import com.cachix.factorseal.resources.save_backup
import com.cachix.factorseal.resources.save_transfer_file
import com.cachix.factorseal.resources.show_password
import com.cachix.factorseal.resources.transfer_credentials
import com.cachix.factorseal.resources.transfer_passphrase
import com.cachix.factorseal.resources.transfer_saved
import com.cachix.factorseal.resources.understand_plaintext
import com.cachix.factorseal.ui.components.Banner
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.Checkbox
import com.cachix.factorseal.ui.components.Dialog
import com.cachix.factorseal.ui.components.IconTile
import com.cachix.factorseal.ui.components.Labeled
import com.cachix.factorseal.ui.components.ListHeader
import com.cachix.factorseal.ui.components.ListRow
import com.cachix.factorseal.ui.components.PageHeader
import com.cachix.factorseal.ui.components.PasswordField
import com.cachix.factorseal.ui.components.RowText
import com.cachix.factorseal.ui.components.Segmented
import com.cachix.factorseal.ui.components.Spinner
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource
import kotlin.io.encoding.Base64

private val Format.encrypted: Boolean get() = this == Format.FactorSeal || this == Format.CxfAge

private fun Format.label(): StringResource = when (this) {
    Format.FactorSeal, Format.CxfAge -> Res.string.encrypted_transfer
    Format.BitwardenJson -> Res.string.format_bitwarden_json
    Format.OnePasswordCsv -> Res.string.format_1password_csv
    Format.OnePasswordPux -> Res.string.format_1password_1pux
    Format.KeePassCsv -> Res.string.format_keepass_csv
}

private fun title(
    backup: Boolean,
    import: Boolean,
): StringResource = when {
    backup && import -> Res.string.restore_backup
    backup -> Res.string.create_backup
    import -> Res.string.import_credentials
    else -> Res.string.export_credentials
}

private fun icon(import: Boolean): DrawableResource = if (import) Res.drawable.glyph_upload else Res.drawable.glyph_download

private class Notice(
    val text: Message,
    val success: Boolean,
    val detail: Message? = null,
)

@Composable
fun TransferPage(
    app: FactorSeal,
    backup: Boolean,
) {
    MainPage {
        BackRow(app)
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
            ListHeader(stringResource(if (backup) Res.string.back_up_vault else Res.string.transfer_credentials))
            listOf(false, true).forEach { import ->
                ListRow(onClick = { app.open(Page.TransferForm(backup, import)) }, chevron = true) {
                    IconTile(icon(import))
                    RowText(stringResource(title(backup, import)), null)
                }
            }
        }
    }
}

@Composable
fun TransferFormPage(
    app: FactorSeal,
    backup: Boolean,
    import: Boolean,
) {
    val files = app.host.rememberFiles()
    val scope = rememberCoroutineScope()
    val colors = Theme.colors
    var format by remember { mutableStateOf(if (backup) Format.FactorSeal else Format.CxfAge) }
    var hybrid by remember { mutableStateOf(false) }
    var keyFile by remember { mutableStateOf<PickedFile?>(null) }
    val passphrase = remember { TextFieldState() }
    val confirmation = remember { TextFieldState() }
    var revealed by remember { mutableStateOf(false) }
    var plaintext by remember { mutableStateOf(false) }
    var replace by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<Notice?>(null) }
    var review by remember { mutableStateOf<Response.ImportReview?>(null) }
    val useKey = format == Format.CxfAge && hybrid
    val failed =
        when {
            backup && import -> Res.string.restore_failed
            backup -> Res.string.backup_failed
            import -> Res.string.import_failed
            else -> Res.string.export_failed
        }

    fun failure(error: Throwable): Notice = Notice(
        if (error is VaultException && error.code == ErrorCode.WeakPassword) {
            Message.Raw(error.message)
        } else {
            message(failed, error.message ?: error.toString())
        },
        success = false,
    )

    fun reset() {
        notice = null
        passphrase.clearText()
        confirmation.clearText()
    }

    fun start() {
        if (busy) return
        val needsPassphrase = format.encrypted && !useKey
        val text = passphrase.text.toString()
        val problem =
            when {
                useKey && keyFile == null -> if (import) Res.string.choose_private_identity else Res.string.choose_public_recipient
                needsPassphrase && text.isEmpty() -> if (backup) Res.string.enter_backup_passphrase else Res.string.enter_transfer_passphrase
                !import && needsPassphrase && text != confirmation.text.toString() -> Res.string.passphrases_differ
                !import && !format.encrypted && !plaintext -> Res.string.confirm_plaintext
                else -> null
            }
        if (problem != null) {
            notice = Notice(message(problem), success = false)
            return
        }
        val key =
            when {
                useKey -> TransferKey(keyFile = keyFile?.bytes?.decodeToString())
                needsPassphrase -> TransferKey(passphrase = text)
                else -> null
            }
        passphrase.clearText()
        confirmation.clearText()
        busy = true
        notice = null
        scope.launch {
            try {
                if (import) {
                    val picked = files.open()
                    if (picked != null) {
                        try {
                            review = app.call<Response.ImportReview>(Request.Import(format, Base64.encode(picked.bytes), key))
                        } finally {
                            picked.bytes.fill(0)
                        }
                    }
                } else {
                    val file = app.call<Response.File>(Request.Export(format, key))
                    val bytes = Base64.decode(file.data)
                    val saved =
                        try {
                            files.save(file.name, bytes)
                        } finally {
                            bytes.fill(0)
                        }
                    if (saved != null) notice = Notice(message(if (backup) Res.string.backup_saved else Res.string.transfer_saved, saved), success = true)
                }
            } catch (error: Exception) {
                notice = failure(error)
            }
            if (review == null) busy = false
        }
    }

    fun finish(confirmed: Boolean) {
        review = null
        scope.launch {
            try {
                if (confirmed) {
                    val summary = app.call<Response.Imported>(Request.ImportCommit(replace))
                    app.refresh()
                    notice =
                        Notice(
                            message(
                                if (backup) Res.string.restored_summary else Res.string.imported_summary,
                                summary.added + summary.replaced + summary.kept,
                                summary.added,
                                summary.replaced,
                                summary.kept,
                            ),
                            success = true,
                            detail = summary.preserved.takeIf { it > 0 }?.let { message(Res.string.preserved_summary, it) },
                        )
                } else {
                    app.call<Response.Status>(Request.ImportCancel)
                }
            } catch (error: Exception) {
                notice = failure(error)
            }
            busy = false
        }
    }

    MainPage {
        BackRow(app)
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            PageHeader(icon(import), stringResource(title(backup, import)))
            Text(
                stringResource(
                    when {
                        backup && import -> Res.string.restore_lead
                        backup -> Res.string.backup_lead
                        import -> Res.string.import_lead
                        else -> Res.string.export_lead
                    },
                ),
                color = colors.mutedForeground,
            )
            if (!backup) {
                Labeled(stringResource(Res.string.file_type)) {
                    Segmented(
                        options = Format.entries.filter { it != Format.FactorSeal && (import || it != Format.OnePasswordPux) },
                        selected = format,
                        label = { stringResource(it.label()) },
                        onSelect = {
                            format = it
                            hybrid = false
                            keyFile = null
                            plaintext = false
                            reset()
                        },
                        enabled = !busy,
                    )
                }
            }
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(colors.background, Shapes.tile)
                    .border(1.dp, colors.border, Shapes.tile)
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    stringResource(
                        when {
                            !format.encrypted -> format.label()
                            backup -> Res.string.encrypted_backup
                            else -> Res.string.encrypted_credential_file
                        },
                    ),
                    weight = Semibold,
                )
                Text(
                    stringResource(
                        when {
                            format == Format.CxfAge -> Res.string.cxf_explanation
                            format.encrypted && import -> Res.string.restore_explanation
                            format.encrypted -> Res.string.backup_explanation
                            import -> Res.string.import_explanation
                            else -> Res.string.export_explanation
                        },
                    ),
                    color = colors.mutedForeground,
                )
                if (format == Format.CxfAge) {
                    Segmented(
                        options = listOf(false, true),
                        selected = hybrid,
                        label = { stringResource(if (it) Res.string.post_quantum_key else Res.string.passphrase) },
                        onSelect = {
                            hybrid = it
                            keyFile = null
                            reset()
                        },
                        enabled = !busy,
                    )
                    if (hybrid) {
                        Text(stringResource(if (import) Res.string.private_key_explanation else Res.string.public_key_explanation))
                        Button(
                            stringResource(if (import) Res.string.choose_private_key else Res.string.choose_public_key),
                            onClick = {
                                scope.launch {
                                    try {
                                        files.open()?.let {
                                            keyFile = it
                                            notice = null
                                        }
                                    } catch (error: Exception) {
                                        notice = failure(error)
                                    }
                                }
                            },
                            icon = Res.drawable.icon_folder_open,
                            enabled = !busy,
                        )
                        keyFile?.let { Text(it.name) }
                    }
                }
                if (format.encrypted && !useKey) {
                    Labeled(stringResource(if (backup) Res.string.backup_passphrase else Res.string.transfer_passphrase)) {
                        PasswordField(
                            state = passphrase,
                            placeholder = stringResource(Res.string.placeholder_archive_passphrase),
                            revealed = revealed,
                            show = stringResource(Res.string.show_password),
                            hide = stringResource(Res.string.hide_password),
                            onReveal = { revealed = !revealed },
                            imeAction = if (import) ImeAction.Done else ImeAction.Next,
                            onSubmit = if (import) ::start else null,
                        )
                    }
                    if (!import) {
                        Labeled(stringResource(Res.string.confirm_passphrase)) {
                            PasswordField(
                                state = confirmation,
                                placeholder = stringResource(Res.string.placeholder_confirm_archive_passphrase),
                                revealed = revealed,
                                show = stringResource(Res.string.show_password),
                                hide = stringResource(Res.string.hide_password),
                                onReveal = { revealed = !revealed },
                                onSubmit = ::start,
                            )
                        }
                    }
                }
                if (!import && !format.encrypted) {
                    Checkbox(
                        checked = plaintext,
                        onChange = {
                            plaintext = it
                            notice = null
                        },
                        label = stringResource(Res.string.understand_plaintext),
                        enabled = !busy,
                    )
                }
            }
            if (import) {
                Checkbox(
                    checked = replace,
                    onChange = {
                        replace = it
                        notice = null
                    },
                    label = stringResource(Res.string.replace_existing),
                    enabled = !busy,
                )
            }
            notice?.let { current ->
                val text = listOfNotNull(current.text, current.detail).map { it.text() }.joinToString(" ")
                if (current.success) {
                    Text(
                        text,
                        Modifier
                            .fillMaxWidth()
                            .background(colors.secondary, Shapes.tile)
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                    )
                } else {
                    Banner(text)
                }
            }
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.End),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (busy) {
                    Spinner(size = 16.dp, color = colors.mutedForeground)
                    Text(
                        stringResource(
                            when {
                                import && backup -> Res.string.restore_in_progress
                                import -> Res.string.import_in_progress
                                backup -> Res.string.preparing_backup
                                else -> Res.string.preparing_export
                            },
                        ),
                        Modifier.weight(1f, fill = false),
                        color = colors.mutedForeground,
                    )
                }
                Button(
                    stringResource(
                        when {
                            import -> Res.string.choose_file_and_review
                            backup -> Res.string.save_backup
                            else -> Res.string.save_transfer_file
                        },
                    ),
                    onClick = ::start,
                    variant = Variant.Primary,
                    icon = icon(import),
                    loading = busy,
                    enabled = !busy,
                )
            }
        }
    }
    review?.let { pending ->
        Dialog(
            title = stringResource(if (backup) Res.string.review_restore else Res.string.review_import),
            onDismiss = { finish(false) },
            actions = {
                Button(stringResource(Res.string.cancel), onClick = { finish(false) })
                Button(stringResource(Res.string.ok), onClick = { finish(true) }, variant = Variant.Primary)
            },
        ) {
            Text(
                stringResource(
                    when {
                        backup && replace -> Res.string.review_restore_replace
                        backup -> Res.string.review_restore_keep
                        replace -> Res.string.review_import_replace
                        else -> Res.string.review_import_keep
                    },
                    pending.items,
                    pending.preserved,
                ),
            )
        }
    }
}
