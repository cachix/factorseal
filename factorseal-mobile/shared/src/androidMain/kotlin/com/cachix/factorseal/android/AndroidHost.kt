package com.cachix.factorseal.android

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PersistableBundle
import android.provider.Settings
import android.view.autofill.AutofillManager
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.core.net.toUri
import com.cachix.factorseal.app.Autofill
import com.cachix.factorseal.app.Files
import com.cachix.factorseal.app.Host
import com.cachix.factorseal.core.Platform
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.Vault
import java.io.File

class AndroidHost(
    private val context: Context,
) : Host {
    private val clipboard = context.getSystemService(ClipboardManager::class.java)
    private val root = File(context.noBackupFilesDir, "factorseal")
    private val preferences = File(context.noBackupFilesDir, "preferences.json")

    override val platform = Platform.Android
    override val directory: String = root.absolutePath
    override val biometric: Boolean
        get() = Biometrics.available(context)
    override val deviceName: String
        get() =
            Settings.Global
                .getString(context.contentResolver, Settings.Global.DEVICE_NAME)
                ?.takeIf { it.isNotBlank() }
                ?: Build.MODEL
    override val autofill: Autofill? =
        context
            .getSystemService(AutofillManager::class.java)
            ?.takeIf { it.isAutofillSupported }
            ?.let { AndroidAutofill(context, it) }

    override fun copy(text: String) {
        val sensitive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
        val clip = ClipData.newPlainText(context.packageName, text)
        clip.description.extras = PersistableBundle().apply { putBoolean(sensitive, true) }
        clipboard.setPrimaryClip(clip)
    }

    override fun clearClipboard(text: String): Boolean {
        val current = runCatching { clipboard.primaryClip }.getOrNull() ?: return false
        if (current.getItemAt(0)?.text?.toString() == text) clipboard.clearPrimaryClip()
        return true
    }

    override fun paste(): String? = runCatching {
        clipboard.primaryClip
            ?.getItemAt(0)
            ?.coerceToText(context)
            ?.toString()
    }.getOrNull()

    override fun open(url: String) {
        runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, url.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    override fun load(): String? = runCatching { preferences.readText() }.getOrNull()

    override fun save(text: String) {
        runCatching {
            val next = File(preferences.parentFile, "${preferences.name}.next")
            next.writeText(text)
            if (!next.renameTo(preferences)) next.delete()
        }
    }

    @Composable
    override fun rememberFiles(): Files = rememberAndroidFiles(context)

    @Composable
    override fun Scanner(
        vault: Vault,
        onScan: (Scan) -> Unit,
        onUnavailable: () -> Unit,
        modifier: Modifier,
    ) = CameraScanner(onScan, onUnavailable, modifier)
}

private class AndroidAutofill(
    private val context: Context,
    private val manager: AutofillManager,
) : Autofill {
    override val enabled: Boolean
        get() = manager.hasEnabledAutofillServices()

    override fun enable() {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, "package:${context.packageName}".toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }
}
