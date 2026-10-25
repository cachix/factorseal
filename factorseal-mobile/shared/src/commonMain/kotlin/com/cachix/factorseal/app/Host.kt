package com.cachix.factorseal.app

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.cachix.factorseal.core.Platform
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.Vault

const val MAX_TRANSFER_FILE_BYTES = 256 * 1024 * 1024

class PickedFile(
    val name: String,
    val bytes: ByteArray,
)

interface Files {
    suspend fun open(): PickedFile?

    suspend fun save(
        name: String,
        bytes: ByteArray,
    ): String?
}

interface Autofill {
    val enabled: Boolean

    fun enable()
}

interface Host {
    val platform: Platform
    val directory: String
    val biometric: Boolean
    val deviceName: String
    val autofill: Autofill?

    fun copy(text: String)

    fun clearClipboard(text: String): Boolean

    fun paste(): String?

    fun open(url: String)

    fun load(): String?

    fun save(text: String)

    @Composable
    fun rememberFiles(): Files

    @Composable
    fun Scanner(
        vault: Vault,
        onScan: (Scan) -> Unit,
        onUnavailable: () -> Unit,
        modifier: Modifier,
    )
}
