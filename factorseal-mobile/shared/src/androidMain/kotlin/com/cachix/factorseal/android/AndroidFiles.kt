package com.cachix.factorseal.android

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import com.cachix.factorseal.app.Files
import com.cachix.factorseal.app.MAX_TRANSFER_FILE_BYTES
import com.cachix.factorseal.app.PickedFile
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream

private class Choice {
    var pending: CompletableDeferred<Uri?>? = null

    fun finish(uri: Uri?) {
        pending?.complete(uri)
        pending = null
    }

    suspend fun await(launch: () -> Unit): Uri? {
        pending?.complete(null)
        val next = CompletableDeferred<Uri?>()
        pending = next
        launch()
        return next.await()
    }
}

@Composable
internal fun rememberAndroidFiles(context: Context): Files {
    val choice = remember { Choice() }
    val open = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument(), choice::finish)
    val create = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream"), choice::finish)
    return remember(open, create) {
        object : Files {
            override suspend fun open(): PickedFile? {
                val uri = choice.await { open.launch(arrayOf("*/*")) } ?: return null
                return withContext(Dispatchers.IO) {
                    val bytes = requireNotNull(context.contentResolver.openInputStream(uri)).use { it.readAtMost(MAX_TRANSFER_FILE_BYTES) }
                    PickedFile(context.displayName(uri), bytes)
                }
            }

            override suspend fun save(
                name: String,
                bytes: ByteArray,
            ): String? {
                val uri = choice.await { create.launch(name) } ?: return null
                return withContext(Dispatchers.IO) {
                    requireNotNull(context.contentResolver.openOutputStream(uri, "wt")).use { it.write(bytes) }
                    context.displayName(uri)
                }
            }
        }
    }
}

private fun InputStream.readAtMost(limit: Int): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (true) {
        val read = read(buffer)
        if (read < 0) return output.toByteArray()
        check(output.size() <= limit - read) { "input exceeds its size limit" }
        output.write(buffer, 0, read)
    }
}

private fun Context.displayName(uri: Uri): String = contentResolver
    .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
    ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
    ?: uri.lastPathSegment.orEmpty()
