package com.cachix.factorseal.ios

import com.cachix.factorseal.app.Files
import com.cachix.factorseal.app.MAX_TRANSFER_FILE_BYTES
import com.cachix.factorseal.app.PickedFile
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSData
import platform.Foundation.NSDataReadingMappedIfSafe
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSURL
import platform.Foundation.NSUUID
import platform.Foundation.create
import platform.Foundation.dataWithContentsOfURL
import platform.Foundation.writeToURL
import platform.UIKit.UIDocumentPickerDelegateProtocol
import platform.UIKit.UIDocumentPickerViewController
import platform.UIKit.UIViewController
import platform.UniformTypeIdentifiers.UTTypeItem
import platform.darwin.NSObject
import platform.posix.memcpy
import kotlin.coroutines.resume

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
internal class IosFiles(
    private val presenter: () -> UIViewController?,
) : Files {
    private var delegate: Picked? = null

    override suspend fun open(): PickedFile? {
        val url = pick(UIDocumentPickerViewController(forOpeningContentTypes = listOf(UTTypeItem), asCopy = true)) ?: return null
        val data = NSData.dataWithContentsOfURL(url, NSDataReadingMappedIfSafe, null) ?: return null
        check(data.length <= MAX_TRANSFER_FILE_BYTES.toULong()) { "input exceeds its size limit" }
        return PickedFile(url.lastPathComponent.orEmpty(), data.toByteArray())
    }

    override suspend fun save(
        name: String,
        bytes: ByteArray,
    ): String? {
        val directory = NSURL.fileURLWithPath(NSTemporaryDirectory()).URLByAppendingPathComponent(NSUUID().UUIDString) ?: return null
        val files = NSFileManager.defaultManager
        files.createDirectoryAtURL(directory, withIntermediateDirectories = true, attributes = null, error = null)
        val file = directory.URLByAppendingPathComponent(name) ?: return null
        return try {
            if (!bytes.toData().writeToURL(file, atomically = true)) return null
            pick(UIDocumentPickerViewController(forExportingURLs = listOf(file), asCopy = true))?.lastPathComponent
        } finally {
            files.removeItemAtURL(directory, error = null)
        }
    }

    private suspend fun pick(picker: UIDocumentPickerViewController): NSURL? {
        val parent = presenter() ?: return null
        return suspendCancellableCoroutine { done ->
            val picked =
                Picked { url ->
                    delegate = null
                    if (done.isActive) done.resume(url)
                }
            delegate = picked
            picker.delegate = picked
            done.invokeOnCancellation { picker.dismissViewControllerAnimated(true, completion = null) }
            parent.presentViewController(picker, animated = true, completion = null)
        }
    }
}

private class Picked(
    private val done: (NSURL?) -> Unit,
) : NSObject(),
    UIDocumentPickerDelegateProtocol {
    override fun documentPicker(
        controller: UIDocumentPickerViewController,
        didPickDocumentsAtURLs: List<*>,
    ) = done(didPickDocumentsAtURLs.firstOrNull() as? NSURL)

    override fun documentPickerWasCancelled(controller: UIDocumentPickerViewController) = done(null)
}

@OptIn(ExperimentalForeignApi::class)
private fun NSData.toByteArray(): ByteArray = ByteArray(length.toInt()).also { array ->
    if (array.isNotEmpty()) array.usePinned { memcpy(it.addressOf(0), bytes, length) }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
private fun ByteArray.toData(): NSData = usePinned { NSData.create(bytes = it.addressOf(0), length = size.toULong()) }
