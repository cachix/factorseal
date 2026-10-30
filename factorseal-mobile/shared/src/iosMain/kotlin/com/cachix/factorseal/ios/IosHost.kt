package com.cachix.factorseal.ios

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.cachix.factorseal.app.CLIPBOARD_SECONDS
import com.cachix.factorseal.app.Files
import com.cachix.factorseal.app.Host
import com.cachix.factorseal.core.Platform
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.Vault
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSDate
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSURL
import platform.Foundation.NSURLIsExcludedFromBackupKey
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUserDomainMask
import platform.Foundation.create
import platform.Foundation.dateWithTimeIntervalSinceNow
import platform.Foundation.stringWithContentsOfURL
import platform.Foundation.writeToURL
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
import platform.UIKit.UIApplication
import platform.UIKit.UIDevice
import platform.UIKit.UIPasteboard
import platform.UIKit.UIPasteboardOptionExpirationDate
import platform.UIKit.UIPasteboardOptionLocalOnly
import platform.UIKit.UIViewController
import platform.UniformTypeIdentifiers.UTTypeUTF8PlainText

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
class IosHost : Host {
    private val files = NSFileManager.defaultManager
    private val support = requireNotNull(files.URLForDirectory(NSApplicationSupportDirectory, NSUserDomainMask, null, true, null))
    private val root = requireNotNull(support.URLByAppendingPathComponent("factorseal"))
    private val preferences = requireNotNull(support.URLByAppendingPathComponent("preferences.json"))
    private val pasteboard = UIPasteboard.generalPasteboard
    private var copied: Long? = null

    init {
        files.createDirectoryAtURL(root, withIntermediateDirectories = true, attributes = null, error = null)
        root.setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
    }

    override val platform = Platform.Ios
    override val directory: String = requireNotNull(root.path)
    override val biometric: Boolean
        get() = LAContext().canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    override val deviceName: String
        get() = UIDevice.currentDevice.name
    override val autofill = null

    override fun copy(text: String) {
        pasteboard.setItems(
            listOf(mapOf(UTTypeUTF8PlainText.identifier to text)),
            options =
            mapOf(
                UIPasteboardOptionLocalOnly to true,
                UIPasteboardOptionExpirationDate to NSDate.dateWithTimeIntervalSinceNow(CLIPBOARD_SECONDS.toDouble()),
            ),
        )
        copied = pasteboard.changeCount
    }

    override fun clearClipboard(text: String): Boolean {
        if (pasteboard.changeCount == copied) pasteboard.items = emptyList<Map<Any?, *>>()
        copied = null
        return true
    }

    override fun paste(): String? = pasteboard.string

    override fun open(url: String) {
        val target = NSURL.URLWithString(url) ?: return
        UIApplication.sharedApplication.openURL(target, options = emptyMap<Any?, Any?>(), completionHandler = null)
    }

    override fun load(): String? = NSString.stringWithContentsOfURL(preferences, NSUTF8StringEncoding, null)

    override fun save(text: String) {
        NSString.create(string = text).writeToURL(preferences, atomically = true, encoding = NSUTF8StringEncoding, error = null)
        preferences.setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
    }

    var presenter: UIViewController? = null

    private val picker =
        IosFiles {
            generateSequence(presenter) { it.presentedViewController }.lastOrNull()
        }

    @Composable
    override fun rememberFiles(): Files = picker

    @Composable
    override fun Scanner(
        vault: Vault,
        onScan: (Scan) -> Unit,
        onUnavailable: () -> Unit,
        modifier: Modifier,
    ) = CameraScanner(vault, onScan, onUnavailable, modifier)
}
