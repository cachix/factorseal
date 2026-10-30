package com.cachix.factorseal.ios

import androidx.compose.ui.window.ComposeUIViewController
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.core.CoreBridge
import com.cachix.factorseal.core.Vault
import com.cachix.factorseal.ui.screens.FactorSealApp
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.MainScope
import platform.Foundation.NSNotificationCenter
import platform.Foundation.NSOperationQueue
import platform.UIKit.UIApplicationDidBecomeActiveNotification
import platform.UIKit.UIApplicationDidEnterBackgroundNotification
import platform.UIKit.UIApplicationProtectedDataWillBecomeUnavailable
import platform.UIKit.UIApplicationWillEnterForegroundNotification
import platform.UIKit.UIApplicationWillResignActiveNotification
import platform.UIKit.UIColor
import platform.UIKit.UIUserInterfaceStyle
import platform.UIKit.UIView
import platform.UIKit.UIViewAutoresizingFlexibleHeight
import platform.UIKit.UIViewAutoresizingFlexibleWidth
import platform.UIKit.UIViewController

fun mainViewController(core: CoreBridge): UIViewController {
    val host = IosHost()
    val app = FactorSeal(Vault(core, Dispatchers.IO), host, MainScope())
    val controller = ComposeUIViewController { FactorSealApp(app) }
    host.presenter = controller
    val center = NSNotificationCenter.defaultCenter
    val main = NSOperationQueue.mainQueue
    var cover: UIView? = null
    center.addObserverForName(UIApplicationWillEnterForegroundNotification, null, main) { _ -> app.foreground() }
    center.addObserverForName(UIApplicationDidEnterBackgroundNotification, null, main) { _ -> app.background() }
    center.addObserverForName(UIApplicationProtectedDataWillBecomeUnavailable, null, main) { _ -> app.lock() }
    center.addObserverForName(UIApplicationWillResignActiveNotification, null, main) { _ ->
        cover?.removeFromSuperview()
        cover = shield(controller).also(controller.view::addSubview)
    }
    center.addObserverForName(UIApplicationDidBecomeActiveNotification, null, main) { _ ->
        cover?.removeFromSuperview()
        cover = null
    }
    return controller
}

@OptIn(ExperimentalForeignApi::class)
private fun shield(controller: UIViewController): UIView = UIView(frame = controller.view.bounds).apply {
    autoresizingMask = UIViewAutoresizingFlexibleWidth or UIViewAutoresizingFlexibleHeight
    backgroundColor =
        if (controller.traitCollection.userInterfaceStyle == UIUserInterfaceStyle.UIUserInterfaceStyleDark) {
            UIColor(red = 0x15 / 255.0, green = 0x15 / 255.0, blue = 0x15 / 255.0, alpha = 1.0)
        } else {
            UIColor(red = 0xF7 / 255.0, green = 0xF3 / 255.0, blue = 0xEA / 255.0, alpha = 1.0)
        }
}
