package com.cachix.factorseal.android

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.view.WindowManager
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.cachix.factorseal.R
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.core.NativeCore
import com.cachix.factorseal.core.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope

class FactorSealApplication : Application() {
    val app: FactorSeal by lazy {
        NativeCore.start(this)
        FactorSeal(Vault(NativeCore, Dispatchers.IO), AndroidHost(this), MainScope())
    }

    private val screenOff =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context,
                intent: Intent,
            ) = app.lock()
        }

    override fun onCreate() {
        super.onCreate()
        ContextCompat.registerReceiver(this, screenOff, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_NOT_EXPORTED)
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) = app.foreground()

                override fun onStop(owner: LifecycleOwner) = app.background()
            },
        )
    }
}

val Activity.session: FactorSeal get() = (application as FactorSealApplication).app

fun Activity.protectWindow() {
    if (resources.getBoolean(R.bool.secure_window)) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    }
}
