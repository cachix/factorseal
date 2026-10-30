package com.cachix.factorseal.android

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.cancel
import kotlinx.coroutines.runBlocking
import org.jetbrains.compose.resources.getString
import java.lang.ref.WeakReference
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher

object Biometrics {
    private const val AUTHORIZED = 0
    private const val CANCELLED = 1
    private const val DENIED = 2
    private const val UNAVAILABLE = 3
    private const val PROMPT_MINUTES = 2L

    @Volatile
    private var activity = WeakReference<Activity>(null)

    fun attach(activity: Activity) {
        this.activity = WeakReference(activity)
    }

    fun available(context: Context): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
        context.getSystemService(BiometricManager::class.java)?.canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    @JvmStatic
    fun authorize(cipher: Cipher): Int {
        val activity = activity.get()
        return if (activity != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) prompt(activity, cipher) else UNAVAILABLE
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun prompt(
        activity: Activity,
        cipher: Cipher,
    ): Int {
        val cancel = runBlocking { getString(Res.string.cancel) }
        val outcome = LinkedBlockingQueue<Int>(1)
        val signal = CancellationSignal()
        activity.runOnUiThread {
            BiometricPrompt
                .Builder(activity)
                .setTitle(activity.applicationInfo.loadLabel(activity.packageManager))
                .setNegativeButton(cancel, activity.mainExecutor) { _, _ -> outcome.offer(CANCELLED) }
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()
                .authenticate(BiometricPrompt.CryptoObject(cipher), signal, activity.mainExecutor, Callback(outcome))
        }
        return outcome.poll(PROMPT_MINUTES, TimeUnit.MINUTES) ?: CANCELLED.also { signal.cancel() }
    }

    private class Callback(
        private val outcome: LinkedBlockingQueue<Int>,
    ) : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            outcome.offer(AUTHORIZED)
        }

        override fun onAuthenticationError(
            code: Int,
            message: CharSequence,
        ) {
            outcome.offer(
                when (code) {
                    BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT, BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT -> DENIED
                    BiometricPrompt.BIOMETRIC_ERROR_CANCELED, BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT -> CANCELLED
                    else -> UNAVAILABLE
                },
            )
        }
    }
}
