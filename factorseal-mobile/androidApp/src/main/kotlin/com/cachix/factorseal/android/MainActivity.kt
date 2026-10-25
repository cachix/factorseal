package com.cachix.factorseal.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.cachix.factorseal.ui.screens.FactorSealApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        protectWindow()
        enableEdgeToEdge()
        setContent { FactorSealApp(session) }
    }

    override fun onResume() {
        super.onResume()
        Biometrics.attach(this)
    }
}
