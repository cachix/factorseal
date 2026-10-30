package com.cachix.factorseal.android

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.cachix.factorseal.core.NativeCore
import com.cachix.factorseal.core.Scan
import java.util.concurrent.Executors

@Composable
fun CameraScanner(
    onScan: (Scan) -> Unit,
    onUnavailable: () -> Unit,
    modifier: Modifier,
) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val unavailable by rememberUpdatedState(onUnavailable)
    val request =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
            granted = allowed
            if (!allowed) unavailable()
        }
    LaunchedEffect(Unit) { if (!granted) request.launch(Manifest.permission.CAMERA) }
    if (!granted) return
    val owner = LocalLifecycleOwner.current
    val found by rememberUpdatedState(onScan)
    val executor = remember { Executors.newSingleThreadExecutor() }
    val preview = remember { PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER } }
    DisposableEffect(owner) {
        val main = ContextCompat.getMainExecutor(context)
        val future = ProcessCameraProvider.getInstance(context)
        var disposed = false
        future.addListener({
            if (disposed) return@addListener
            runCatching {
                val camera = future.get()
                val shown = Preview.Builder().build().also { it.surfaceProvider = preview.surfaceProvider }
                val analysis =
                    ImageAnalysis
                        .Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                analysis.setAnalyzer(executor) { image ->
                    image.use {
                        val plane = it.planes[0]
                        val scan = NativeCore.scanFrame(plane.buffer, it.width, it.height, plane.rowStride)
                        if (scan !is Scan.Nothing) main.execute { found(scan) }
                    }
                }
                camera.unbindAll()
                camera.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, shown, analysis)
            }.onFailure { main.execute { unavailable() } }
        }, main)
        onDispose {
            disposed = true
            if (future.isDone) runCatching { future.get().unbindAll() }
            executor.shutdown()
        }
    }
    AndroidView(factory = { preview }, modifier = modifier)
}
