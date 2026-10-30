package com.cachix.factorseal.ios

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.UIKitView
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Scan
import com.cachix.factorseal.core.Vault
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.launch
import platform.AVFoundation.AVAuthorizationStatusAuthorized
import platform.AVFoundation.AVAuthorizationStatusNotDetermined
import platform.AVFoundation.AVCaptureConnection
import platform.AVFoundation.AVCaptureDevice
import platform.AVFoundation.AVCaptureDeviceInput
import platform.AVFoundation.AVCaptureMetadataOutput
import platform.AVFoundation.AVCaptureMetadataOutputObjectsDelegateProtocol
import platform.AVFoundation.AVCaptureOutput
import platform.AVFoundation.AVCaptureSession
import platform.AVFoundation.AVCaptureVideoPreviewLayer
import platform.AVFoundation.AVLayerVideoGravityResizeAspectFill
import platform.AVFoundation.AVMediaTypeVideo
import platform.AVFoundation.AVMetadataMachineReadableCodeObject
import platform.AVFoundation.AVMetadataObjectTypeQRCode
import platform.AVFoundation.authorizationStatusForMediaType
import platform.AVFoundation.requestAccessForMediaType
import platform.CoreGraphics.CGRectMake
import platform.UIKit.UIView
import platform.darwin.NSObject
import platform.darwin.dispatch_async
import platform.darwin.dispatch_get_main_queue
import platform.darwin.dispatch_queue_create
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@Composable
internal fun CameraScanner(
    vault: Vault,
    onScan: (Scan) -> Unit,
    onUnavailable: () -> Unit,
    modifier: Modifier,
) {
    var allowed by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        allowed =
            when (AVCaptureDevice.authorizationStatusForMediaType(AVMediaTypeVideo)) {
                AVAuthorizationStatusAuthorized -> true
                AVAuthorizationStatusNotDetermined -> suspendCoroutine { done -> AVCaptureDevice.requestAccessForMediaType(AVMediaTypeVideo) { done.resume(it) } }
                else -> false
            }
        if (!allowed) onUnavailable()
    }
    if (!allowed) return
    val scope = rememberCoroutineScope()
    val scanned by rememberUpdatedState(onScan)
    val camera =
        remember {
            Camera { text ->
                scope.launch {
                    scanned(runCatching { vault.ask<Response.Scanned>(Request.Classify(text)).scan }.getOrDefault(Scan.Unsupported))
                }
            }
        }
    DisposableEffect(camera) {
        if (camera.ready) camera.start() else onUnavailable()
        onDispose { camera.stop() }
    }
    UIKitView(factory = { camera.preview }, modifier = modifier)
}

@OptIn(ExperimentalForeignApi::class)
private class Preview(
    session: AVCaptureSession,
) : UIView(frame = CGRectMake(0.0, 0.0, 0.0, 0.0)) {
    private val video = AVCaptureVideoPreviewLayer(session = session).apply { videoGravity = AVLayerVideoGravityResizeAspectFill }

    init {
        layer.addSublayer(video)
    }

    override fun layoutSubviews() {
        super.layoutSubviews()
        video.frame = bounds
    }
}

@OptIn(ExperimentalForeignApi::class)
private class Camera(
    private val onText: (String) -> Unit,
) : NSObject(),
    AVCaptureMetadataOutputObjectsDelegateProtocol {
    private val session = AVCaptureSession()
    private val queue = dispatch_queue_create("com.cachix.factorseal.camera", null)
    private var last: String? = null
    val preview = Preview(session)
    val ready: Boolean

    init {
        val input = AVCaptureDevice.defaultDeviceWithMediaType(AVMediaTypeVideo)?.let { AVCaptureDeviceInput.deviceInputWithDevice(it, null) }
        val output = AVCaptureMetadataOutput()
        ready = input != null && session.canAddInput(input) && session.canAddOutput(output)
        if (ready) {
            session.addInput(requireNotNull(input))
            session.addOutput(output)
            output.setMetadataObjectsDelegate(this, dispatch_get_main_queue())
            output.metadataObjectTypes = listOf(AVMetadataObjectTypeQRCode)
        }
    }

    fun start() = dispatch_async(queue) { session.startRunning() }

    fun stop() = dispatch_async(queue) { session.stopRunning() }

    override fun captureOutput(
        output: AVCaptureOutput,
        didOutputMetadataObjects: List<*>,
        fromConnection: AVCaptureConnection,
    ) {
        val text = didOutputMetadataObjects.filterIsInstance<AVMetadataMachineReadableCodeObject>().firstNotNullOfOrNull { it.stringValue } ?: return
        if (text == last) return
        last = text
        onText(text)
    }
}
