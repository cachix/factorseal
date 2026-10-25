package com.cachix.factorseal.core

import android.content.Context
import java.nio.ByteBuffer

object NativeCore : CoreBridge {
    init {
        System.loadLibrary("factorseal_mobile")
    }

    @JvmStatic
    private external fun initialize(context: Context)

    @JvmStatic
    private external fun call(request: ByteArray): ByteArray

    @JvmStatic
    private external fun scan(
        pixels: ByteBuffer,
        width: Int,
        height: Int,
        stride: Int,
    ): ByteArray

    @JvmStatic
    private external fun seal()

    fun start(context: Context) = initialize(context.applicationContext)

    override fun call(request: String): String {
        val bytes = request.encodeToByteArray()
        val response = call(bytes)
        bytes.fill(0)
        return response.decodeToString().also { response.fill(0) }
    }

    fun scanFrame(
        pixels: ByteBuffer,
        width: Int,
        height: Int,
        stride: Int,
    ): Scan {
        val response = scan(pixels, width, height, stride)
        return protocol.decodeFromString(Scan.serializer(), response.decodeToString().also { response.fill(0) })
    }

    override fun sealVault() = seal()
}
