package com.cachix.factorseal.app

import com.cachix.factorseal.core.GeneratorOptions
import com.cachix.factorseal.core.Lease
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

val IdleChoices = listOf(60L, 300L, 900L, 1800L, 3600L)
val MaximumChoices = listOf(900L, 3600L, 14_400L, 28_800L, 86_400L)

@Serializable
data class Preferences(
    val idleSeconds: Long = 300,
    val maximumSeconds: Long = 28_800,
    val reducedMotion: Boolean = false,
    val generator: GeneratorOptions = GeneratorOptions(),
    val deviceName: String? = null,
    val offerAutofill: Boolean = true,
) {
    val lease: Lease get() = Lease(idleSeconds, maximumSeconds)

    val valid: Boolean get() = idleSeconds in 1..maximumSeconds

    fun encode(): String = format.encodeToString(serializer(), this)

    companion object {
        private val format =
            Json {
                ignoreUnknownKeys = true
                coerceInputValues = true
                encodeDefaults = true
            }

        fun decode(text: String?): Preferences = text
            ?.let { runCatching { format.decodeFromString(serializer(), it) }.getOrNull() }
            ?.takeIf { it.valid }
            ?: Preferences()
    }
}

fun validDeviceName(name: String): Boolean = name.isNotBlank() && name.encodeToByteArray().size in 1..80 && name.none { it.isISOControl() }
