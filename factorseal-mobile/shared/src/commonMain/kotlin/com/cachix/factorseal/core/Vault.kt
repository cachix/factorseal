package com.cachix.factorseal.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNamingStrategy

interface CoreBridge {
    fun call(request: String): String

    fun sealVault()
}

class VaultException(
    val code: ErrorCode,
    override val message: String,
) : Exception(message)

@OptIn(ExperimentalSerializationApi::class)
val protocol =
    Json {
        classDiscriminator = "type"
        namingStrategy = JsonNamingStrategy.KebabCase
        explicitNulls = true
        encodeDefaults = true
        ignoreUnknownKeys = false
    }

class Vault(
    private val native: CoreBridge,
    private val dispatcher: CoroutineDispatcher,
) {
    suspend fun send(request: Request): Response = withContext(dispatcher) {
        val response =
            protocol.decodeFromString(
                Response.serializer(),
                native.call(protocol.encodeToString(Request.serializer(), request)),
            )
        if (response is Response.Error) throw VaultException(response.code, response.message)
        response
    }

    suspend inline fun <reified T : Response> ask(request: Request): T = when (val response = send(request)) {
        is T -> response
        else -> throw VaultException(ErrorCode.Failed, "unexpected response ${response::class.simpleName}")
    }

    fun sealNow() = native.sealVault()
}
