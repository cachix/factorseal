package com.cachix.factorseal.core

import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

class ProtocolTest {
    private val messages = Json.parseToJsonElement(File("../protocol/messages.json").readText()).jsonObject

    private fun samples(name: String) = messages.getValue(name).jsonArray

    private fun JsonElement.type() = jsonObject.getValue("type").jsonPrimitive.content

    private fun SerialDescriptor.subtypes() = getElementDescriptor(1).elementNames.toSet()

    private fun values(name: String) = messages.getValue("enums").jsonObject.getValue(name).jsonArray.map { it.jsonPrimitive.content }

    @Test
    fun every_request_the_app_sends_reads_exactly_like_the_shared_samples() {
        samples("requests").forEach { sample ->
            val request = protocol.decodeFromJsonElement(Request.serializer(), sample)
            assertEquals(sample, protocol.encodeToJsonElement(Request.serializer(), request))
        }
        assertEquals(Request.serializer().descriptor.subtypes(), samples("requests").map { it.type() }.toSet())
    }

    @Test
    fun every_response_the_core_sends_is_read_without_losing_anything() {
        samples("responses").forEach { sample ->
            val response = protocol.decodeFromJsonElement(Response.serializer(), sample)
            assertEquals(sample, protocol.encodeToJsonElement(Response.serializer(), response))
        }
        assertEquals(Response.serializer().descriptor.subtypes(), samples("responses").map { it.type() }.toSet())
        val scans = samples("responses").filter { it.type() == "scanned" }.map { it.jsonObject.getValue("scan").type() }
        assertEquals(Scan.serializer().descriptor.subtypes(), scans.toSet())
    }

    @Test
    fun the_app_knows_every_value_the_core_can_send() {
        assertEquals(values("error-code"), ErrorCode.serializer().descriptor.elementNames.toList())
        assertEquals(values("field-type"), FieldType.serializer().descriptor.elementNames.toList())
        assertEquals(values("kind"), Kind.serializer().descriptor.elementNames.toList())
        assertEquals(values("login-change"), LoginChange.serializer().descriptor.elementNames.toList())
        assertEquals(values("strength"), Strength.serializer().descriptor.elementNames.toList())
        assertEquals(values("vault-state"), VaultState.serializer().descriptor.elementNames.toList())
    }
}
