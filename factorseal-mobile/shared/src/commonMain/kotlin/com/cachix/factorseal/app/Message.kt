package com.cachix.factorseal.app

import androidx.compose.runtime.Composable
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource

sealed interface Message {
    data class Of(
        val resource: StringResource,
        val args: List<Any> = emptyList(),
    ) : Message

    data class Raw(
        val text: String,
    ) : Message
}

fun message(
    resource: StringResource,
    vararg args: Any,
): Message = Message.Of(resource, args.toList())

@Composable
fun Message.text(): String = when (this) {
    is Message.Of -> stringResource(resource, *args.toTypedArray())
    is Message.Raw -> text
}
