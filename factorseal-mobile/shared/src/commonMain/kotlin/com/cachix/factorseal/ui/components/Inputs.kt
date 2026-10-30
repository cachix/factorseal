package com.cachix.factorseal.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicSecureTextField
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.KeyboardActionHandler
import androidx.compose.foundation.text.input.TextFieldDecorator
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.semantics.editableText
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.icon_eye
import com.cachix.factorseal.resources.icon_eye_off
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type

val FieldHeight = 44.dp

@Composable
fun fieldFrame(
    interaction: MutableInteractionSource,
    error: Boolean,
    plain: Boolean = false,
): Modifier {
    val focused by interaction.collectIsFocusedAsState()
    val colors = Theme.colors
    val target =
        when {
            error -> colors.danger
            focused -> colors.foreground
            plain -> Color.Transparent
            else -> colors.border
        }
    val border by animateColorAsState(target, Theme.motion.hover())
    return Modifier
        .background(if (plain && !focused) Color.Transparent else colors.inputBackground, Shapes.input)
        .border(if (focused || error) 2.dp else 1.dp, border, Shapes.input)
}

private fun decorator(
    state: TextFieldState,
    placeholder: String,
    style: TextStyle,
    color: Color,
    leading: (@Composable () -> Unit)?,
    trailing: (@Composable () -> Unit)?,
    multiline: Boolean,
) = TextFieldDecorator { inner ->
    Row(
        Modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = FieldHeight)
            .padding(start = if (leading == null) 12.dp else 10.dp, end = if (trailing == null) 12.dp else 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = if (multiline) Alignment.Top else Alignment.CenterVertically,
    ) {
        leading?.invoke()
        Box(
            Modifier
                .weight(1f)
                .padding(vertical = if (multiline) 11.dp else 0.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            if (state.text.isEmpty()) Text(placeholder, style = style, color = color, maxLines = 1)
            inner()
        }
        trailing?.invoke()
    }
}

@Composable
fun TextInput(
    state: TextFieldState,
    placeholder: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    multiline: Boolean = false,
    error: Boolean = false,
    plain: Boolean = false,
    style: TextStyle = Type.body,
    keyboard: KeyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences, imeAction = ImeAction.Done),
    onSubmit: (() -> Unit)? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    val colors = Theme.colors
    BasicTextField(
        state = state,
        modifier = modifier.fillMaxWidth().then(fieldFrame(interaction, error, plain)),
        enabled = enabled,
        textStyle = style.merge(color = colors.foreground),
        keyboardOptions = keyboard,
        onKeyboardAction = onSubmit?.let { submit -> KeyboardActionHandler { submit() } },
        lineLimits = if (multiline) TextFieldLineLimits.MultiLine(minHeightInLines = 1) else TextFieldLineLimits.SingleLine,
        interactionSource = interaction,
        cursorBrush = SolidColor(colors.foreground),
        decorator = decorator(state, placeholder, style, colors.mutedForeground, leading, trailing, multiline),
    )
}

@Composable
fun SecretInput(
    state: TextFieldState,
    placeholder: String,
    revealed: Boolean,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    error: Boolean = false,
    plain: Boolean = false,
    style: TextStyle = Type.body,
    imeAction: ImeAction = ImeAction.Done,
    onSubmit: (() -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    val colors = Theme.colors
    BasicSecureTextField(
        state = state,
        modifier =
        modifier
            .fillMaxWidth()
            .then(fieldFrame(interaction, error, plain))
            .semantics { editableText = AnnotatedString("•".repeat(state.text.length)) },
        enabled = enabled,
        textStyle = style.merge(color = colors.foreground),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = imeAction),
        onKeyboardAction = onSubmit?.let { submit -> KeyboardActionHandler { submit() } },
        interactionSource = interaction,
        cursorBrush = SolidColor(colors.foreground),
        decorator = decorator(state, placeholder, style, colors.mutedForeground, null, trailing, false),
        textObfuscationMode = if (revealed) TextObfuscationMode.Visible else TextObfuscationMode.RevealLastTyped,
    )
}

@Composable
fun RevealButton(
    revealed: Boolean,
    show: String,
    hide: String,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    IconButton(
        icon = if (revealed) Res.drawable.icon_eye_off else Res.drawable.icon_eye,
        description = if (revealed) hide else show,
        onClick = onToggle,
        modifier = modifier,
    )
}

@Composable
fun PasswordField(
    state: TextFieldState,
    placeholder: String,
    revealed: Boolean,
    show: String,
    hide: String,
    onReveal: () -> Unit,
    modifier: Modifier = Modifier,
    error: Boolean = false,
    imeAction: ImeAction = ImeAction.Done,
    onSubmit: (() -> Unit)? = null,
) {
    Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        SecretInput(
            state = state,
            placeholder = placeholder,
            revealed = revealed,
            modifier = Modifier.weight(1f),
            error = error,
            imeAction = imeAction,
            onSubmit = onSubmit,
        )
        RevealButton(revealed, show, hide, onReveal)
    }
}
