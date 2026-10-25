package com.cachix.factorseal.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.icon_chevron_down
import com.cachix.factorseal.ui.theme.Colors
import com.cachix.factorseal.ui.theme.Medium
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.DrawableResource

enum class Variant { Primary, Default, Ghost, Danger }

enum class ButtonSize(
    val height: Dp,
    val padding: Dp,
    val icon: Dp,
    val gap: Dp,
) {
    XSmall(28.dp, 6.dp, 14.dp, 4.dp),
    Small(34.dp, 10.dp, 16.dp, 6.dp),
    Medium(42.dp, 14.dp, 18.dp, 8.dp),
    Large(48.dp, 16.dp, 18.dp, 8.dp),
}

private class Palette(
    val fill: Color,
    val text: Color,
    val border: Color,
)

private fun palette(
    colors: Colors,
    variant: Variant,
    pressed: Boolean,
    selected: Boolean,
    enabled: Boolean,
): Palette = when (variant) {
    Variant.Primary ->
        when {
            !enabled -> Palette(colors.primary.copy(alpha = 0.15f), colors.mutedForeground.copy(alpha = 0.5f), Color.Transparent)
            pressed || selected -> Palette(colors.primaryActive, colors.primaryForeground, colors.primaryActive)
            else -> Palette(colors.primary, colors.primaryForeground, colors.primary)
        }

    Variant.Default ->
        when {
            !enabled -> Palette(colors.inputBackground.copy(alpha = 0.5f), colors.mutedForeground.copy(alpha = 0.5f), colors.border)
            pressed || selected -> Palette(colors.selection, colors.foreground, colors.border)
            else -> Palette(colors.secondary, colors.foreground, colors.border)
        }

    Variant.Ghost ->
        when {
            !enabled -> Palette(Color.Transparent, colors.mutedForeground.copy(alpha = 0.5f), Color.Transparent)
            pressed -> Palette(colors.secondaryHover, colors.foreground, Color.Transparent)
            selected -> Palette(colors.selection, colors.foreground, Color.Transparent)
            else -> Palette(Color.Transparent, colors.foreground, Color.Transparent)
        }

    Variant.Danger ->
        when {
            !enabled -> Palette(colors.danger.copy(alpha = 0.15f), colors.mutedForeground.copy(alpha = 0.5f), Color.Transparent)
            pressed -> Palette(colors.danger.copy(alpha = 0.85f), colors.primaryForeground, Color.Transparent)
            else -> Palette(colors.danger, colors.primaryForeground, colors.danger)
        }
}

@Composable
fun Button(
    label: String?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    variant: Variant = Variant.Default,
    size: ButtonSize = ButtonSize.Medium,
    icon: DrawableResource? = null,
    enabled: Boolean = true,
    loading: Boolean = false,
    selected: Boolean = false,
    description: String? = null,
    tint: Color? = null,
    caret: Boolean = false,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val active = enabled && !loading
    val colors = Theme.colors
    val target = palette(colors, variant, pressed, selected, enabled)
    val fill by animateColorAsState(target.fill, Theme.motion.hover())
    val text by animateColorAsState(target.text, Theme.motion.hover())
    val border by animateColorAsState(target.border, Theme.motion.hover())
    Row(
        modifier
            .alpha(if (loading) 0.8f else 1f)
            .height(size.height)
            .defaultMinSize(minWidth = size.height)
            .background(fill, Shapes.control)
            .border(1.dp, border, Shapes.control)
            .clickable(interaction, indication = null, enabled = active, role = if (caret) Role.DropdownList else Role.Button, onClick = onClick)
            .semantics {
                if (description != null) contentDescription = description
                if (label != null && description != null) stateDescription = label
                if (selected) this.selected = true
            }.padding(horizontal = if (label == null) 0.dp else size.padding),
        horizontalArrangement = Arrangement.spacedBy(size.gap, Alignment.CenterHorizontally),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        when {
            loading -> Spinner(size = size.icon, color = text)
            icon != null -> Icon(icon, size = size.icon, tint = tint ?: text)
        }
        if (label != null) {
            Text(
                label,
                style = if (size == ButtonSize.XSmall) Type.caption else Type.body.copy(fontSize = 16.sp),
                color = tint ?: text,
                weight = Medium,
                maxLines = 1,
            )
        }
        if (caret) Icon(Res.drawable.icon_chevron_down, size = size.icon, tint = tint ?: text)
    }
}

@Composable
fun IconButton(
    icon: DrawableResource,
    description: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    variant: Variant = Variant.Ghost,
    size: ButtonSize = ButtonSize.Medium,
    enabled: Boolean = true,
    loading: Boolean = false,
    selected: Boolean = false,
    tint: Color? = null,
) {
    Button(
        label = null,
        onClick = onClick,
        modifier = modifier.size(size.height),
        variant = variant,
        size = size,
        icon = icon,
        enabled = enabled,
        loading = loading,
        selected = selected,
        description = description,
        tint = tint,
    )
}
