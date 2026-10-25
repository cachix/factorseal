package com.cachix.factorseal.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.layout
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.icon_chevron_right
import com.cachix.factorseal.resources.icon_inbox
import com.cachix.factorseal.ui.theme.Medium
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import kotlinx.coroutines.delay
import org.jetbrains.compose.resources.DrawableResource

@Composable
fun Modifier.entering(
    key: Any?,
    travel: Dp = 6.dp,
): Modifier {
    val motion = Theme.motion
    val progress = remember(key) { Animatable(if (motion.reduced) 1f else 0f) }
    LaunchedEffect(key) { progress.animateTo(1f, motion.enter()) }
    val distance = with(LocalDensity.current) { travel.toPx() }
    return graphicsLayer {
        alpha = progress.value
        translationY = distance * (1f - progress.value)
    }
}

@Composable
fun Modifier.afterAMoment(): Modifier {
    var shown by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        delay(240)
        shown = true
    }
    return graphicsLayer { alpha = if (shown) 1f else 0f }.entering(shown, 0.dp)
}

fun Modifier.outdent(inset: Dp): Modifier = layout { measurable, constraints ->
    val extra = inset.roundToPx()
    val maxWidth = if (constraints.hasBoundedWidth) constraints.maxWidth + extra else constraints.maxWidth
    val placeable = measurable.measure(constraints.copy(minWidth = 0, maxWidth = maxWidth))
    val width = (placeable.width - extra).coerceIn(constraints.minWidth, constraints.maxWidth)
    layout(width, placeable.height) { placeable.place(-extra, 0) }
}

@Composable
fun VaultCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier
            .fillMaxWidth()
            .background(Theme.colors.surface, Shapes.card)
            .border(1.dp, Theme.colors.border, Shapes.card)
            .padding(horizontal = 24.dp, vertical = 28.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
        content = content,
    )
}

@Composable
fun Banner(
    message: String,
    modifier: Modifier = Modifier,
    color: Color = Theme.colors.danger,
) {
    Box(
        modifier
            .entering(message)
            .fillMaxWidth()
            .background(color.copy(alpha = 0.1f), Shapes.tile)
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(message, color = color)
    }
}

@Composable
fun InfoBox(
    modifier: Modifier = Modifier,
    fill: Color = Theme.colors.muted,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier
            .fillMaxWidth()
            .background(fill, Shapes.tile)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        content = content,
    )
}

@Composable
fun FieldError(
    message: String?,
    modifier: Modifier = Modifier,
) {
    if (message != null) Text(message, modifier.entering(message), style = Type.caption, color = Theme.colors.danger)
}

@Composable
fun Labeled(
    label: String,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, weight = Medium)
        content()
    }
}

@Composable
fun IconTile(
    icon: DrawableResource,
    modifier: Modifier = Modifier,
    size: Dp = 36.dp,
    tint: Color = Theme.colors.foreground,
) {
    Box(
        modifier
            .size(size)
            .background(Theme.colors.tile, Shapes.tile),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, size = size / 2, tint = tint)
    }
}

@Composable
fun EmptyState(
    title: String,
    line: String,
    modifier: Modifier = Modifier,
    icon: DrawableResource = Res.drawable.icon_inbox,
    actions: (@Composable RowScope.() -> Unit)? = null,
) {
    Column(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(icon, size = 40.dp, tint = Theme.colors.mutedForeground)
        Text(title, style = Type.lead, weight = Semibold, align = TextAlign.Center)
        Text(line, Modifier.widthIn(max = 420.dp), color = Theme.colors.mutedForeground, align = TextAlign.Center)
        if (actions != null) {
            Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), content = actions)
        }
    }
}

@Composable
fun ListRow(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    selected: Boolean = false,
    chevron: Boolean = false,
    content: @Composable RowScope.() -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val colors = Theme.colors
    Column(modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(if (pressed || selected) colors.selection else Color.Transparent)
                .clickable(interaction, indication = null, role = Role.Button, onClick = onClick)
                .defaultMinSize(minHeight = 60.dp)
                .padding(horizontal = 16.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            content()
            if (chevron) Icon(Res.drawable.icon_chevron_right, tint = colors.mutedForeground)
        }
        Divider()
    }
}

@Composable
fun RowScope.RowText(
    title: String,
    detail: String?,
    leading: (@Composable () -> Unit)? = null,
) {
    Column(Modifier.weight(1f)) {
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
            leading?.invoke()
            Text(title, weight = Semibold, maxLines = 1)
        }
        if (detail != null) Text(detail, style = Type.caption, color = Theme.colors.mutedForeground, maxLines = 1)
    }
}

@Composable
fun PageHeader(
    icon: DrawableResource,
    title: String,
    modifier: Modifier = Modifier,
    detail: String? = null,
    actions: (@Composable RowScope.() -> Unit)? = null,
) {
    Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.CenterVertically) {
        IconTile(icon, size = 56.dp)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = Type.title, maxLines = 2)
            if (detail != null) Text(detail, color = Theme.colors.mutedForeground, maxLines = 2)
        }
        if (actions != null) Row(horizontalArrangement = Arrangement.spacedBy(8.dp), content = actions)
    }
}

@Composable
fun ListHeader(
    title: String,
    modifier: Modifier = Modifier,
    trailing: (@Composable RowScope.() -> Unit)? = null,
) {
    Column(modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 42.dp)
                .padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(title, Modifier.weight(1f), style = Type.heading, maxLines = 1)
            trailing?.invoke(this)
        }
        Divider()
    }
}

@Composable
fun Pill(
    text: String,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier
            .background(Theme.colors.muted, Shapes.pill)
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(text, color = Theme.colors.mutedForeground, maxLines = 1)
    }
}
