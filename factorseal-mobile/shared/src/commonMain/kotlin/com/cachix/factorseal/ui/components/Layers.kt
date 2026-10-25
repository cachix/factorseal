package com.cachix.factorseal.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animate
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupPositionProvider
import androidx.compose.ui.window.PopupProperties
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.icon_check
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.DrawableResource

enum class LayerKind { Dialog, Sheet }

class Layer internal constructor(
    val kind: LayerKind,
    val dismiss: State<() -> Unit>,
    val content: State<@Composable () -> Unit>,
)

class Layers {
    internal val entries = mutableStateListOf<Layer>()
}

private val LocalLayers = staticCompositionLocalOf<Layers> { error("no layer host") }

@Composable
private fun Present(
    kind: LayerKind,
    onDismiss: () -> Unit,
    content: @Composable () -> Unit,
) {
    val layers = LocalLayers.current
    val focus = LocalFocusManager.current
    val dismiss = rememberUpdatedState(onDismiss)
    val body = rememberUpdatedState(content)
    DisposableEffect(layers) {
        focus.clearFocus()
        val layer = Layer(kind, dismiss, body)
        layers.entries.add(layer)
        onDispose { layers.entries.remove(layer) }
    }
}

@Composable
fun LayerHost(
    layers: Layers,
    content: @Composable BoxScope.() -> Unit,
) {
    CompositionLocalProvider(LocalLayers provides layers) {
        Box(Modifier.fillMaxSize()) {
            content()
            layers.entries.forEach { layer -> key(layer) { Shown(layer) } }
        }
    }
}

@Composable
private fun Shown(layer: Layer) {
    val motion = Theme.motion
    val progress = remember { Animatable(if (motion.reduced) 1f else 0f) }
    LaunchedEffect(Unit) { progress.animateTo(1f, motion.dialog()) }
    val density = LocalDensity.current
    Back { layer.dismiss.value() }
    Box(Modifier.fillMaxSize()) {
        Box(
            Modifier
                .fillMaxSize()
                .graphicsLayer { alpha = progress.value }
                .background(Theme.colors.overlay)
                .clickable(remember { MutableInteractionSource() }, indication = null) { layer.dismiss.value() },
        )
        when (layer.kind) {
            LayerKind.Dialog ->
                Box(
                    Modifier
                        .fillMaxSize()
                        .windowInsetsPadding(WindowInsets.safeDrawing.union(WindowInsets.ime))
                        .padding(horizontal = 16.dp, vertical = 24.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Box(
                        Modifier.graphicsLayer {
                            alpha = progress.value
                            translationY = with(density) { -12.dp.toPx() } * (1f - progress.value)
                        },
                    ) { layer.content.value() }
                }

            LayerKind.Sheet -> {
                var offset by remember { mutableFloatStateOf(0f) }
                var height by remember { mutableIntStateOf(0) }
                val fast = with(density) { 400.dp.toPx() }
                val connection =
                    remember(layer) {
                        object : NestedScrollConnection {
                            override fun onPreScroll(
                                available: Offset,
                                source: NestedScrollSource,
                            ): Offset {
                                if (available.y >= 0f || offset <= 0f) return Offset.Zero
                                val used = maxOf(available.y, -offset)
                                offset += used
                                return Offset(0f, used)
                            }

                            override fun onPostScroll(
                                consumed: Offset,
                                available: Offset,
                                source: NestedScrollSource,
                            ): Offset {
                                if (source != NestedScrollSource.UserInput || available.y <= 0f) return Offset.Zero
                                offset += available.y
                                return Offset(0f, available.y)
                            }

                            override suspend fun onPreFling(available: Velocity): Velocity {
                                if (offset <= 0f) return Velocity.Zero
                                if (offset > height / 4f || available.y > fast) {
                                    layer.dismiss.value()
                                } else {
                                    animate(offset, 0f, animationSpec = motion.navigate()) { value, _ -> offset = value }
                                }
                                return available
                            }
                        }
                    }
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
                    Box(
                        Modifier
                            .onSizeChanged { height = it.height }
                            .nestedScroll(connection)
                            .graphicsLayer { translationY = size.height * (1f - progress.value) + offset },
                    ) { layer.content.value() }
                }
            }
        }
    }
}

@Composable
fun Dialog(
    title: String,
    onDismiss: () -> Unit,
    actions: @Composable () -> Unit,
    leading: @Composable () -> Unit = {},
    body: @Composable ColumnScope.() -> Unit,
) {
    Present(LayerKind.Dialog, onDismiss) {
        Column(
            Modifier
                .widthIn(max = 440.dp)
                .fillMaxWidth()
                .shadow(16.dp, Shapes.card)
                .background(Theme.colors.background, Shapes.card)
                .border(1.dp, Theme.colors.border, Shapes.card)
                .clickable(remember { MutableInteractionSource() }, indication = null) {}
                .semantics { paneTitle = title }
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(title, style = Type.heading)
            Column(
                Modifier
                    .heightIn(max = 520.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                content = body,
            )
            DialogActions(leading, actions)
        }
    }
}

@Composable
private fun DialogActions(
    leading: @Composable () -> Unit,
    trailing: @Composable () -> Unit,
) {
    Layout(contents = listOf(leading, trailing), modifier = Modifier.fillMaxWidth()) { (start, end), constraints ->
        val gap = 8.dp.roundToPx()
        val width = constraints.maxWidth
        val all = start + end
        val natural = all.sumOf { it.maxIntrinsicWidth(Constraints.Infinity) } + gap * (all.size - 1).coerceAtLeast(0)
        if (natural <= width) {
            val first = start.map { it.measure(Constraints(maxWidth = width)) }
            val last = end.map { it.measure(Constraints(maxWidth = width)) }
            val height = (first + last).maxOfOrNull { it.height } ?: 0
            layout(width, height) {
                var x = 0
                first.forEach { placeable ->
                    placeable.placeRelative(x, (height - placeable.height) / 2)
                    x += placeable.width + gap
                }
                x = width
                last.asReversed().forEach { placeable ->
                    x -= placeable.width
                    placeable.placeRelative(x, (height - placeable.height) / 2)
                    x -= gap
                }
            }
        } else {
            val stacked = (end.asReversed() + start).map { it.measure(Constraints.fixedWidth(width)) }
            val height = stacked.sumOf { it.height } + gap * (stacked.size - 1).coerceAtLeast(0)
            layout(width, height) {
                var y = 0
                stacked.forEach { placeable ->
                    placeable.placeRelative(0, y)
                    y += placeable.height + gap
                }
            }
        }
    }
}

private val SheetShape = RoundedCornerShape(topStart = 12.dp, topEnd = 12.dp)

@Composable
fun Sheet(
    title: String,
    onDismiss: () -> Unit,
    body: @Composable ColumnScope.() -> Unit,
) {
    Present(LayerKind.Sheet, onDismiss) {
        Column(
            Modifier
                .fillMaxWidth()
                .background(Theme.colors.surface, SheetShape)
                .border(1.dp, Theme.colors.border, SheetShape)
                .clickable(remember { MutableInteractionSource() }, indication = null) {}
                .semantics { paneTitle = title }
                .windowInsetsPadding(WindowInsets.navigationBars.union(WindowInsets.ime))
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Box(
                Modifier
                    .align(Alignment.CenterHorizontally)
                    .size(width = 36.dp, height = 4.dp)
                    .background(Theme.colors.border, Shapes.pill),
            )
            Text(title, style = Type.heading)
            body()
        }
    }
}

class MenuItem(
    val label: String,
    val onClick: () -> Unit,
    val icon: DrawableResource? = null,
    val checked: Boolean = false,
    val header: Boolean = false,
    val indent: Boolean = false,
)

private class Below(
    private val margin: Int,
    private val end: Boolean,
) : PopupPositionProvider {
    override fun calculatePosition(
        anchorBounds: IntRect,
        windowSize: IntSize,
        layoutDirection: LayoutDirection,
        popupContentSize: IntSize,
    ): IntOffset {
        val x =
            (if (end) anchorBounds.right - popupContentSize.width else anchorBounds.left)
                .coerceIn(margin, (windowSize.width - popupContentSize.width - margin).coerceAtLeast(margin))
        val below = anchorBounds.bottom + margin / 2
        val above = anchorBounds.top - popupContentSize.height - margin / 2
        val lowest = windowSize.height - popupContentSize.height - margin
        val y =
            when {
                below <= lowest -> below
                above >= margin -> above
                else -> lowest.coerceAtLeast(margin)
            }
        return IntOffset(x, y)
    }
}

@Composable
fun Menu(
    expanded: Boolean,
    onDismiss: () -> Unit,
    items: List<MenuItem>,
    end: Boolean = true,
) {
    if (!expanded) return
    val margin = with(LocalDensity.current) { 8.dp.roundToPx() }
    Popup(
        popupPositionProvider = remember(margin, end) { Below(margin, end) },
        onDismissRequest = onDismiss,
        properties = PopupProperties(focusable = true),
    ) {
        Column(
            Modifier
                .entering(Unit)
                .widthIn(min = 200.dp, max = 320.dp)
                .width(IntrinsicSize.Max)
                .heightIn(max = 480.dp)
                .shadow(8.dp, Shapes.control)
                .background(Theme.colors.surface, Shapes.control)
                .border(1.dp, Theme.colors.foreground.copy(alpha = 0.1f), Shapes.control)
                .verticalScroll(rememberScrollState())
                .padding(4.dp),
        ) {
            items.forEach { item ->
                if (item.header) {
                    Divider(Modifier.padding(vertical = 4.dp))
                    Text(
                        item.label,
                        Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        style = Type.caption,
                        color = Theme.colors.mutedForeground,
                        weight = Semibold,
                    )
                } else {
                    MenuRow(item) {
                        onDismiss()
                        item.onClick()
                    }
                }
            }
        }
    }
}

@Composable
private fun MenuRow(
    item: MenuItem,
    onClick: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    Row(
        Modifier
            .fillMaxWidth()
            .background(if (pressed) Theme.colors.secondaryHover else Color.Transparent, Shapes.input)
            .clickable(interaction, indication = null, role = Role.Button, onClick = onClick)
            .semantics { selected = item.checked }
            .defaultMinSize(minHeight = 44.dp)
            .padding(start = if (item.indent) 20.dp else 12.dp, end = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (item.icon != null) Icon(item.icon, tint = Theme.colors.mutedForeground)
        Text(item.label, Modifier.weight(1f), maxLines = 1)
        if (item.checked) Icon(Res.drawable.icon_check) else Spacer(Modifier)
    }
}
