package com.cachix.factorseal.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.setProgress
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.core.Strength
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.icon_check
import com.cachix.factorseal.ui.theme.Medium
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import kotlin.math.abs
import kotlin.math.roundToInt

@Composable
fun Switch(
    checked: Boolean,
    onChange: (Boolean) -> Unit,
    description: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val colors = Theme.colors
    val track by animateColorAsState(if (checked) colors.primary else colors.selection, Theme.motion.hover())
    val offset by animateDpAsState(if (checked) 20.dp else 0.dp, Theme.motion.hover())
    Box(
        modifier
            .alpha(if (enabled) 1f else 0.5f)
            .size(width = 44.dp, height = 24.dp)
            .background(track, Shapes.pill)
            .toggleable(
                value = checked,
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                enabled = enabled,
                role = Role.Switch,
                onValueChange = onChange,
            ).semantics { contentDescription = description }
            .padding(2.dp),
    ) {
        Box(
            Modifier
                .offset(x = offset)
                .size(20.dp)
                .background(colors.background, CircleShape),
        )
    }
}

@Composable
fun Checkbox(
    checked: Boolean,
    onChange: (Boolean) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val colors = Theme.colors
    val fill by animateColorAsState(if (checked) colors.primary else colors.inputBackground, Theme.motion.hover())
    Row(
        modifier
            .fillMaxWidth()
            .alpha(if (enabled) 1f else 0.5f)
            .defaultMinSize(minHeight = 48.dp)
            .toggleable(
                value = checked,
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                enabled = enabled,
                role = Role.Checkbox,
                onValueChange = onChange,
            ),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(18.dp)
                .background(fill, CheckboxShape)
                .border(1.dp, if (checked) colors.primary else colors.border, CheckboxShape),
            contentAlignment = Alignment.Center,
        ) {
            if (checked) Icon(Res.drawable.icon_check, size = 14.dp, tint = colors.primaryForeground)
        }
        Text(label, Modifier.weight(1f))
    }
}

private val CheckboxShape = RoundedCornerShape(4.dp)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun <T> Segmented(
    options: List<T>,
    selected: T,
    label: @Composable (T) -> String,
    onSelect: (T) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val colors = Theme.colors
    FlowRow(
        modifier
            .alpha(if (enabled) 1f else 0.5f)
            .background(colors.muted, Shapes.tile)
            .border(1.dp, colors.border, Shapes.tile)
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        options.forEach { option ->
            val chosen = option == selected
            val fill by animateColorAsState(
                if (chosen) (if (colors.dark) colors.secondary else colors.background) else Color.Transparent,
                Theme.motion.hover(),
            )
            Box(
                Modifier
                    .then(if (chosen) Modifier.shadow(1.dp, Shapes.control) else Modifier)
                    .background(fill, Shapes.control)
                    .border(1.dp, if (chosen) colors.border else Color.Transparent, Shapes.control)
                    .clickable(
                        remember { MutableInteractionSource() },
                        indication = null,
                        enabled = enabled,
                        role = Role.Tab,
                        onClick = { onSelect(option) },
                    ).semantics { this.selected = chosen }
                    .defaultMinSize(minHeight = 36.dp)
                    .padding(horizontal = 14.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label(option),
                    color = if (chosen) colors.foreground else colors.mutedForeground,
                    weight = Medium,
                    maxLines = 1,
                )
            }
        }
    }
}

@Composable
fun Slider(
    value: Int,
    range: IntProgression,
    onChange: (Int) -> Unit,
    description: String,
    modifier: Modifier = Modifier,
) {
    val colors = Theme.colors
    val steps = range.toList()
    val index = steps.indexOf(value).coerceAtLeast(0)
    val fraction = if (steps.size <= 1) 0f else index.toFloat() / (steps.size - 1)
    val change by rememberUpdatedState(onChange)
    BoxWithConstraints(
        modifier
            .fillMaxWidth()
            .height(32.dp)
            .semantics {
                contentDescription = description
                progressBarRangeInfo = ProgressBarRangeInfo(value.toFloat(), range.first.toFloat()..range.last.toFloat(), steps.size - 2)
                setProgress { target ->
                    change(steps.minBy { abs(it - target) })
                    true
                }
            },
        contentAlignment = Alignment.CenterStart,
    ) {
        val width = constraints.maxWidth.toFloat()
        val travel = maxWidth - 20.dp
        fun pick(x: Float) {
            val position = (x / width).coerceIn(0f, 1f)
            change(steps[(position * (steps.size - 1)).roundToInt()])
        }
        Box(
            Modifier
                .fillMaxWidth()
                .fillMaxHeight()
                .pointerInput(steps) { detectTapGestures { pick(it.x) } }
                .pointerInput(steps) { detectHorizontalDragGestures { change, _ -> pick(change.position.x) } },
            contentAlignment = Alignment.CenterStart,
        ) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .background(colors.foreground.copy(alpha = 0.2f), Shapes.pill),
            )
            Box(
                Modifier
                    .fillMaxWidth(fraction)
                    .height(6.dp)
                    .background(colors.foreground, Shapes.pill),
            )
            Box(
                Modifier
                    .offset(x = travel * fraction)
                    .size(20.dp)
                    .background(colors.foreground, CircleShape)
                    .padding(3.dp)
                    .background(colors.background, CircleShape),
            )
        }
    }
}

@Composable
fun StrengthMeter(
    strength: Strength,
    label: String,
    modifier: Modifier = Modifier,
) {
    val colors = Theme.colors
    val (level, color) =
        when (strength) {
            Strength.Weak -> 1 to colors.danger
            Strength.Good -> 2 to colors.warning
            Strength.Strong -> 3 to colors.success
        }
    Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(3) { bar ->
                val fill by animateColorAsState(if (bar < level) color else colors.muted, Theme.motion.enter())
                Box(
                    Modifier
                        .weight(1f)
                        .height(4.dp)
                        .background(fill, Shapes.pill),
                )
            }
        }
        Text(label, Modifier.width(64.dp), color = colors.mutedForeground, maxLines = 1)
    }
}

@Composable
fun SettingRow(
    label: String,
    modifier: Modifier = Modifier,
    control: @Composable () -> Unit,
) {
    Column(modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 56.dp)
                .padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, Modifier.weight(1f), color = Theme.colors.mutedForeground)
            Box(Modifier.wrapContentWidth()) { control() }
        }
        Divider()
    }
}

@Composable
fun KeyValueRow(
    key: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 48.dp)
                .padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(key, Modifier.width(140.dp), color = Theme.colors.mutedForeground)
            Text(value, Modifier.weight(1f))
        }
        Divider()
    }
}

@Composable
fun Caption(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = Theme.colors.mutedForeground,
) {
    Text(text, modifier, style = Type.caption, color = color)
}
