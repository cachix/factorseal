package com.cachix.factorseal.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.glyph_mark
import com.cachix.factorseal.resources.glyph_mark_micro
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.painterResource

@Composable
fun Text(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = Type.body,
    color: Color = Theme.colors.foreground,
    weight: FontWeight? = null,
    align: TextAlign? = null,
    maxLines: Int = Int.MAX_VALUE,
) {
    BasicText(
        text = text,
        modifier = modifier,
        style = style.merge(color = color, fontWeight = weight, textAlign = align ?: TextAlign.Unspecified),
        overflow = TextOverflow.Ellipsis,
        maxLines = maxLines,
    )
}

@Composable
fun Text(
    text: AnnotatedString,
    modifier: Modifier = Modifier,
    style: TextStyle = Type.body,
    color: Color = Theme.colors.foreground,
    weight: FontWeight? = null,
    maxLines: Int = Int.MAX_VALUE,
) {
    BasicText(
        text = text,
        modifier = modifier,
        style = style.merge(color = color, fontWeight = weight),
        overflow = TextOverflow.Ellipsis,
        maxLines = maxLines,
    )
}

@Composable
fun Icon(
    icon: DrawableResource,
    modifier: Modifier = Modifier,
    size: Dp = 16.dp,
    tint: Color = Theme.colors.foreground,
    description: String? = null,
) {
    Image(
        painter = painterResource(icon),
        contentDescription = description,
        modifier = modifier.size(size),
        colorFilter = ColorFilter.tint(tint),
    )
}

@Composable
fun Mark(
    size: Dp,
    modifier: Modifier = Modifier,
    tint: Color = Theme.colors.foreground,
) {
    Icon(
        icon = if (size < 32.dp) Res.drawable.glyph_mark_micro else Res.drawable.glyph_mark,
        modifier = modifier.clearAndSetSemantics {},
        size = size,
        tint = tint,
    )
}

@Composable
fun Spinner(
    modifier: Modifier = Modifier,
    size: Dp = 16.dp,
    color: Color = Theme.colors.foreground,
) {
    val turn by rememberInfiniteTransition()
        .animateFloat(0f, 360f, infiniteRepeatable(tween(800, easing = LinearEasing), RepeatMode.Restart))
    Canvas(modifier.size(size)) {
        val stroke = this.size.minDimension * 0.12f
        drawArc(
            color = color.copy(alpha = 0.2f),
            startAngle = 0f,
            sweepAngle = 360f,
            useCenter = false,
            style = Stroke(stroke),
        )
        drawArc(
            color = color,
            startAngle = turn - 90f,
            sweepAngle = 90f,
            useCenter = false,
            style = Stroke(stroke, cap = StrokeCap.Round),
        )
    }
}

@Composable
fun Ring(
    fraction: Float,
    color: Color,
    modifier: Modifier = Modifier,
    size: Dp = 20.dp,
) {
    val shown by animateFloatAsState(fraction, Theme.motion.hover())
    Canvas(modifier.size(size)) {
        val stroke = this.size.minDimension * 0.15f
        val inset = stroke / 2
        val arcSize = Size(this.size.width - stroke, this.size.height - stroke)
        val origin = Offset(inset, inset)
        drawArc(color.copy(alpha = 0.2f), 0f, 360f, false, origin, arcSize, style = Stroke(stroke))
        drawArc(color, -90f, 360f * shown, false, origin, arcSize, style = Stroke(stroke))
    }
}

@Composable
fun Divider(modifier: Modifier = Modifier) {
    Box(
        modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(Theme.colors.border),
    )
}

@Composable
fun Dot(
    color: Color,
    modifier: Modifier = Modifier,
    size: Dp = 8.dp,
) {
    Box(
        modifier
            .size(size)
            .background(color, Shapes.pill),
    )
}

@Composable
fun Back(
    enabled: Boolean = true,
    onBack: () -> Unit,
) {
    NavigationBackHandler(rememberNavigationEventState(NavigationEventInfo.None), isBackEnabled = enabled, onBackCompleted = onBack)
}
