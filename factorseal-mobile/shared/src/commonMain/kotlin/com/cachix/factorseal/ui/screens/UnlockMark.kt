package com.cachix.factorseal.ui.screens

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.glyph_mark
import com.cachix.factorseal.ui.components.Mark
import com.cachix.factorseal.ui.theme.Theme
import org.jetbrains.compose.resources.painterResource
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sign
import kotlin.math.sin
import kotlin.math.sqrt

private const val VIEWBOX = 160f
private const val KEYHOLE_OFFSET = 65.644f - VIEWBOX / 2f

private class Vertex(
    val x: Float,
    val y: Float,
    val z: Float,
) {
    fun turn(angle: Float): Vertex = Vertex(x * cos(angle) - y * sin(angle), x * sin(angle) + y * cos(angle), z)

    fun depth(): Float = x * 0.8f - y * 0.24f + z
}

private class Face(
    val vertices: List<Vertex>,
    val color: Color,
)

private fun shaded(
    vertices: List<Vertex>,
    color: Color,
): Face {
    val a = vertices[0]
    val first = Vertex(vertices[1].x - a.x, vertices[1].y - a.y, vertices[1].z - a.z)
    val second = Vertex(vertices[2].x - a.x, vertices[2].y - a.y, vertices[2].z - a.z)
    val normal =
        Vertex(
            first.y * second.z - first.z * second.y,
            first.z * second.x - first.x * second.z,
            first.x * second.y - first.y * second.x,
        )
    val length = sqrt(normal.x * normal.x + normal.y * normal.y + normal.z * normal.z)
    val light = (-0.4f * normal.x - 0.65f * normal.y + 0.65f * normal.z) * normal.depth().sign / max(length, 0.001f)
    val shading = 0.08f + 0.10f * (1f - light.coerceIn(-1f, 1f))
    return Face(vertices, lightened(color, shading))
}

private fun lightened(
    color: Color,
    amount: Float,
): Color {
    val high = max(color.red, max(color.green, color.blue))
    val low = min(color.red, min(color.green, color.blue))
    val lightness = (high + low) / 2f
    val delta = high - low
    val saturation = if (delta == 0f) 0f else delta / (1f - abs(2f * lightness - 1f))
    val hue =
        when {
            delta == 0f -> 0f
            high == color.red -> 60f * (((color.green - color.blue) / delta).mod(6f))
            high == color.green -> 60f * ((color.blue - color.red) / delta + 2f)
            else -> 60f * ((color.red - color.green) / delta + 4f)
        }
    val target = (lightness + if (lightness > 0.5f) -amount else amount).coerceIn(0f, 1f)
    return Color.hsl(hue, saturation.coerceIn(0f, 1f), target)
}

private fun solid(
    faces: MutableList<Face>,
    front: List<Vertex>,
    back: List<Vertex>,
    color: Color,
) {
    faces.add(Face(back, color))
    for (index in front.indices) {
        val next = (index + 1) % front.size
        faces.add(shaded(listOf(front[index], back[index], back[next], front[next]), color))
    }
    faces.add(Face(front, color))
}

private fun smooth(
    phase: Float,
    start: Float,
    end: Float,
): Float {
    val progress = ((phase - start) / (end - start)).coerceIn(0f, 1f)
    return progress * progress * (3f - 2f * progress)
}

private fun bow(
    step: Int,
    halfWidth: Float,
    halfHeight: Float,
    radius: Float,
): Pair<Float, Float> {
    val corner = (step / 8) % 4
    val angle = (-PI / 2 + corner * PI / 2 + (step % 8) * PI / 16).toFloat()
    val x = if (corner < 2) halfWidth - radius else radius - halfWidth
    val z = if (corner == 0 || corner == 3) radius - halfHeight else halfHeight - radius
    return (x + radius * cos(angle)) to (128f + z + radius * sin(angle))
}

private fun key(
    phase: Float,
    ink: Color,
): List<Face> {
    val faces = ArrayList<Face>(320)
    val insertion = smooth(phase, 0.18f, 0.44f) - smooth(phase, 0.90f, 0.99f)
    val turn = (smooth(phase, 0.54f, 0.69f) - smooth(phase, 0.79f, 0.87f)) * PI.toFloat() * 0.5f
    val tip = 54f - insertion * 112f
    fun plate(outline: List<Pair<Float, Float>>) {
        fun layer(y: Float) = outline.map { (x, z) -> Vertex(y, x, max(z + tip, 3f)).turn(turn) }
        solid(faces, layer(-3.5f), layer(3.5f), ink)
    }
    plate(listOf(-4.5f to 0f, 4.5f to 0f, 4.5f to 103f, -4.5f to 103f))
    for (z in listOf(6f, 20f, 34f)) {
        if (tip + z + 8f > 3f) plate(listOf(4.5f to z, 14f to z, 14f to z + 8f, 4.5f to z + 8f))
    }
    for (step in 0 until 32) {
        plate(listOf(bow(step, 28f, 32f, 3f), bow(step + 1, 28f, 32f, 3f), bow(step + 1, 18f, 22f, 2f), bow(step, 18f, 22f, 2f)))
    }
    return faces.sortedBy { face -> face.vertices.sumOf { it.depth().toDouble() } / face.vertices.size }
}

@Composable
fun UnlockMark(
    unlocking: Boolean,
    modifier: Modifier = Modifier,
) {
    val ink = Theme.colors.foreground
    Box(
        modifier
            .size(width = 260.dp, height = 104.dp)
            .clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        if (!unlocking || Theme.motion.reduced) {
            Mark(72.dp, tint = ink)
        } else {
            Turning(ink)
        }
    }
}

@Composable
private fun Turning(ink: Color) {
    val painter = painterResource(Res.drawable.glyph_mark)
    val intro = remember { Animatable(0f) }
    LaunchedEffect(Unit) { intro.animateTo(1f, tween(450, easing = LinearEasing)) }
    val phase by rememberInfiniteTransition()
        .animateFloat(0f, 1f, infiniteRepeatable(tween(3000, easing = LinearEasing), RepeatMode.Restart))
    Canvas(Modifier.size(width = 260.dp, height = 104.dp)) {
        val reveal = smooth(intro.value, 0f, 1f)
        val unit = size.width / 260f
        val markSize = (72f - 20f * reveal) * unit
        val shift = 20f * reveal * unit
        val center = Offset(size.width / 2f + shift, size.height / 2f)
        translate(center.x - markSize / 2f, center.y - markSize / 2f) {
            with(painter) { draw(Size(markSize, markSize), colorFilter = ColorFilter.tint(ink)) }
        }
        val opacity = smooth(reveal, 0.8f, 1f)
        if (opacity == 0f) return@Canvas
        val scale = (72f + 28f * reveal) / VIEWBOX * unit
        val keyhole = KEYHOLE_OFFSET * (72f - 20f * reveal) / VIEWBOX * unit
        for (face in key(phase, ink)) {
            val path = Path()
            face.vertices.forEachIndexed { index, vertex ->
                val x = size.width / 2f + shift + (vertex.x - vertex.z * 0.8f) * scale
                val y = size.height / 2f + (vertex.y + vertex.x * 0.3f) * scale + keyhole
                if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            path.close()
            drawPath(path, face.color.copy(alpha = opacity))
        }
    }
}
