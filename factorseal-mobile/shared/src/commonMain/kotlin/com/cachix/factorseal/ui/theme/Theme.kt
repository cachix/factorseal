package com.cachix.factorseal.ui.theme

import androidx.compose.animation.core.Easing
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Immutable
data class Colors(
    val background: Color,
    val foreground: Color,
    val surface: Color,
    val muted: Color,
    val mutedForeground: Color,
    val border: Color,
    val secondary: Color,
    val secondaryHover: Color,
    val selection: Color,
    val success: Color,
    val danger: Color,
    val warning: Color,
    val primaryActive: Color,
    val inputBackground: Color,
    val dark: Boolean,
) {
    val primary: Color get() = foreground
    val primaryForeground: Color get() = background
    val overlay: Color get() = Color(0xFF151515).copy(alpha = 0.56f)
    val tile: Color get() = if (dark) foreground.copy(alpha = 0.1f) else secondary
}

val LightColors =
    Colors(
        background = Color(0xFFF7F3EA),
        foreground = Color(0xFF151515),
        surface = Color(0xFFFFFCF6),
        muted = Color(0xFFEFEAE1),
        mutedForeground = Color(0xFF68635B),
        border = Color(0xFFD9D2C7),
        secondary = Color(0xFFE9E3D9),
        secondaryHover = Color(0xFFDDD6CA),
        selection = Color(0xFFD7D0C5),
        success = Color(0xFF2F6B4F),
        danger = Color(0xFFA33D32),
        warning = Color(0xFFA15C22),
        primaryActive = Color(0xFF000000),
        inputBackground = Color(0xFFF7F3EA),
        dark = false,
    )

val DarkColors =
    Colors(
        background = Color(0xFF151515),
        foreground = Color(0xFFF7F3EA),
        surface = Color(0xFF1D1D1B),
        muted = Color(0xFF242421),
        mutedForeground = Color(0xFFB9B5AC),
        border = Color(0xFF3B3934),
        secondary = Color(0xFF292825),
        secondaryHover = Color(0xFF34322E),
        selection = Color(0xFF3C3933),
        success = Color(0xFF81C995),
        danger = Color(0xFFF28B82),
        warning = Color(0xFFA15C22),
        primaryActive = Color(0xFFD8D2C8),
        inputBackground = Color(0xFF3B3934).copy(alpha = 0.3f).compositeOver(Color(0xFF151515)),
        dark = true,
    )

object Type {
    private val base = TextStyle(fontFamily = FontFamily.Default)
    val caption = base.copy(fontSize = 13.sp, lineHeight = 18.sp)
    val body = base.copy(fontSize = 15.sp, lineHeight = 21.sp)
    val lead = base.copy(fontSize = 17.sp, lineHeight = 24.sp)
    val heading = base.copy(fontSize = 20.sp, lineHeight = 26.sp, fontWeight = FontWeight.SemiBold)
    val title = base.copy(fontSize = 24.sp, lineHeight = 30.sp, fontWeight = FontWeight.SemiBold)
    val wordmark = base.copy(fontSize = 31.sp, lineHeight = 36.sp, fontWeight = FontWeight.SemiBold)
    val code = base.copy(fontFamily = FontFamily.Monospace, fontSize = 20.sp, lineHeight = 26.sp, fontWeight = FontWeight.SemiBold)
    val mono = base.copy(fontFamily = FontFamily.Monospace, fontSize = 14.sp, lineHeight = 20.sp)
}

val Semibold = FontWeight.SemiBold
val Medium = FontWeight.Medium

object Shapes {
    val control = RoundedCornerShape(7.dp)
    val input = RoundedCornerShape(6.dp)
    val tile = RoundedCornerShape(8.dp)
    val card = RoundedCornerShape(12.dp)
    val pill = RoundedCornerShape(50)
}

val EaseOutCubic = Easing { fraction -> 1f - (1f - fraction) * (1f - fraction) * (1f - fraction) }

@Immutable
data class Motion(
    val reduced: Boolean,
) {
    fun <T> enter(): FiniteAnimationSpec<T> = spec(160)

    fun <T> navigate(): FiniteAnimationSpec<T> = spec(200)

    fun <T> hover(): FiniteAnimationSpec<T> = spec(120)

    fun <T> leave(): FiniteAnimationSpec<T> = spec(140)

    fun <T> dialog(): FiniteAnimationSpec<T> = spec(250)

    private fun <T> spec(milliseconds: Int): FiniteAnimationSpec<T> = if (reduced) snap() else tween(milliseconds, easing = EaseOutCubic)
}

private val LocalColors = staticCompositionLocalOf { LightColors }
private val LocalMotion = staticCompositionLocalOf { Motion(reduced = false) }

object Theme {
    val colors: Colors
        @Composable @ReadOnlyComposable
        get() = LocalColors.current

    val motion: Motion
        @Composable @ReadOnlyComposable
        get() = LocalMotion.current
}

@Composable
fun FactorSealTheme(
    reducedMotion: Boolean,
    dark: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(
        LocalColors provides if (dark) DarkColors else LightColors,
        LocalMotion provides Motion(reducedMotion),
        content = content,
    )
}
