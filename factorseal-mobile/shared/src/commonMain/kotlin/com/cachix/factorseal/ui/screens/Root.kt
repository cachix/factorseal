package com.cachix.factorseal.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.CLIPBOARD_SECONDS
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Phase
import com.cachix.factorseal.app.Toast
import com.cachix.factorseal.app.text
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.clears_in
import com.cachix.factorseal.resources.copied_to_clipboard
import com.cachix.factorseal.resources.dismiss
import com.cachix.factorseal.resources.glyph_close
import com.cachix.factorseal.resources.icon_check
import com.cachix.factorseal.resources.icon_circle_x
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.ButtonSize
import com.cachix.factorseal.ui.components.Icon
import com.cachix.factorseal.ui.components.IconButton
import com.cachix.factorseal.ui.components.LayerHost
import com.cachix.factorseal.ui.components.Layers
import com.cachix.factorseal.ui.components.Spinner
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.components.afterAMoment
import com.cachix.factorseal.ui.components.entering
import com.cachix.factorseal.ui.theme.FactorSealTheme
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.pluralStringResource
import org.jetbrains.compose.resources.stringResource
import kotlin.math.ceil

private fun Phase.key(settings: Boolean): String = when {
    settings && this !is Phase.Unsealed -> "settings"
    this is Phase.Starting -> "starting"
    this is Phase.Setup -> "setup"
    this is Phase.Creating -> "creating"
    this is Phase.Sealed -> "sealed"
    this is Phase.Sealing -> "sealing"
    this is Phase.Unavailable -> "error"
    else -> "unsealed"
}

@Composable
fun AppFrame(
    app: FactorSeal,
    layers: Layers,
    content: @Composable BoxScope.() -> Unit,
) {
    FactorSealTheme(reducedMotion = app.preferences.reducedMotion) {
        LaunchedEffect(app) { app.start() }
        val focused = LocalWindowInfo.current.isWindowFocused
        LaunchedEffect(focused) { if (focused) app.focused() }
        LayerHost(layers) {
            Box(
                Modifier
                    .fillMaxSize()
                    .background(Theme.colors.background)
                    .pointerInput(app) {
                        awaitPointerEventScope {
                            while (true) {
                                awaitPointerEvent(PointerEventPass.Initial)
                                app.active()
                            }
                        }
                    },
                content = content,
            )
        }
    }
}

@Composable
fun Starting() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Spinner(Modifier.afterAMoment(), size = 24.dp, color = Theme.colors.mutedForeground)
    }
}

@Composable
fun FactorSealApp(app: FactorSeal) {
    AppFrame(app, app.layers) {
        Screens(app)
        Notices(app)
    }
}

@Composable
private fun Screens(app: FactorSeal) {
    val motion = Theme.motion
    val focus = LocalFocusManager.current
    val key = app.phase.key(app.settingsOpen)
    LaunchedEffect(key) { focus.clearFocus() }
    val travel = with(LocalDensity.current) { 6.dp.roundToPx() }
    AnimatedContent(
        targetState = app.phase to app.settingsOpen,
        contentKey = { (phase, settings) -> phase.key(settings) },
        transitionSpec = { (fadeIn(motion.enter()) + slideInVertically(motion.enter()) { travel }) togetherWith fadeOut(motion.leave()) },
    ) { (phase, _) ->
        when (phase) {
            Phase.Starting -> Starting()
            Phase.Setup -> SetupScreen(app)
            Phase.Creating -> ProgressScreen(app, creating = true)
            is Phase.Sealed -> SealedScreen(app)
            Phase.Sealing -> ProgressScreen(app, creating = false)
            is Phase.Unavailable -> UnavailableScreen(app, phase.failure)
            Phase.Unsealed -> VaultScreen(app)
        }
    }
}

@Composable
private fun BoxScope.Notices(app: FactorSeal) {
    Column(
        Modifier
            .align(Alignment.BottomCenter)
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .padding(bottom = if (app.phase == Phase.Unsealed && app.pages.isEmpty()) 60.dp else 0.dp)
            .widthIn(max = 480.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        app.toasts.forEach { toast -> key(toast.id) { ToastPill(app, toast) } }
        app.clip?.let { clip -> key(clip) { ClipNotice(app) } }
    }
}

@Composable
private fun Notice(
    modifier: Modifier = Modifier,
    content: @Composable RowScope.() -> Unit,
) {
    Box(
        Modifier
            .entering(Unit)
            .shadow(6.dp, Shapes.input)
            .background(Theme.colors.surface, Shapes.input)
            .border(1.dp, Theme.colors.border, Shapes.input)
            .clip(Shapes.input),
    ) {
        Row(
            modifier.padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            content = content,
        )
    }
}

@Composable
private fun ToastPill(
    app: FactorSeal,
    toast: Toast,
) {
    Notice {
        Icon(
            if (toast.error) Res.drawable.icon_circle_x else Res.drawable.icon_check,
            size = 16.dp,
            tint = if (toast.error) Theme.colors.danger else Theme.colors.success,
        )
        Text(toast.message.text(), Modifier.weight(1f, fill = false), style = Type.caption)
        toast.action?.let { action ->
            Button(
                action.label.text(),
                onClick = {
                    app.dismiss(toast)
                    app.run(action.run)
                },
                variant = Variant.Ghost,
                size = ButtonSize.XSmall,
            )
        }
        IconButton(Res.drawable.glyph_close, stringResource(Res.string.dismiss), onClick = { app.dismiss(toast) }, size = ButtonSize.XSmall)
    }
}

@Composable
private fun ClipNotice(app: FactorSeal) {
    val clip = app.clip ?: return
    val total = CLIPBOARD_SECONDS * 1000
    val remaining = remember(clip) { Animatable((1f - clip.copied.elapsedNow().inWholeMilliseconds.toFloat() / total).coerceIn(0f, 1f)) }
    LaunchedEffect(clip) { remaining.animateTo(0f, tween((remaining.value * total).toInt(), easing = LinearEasing)) }
    val left by remember(clip) { derivedStateOf { ceil(remaining.value * CLIPBOARD_SECONDS).toInt() } }
    val bar = Theme.colors.primary
    Notice(
        Modifier.drawBehind {
            val height = 2.dp.toPx()
            drawRect(bar, Offset(0f, size.height - height), Size(size.width * remaining.value, height))
        },
    ) {
        Icon(Res.drawable.icon_check, size = 16.dp, tint = Theme.colors.success)
        Text(stringResource(Res.string.copied_to_clipboard), style = Type.caption)
        Text(pluralStringResource(Res.plurals.clears_in, left, left), style = Type.caption, color = Theme.colors.mutedForeground)
        IconButton(Res.drawable.glyph_close, stringResource(Res.string.dismiss), onClick = app::dismissClip, size = ButtonSize.XSmall)
    }
}
