package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Page
import com.cachix.factorseal.app.dayLabel
import com.cachix.factorseal.app.localDate
import com.cachix.factorseal.app.timeLabel
import com.cachix.factorseal.core.Access
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Requester
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Summary
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.activity
import com.cachix.factorseal.resources.deleted_secret
import com.cachix.factorseal.resources.denied
import com.cachix.factorseal.resources.denied_times
import com.cachix.factorseal.resources.glyph_clock
import com.cachix.factorseal.resources.icon_arrow_right
import com.cachix.factorseal.resources.icon_circle_x
import com.cachix.factorseal.resources.icon_eye
import com.cachix.factorseal.resources.no_activity
import com.cachix.factorseal.resources.no_activity_line
import com.cachix.factorseal.resources.open_secret
import com.cachix.factorseal.resources.read_once
import com.cachix.factorseal.resources.reads
import com.cachix.factorseal.resources.reads_title
import com.cachix.factorseal.resources.requester_app
import com.cachix.factorseal.resources.requester_application
import com.cachix.factorseal.resources.time_range
import com.cachix.factorseal.resources.type_website
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.EmptyState
import com.cachix.factorseal.ui.components.Icon
import com.cachix.factorseal.ui.components.KeyValueRow
import com.cachix.factorseal.ui.components.ListHeader
import com.cachix.factorseal.ui.components.ListRow
import com.cachix.factorseal.ui.components.PageHeader
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.theme.Medium
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Shapes
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource
import kotlin.time.Clock

class AccessLog(
    val entries: List<Access>?,
    val failure: VaultException?,
    val retry: () -> Unit,
)

@Composable
fun accessLog(app: FactorSeal): AccessLog {
    var attempt by remember { mutableIntStateOf(0) }
    var entries by remember { mutableStateOf<List<Access>?>(null) }
    var failure by remember { mutableStateOf<VaultException?>(null) }
    LaunchedEffect(app.revision, attempt) {
        try {
            entries = app.call<Response.Activity>(Request.Activity).entries
            failure = null
        } catch (error: VaultException) {
            failure = error.takeIf { it.code != ErrorCode.Sealed }
        }
    }
    return AccessLog(entries, failure) { attempt++ }
}

private fun visible(text: String): String = text
    .filter { it.category != CharCategory.CONTROL && it.category != CharCategory.FORMAT }
    .split(' ', '\n', '\t')
    .filter { it.isNotEmpty() }
    .joinToString(" ")

fun Access.requesterName(): String = visible(
    when (requester) {
        Requester.Website, Requester.Browser -> name.substringAfter("://").trimEnd('/')
        Requester.Program -> name.substringAfterLast('/')
        Requester.App -> name
    },
)

fun avatarLetter(name: String): String = name.firstOrNull { it.isLetterOrDigit() }?.uppercase() ?: "?"

@Composable
fun AppAvatar(
    name: String,
    size: Dp = 28.dp,
    style: TextStyle = Type.body,
) {
    Box(
        Modifier.size(size).background(Theme.colors.secondary, Shapes.tile),
        contentAlignment = Alignment.Center,
    ) {
        Text(avatarLetter(name), style = style, color = Theme.colors.foreground, weight = Semibold, maxLines = 1)
    }
}

class AccessGroup(
    val access: Access,
    val count: Int,
    val first: Long,
    val last: Long,
    val reads: List<Access>,
)

fun List<Access>.merged(): List<AccessGroup> = groupBy { it.copy(at = 0, count = 0) }.values.map { reads ->
    AccessGroup(reads.first(), reads.sumOf { it.count }, reads.last().at, reads.first().at, reads)
}

fun List<Access>.row(latest: Access): AccessGroup? {
    val day = localDate(latest.at)
    val read = latest.copy(at = 0, count = 0)
    return filter { localDate(it.at) == day }.merged().firstOrNull { it.access.copy(at = 0, count = 0) == read }
}

@Composable
fun outcome(
    allowed: Boolean,
    count: Int,
    always: Boolean = false,
): String? = when {
    !allowed && count == 1 -> stringResource(Res.string.denied)
    !allowed -> stringResource(Res.string.denied_times, count)
    count == 1 -> if (always) stringResource(Res.string.read_once) else null
    else -> stringResource(Res.string.reads, count)
}

@Composable
fun Outcome(
    allowed: Boolean,
    count: Int,
    always: Boolean = false,
) {
    val outcome = outcome(allowed, count, always) ?: return
    val color = if (allowed) Theme.colors.mutedForeground else Theme.colors.danger
    val background = if (allowed) Theme.colors.muted else Theme.colors.danger.copy(alpha = 0.1f)
    Row(
        Modifier
            .background(background, Shapes.pill)
            .padding(horizontal = 8.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(if (allowed) Res.drawable.icon_eye else Res.drawable.icon_circle_x, size = 12.dp, tint = color)
        Text(outcome, style = Type.caption, color = color, weight = Medium, maxLines = 1)
    }
}

@Composable
fun timeRange(
    first: Long,
    last: Long,
): String {
    val (from, to) = timeLabel(first) to timeLabel(last)
    return if (from == to) to else stringResource(Res.string.time_range, from, to)
}

@Composable
fun ActivityPage(app: FactorSeal) {
    val log = accessLog(app)
    val entries = log.entries
    val known = app.items.orEmpty().associateBy { it.id }
    val now = Clock.System.now().epochSeconds
    MainPage {
        BackRow(app)
        ListHeader(stringResource(Res.string.activity))
        when {
            log.failure != null ->
                Box(Modifier.padding(16.dp)) { ErrorNotice(log.failure, app, retry = log.retry) }

            entries == null -> Unit

            entries.isEmpty() ->
                EmptyState(
                    stringResource(Res.string.no_activity),
                    stringResource(Res.string.no_activity_line),
                    icon = Res.drawable.glyph_clock,
                )

            else -> {
                val days = entries.groupBy { localDate(it.at) }.values.toList()
                val labels = days.map { dayLabel(it.first().at, now) }
                val deleted = stringResource(Res.string.deleted_secret)
                LazyColumn(Modifier.fillMaxSize()) {
                    days.forEachIndexed { index, day ->
                        item(key = "day-${day.first().at}") { DayHeader(labels[index]) }
                        items(day.merged()) { group ->
                            val item = group.access.item?.let(known::get)
                            AccessRow(group, item, item?.title?.let(::visible) ?: deleted) {
                                app.open(Page.Reads(group.access))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DayHeader(label: String) {
    Column(Modifier.fillMaxWidth()) {
        Text(
            label,
            Modifier.padding(start = 16.dp, end = 16.dp, top = 20.dp, bottom = 8.dp),
            style = Type.lead,
            weight = Semibold,
        )
        Divider()
    }
}

@Composable
private fun AccessRow(
    group: AccessGroup,
    item: Summary?,
    secret: String,
    onClick: () -> Unit,
) {
    val muted = Theme.colors.mutedForeground
    val requester = group.access.requesterName()
    ListRow(
        onClick = onClick,
        modifier = if (group.access.allowed) Modifier else Modifier.background(Theme.colors.danger.copy(alpha = 0.06f)),
        chevron = true,
    ) {
        AppAvatar(requester)
        Column(Modifier.weight(1f)) {
            Text(secret, color = if (item == null) muted else Theme.colors.foreground, weight = Semibold, maxLines = 1)
            Text(requester, style = Type.caption, color = muted, maxLines = 1)
        }
        Outcome(group.access.allowed, group.count)
        Text(timeRange(group.first, group.last), color = muted, maxLines = 1)
    }
}

@Composable
fun ReadsPage(
    app: FactorSeal,
    latest: Access,
) {
    val row = accessLog(app).entries?.row(latest)
    val now = Clock.System.now().epochSeconds
    MainPage {
        BackRow(app)
        if (row == null) return@MainPage
        val requester = row.access.requesterName()
        val item = row.access.item?.let { id -> app.items.orEmpty().firstOrNull { it.id == id } }
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            PageHeader(
                { AppAvatar(requester, size = 56.dp, style = Type.title) },
                item?.title?.let(::visible) ?: stringResource(Res.string.deleted_secret),
                detail = "$requester · ${dayLabel(row.last, now)}",
            )
            KeyValueRow(stringResource(row.access.requester.label()), visible(row.access.name))
            if (item != null) {
                Button(stringResource(Res.string.open_secret), onClick = { app.open(Page.Entry(item.id)) }, icon = Res.drawable.icon_arrow_right)
            }
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(Res.string.reads_title), style = Type.lead, weight = Semibold)
                Column(Modifier.fillMaxWidth()) {
                    row.reads.forEach { read ->
                        Row(
                            Modifier.fillMaxWidth().defaultMinSize(minHeight = 44.dp).padding(vertical = 10.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(timeLabel(read.at), Modifier.weight(1f), weight = Medium, maxLines = 1)
                            Outcome(read.allowed, read.count, always = true)
                        }
                        Divider()
                    }
                }
            }
        }
    }
}

private fun Requester.label(): StringResource = when (this) {
    Requester.Website, Requester.Browser -> Res.string.type_website
    Requester.App -> Res.string.requester_app
    Requester.Program -> Res.string.requester_application
}
