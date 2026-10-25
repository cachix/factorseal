package com.cachix.factorseal.android

import android.content.Context
import android.content.IntentSender
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.Presentations
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.cachix.factorseal.R
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Site
import com.cachix.factorseal.ui.screens.AutofillTask
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.minutes
import kotlin.time.TimeMark
import kotlin.time.TimeSource

class PendingSave(
    val site: Site,
    val label: String,
    val username: String,
    val password: String,
) {
    val task = AutofillTask<String>()
}

open class Pending<T : Any> {
    private val lifetime = 10.minutes
    private val tokens = AtomicInteger()
    private val pending = ConcurrentHashMap<Int, Pair<TimeMark, T>>()

    fun put(value: T): Int {
        pending.values.removeIf { (created) -> created.elapsedNow() > lifetime }
        return tokens.incrementAndGet().also { pending[it] = TimeSource.Monotonic.markNow() to value }
    }

    fun get(token: Int): T? = pending[token]?.takeIf { (created) -> created.elapsedNow() <= lifetime }?.second

    fun remove(token: Int) {
        pending.remove(token)
    }
}

object Saves : Pending<PendingSave>()

object Fills : Pending<AutofillTask<Response.Credentials>>()

const val SAVE_TOKEN = "com.cachix.factorseal.SAVE_TOKEN"
const val FILL_TOKEN = "com.cachix.factorseal.FILL_TOKEN"

fun Context.label(
    site: Site,
    domain: String?,
): String = site.app?.let { application ->
    runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(application, 0)).toString() }.getOrDefault(application)
} ?: domain ?: site.web.orEmpty()

fun Context.suggestion(detail: String): RemoteViews = RemoteViews(packageName, R.layout.autofill_suggestion).apply {
    setTextViewText(R.id.title, getString(R.string.autofill_suggestion))
    setTextViewText(R.id.detail, detail)
}

fun dataset(
    presentation: RemoteViews,
    values: Map<AutofillId, AutofillValue?>,
    authentication: IntentSender? = null,
): Dataset {
    val builder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Dataset.Builder(Presentations.Builder().setMenuPresentation(presentation).build()).apply {
                values.forEach { (id, value) -> setField(id, Field.Builder().apply { value?.let(::setValue) }.build()) }
            }
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(presentation).apply { values.forEach { (id, value) -> setValue(id, value) } }
        }
    authentication?.let(builder::setAuthentication)
    return builder.build()
}
