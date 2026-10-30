package com.cachix.factorseal.android

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.content.IntentCompat
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.ui.screens.AutofillSaveScreen
import com.cachix.factorseal.ui.screens.AutofillScreen
import com.cachix.factorseal.ui.screens.AutofillTask

class AutofillActivity : ComponentActivity() {
    private val token: Int get() = intent.getIntExtra(SAVE_TOKEN, 0)
    private var request = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        protectWindow()
        enableEdgeToEdge()
        val save = Saves.get(token)
        if (save != null) {
            setContent { AutofillSaveScreen(session, save.task, save.site, save.label, save.username, save.password, onDone = ::saved) }
            return
        }
        val structure = IntentCompat.getParcelableExtra(intent, AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        val form = structure?.form()
        val site = structure?.let { form?.site(it.activityComponent.packageName, packageName, this::browser) }
        if (form == null || site == null) {
            finish()
            return
        }
        request = savedInstanceState?.getInt(FILL_TOKEN) ?: 0
        val task = Fills.get(request) ?: AutofillTask<Response.Credentials>().also { request = Fills.put(it) }
        val shown = label(site, form.domain)
        setContent { AutofillScreen(session, task, site, shown, onFill = { fill(form, shown, it) }, onClose = ::finish) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(FILL_TOKEN, request)
    }

    override fun onResume() {
        super.onResume()
        Biometrics.attach(this)
    }

    override fun onDestroy() {
        if (isFinishing) {
            Saves.remove(token)
            Fills.remove(request)
        }
        super.onDestroy()
    }

    private fun fill(
        form: Form<AutofillId>,
        label: String,
        credentials: Response.Credentials,
    ) {
        val values =
            form.usernames.associateWith { AutofillValue.forText(credentials.username) } +
                form.passwords.associateWith { AutofillValue.forText(credentials.password) }
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset(suggestion(label), values)))
        finish()
    }

    private fun saved(message: String?) {
        message?.let { Toast.makeText(this, it, Toast.LENGTH_SHORT).show() }
        finish()
    }
}
