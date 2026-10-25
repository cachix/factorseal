package com.cachix.factorseal.android

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.VaultState
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class FactorSealAutofill : AutofillService() {
    private val scope = MainScope()
    private val app: FactorSeal get() = (application as FactorSealApplication).app

    override fun onFillRequest(
        request: FillRequest,
        cancellation: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.last().structure
        val form = structure.form()
        val site = form.site(structure.activityComponent.packageName, packageName, this::browser) ?: return callback.onSuccess(null)
        val job =
            scope.launch {
                val ready =
                    runCatching {
                        app.vault.ask<Response.Status>(Request.Start(app.host.directory, app.host.platform)).vault != VaultState.Absent
                    }.getOrDefault(false)
                callback.onSuccess(if (ready) response(form, label(site, form.domain)) else null)
            }
        cancellation.setOnCancelListener { job.cancel() }
    }

    override fun onSaveRequest(
        request: SaveRequest,
        callback: SaveCallback,
    ) {
        val form = merged(request.fillContexts.map { it.structure.form() })
        val structure = request.fillContexts.last().structure
        val site = form?.site(structure.activityComponent.packageName, packageName, this::browser)
        val password = form?.password
        if (form == null || site == null || password == null) return callback.onFailure(null)
        val token = Saves.put(PendingSave(site, label(site, form.domain), form.username.orEmpty(), password))
        val intent = Intent(this, AutofillActivity::class.java).putExtra(SAVE_TOKEN, token)
        callback.onSuccess(PendingIntent.getActivity(this, token, intent, PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE).intentSender)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun response(
        form: Form<AutofillId>,
        label: String,
    ): FillResponse {
        val intent = Intent(this, AutofillActivity::class.java)
        val authentication = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        val response = FillResponse.Builder().addDataset(dataset(suggestion(label), form.ids.associateWith { null }, authentication))
        if (form.passwords.isNotEmpty()) {
            response.setSaveInfo(
                SaveInfo
                    .Builder(SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD, form.passwords.toTypedArray())
                    .apply { if (form.usernames.isNotEmpty()) setOptionalIds(form.usernames.toTypedArray()) }
                    .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
                    .build(),
            )
        } else {
            response.setSaveInfo(
                SaveInfo
                    .Builder(SaveInfo.SAVE_DATA_TYPE_USERNAME, form.usernames.toTypedArray())
                    .setFlags(SaveInfo.FLAG_DELAY_SAVE)
                    .build(),
            )
        }
        return response.build()
    }
}
